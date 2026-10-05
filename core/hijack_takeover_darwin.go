//go:build darwin

package fastime

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// darwinDNSSnapshotFile 快照持久化文件（工作目录）：进程被强杀后各网络
// 服务的 DNS 仍指向 127.0.0.1，下次启动先按此文件恢复再重新接管，
// 避免快照被污染成 127.0.0.1 本身。
const darwinDNSSnapshotFile = "fastime-darwin-dns-snapshot.json"

// takeoverSystemDNS macOS 接管：把所有启用的网络服务（Wi-Fi / Ethernet /
// USB 共享等）的 DNS 指到 127.0.0.1，快照原设置持久化到文件，退出时恢复
// （原 DHCP 的恢复成 empty 即自动获取，原静态的恢复成原列表）。看门狗每
// 5s 复查：运行中新出现的网络服务/VPN 立即接管（泄漏窗口 ≤5s）。
// 需要 root（sudo）运行。
//
// 已知残余泄漏面（README 亦注明）：通过 scutil/配置描述文件安装的
// "作用域解析器"（VPN split-DNS 按域名指定服务器）优先级高于全局 127.0.0.1，
// 这类按域名的查询不经过本拦截器；硬编码外部 DNS 且不走系统解析器的程序同理。
func (s *Server) takeoverSystemDNS() (func(), error) {
	// 崩溃恢复：上次强杀残留的快照先还原
	if old, err := loadDarwinDNSSnapshots(); err == nil && len(old) > 0 {
		s.log.Infof("53 劫持：发现上次异常退出的 DNS 快照（%d 个网络服务），先恢复原设置", len(old))
		restoreDarwinDNS(old)
		_ = os.Remove(darwinDNSSnapshotFile)
	}

	services := darwinListServices()
	if len(services) == 0 {
		return nil, fmt.Errorf("未找到可用网络服务")
	}
	snaps := map[string][]string{} // 服务名 → 原 DNS（空 = DHCP）
	for _, svc := range services {
		snaps[svc] = darwinGetDNS(svc)
		if err := darwinSetLocalDNS(svc); err != nil {
			s.log.Infof("53 劫持：网络服务 %q DNS 指向 127.0.0.1 失败（忽略）: %v", svc, err)
			delete(snaps, svc)
			continue
		}
		s.log.Infof("53 劫持：网络服务 %q 的系统 DNS 已指向 127.0.0.1（原 %v）", svc, snaps[svc])
	}
	if len(snaps) == 0 {
		return nil, fmt.Errorf("所有网络服务的 DNS 接管均失败（需 sudo 运行？）")
	}
	saveDarwinDNSSnapshots(snaps)
	darwinFlushDNSCache()

	// 看门狗：接管后新出现的网络服务（VPN/热点/新位置）每 5s 发现并接管
	stop := make(chan struct{})
	go func() {
		tk := time.NewTicker(5 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
			}
			changed := false
			for _, svc := range darwinListServices() {
				cur := darwinGetDNS(svc)
				if len(cur) == 1 && cur[0] == "127.0.0.1" {
					continue // 已接管
				}
				if _, known := snaps[svc]; !known {
					snaps[svc] = cur // 新服务：先快照原设置
				}
				if err := darwinSetLocalDNS(svc); err != nil {
					continue
				}
				s.log.Infof("53 劫持：看门狗接管新网络服务 %q（原 %v）", svc, cur)
				changed = true
			}
			if changed {
				saveDarwinDNSSnapshots(snaps)
				darwinFlushDNSCache()
			}
		}
	}()

	return func() {
		close(stop)
		restoreDarwinDNS(snaps)
		_ = os.Remove(darwinDNSSnapshotFile)
	}, nil
}

// darwinListServices 列出全部启用的网络服务（跳过 "*" 前缀的已禁用服务）。
func darwinListServices() []string {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil
	}
	var svcs []string
	for _, line := range strings.Split(string(out), "\n") {
		svc := strings.TrimSpace(line)
		if svc == "" || strings.HasPrefix(svc, "An asterisk") || strings.HasPrefix(svc, "*") {
			continue
		}
		svcs = append(svcs, svc)
	}
	return svcs
}

// darwinGetDNS 读服务当前 DNS；"There aren't any DNS Servers set"（DHCP）→ 空列表。
func darwinGetDNS(svc string) []string {
	cur, _ := exec.Command("networksetup", "-getdnsservers", svc).Output()
	var prev []string
	for _, l := range strings.Split(string(cur), "\n") {
		l = strings.TrimSpace(l)
		if ip := parseDNSLineIP(l); ip != "" {
			prev = append(prev, ip)
		}
	}
	return prev
}

// darwinSetLocalDNS 把服务的 DNS 指向本机拦截器。
func darwinSetLocalDNS(svc string) error {
	out, err := exec.Command("networksetup", "-setdnsservers", svc, "127.0.0.1").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// darwinFlushDNSCache 清系统解析缓存，让接管/恢复立即生效。
func darwinFlushDNSCache() {
	_ = exec.Command("dscacheutil", "-flushcache").Run()
	_ = exec.Command("killall", "-HUP", "mDNSResponder").Run()
}

// restoreDarwinDNS 按快照恢复各服务 DNS（空列表 = 恢复 DHCP 自动获取）。
func restoreDarwinDNS(snaps map[string][]string) {
	for svc, servers := range snaps {
		if len(servers) == 0 {
			_ = exec.Command("networksetup", "-setdnsservers", svc, "empty").Run()
		} else {
			args := append([]string{"-setdnsservers", svc}, servers...)
			_ = exec.Command("networksetup", args...).Run()
		}
	}
	darwinFlushDNSCache()
}

// loadDarwinDNSSnapshots / saveDarwinDNSSnapshots 快照文件读写（崩溃恢复用）。
func loadDarwinDNSSnapshots() (map[string][]string, error) {
	data, err := os.ReadFile(darwinDNSSnapshotFile)
	if err != nil {
		return nil, err
	}
	var snaps map[string][]string
	if err := json.Unmarshal(data, &snaps); err != nil {
		return nil, err
	}
	return snaps, nil
}

func saveDarwinDNSSnapshots(snaps map[string][]string) {
	data, err := json.Marshal(snaps)
	if err != nil {
		return
	}
	tmp := darwinDNSSnapshotFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err == nil {
		_ = os.Rename(tmp, darwinDNSSnapshotFile)
	}
}

// parseDNSLineIP 校验一行是否为纯 IP（过滤 networksetup 的提示文本）。
func parseDNSLineIP(s string) string {
	if net.ParseIP(s) != nil {
		return s
	}
	return ""
}
