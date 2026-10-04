//go:build windows

package fastime

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// winDNSSnapshot 一张网卡接管前的 DNS 设置快照（退出/崩溃恢复用）。
type winDNSSnapshot struct {
	Name    string   `json:"name"`
	GUID    string   `json:"guid"`
	Servers []string `json:"servers"` // 原静态 DNS；空 = DHCP 自动获取
	DHCP    bool     `json:"dhcp"`
}

// winDNSSnapshotFile 快照持久化文件（工作目录）：进程被强杀后 DNS 仍指向
// 127.0.0.1，下次启动先按此文件恢复原设置再重新接管，避免快照被污染成
// 127.0.0.1 本身。
const winDNSSnapshotFile = "fastime-windns-snapshot.json"

const ifTypeLoopback = 24 // IF_TYPE_SOFTWARE_LOOPBACK

// allUpInterfaces 枚举所有在线网卡（含 VPN 虚拟网卡）。
// Windows 8+ 的多宿主并行解析会同时向所有在线网卡的 DNS 发查询并采纳最快
// 应答——只接管物理网卡的话，在线 VPN 网卡（TAP/Wintun…）的 DNS 就是泄漏
// 通道，所以接管范围必须是"全部在线网卡"，与物理网卡识别（virtualIfKeywords）
// 的用途相反：那里是挑真实 DNS 来源，这里是堵泄漏。
func allUpInterfaces() []winIface {
	var size uint32
	_ = windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, nil, &size)
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	if err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, aa, &size); err != nil {
		return nil
	}
	var out []winIface
	for p := aa; p != nil; p = p.Next {
		if p.OperStatus != ifOperStatusUp || p.IfType == ifTypeLoopback {
			continue
		}
		guid := windows.BytePtrToString(p.AdapterName)
		if guid == "" {
			continue
		}
		out = append(out, winIface{
			guid: guid,
			name: windows.UTF16PtrToString(p.FriendlyName),
		})
	}
	return out
}

// ifaceV4NameServer 读网卡 IPv4 静态 DNS（NameServer 值，可能逗号/空格分隔）。
func ifaceV4NameServer(guid string) []string {
	sk, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\`+guid, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer sk.Close()
	v, _, err := sk.GetStringValue("NameServer")
	if err != nil {
		return nil
	}
	var out []string
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
		if validDNSIP(f) {
			out = append(out, f)
		}
	}
	return out
}

// ifaceTakenOver 该网卡当前 DNS 是否已指向本机（127.0.0.1）。
func ifaceTakenOver(guid string) bool {
	ns := ifaceV4NameServer(guid)
	return len(ns) == 1 && ns[0] == "127.0.0.1"
}

// takeoverSystemDNS Windows 接管：把所有在线网卡（物理+虚拟）的 DNS
// （IPv4+IPv6）静态指到 127.0.0.1 / ::1，快照原设置持久化到文件，退出时
// 恢复（原 DHCP 的恢复成自动获取，原静态的恢复成原列表）。看门狗每 5s
// 复查：新上线/被 VPN 客户端改写的网卡立即重新接管。需要管理员权限。
func (s *Server) takeoverSystemDNS() (func(), error) {
	// 崩溃恢复：上次强杀残留的快照先还原（此时系统 DNS 多半还指着 127.0.0.1，
	// 直接快照会把"原设置"记成 127.0.0.1）
	if old, err := loadWinDNSSnapshots(); err == nil && len(old) > 0 {
		s.log.Infof("53 劫持：发现上次异常退出的 DNS 快照（%d 张网卡），先恢复原设置", len(old))
		s.restoreWindowsDNS(old)
		_ = os.Remove(winDNSSnapshotFile)
	}

	ifs := allUpInterfaces()
	if len(ifs) == 0 {
		return nil, fmt.Errorf("未识别到在线网卡，无法接管系统 DNS")
	}
	snaps := map[string]winDNSSnapshot{}
	for _, ifa := range ifs {
		sn, err := s.takeoverOneInterface(ifa)
		if err != nil {
			s.restoreWindowsDNS(mapsValues(snaps))
			return nil, err
		}
		snaps[sn.GUID] = sn
	}
	saveWinDNSSnapshots(mapsValues(snaps))
	_ = exec.Command("ipconfig", "/flushdns").Run() // 清系统解析器缓存，立即生效

	// 看门狗：运行中新出现的网卡/VPN、被 VPN 客户端周期性改写的 DNS，
	// 每 5s 复查并重新接管（泄漏窗口 ≤5s）
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
			for _, ifa := range allUpInterfaces() {
				if ifaceTakenOver(ifa.guid) {
					continue
				}
				sn, err := s.takeoverOneInterface(ifa)
				if err != nil {
					s.log.Errorf("53 劫持：网卡 %q 接管失败（该网卡 DNS 可能泄漏）: %v", ifa.name, err)
					continue
				}
				if _, known := snaps[sn.GUID]; !known {
					snaps[sn.GUID] = sn
				}
				changed = true
			}
			if changed {
				saveWinDNSSnapshots(mapsValues(snaps))
				_ = exec.Command("ipconfig", "/flushdns").Run()
			}
		}
	}()

	return func() {
		close(stop)
		s.restoreWindowsDNS(mapsValues(snaps))
		_ = os.Remove(winDNSSnapshotFile)
	}, nil
}

// takeoverOneInterface 快照并接管单张网卡（IPv4 指 127.0.0.1，IPv6 指 ::1）。
func (s *Server) takeoverOneInterface(ifa winIface) (winDNSSnapshot, error) {
	ifa.fillDNS()
	sn := winDNSSnapshot{Name: ifa.name, GUID: ifa.guid, Servers: ifa.servers, DHCP: ifa.dhcpDNS}
	if out, err := exec.Command("netsh", "interface", "ip", "set", "dns",
		"name="+ifa.name, "static", "127.0.0.1").CombinedOutput(); err != nil {
		return sn, fmt.Errorf("netsh 设置网卡 %q DNS 失败（需管理员权限）: %v (%s)",
			ifa.name, err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("netsh", "interface", "ipv6", "set", "dnsservers",
		ifa.name, "static", "::1").CombinedOutput(); err != nil {
		s.log.Infof("53 劫持：网卡 %q IPv6 DNS 指向 ::1 失败（忽略）: %v (%s)",
			ifa.name, err, strings.TrimSpace(string(out)))
	}
	s.log.Infof("53 劫持：网卡 %q 的系统 DNS 已指向 127.0.0.1（原 %v）", ifa.name, ifa.servers)
	return sn, nil
}

// restoreWindowsDNS 按快照恢复各网卡 DNS 设置。
func (s *Server) restoreWindowsDNS(snaps []winDNSSnapshot) {
	for _, sn := range snaps {
		if sn.DHCP || len(sn.Servers) == 0 {
			_ = exec.Command("netsh", "interface", "ip", "set", "dns", "name="+sn.Name, "dhcp").Run()
			_ = exec.Command("netsh", "interface", "ipv6", "set", "dnsservers", sn.Name, "dhcp").Run()
			continue
		}
		_ = exec.Command("netsh", "interface", "ip", "set", "dns",
			"name="+sn.Name, "static", sn.Servers[0]).Run()
		for _, extra := range sn.Servers[1:] {
			_ = exec.Command("netsh", "interface", "ip", "add", "dns", "name="+sn.Name, extra).Run()
		}
	}
	_ = exec.Command("ipconfig", "/flushdns").Run()
	s.log.Infof("53 劫持：系统 DNS 已恢复原设置（%d 张网卡）", len(snaps))
}

// loadWinDNSSnapshots / saveWinDNSSnapshots 快照文件读写（崩溃恢复用）。
func loadWinDNSSnapshots() ([]winDNSSnapshot, error) {
	data, err := os.ReadFile(winDNSSnapshotFile)
	if err != nil {
		return nil, err
	}
	var snaps []winDNSSnapshot
	if err := json.Unmarshal(data, &snaps); err != nil {
		return nil, err
	}
	return snaps, nil
}

func saveWinDNSSnapshots(snaps []winDNSSnapshot) {
	data, err := json.Marshal(snaps)
	if err != nil {
		return
	}
	tmp := winDNSSnapshotFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err == nil {
		_ = os.Rename(tmp, winDNSSnapshotFile)
	}
}

// mapsValues map → slice（避免引入泛型工具依赖）。
func mapsValues(m map[string]winDNSSnapshot) []winDNSSnapshot {
	out := make([]winDNSSnapshot, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}
