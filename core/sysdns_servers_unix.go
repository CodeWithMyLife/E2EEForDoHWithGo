//go:build !windows && !android && !ios && (!darwin || !cgo)

package fastime

import (
	"net"
	"os"
	"runtime"
	"strings"
)

// systemDNSServers 读取 /etc/resolv.conf 的 nameserver 行。
// 覆盖：Linux、macOS/iOS 的无 cgo 构建（回退途径；cgo 构建走 libresolv 更准）。
//
// VPN/代理程序接管全局流量时常把 resolv.conf 改写为 127.x 本地桩或虚拟
// 网卡 DNS——若结果全是回环桩地址，依次读 systemd-resolved / resolvconf /
// NetworkManager 保存的真实上游文件，还原出物理网络的真实 DNS。
// 文件不存在时返回空，由 sysResolver 回退 Go 系统解析器。
func systemDNSServers() []string {
	// macOS 无 cgo 构建：先经 scutil 取物理接口（en0/en1）的真实 DNS，
	// 跳过 utun 等 VPN 虚拟接口
	if runtime.GOOS == "darwin" {
		if out := darwinPhysicalDNS(); len(out) > 0 {
			return out
		}
	}
	out := parseResolvConf("/etc/resolv.conf")
	if len(out) > 0 && !allLoopback(out) {
		return out
	}
	// resolv.conf 为空或只有本地桩（127.0.0.53 等）：找真实上游列表
	for _, f := range []string{
		"/run/systemd/resolve/resolv.conf", // systemd-resolved 的真实上游
		"/run/resolvconf/resolv.conf",      // resolvconf 合并结果
		"/run/NetworkManager/resolv.conf",  // NetworkManager 直连模式
	} {
		if real := parseResolvConf(f); len(real) > 0 && !allLoopback(real) {
			return real
		}
	}
	return out // 全是桩也返回（非劫持模式下本地桩照常工作）
}

// parseResolvConf 解析 resolv.conf 的 nameserver 行（去重、剔除无效地址）。
func parseResolvConf(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" && net.ParseIP(f[1]) != nil && !seen[f[1]] {
			seen[f[1]] = true
			out = append(out, net.JoinHostPort(f[1], "53"))
		}
	}
	return out
}

// allLoopback 报告列表是否全是回环地址（127.0.0.53 本地桩 / 127.0.0.1 本地代理）。
func allLoopback(servers []string) bool {
	if len(servers) == 0 {
		return false
	}
	for _, s := range servers {
		h, _, err := net.SplitHostPort(s)
		if err != nil {
			return false
		}
		if ip := net.ParseIP(h); ip == nil || !ip.IsLoopback() {
			return false
		}
	}
	return true
}
