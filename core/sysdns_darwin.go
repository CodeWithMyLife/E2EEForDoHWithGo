//go:build darwin || ios

package fastime

import (
	"os"
	"os/exec"
)

// detectSystemDNS macOS：scutil --dns 的默认解析器（resolver #1）——
// 即当前真实网络（Wi-Fi/有线，通常就是路由器下发的地址）。
// iOS 沙盒内没有 scutil：回退读 /etc/resolv.conf（多数情况下不可读，静默降级）。
func detectSystemDNS(log *logger) (servers []string, via string) {
	if out, err := exec.Command("scutil", "--dns").Output(); err == nil {
		if ips := parseScutilDNS(string(out)); len(ips) > 0 {
			return ips, "scutil"
		}
	}
	if raw, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		if ips := parseResolvConf(string(raw)); len(ips) > 0 {
			return ips, "/etc/resolv.conf"
		}
	}
	return nil, ""
}
