//go:build linux && !android

package fastime

import (
	"os"
	"os/exec"
)

// detectSystemDNS Linux：/etc/resolv.conf。
// 只剩 systemd-resolved 本地桩（127.0.0.53 / 127.0.0.1）时，改读
// `resolvectl dns` 拿各链路真实 DNS（通常就是路由器下发的地址）。
func detectSystemDNS(log *logger) (servers []string, via string) {
	if raw, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		if ips := parseResolvConf(string(raw)); len(ips) > 0 {
			return ips, "/etc/resolv.conf"
		}
	}
	if out, err := exec.Command("resolvectl", "dns").Output(); err == nil {
		if ips := parseResolvectl(string(out)); len(ips) > 0 {
			return ips, "resolvectl"
		}
	}
	return nil, ""
}
