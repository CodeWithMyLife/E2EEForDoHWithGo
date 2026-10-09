//go:build !android && !windows && !darwin && !ios && !linux

package fastime

// 其他平台：读 /etc/resolv.conf 尽力而为。

import "os"

func detectSystemDNS(log *logger) (servers []string, via string) {
	if raw, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		if ips := parseResolvConf(string(raw)); len(ips) > 0 {
			return ips, "/etc/resolv.conf"
		}
	}
	return nil, ""
}
