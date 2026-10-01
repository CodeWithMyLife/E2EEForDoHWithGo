//go:build !windows && !android && !ios && (!darwin || !cgo)

package fastime

import (
	"net"
	"os"
	"strings"
)

// systemDNSServers 读取 /etc/resolv.conf 的 nameserver 行。
// 覆盖：Linux、macOS/iOS 的无 cgo 构建（回退途径；cgo 构建走 libresolv 更准）。
// 文件不存在时返回空，由 sysResolver 回退 Go 系统解析器。
func systemDNSServers() []string {
	data, err := os.ReadFile("/etc/resolv.conf")
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
