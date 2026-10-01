//go:build windows

package fastime

import (
	"net"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// systemDNSServers 从注册表读取各网卡配置的 DNS 服务器：
// HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}
// 下的 NameServer（静态）与 DhcpNameServer（DHCP 下发，即运营商 DNS），
// 逗号/空格分隔，去重后返回。
func systemDNSServers() []string {
	var out []string
	seen := map[string]bool{}
	add := func(v string) {
		for _, s := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
			if net.ParseIP(s) != nil && !seen[s] {
				seen[s] = true
				out = append(out, net.JoinHostPort(s, "53"))
			}
		}
	}
	root, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`,
		registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer root.Close()
	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}
	for _, name := range names {
		sk, err := registry.OpenKey(root, name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		if v, _, err := sk.GetStringValue("NameServer"); err == nil {
			add(v)
		}
		if v, _, err := sk.GetStringValue("DhcpNameServer"); err == nil {
			add(v)
		}
		sk.Close()
	}
	return out
}
