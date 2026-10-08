//go:build windows

package fastime

import (
	"os/exec"
	"strings"
	"syscall"
)

// 虚拟网卡关键词：命中其一即跳过该网卡的 DNS（VPN/代理/虚拟化网卡的 DNS
// 是虚拟地址或隧道内地址，不是真实网络下发的）。
var virtualIfKeywords = []string{
	"vpn", "tap", "wintun", "wireguard", "tun", "openvpn", "tailscale", "zerotier",
	"hyper-v", "vmware", "virtualbox", "loopback", "bluetooth", "ppp", "wan miniport",
	"virtual", "pseudo",
}

// detectSystemDNS Windows：PowerShell Get-DnsClientServerAddress 枚举全部网卡
// 的 IPv4/IPv6 DNS，过滤虚拟网卡后合并去重。locale 无关（Cmdlet 输出）。
func detectSystemDNS(log *logger) (servers []string, via string) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`Get-DnsClientServerAddress -ErrorAction SilentlyContinue | `+
			`Where-Object { $_.ServerAddresses.Count -gt 0 } | `+
			`ForEach-Object { $_.InterfaceAlias + '|' + ($_.ServerAddresses -join ',') }`)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		log.Debugf("Get-DnsClientServerAddress 失败: %v", err)
		return nil, ""
	}
	var ips []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		i := strings.IndexByte(line, '|')
		if i <= 0 {
			continue
		}
		alias := strings.ToLower(line[:i])
		skip := false
		for _, kw := range virtualIfKeywords {
			if strings.Contains(alias, kw) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		for _, tok := range strings.Split(line[i+1:], ",") {
			if v := strings.TrimSpace(tok); validDNS(v) {
				ips = append(ips, v)
			}
		}
	}
	if len(ips) == 0 {
		return nil, ""
	}
	return dedupStrings(ips), "网卡配置（已滤虚拟网卡）"
}
