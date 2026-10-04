//go:build darwin

package fastime

import (
	"net"
	"os/exec"
	"strings"
)

// darwinPhysicalDNS 经 `scutil --dns` 取物理接口（en0 Wi-Fi / en1+ 有线等）
// 的 scoped resolver DNS，跳过 utun/ipsec/ppp 等 VPN 虚拟接口——
// VPN 程序接管全局流量时，libresolv 读到的默认 resolver 是 VPN 的虚拟 DNS，
// 而 scoped resolver 仍保留物理网络 DHCP 下发的真实 DNS。
// 返回 IP:53 列表；解析失败返回 nil（调用方回退 libresolv / resolv.conf）。
func darwinPhysicalDNS() []string {
	out, err := exec.Command("scutil", "--dns").Output()
	if err != nil {
		return nil
	}
	// resolver 块格式：
	//   resolver #1
	//     nameserver[0] : 192.168.1.1
	//     if_index : 6 (en0)
	//     flags    : Scoped, Request A records
	scoped := map[string][]string{} // ifname -> nameservers（只收带 if_index 的 scoped resolver）
	var curIf string
	var curNS []string
	flush := func() {
		if curIf != "" && len(curNS) > 0 {
			scoped[curIf] = append(scoped[curIf], curNS...)
		}
		curIf, curNS = "", nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "resolver #") {
			flush()
			continue
		}
		if strings.HasPrefix(line, "nameserver[") {
			if i := strings.Index(line, ":"); i >= 0 {
				if ip := net.ParseIP(strings.TrimSpace(line[i+1:])); ip != nil && !ip.IsUnspecified() {
					curNS = append(curNS, ip.String())
				}
			}
			continue
		}
		if strings.HasPrefix(line, "if_index") {
			// "if_index : 6 (en0)"
			if i := strings.Index(line, "("); i >= 0 {
				if j := strings.Index(line[i:], ")"); j > 0 {
					curIf = line[i+1 : i+j]
				}
			}
			continue
		}
	}
	flush()
	var outList []string
	seen := map[string]bool{}
	// en0（Wi-Fi）优先，其后 en1/en2...（有线/雷电），其它接口忽略
	for _, ifname := range []string{"en0", "en1", "en2", "en3"} {
		for _, ns := range scoped[ifname] {
			if !seen[ns] {
				seen[ns] = true
				outList = append(outList, net.JoinHostPort(ns, "53"))
			}
		}
	}
	return outList
}
