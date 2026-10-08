package fastime

import (
	"net"
	"regexp"
	"strings"
)

// resolv.conf 代管（Android root）的纯解析工具函数——无平台依赖，
// 单独成文件以便跨平台单元测试。
// tunDNSNet：198.18.0.0/15（IANA 基准测试保留段）——TUN 模式代理
// （sing-box / Clash 等）普遍用 198.18.0.x 做虚拟网关与假 DNS，
// 绝不是真实网络下发的 DNS，全平台过滤。
var tunDNSNet = &net.IPNet{IP: net.IP{198, 18, 0, 0}, Mask: net.CIDRMask(15, 32)}

// validDNS 过滤无效/占位 DNS 地址：未指定地址（0.0.0.0、::）、
// 回环（127.x、::1）、链路本地（169.254.x、fe80::）、TUN 假 DNS（198.18.x）。
// 注意：169.254.254.254 是我们自己的污染虚假 IP，绝不回写进 resolv.conf。
func validDNS(v string) bool {
	ip := net.ParseIP(v)
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.Equal(fakeIP4) || ip.Equal(fakeIP6) {
		return false
	}
	if tunDNSNet.Contains(ip) {
		return false
	}
	return true
}

// parseDNSLines 解析每行一个 IP 的输出，去重、过滤非法值与占位地址。
func parseDNSLines(out string) []string {
	seen := map[string]bool{}
	var ips []string
	for _, line := range strings.Split(out, "\n") {
		v := strings.TrimSpace(line)
		if v == "" || seen[v] {
			continue
		}
		if validDNS(v) {
			seen[v] = true
			ips = append(ips, v)
		}
	}
	return ips
}

// parseDumpsysDNS 从 dumpsys connectivity 文本提取活动网络的 DNS。
// 优先只取「Active default network」所在块，避免把没连上的网络
// （如关掉的蜂窝）DNS 混进来；活动 ID 匹配不上时宽松兜底——
// 收集所有非 VPN 块的 DNS（宁多勿空，VPN 虚拟地址仍被排除）。
//
// 真实输出里 DnsAddresses 是「逗号无空格」分隔且带 / 前缀：
//
//	DnsAddresses: [ /120.196.165.24,/211.136.112.50 ]
//
// 必须按逗号切分——按空白切分会把多个地址连成一个 token 被整体丢弃。
func parseDumpsysDNS(text string) []string {
	// 找活动网络 ID，形如: "Active default network: 101"
	activeID := ""
	for _, line := range strings.Split(text, "\n") {
		if i := strings.Index(line, "Active default network:"); i >= 0 {
			activeID = strings.TrimSpace(line[i+len("Active default network:"):])
			break
		}
	}
	if activeID == "none" {
		activeID = ""
	}
	// 按 NetworkAgentInfo{ 分块
	var blocks []string
	var cur strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "NetworkAgentInfo{") && cur.Len() > 0 {
			blocks = append(blocks, cur.String())
			cur.Reset()
		}
		cur.WriteString(line)
		cur.WriteByte('\n')
	}
	if cur.Len() > 0 {
		blocks = append(blocks, cur.String())
	}
	collect := func(requireActive bool) []string {
		seen := map[string]bool{}
		var ips []string
		for _, blk := range blocks {
			// VPN 虚拟网络块跳过：其 DNS 是虚拟/代理地址，不是真实网络下发的
			if isVPNBlock(blk) {
				continue
			}
			// 现代 dumpsys 块里有 "network: 102" 字段；老格式宽松词边界匹配
			if requireActive && activeID != "" && !blockHasNetID(blk, activeID) {
				continue
			}
			for _, line := range strings.Split(blk, "\n") {
				for _, tok := range dnsAddrTokens(line) {
					if validDNS(tok) && !seen[tok] {
						seen[tok] = true
						ips = append(ips, tok)
					}
				}
			}
		}
		return ips
	}
	if ips := collect(true); len(ips) > 0 {
		return ips
	}
	return collect(false)
}

// isVPNBlock 判断 dumpsys 块是否 VPN 网络（Transports 里带 VPN）。
func isVPNBlock(blk string) bool {
	i := strings.Index(blk, "Transports:")
	if i < 0 {
		return false
	}
	seg := blk[i:]
	if end := strings.IndexAny(seg, "\n]}"); end > 0 {
		seg = seg[:end]
	}
	return strings.Contains(seg, "VPN")
}

// dnsAddrTokens 从一行 dumpsys 文本提取 DnsAddresses 列表的全部地址 token：
// 按逗号/空白/方括号切分，去掉每个地址的 / 前缀。
func dnsAddrTokens(line string) []string {
	i := strings.Index(line, "DnsAddresses:")
	if i < 0 {
		return nil
	}
	seg := line[i+len("DnsAddresses:"):]
	if j := strings.IndexByte(seg, ']'); j >= 0 {
		seg = seg[:j]
	}
	var out []string
	for _, tok := range strings.FieldsFunc(seg, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '[' || r == '('
	}) {
		tok = strings.TrimPrefix(tok, "/")
		if tok != "" {
			out = append(out, tok)
		}
	}
	return out
}

// blockHasNetID 判断 dumpsys 块是否属于指定网络 ID：
// 优先匹配 "network: <id>"（现代格式），否则词边界宽松匹配。
func blockHasNetID(blk, id string) bool {
	if strings.Contains(blk, "network: "+id+" ") || strings.Contains(blk, "network: "+id+"\n") ||
		strings.HasSuffix(blk, "network: "+id) {
		return true
	}
	return regexp.MustCompile(`\b` + regexp.QuoteMeta(id) + `\b`).MatchString(blk)
}

// parseResolvConf 解析 resolv.conf 的 nameserver 行，过滤无效地址。
func parseResolvConf(text string) []string {
	var ips []string
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" && validDNS(f[1]) && !seen[f[1]] {
			seen[f[1]] = true
			ips = append(ips, f[1])
		}
	}
	return ips
}

// parseScutilDNS 解析 `scutil --dns` 输出：只取 resolver #1（默认解析器，
// 即当前真实网络下发的 DNS），跳过 scoped/if_index 与各域名专用解析器。
func parseScutilDNS(text string) []string {
	var ips []string
	seen := map[string]bool{}
	inFirst := false
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "resolver #") {
			if inFirst {
				break // 只取 resolver #1
			}
			inFirst = strings.HasPrefix(t, "resolver #1")
			continue
		}
		if !inFirst || !strings.HasPrefix(t, "nameserver[") {
			continue
		}
		i := strings.Index(t, ":")
		if i < 0 {
			continue
		}
		if v := strings.TrimSpace(t[i+1:]); validDNS(v) && !seen[v] {
			seen[v] = true
			ips = append(ips, v)
		}
	}
	return ips
}

// parseResolvectl 解析 `resolvectl dns` 输出：
// 形如 "Global: 1.1.1.1" 与 "Link 2 (wlan0): 192.168.1.1 fd00::1"。
func parseResolvectl(text string) []string {
	var ips []string
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		i := strings.Index(line, ":")
		if i < 0 {
			continue
		}
		for _, tok := range strings.Fields(line[i+1:]) {
			if validDNS(tok) && !seen[tok] {
				seen[tok] = true
				ips = append(ips, tok)
			}
		}
	}
	return ips
}

// propDNSRe 匹配 getprop 全量输出里的 DNS 属性：
// [net.dns1]: [223.5.5.5] / [net.rmnet_data0.dns1]: [x.x.x.x] / [dhcp.wlan0.dns1]: [x]
var propDNSRe = regexp.MustCompile(`^\[([^\]]*[._]?dns[1-4])\]: \[([^\]]*)\]$`)

// parseGetpropDNS 解析 `getprop` 全量输出：优先全局 net.dns1/2，
// 其次各接口属性（net.<if>.dnsN、dhcp.<if>.dnsN）——
// 移动数据（rmnet_data*）与 Wi-Fi（wlan*）的 DNS 都能拿到。
func parseGetpropDNS(text string) []string {
	var global, perIf []string
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		m := propDNSRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		v := strings.TrimSpace(m[2])
		if !validDNS(v) || seen[v] {
			continue
		}
		seen[v] = true
		if strings.HasPrefix(m[1], "net.dns") {
			global = append(global, v)
		} else {
			perIf = append(perIf, v)
		}
	}
	return append(global, perIf...)
}
