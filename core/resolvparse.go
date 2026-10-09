package fastime

import (
	"net"
	"regexp"
	"strconv"
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

// ================= dumpsys connectivity 块解析（Android root 主来源） =================

// dumpsysNet 一个「能上网」网络的解析结果。
type dumpsysNet struct {
	kind  string // WIFI / MOBILE
	netID string // network{数字} / ni{[数字}，正则匹配失败时为空（降级不依赖 netId）
	iface string // InterfaceName: xxx，可能为空
	dns   []string
}

var (
	dumpsysNetIDRe1 = regexp.MustCompile(`network\{(\d+)\}`) // 现代格式
	dumpsysNetIDRe2 = regexp.MustCompile(`ni\{\[(\d+)`)      // 老格式/部分 ROM
	dumpsysIfaceRe  = regexp.MustCompile(`InterfaceName:\s*(\S+)`)
)

// parseDumpsysNets 按 NetworkAgentInfo 切块并解析出全部「能上网」的网络。
//
// 分类只看每块第一行——防止块内 NetworkRequest 里的 "CELLULAR|WIFI" 干扰：
//   - 不含 INTERNET 能力 → 丢弃（排除 IMS/RCS 等专用承载，只留能上网的）
//   - 含 Transports: WIFI     → WIFI
//   - 含 Transports: CELLULAR → MOBILE
//   - 都不是                 → 丢弃（VPN 块天然在此被排除）
func parseDumpsysNets(text string) []dumpsysNet {
	var nets []dumpsysNet
	var blk []string
	flush := func() {
		if len(blk) == 0 {
			return
		}
		if n, ok := parseDumpsysBlock(blk); ok {
			nets = append(nets, n)
		}
		blk = nil
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "NetworkAgentInfo{") {
			flush()
			blk = []string{line}
			continue
		}
		if blk != nil {
			blk = append(blk, line)
		}
	}
	flush()
	return nets
}

// parseDumpsysBlock 解析单个网络块：首行分类 + 全文提取 netId/iface/DNS。
// DNS 列表为空的块不返回（没 DNS 的网络对我们没有意义）。
func parseDumpsysBlock(lines []string) (dumpsysNet, bool) {
	first := lines[0]
	if !strings.Contains(first, "INTERNET") {
		return dumpsysNet{}, false
	}
	var kind string
	switch {
	case strings.Contains(first, "Transports: WIFI"):
		kind = "WIFI"
	case strings.Contains(first, "Transports: CELLULAR"):
		kind = "MOBILE"
	default:
		return dumpsysNet{}, false
	}
	n := dumpsysNet{kind: kind}
	body := strings.Join(lines, "\n")
	if m := dumpsysNetIDRe1.FindStringSubmatch(body); m != nil {
		n.netID = m[1]
	} else if m := dumpsysNetIDRe2.FindStringSubmatch(body); m != nil {
		n.netID = m[1]
	}
	if m := dumpsysIfaceRe.FindStringSubmatch(body); m != nil {
		n.iface = m[1]
	}
	seen := map[string]bool{}
	for _, line := range lines {
		for _, tok := range dnsAddrTokens(line) {
			tok = strings.SplitN(tok, "%", 2)[0] // 去 %网卡 后缀（IPv6 zone id）
			if validDNS(tok) && !seen[tok] {
				seen[tok] = true
				n.dns = append(n.dns, tok)
			}
		}
	}
	if len(n.dns) == 0 {
		return dumpsysNet{}, false
	}
	return n, true
}

// selectDumpsysDNS 挑选当前在用的网络并产出 DNS 列表：
//   - 只有 WIFI   → 当前用 Wi-Fi，输出其 DNS
//   - 只有 MOBILE → 当前用移动数据，输出其 DNS
//   - 两者同时存在 → 双通道并发，两个网络的 DNS 都输出，
//     desc 里带 netId/iface 标明归属
//
// 同类多块取第一个有 DNS 的；netId 缺失时降级为按块顺序输出（不依赖 netId）。
func selectDumpsysDNS(nets []dumpsysNet) (ips []string, desc string) {
	var wifi, mobile *dumpsysNet
	for i := range nets {
		switch nets[i].kind {
		case "WIFI":
			if wifi == nil {
				wifi = &nets[i]
			}
		case "MOBILE":
			if mobile == nil {
				mobile = &nets[i]
			}
		}
	}
	seen := map[string]bool{}
	var parts []string
	add := func(n *dumpsysNet) {
		for _, ip := range n.dns {
			if !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}
		id := n.iface
		if n.netID != "" {
			if id != "" {
				id += "#" + n.netID
			} else {
				id = "netId " + n.netID
			}
		}
		if id == "" {
			id = "未知接口"
		}
		parts = append(parts, n.kind+" "+id)
	}
	if wifi != nil {
		add(wifi)
	}
	if mobile != nil {
		add(mobile)
	}
	return ips, strings.Join(parts, " + ")
}

// scanAllDnsAddrs 全文扫描兜底：ROM 定制格式导致块结构完全对不上时，
// 扫描所有 DnsAddresses 行。validDNS 仍会滤掉 TUN 假 DNS（198.18.x）、
// 回环、链路本地与占位地址。
func scanAllDnsAddrs(text string) []string {
	seen := map[string]bool{}
	var ips []string
	for _, line := range strings.Split(text, "\n") {
		for _, tok := range dnsAddrTokens(line) {
			tok = strings.SplitN(tok, "%", 2)[0]
			if validDNS(tok) && !seen[tok] {
				seen[tok] = true
				ips = append(ips, tok)
			}
		}
	}
	return ips
}

// ================= /proc/net/tcp 的 DoT(853) 对端提取 =================

// parseProcNetTCP853 从 /proc/net/tcp（v4）/ tcp6（v6）文本提取
// 处于 ESTABLISHED 状态、远端端口为 853（DoT）的连接对端 IP。
// Private DNS 开启时，这就是系统真实使用的加密 DNS 出口。
func parseProcNetTCP853(text string, v6 bool) []string {
	var ips []string
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || !strings.HasSuffix(f[0], ":") {
			continue // 表头/空行
		}
		parts := strings.SplitN(f[2], ":", 2) // rem_address
		if len(parts) != 2 || !strings.EqualFold(parts[1], "0215") {
			continue
		}
		if f[3] != "01" { // 01 = ESTABLISHED
			continue
		}
		ip := decodeProcHexIP(parts[0], v6)
		if ip != "" && validDNS(ip) && !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	return ips
}

// decodeProcHexIP 解码 /proc/net/tcp 的十六进制地址：
// v4 为 8 字符小端（"0100007F" → 127.0.0.1）；
// v6 为 32 字符、按 8 字符一个字、字内小端。
func decodeProcHexIP(hexAddr string, v6 bool) string {
	if !v6 {
		if len(hexAddr) != 8 {
			return ""
		}
		var b [4]byte
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(hexAddr[i*2:i*2+2], 16, 8)
			if err != nil {
				return ""
			}
			b[i] = byte(v)
		}
		return net.IPv4(b[3], b[2], b[1], b[0]).String()
	}
	if len(hexAddr) != 32 {
		return ""
	}
	var b [16]byte
	for w := 0; w < 4; w++ {
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(hexAddr[w*8+i*2:w*8+i*2+2], 16, 8)
			if err != nil {
				return ""
			}
			b[w*4+3-i] = byte(v) // 字内小端
		}
	}
	return net.IP(b[:]).String()
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
