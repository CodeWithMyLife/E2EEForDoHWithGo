package fastime

import (
	"net"
	"regexp"
	"strings"
)

// validDNSIP 校验 DNS 服务器地址：必须是合法 IP，且剔除无效占位地址
// （0.0.0.0 / :: 常见于 dumpsys 里未就绪网络的占位，拨它们必然超时）。
func validDNSIP(s string) bool {
	s = strings.Trim(strings.TrimSpace(s), "[]/,")
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return !ip.IsUnspecified() // 0.0.0.0 与 :: 一律丢弃
}

// ---------- Android dumpsys connectivity 精确解析 ----------

var (
	// "Active default network: 5301" —— 当前默认网络的 netId
	reActiveNet = regexp.MustCompile(`Active default network:\s*(\d+)`)
	// 单行格式（Android 10+）：NetworkAgentInfo{ ... network{5301} ... DnsAddresses: [ /x.x.x.x ] }
	reNetIDBrace = regexp.MustCompile(`network\{(\d+)\}`)
	// 多行格式（Android 8/9）块头："NetworkAgentInfo [WIFI () - 5301]" 或 "(...) - 5301]"
	reNetIDTail = regexp.MustCompile(`-\s*(\d+)[)\]]`)
	reIP        = regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3})|([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})`)
)

// parseActiveNetID 从 dumpsys connectivity 输出提取当前默认网络 netId。
func parseActiveNetID(dump string) string {
	if m := reActiveNet.FindStringSubmatch(dump); m != nil {
		return m[1]
	}
	return ""
}

// extractIPsFromLine 抽取一行里的全部 IP（剔除无效地址）。
func extractIPsFromLine(line string) []string {
	var out []string
	for _, m := range reIP.FindAllString(line, -1) {
		if validDNSIP(m) {
			out = append(out, m)
		}
	}
	return out
}

// extractDnsAddrs 只抽取 DnsAddresses 段（"DnsAddresses: [ /a,/b ]"）内的 IP，
// 避免误抓同一行 LinkAddresses 里的本机接口地址。
func extractDnsAddrs(line string) []string {
	i := strings.Index(line, "DnsAddresses")
	if i < 0 {
		return nil
	}
	seg := line[i:]
	if j := strings.Index(seg, "]"); j >= 0 {
		seg = seg[:j+1]
	}
	return extractIPsFromLine(seg)
}

// netBlock 一个 NetworkAgentInfo 块解析结果（单行/多行格式统一）：
// id 是 netId，dns 是该网络 DnsAddresses 段内的地址，vpn/wifi/cell/eth
// 按块文本里的传输类型关键词分类。
type netBlock struct {
	id   string
	dns  []string
	vpn  bool
	wifi bool
	cell bool
	eth  bool
}

// parseNetBlocks 把 dumpsys connectivity 输出拆成逐网络块。
// 单行格式（Android 10+）一行一个 NetworkAgentInfo{...}；
// 多行格式（Android 8/9）块头行之后跟缩进的 LinkProperties 行，
// 直至下一个 NetworkAgentInfo 行。
func parseNetBlocks(dump string) []netBlock {
	var blocks []netBlock
	var cur *netBlock
	flush := func() {
		if cur == nil {
			return
		}
		blocks = append(blocks, *cur)
		cur = nil
	}
	for _, line := range strings.Split(dump, "\n") {
		if strings.Contains(line, "NetworkAgentInfo") {
			flush()
			cur = &netBlock{}
			if m := reNetIDBrace.FindStringSubmatch(line); m != nil {
				cur.id = m[1]
			} else if m := reNetIDTail.FindStringSubmatch(line); m != nil {
				cur.id = m[1]
			}
		}
		if cur == nil {
			continue
		}
		if strings.Contains(line, "VPN") {
			cur.vpn = true
		}
		if strings.Contains(line, "WIFI") {
			cur.wifi = true
		}
		if strings.Contains(line, "MOBILE") || strings.Contains(line, "CELLULAR") {
			cur.cell = true
		}
		if strings.Contains(line, "ETHERNET") {
			cur.eth = true
		}
		if strings.Contains(line, "DnsAddresses") {
			cur.dns = append(cur.dns, extractDnsAddrs(line)...)
		}
	}
	flush()
	return blocks
}

// dnsFromConnectivityDump 取「当前默认网络」的 DnsAddresses：
// 连 Wi-Fi 就是 Wi-Fi 的 DNS，切移动数据就是流量的 DNS，
// 其余网络（热点/历史网络）的 DNS 一律不混入。
//
// 例外：VPN 类程序用虚拟网卡强制接管全局流量时，「当前默认网络」可能
// 变成 VPN 网络，其 DnsAddresses 是虚拟/代理地址——此时跳过 VPN 块，
// 改取真实底层网络的 DNS（Wi-Fi > 蜂窝 > 有线）。
func dnsFromConnectivityDump(dump string) []string {
	if b := pickPhysicalBlock(dump); b != nil {
		return b.dns
	}
	return nil
}

// physicalNetIDFromDump 返回代管查询应直达的物理网络 netId（用于
// SO_MARK 的 fwmark 低位，VPN 旁路路由，见 sockmark_linux.go）；
// 选不出物理网络时返回空串。
func physicalNetIDFromDump(dump string) string {
	if b := pickPhysicalBlock(dump); b != nil && !b.vpn {
		return b.id
	}
	return ""
}

// pickPhysicalBlock 选出当前真实上网的物理网络块：
// 活跃网络不是 VPN → 它；活跃网络是 VPN → Wi-Fi > 蜂窝 > 有线；
// 都没有 → 活跃块（哪怕是 VPN 的，聊胜于无）。
func pickPhysicalBlock(dump string) *netBlock {
	blocks := parseNetBlocks(dump)
	if len(blocks) == 0 {
		return nil
	}
	netID := parseActiveNetID(dump)
	var active *netBlock
	for i := range blocks {
		if netID != "" && blocks[i].id == netID {
			active = &blocks[i]
			break
		}
	}
	// 常规：活跃网络不是 VPN → 用它
	if active != nil && !active.vpn && len(active.dns) > 0 {
		return active
	}
	// 活跃网络是 VPN（或没匹配到活跃块）：取真实物理网络
	for _, match := range []func(*netBlock) bool{
		func(b *netBlock) bool { return b.wifi },
		func(b *netBlock) bool { return b.cell },
		func(b *netBlock) bool { return b.eth },
	} {
		for i := range blocks {
			if b := &blocks[i]; !b.vpn && match(b) && len(b.dns) > 0 {
				return b
			}
		}
	}
	// 实在没有物理网络信息：退回活跃网络（哪怕是 VPN 的，聊胜于无）
	if active != nil && len(active.dns) > 0 {
		return active
	}
	return nil
}

// dnsFromDumpAny 宽松回退：抓取 dump 里所有 marker 行的 IP（老行为，含全网络）。
// marker 为 DnsAddresses 时只抽该段，避免误抓同行其它地址。
func dnsFromDumpAny(dump, marker string) []string {
	var out []string
	for _, line := range strings.Split(dump, "\n") {
		if !strings.Contains(line, marker) {
			continue
		}
		if marker == "DnsAddresses" {
			out = append(out, extractDnsAddrs(line)...)
		} else {
			out = append(out, extractIPsFromLine(line)...)
		}
	}
	return out
}
