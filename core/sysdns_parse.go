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

// dnsFromConnectivityDump 只取「当前默认网络」的 DnsAddresses：
// 连 Wi-Fi 就是 Wi-Fi 的 DNS，切移动数据就是流量的 DNS，
// 其余网络（VPN、热点、历史网络）的 DNS 一律不混入。
//
// 两种 dumpsys 格式都兼容：
//   - 单行格式（Android 10+）：NetworkAgentInfo{ ... network{netId} ... DnsAddresses: [...] } 一行内
//   - 多行格式（Android 8/9）：NetworkAgentInfo 块头行含 "- netId)"，DnsAddresses 在后续缩进行
//
// 找不到活跃网络时返回 nil（调用方再决定是否回退宽松匹配）。
func dnsFromConnectivityDump(dump string) []string {
	netID := parseActiveNetID(dump)
	if netID == "" {
		return nil
	}
	braceTag := "network{" + netID + "}"
	inBlock := false // 多行格式：当前是否处于活跃网络的 NetworkAgentInfo 块内
	for _, line := range strings.Split(dump, "\n") {
		isHeader := strings.Contains(line, "NetworkAgentInfo")
		if isHeader {
			// 块头自带归属：单行格式看 network{id}，多行格式看 "- id)" 结尾
			inBlock = strings.Contains(line, braceTag)
			if !inBlock {
				if m := reNetIDTail.FindStringSubmatch(line); m != nil && m[1] == netID {
					inBlock = true
				}
			}
		}
		if !strings.Contains(line, "DnsAddresses") {
			continue
		}
		// 单行格式：DnsAddresses 与 network{id} 同一行
		if strings.Contains(line, braceTag) || inBlock {
			if ips := extractDnsAddrs(line); len(ips) > 0 {
				return ips
			}
		}
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
