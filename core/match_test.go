package fastime

import (
	"encoding/binary"
	"net"
	"testing"
)

// 构造 CNAME 链应答：qname → CNAME → CNAME → A
func cnameChainResponse(qname string, cnames []string, ip string) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[2:4], 0x8180)
	an := uint16(len(cnames) + 1)
	binary.BigEndian.PutUint16(msg[4:6], 1) // qd
	binary.BigEndian.PutUint16(msg[6:8], an)
	writeName := func(b []byte, name string) []byte {
		for _, l := range splitLabels(name) {
			b = append(b, byte(len(l)))
			b = append(b, l...)
		}
		return append(b, 0)
	}
	body := writeName(nil, qname)
	body = append(body, 0, 1, 0, 1) // QTYPE=A QCLASS=IN
	cur := qname
	for _, tgt := range cnames {
		body = append(body, 0xc0, 0x0c)                    // name = 指针回问题区
		body = append(body, 0, 5, 0, 1, 0, 0, 0, 10, 0, 0) // CNAME IN TTL10 rdlen 占位
		rdstart := len(body)
		body = writeName(body, tgt)
		binary.BigEndian.PutUint16(body[rdstart-2:], uint16(len(body)-rdstart))
		cur = tgt
	}
	_ = cur
	body = append(body, 0xc0, 0x0c) // A 记录（名字指针回问题区即可，测试用）
	body = append(body, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4)
	body = append(body, net.ParseIP(ip).To4()...)
	return append(msg, body...)
}

func splitLabels(name string) []string {
	var out []string
	cur := ""
	for _, c := range name {
		if c == '.' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func TestMatchAnswerCNAMEChain(t *testing.T) {
	l := &ipList{nets: parseIPList("222.192.0.0/11\n# comment\n2606:2800:220::/45\n")}
	s := &Server{iplist: l}
	body := cnameChainResponse("gips2.baidu.com",
		[]string{"gips2.baidu.com.a.bdydns.com", "opencdnbdabroadzlv6.jomodns.com"},
		"222.199.191.38")
	ip, ok := s.matchAnswer(body)
	if !ok || ip != "222.199.191.38" {
		t.Fatalf("CNAME 链应答应命中 222.192.0.0/11，got ip=%q ok=%v", ip, ok)
	}
}

func TestMatchAnswerMiss(t *testing.T) {
	l := &ipList{nets: parseIPList("222.192.0.0/11\n")}
	s := &Server{iplist: l}
	body := cnameChainResponse("a.com", []string{"b.com"}, "8.8.8.8")
	if ip, ok := s.matchAnswer(body); ok {
		t.Fatalf("段外 IP 不应命中，got %s", ip)
	}
}

func TestParseIPListVariants(t *testing.T) {
	nets := parseIPList("222.192.0.0/11\r\n; c\n1.2.3.4\n# x\n::1\n\n  10.0.0.0/8  \n")
	if len(nets) != 4 {
		t.Fatalf("期望 4 条（CRLF/注释/裸 IP/空行/首尾空格），got %d", len(nets))
	}
	l := &ipList{nets: nets}
	for _, ip := range []string{"222.199.191.38", "222.192.0.1", "1.2.3.4", "::1", "10.9.8.7"} {
		if !l.Contains(net.ParseIP(ip)) {
			t.Fatalf("%s 应命中", ip)
		}
	}
	if l.Contains(net.ParseIP("222.224.0.1")) { // 223 出界: 222.224 不在 /11（110xxxxx）
		t.Fatal("222.224.0.1 不应命中 222.192.0.0/11")
	}
}
