// DNS 报文只读解析：供缓存查看页把缓存键（查询）与缓存体（应答）
// 还原成人类可读的 域名 / 记录类型 / IP / TTL 信息。
// 只做解析不做构造，出错立即返回已解析部分，绝不 panic。
package fastime

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// dnsQuestion 查询问题区解析结果。
type dnsQuestion struct {
	Name  string
	Qtype uint16
}

// dnsAnswer 应答记录解析结果（Data 已格式化为可读文本）。
type dnsAnswer struct {
	Type string
	Data string
	TTL  uint32
}

// qtypeName 常见记录类型助记名，未知类型回退 "TYPE<n>"（RFC 3597）。
func qtypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 41:
		return "OPT"
	case 43:
		return "DS"
	case 46:
		return "RRSIG"
	case 47:
		return "NSEC"
	case 48:
		return "DNSKEY"
	case 64:
		return "SVCB"
	case 65:
		return "HTTPS"
	case 255:
		return "ANY"
	case 257:
		return "CAA"
	}
	return fmt.Sprintf("TYPE%d", t)
}

// decodeName 读取域名（含 0xC0 压缩指针），返回点分域名与
// "继续解析的偏移"（遇指针时为指针之后的偏移）。
func decodeName(msg []byte, off int) (string, int, error) {
	var labels []string
	next := -1
	seen := 0
	for {
		if off >= len(msg) {
			return "", 0, errors.New("DNS 名称越界")
		}
		if seen++; seen > 32 { // 指针成环保护
			return "", 0, errors.New("DNS 压缩指针成环")
		}
		b := msg[off]
		switch {
		case b == 0:
			if next < 0 {
				next = off + 1
			}
			return strings.Join(labels, "."), next, nil
		case b&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return "", 0, errors.New("DNS 指针越界")
			}
			if next < 0 {
				next = off + 2
			}
			off = int(b&0x3F)<<8 | int(msg[off+1])
		case b&0xC0 == 0:
			if off+1+int(b) > len(msg) {
				return "", 0, errors.New("DNS 标签越界")
			}
			labels = append(labels, string(msg[off+1:off+1+int(b)]))
			off += 1 + int(b)
		default:
			return "", 0, errors.New("非法 DNS 标签")
		}
	}
}

// parseQuestion 解析查询报文问题区（取第一个问题）。
func parseQuestion(msg []byte) (dnsQuestion, error) {
	var q dnsQuestion
	if len(msg) < 12 {
		return q, errors.New("报文过短")
	}
	if int(binary.BigEndian.Uint16(msg[4:6])) < 1 {
		return q, errors.New("无问题区")
	}
	name, next, err := decodeName(msg, 12)
	if err != nil {
		return q, err
	}
	if next+4 > len(msg) {
		return q, errors.New("问题区截断")
	}
	q.Name = name
	q.Qtype = binary.BigEndian.Uint16(msg[next:])
	return q, nil
}

// buildAnswer 用本地解析到的 IP 构造 DNS 应答（上游域名本地代答用）。
// 保留客户端事务 ID 与问题区原样（含大小写），回答区用 0xC00C 指针指回问题。
// 只取与 qtype 匹配的地址族；无匹配时为合法的 NODATA（RCODE=0，ANCOUNT=0）。
func buildAnswer(query []byte, qtype uint16, ips []net.IP, ttl uint32) ([]byte, error) {
	if len(query) < 12 {
		return nil, errors.New("查询报文过短")
	}
	_, qend, err := decodeName(query, 12)
	if err != nil {
		return nil, err
	}
	if qend += 4; qend > len(query) {
		return nil, errors.New("问题区截断")
	}
	out := make([]byte, 0, qend+len(ips)*28)
	out = append(out, query[:qend]...)
	// QR=1 + RA=1，保留客户端 RD/CD 等标志位，RCODE=0
	binary.BigEndian.PutUint16(out[2:4], binary.BigEndian.Uint16(query[2:4])|0x8080)
	binary.BigEndian.PutUint16(out[4:6], 1) // QDCOUNT：代答只回第一个问题
	an := 0
	for _, ip := range ips {
		var rdata []byte
		rt := qtype
		if qtype == dnsTypeA {
			if rdata = ip.To4(); rdata == nil {
				continue
			}
		} else if qtype == dnsTypeAAAA {
			if ip.To4() != nil {
				continue
			}
			if rdata = ip.To16(); rdata == nil {
				continue
			}
		} else {
			continue
		}
		var h [10]byte
		binary.BigEndian.PutUint16(h[0:], rt)
		binary.BigEndian.PutUint16(h[2:], dnsClassIN)
		binary.BigEndian.PutUint32(h[4:], ttl)
		binary.BigEndian.PutUint16(h[8:], uint16(len(rdata)))
		out = append(out, 0xC0, 0x0C) // 名称指针 → 偏移 12 的问题区域名
		out = append(out, h[:]...)
		out = append(out, rdata...)
		an++
	}
	binary.BigEndian.PutUint16(out[6:8], uint16(an))
	binary.BigEndian.PutUint16(out[8:10], 0)  // NSCOUNT
	binary.BigEndian.PutUint16(out[10:12], 0) // ARCOUNT：应答从简，不带 EDNS
	return out, nil
}

// parseResponse 解析应答报文：返回 RCODE 与全部回答区记录。
// 权威区/附加区不展示（缓存页只关心最终答案）。
func parseResponse(msg []byte) (rcode int, answers []dnsAnswer, err error) {
	if len(msg) < 12 {
		return 0, nil, errors.New("报文过短")
	}
	rcode = int(msg[3] & 0x0f)
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	for i := 0; i < qd; i++ { // 跳过问题区
		if _, off, err = decodeName(msg, off); err != nil {
			return rcode, nil, err
		}
		off += 4
	}
	for i := 0; i < an; i++ {
		if _, off, err = decodeName(msg, off); err != nil {
			return rcode, answers, nil // 出错返回已解析部分
		}
		if off+10 > len(msg) {
			return rcode, answers, nil
		}
		rtype := binary.BigEndian.Uint16(msg[off:])
		ttl := binary.BigEndian.Uint32(msg[off+4:])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8:]))
		off += 10
		if off+rdlen > len(msg) {
			return rcode, answers, nil
		}
		rdata := msg[off : off+rdlen]
		a := dnsAnswer{Type: qtypeName(rtype), TTL: ttl}
		switch {
		case rtype == dnsTypeA && rdlen == 4:
			a.Data = net.IP(rdata).String()
		case rtype == dnsTypeAAAA && rdlen == 16:
			a.Data = net.IP(rdata).String()
		case rtype == 5 || rtype == 2 || rtype == 12: // CNAME / NS / PTR
			if name, _, e := decodeName(msg, off); e == nil {
				a.Data = name
			} else {
				a.Data = fmt.Sprintf("%d 字节", rdlen)
			}
		case rtype == 15 && rdlen > 2: // MX
			if name, _, e := decodeName(msg, off+2); e == nil {
				a.Data = fmt.Sprintf("优先级 %d → %s", binary.BigEndian.Uint16(rdata), name)
			} else {
				a.Data = fmt.Sprintf("%d 字节", rdlen)
			}
		case rtype == 16: // TXT
			var txts []string
			for j := 0; j < len(rdata); {
				l := int(rdata[j])
				if j+1+l > len(rdata) {
					break
				}
				txts = append(txts, string(rdata[j+1:j+1+l]))
				j += 1 + l
			}
			a.Data = strings.Join(txts, " ")
		default:
			a.Data = fmt.Sprintf("%d 字节", rdlen)
		}
		answers = append(answers, a)
		off += rdlen
	}
	return rcode, answers, nil
}
