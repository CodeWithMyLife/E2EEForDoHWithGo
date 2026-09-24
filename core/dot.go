// 手写 DNS wire 协议查询（DoT），替代 miekg/dns 依赖以精简二进制。
// 仅实现 A/AAAA 查询与应答解析，报文格式见 RFC 1035。
package fastime

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	dnsTypeA    = 1
	dnsTypeAAAA = 28
	dnsClassIN  = 1
)

// dotQuery 通过 DoT 查询 host 的 A + AAAA 记录，返回所有 IP。
func dotQuery(ctx context.Context, server, serverName, host string) ([]net.IP, error) {
	d := &net.Dialer{Timeout: 4 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", server, &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	}

	var ips []net.IP
	var lastErr error
	for _, qtype := range []uint16{dnsTypeA, dnsTypeAAAA} {
		r, err := dotExchange(conn, host, qtype)
		if err != nil {
			lastErr = err
			continue
		}
		ips = append(ips, r...)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("DoT 查询失败: %w", lastErr)
	}
	return ips, nil
}

// dotExchange 发送单个查询并解析应答。
// DoT 在 TLS 流上用 2 字节长度前缀分包（RFC 7858）。
func dotExchange(conn *tls.Conn, host string, qtype uint16) ([]net.IP, error) {
	q := buildQuery(host, qtype)
	var lp [2]byte
	binary.BigEndian.PutUint16(lp[:], uint16(len(q)))
	if _, err := conn.Write(append(lp[:], q...)); err != nil {
		return nil, err
	}
	if _, err := readFull(conn, lp[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(lp[:]))
	if _, err := readFull(conn, resp); err != nil {
		return nil, err
	}
	return parseAnswers(resp, qtype)
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := conn.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// buildQuery 构造标准 DNS 查询报文（RD=1，单问题）。
func buildQuery(host string, qtype uint16) []byte {
	buf := make([]byte, 0, 64)
	var hdr [12]byte
	_, _ = rand.Read(hdr[0:2])                // ID 随机
	binary.BigEndian.PutUint16(hdr[2:], 0x0100) // RD
	binary.BigEndian.PutUint16(hdr[4:], 1)      // QDCOUNT
	buf = append(buf, hdr[:]...)
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			continue
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0) // 根标签结束
	var q [4]byte
	binary.BigEndian.PutUint16(q[0:], qtype)
	binary.BigEndian.PutUint16(q[2:], dnsClassIN)
	return append(buf, q[:]...)
}

// parseAnswers 解析应答中的 A/AAAA 记录，跳过名称压缩指针与无关记录。
func parseAnswers(msg []byte, want uint16) ([]net.IP, error) {
	if len(msg) < 12 {
		return nil, errors.New("DNS 应答过短")
	}
	if msg[3]&0x0f != 0 {
		return nil, fmt.Errorf("DNS RCODE=%d", msg[3]&0x0f)
	}
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	an := int(binary.BigEndian.Uint16(msg[6:]))
	off := 12
	var err error
	for i := 0; i < qd; i++ { // 跳过问题区
		if off, err = skipName(msg, off); err != nil {
			return nil, err
		}
		off += 4
	}
	var ips []net.IP
	for i := 0; i < an; i++ {
		if off, err = skipName(msg, off); err != nil {
			return ips, nil // 出错就返回已解析到的
		}
		if off+10 > len(msg) {
			return ips, nil
		}
		rtype := binary.BigEndian.Uint16(msg[off:])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8:]))
		off += 10
		if off+rdlen > len(msg) {
			return ips, nil
		}
		switch {
		case rtype == dnsTypeA && want == dnsTypeA && rdlen == 4:
			ips = append(ips, net.IP(msg[off:off+4]))
		case rtype == dnsTypeAAAA && want == dnsTypeAAAA && rdlen == 16:
			ips = append(ips, net.IP(msg[off:off+16]))
		}
		off += rdlen
	}
	return ips, nil
}

// skipName 跳过域名（含 0xC0 压缩指针），返回下一个偏移。
func skipName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, errors.New("DNS 名称越界")
		}
		b := msg[off]
		switch {
		case b == 0:
			return off + 1, nil
		case b&0xC0 == 0xC0: // 压缩指针，占 2 字节，结束
			return off + 2, nil
		case b&0xC0 == 0:
			off += 1 + int(b)
		default:
			return 0, errors.New("非法 DNS 标签")
		}
	}
}
