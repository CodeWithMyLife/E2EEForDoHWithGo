package fastime

import (
	"encoding/binary"
	"reflect"
	"testing"
)

// 构造一个最简 DNS 查询报文（A 记录，example.com）；splitLabels 复用 match_test.go
func testQueryMsg(tid uint16, name string, qtype uint16) []byte {
	msg := []byte{byte(tid >> 8), byte(tid), 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, l := range splitLabels(name) {
		msg = append(msg, byte(len(l)))
		msg = append(msg, l...)
	}
	msg = append(msg, 0, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return msg
}

func TestValidDNSQuery(t *testing.T) {
	q := testQueryMsg(0x1234, "example.com", 1)
	if !validDNSQuery(q) {
		t.Fatal("正常查询被误判为非 DNS")
	}
	// QR=1（应答报文）
	resp := append([]byte(nil), q...)
	resp[2] |= 0x80
	if validDNSQuery(resp) {
		t.Error("应答报文不应通过校验")
	}
	// OPCODE != 0
	op := append([]byte(nil), q...)
	op[2] |= 0x08
	if validDNSQuery(op) {
		t.Error("非标准查询（OPCODE!=0）不应通过校验")
	}
	// 垃圾数据
	for _, junk := range [][]byte{nil, {}, {1, 2, 3}, make([]byte, 12), []byte("GET / HTTP/1.1\r\n")} {
		if validDNSQuery(junk) {
			t.Errorf("垃圾数据 %q 不应通过校验", junk)
		}
	}
	// QDCOUNT=0
	zero := append([]byte(nil), q...)
	binary.BigEndian.PutUint16(zero[4:6], 0)
	if validDNSQuery(zero) {
		t.Error("无问题区的报文不应通过校验")
	}
}

func TestBuildDNSError(t *testing.T) {
	q := testQueryMsg(0x1234, "example.com", 1)
	e := buildDNSError(q, 2)
	if len(e) != len(q) {
		t.Fatalf("错误应答长度 %d, want %d", len(e), len(q))
	}
	if binary.BigEndian.Uint16(e[0:2]) != 0x1234 {
		t.Error("事务 ID 未保留")
	}
	if e[2]&0x80 == 0 {
		t.Error("QR 位未置 1")
	}
	if e[3]&0x0F != 2 {
		t.Error("RCODE 不是 SERVFAIL(2)")
	}
	if binary.BigEndian.Uint16(e[6:8]) != 0 {
		t.Error("错误应答不应带回答记录")
	}
	// 问题区原样保留
	if !reflect.DeepEqual(e[12:], q[12:]) {
		t.Error("问题区未原样保留")
	}
}
