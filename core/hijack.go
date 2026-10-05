package fastime

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// 53 端口 DNS 劫持拦截器（turbo 模式，HIJACK_DNS=true，需 root/管理员）：
// 劫持本机 UDP/TCP 53 的全部流量，正常 DNS 查询走与 /e2e 完全相同的管线——
//
//	正常 DNS 查询：取域名+QTYPE 匹配内部缓存，命中按现有内容直接应答
//	（系统 DNS 代管/强制的域名交给系统 DNS 解析后返回）；未命中则打包成
//	端到端加密发主备上游竞速，应答 IP 未命中 IP 段直接响应，命中则改交
//	系统 DNS 解析并返回系统 DNS 的结果。
//	非 DNS 流量：立即返回空数据（UDP 空报文 / TCP 零长度帧），绝不送上游。
//
// 自己发往系统 DNS 的 53 查询不被劫持：linux/android 由 SO_MARK +
// iptables mark 放行实现；windows/darwin 直接拨真实服务器地址，天然不经过
// 本机监听器。
type hijacker struct {
	s       *Server
	addr    string
	udp     *net.UDPConn
	tcp     net.Listener
	cleanup func() // 平台清理：撤 iptables 规则 / 恢复系统 DNS 设置
	reqs    atomic.Int64
	emptys  atomic.Int64 // 非 DNS 流量回空次数
	fails   atomic.Int64 // 解析失败回 SERVFAIL 次数
	closed  atomic.Bool
}

// startHijack 启动 53 劫持。任何失败只记日志——HTTP 入口照常可用。
func (s *Server) startHijack() {
	addr := s.cfg.HijackListen
	manual := addr != "" // 自定义监听地址（调试/手动转发）：不装 iptables、不改系统 DNS
	if addr == "" {
		addr = hijackDefaultAddr()
	}
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		s.log.Errorf("53 劫持：监听地址 %q 无效: %v", addr, err)
		return
	}
	udpConn, err := net.ListenUDP("udp", ua)
	if err != nil {
		s.log.Errorf("53 劫持：UDP 监听 %s 失败（需 root/管理员权限？）: %v", addr, err)
		return
	}
	tcpLn, err := net.Listen("tcp", addr)
	if err != nil {
		_ = udpConn.Close()
		s.log.Errorf("53 劫持：TCP 监听 %s 失败: %v", addr, err)
		return
	}
	h := &hijacker{s: s, addr: addr, udp: udpConn, tcp: tcpLn}
	if !manual {
		cleanup, err := s.hijackPlatformSetup(addr)
		if err != nil {
			_ = udpConn.Close()
			_ = tcpLn.Close()
			s.log.Errorf("53 劫持：平台接管失败: %v（HTTP 入口不受影响）", err)
			return
		}
		h.cleanup = cleanup
	}
	s.hijack = h
	go h.serveUDP()
	go h.serveTCP()
	if manual {
		s.log.Infof("DNS 拦截器已启动：监听 %s（UDP+TCP，自定义监听模式，未改动系统配置）", addr)
	} else {
		s.log.Infof("53 端口 DNS 劫持已启动：监听 %s（UDP+TCP）", addr)
	}
}

// close 关闭监听并执行平台清理（撤规则/恢复系统 DNS）。幂等。
func (h *hijacker) close() {
	if h.closed.Swap(true) {
		return
	}
	_ = h.udp.Close()
	_ = h.tcp.Close()
	if h.cleanup != nil {
		h.cleanup()
	}
}

// stats 供状态页展示。
func (h *hijacker) stats() (addr string, reqs, emptys, fails int64) {
	return h.addr, h.reqs.Load(), h.emptys.Load(), h.fails.Load()
}

// ---------- UDP ----------

func (h *hijacker) serveUDP() {
	buf := make([]byte, 64*1024)
	for {
		n, src, err := h.udp.ReadFromUDP(buf)
		if err != nil {
			return // 监听关闭
		}
		pkt := append([]byte(nil), buf[:n]...)
		go func() {
			resp, isDNS := h.answer(pkt)
			if !isDNS {
				h.emptys.Add(1)
				_, _ = h.udp.WriteToUDP([]byte{}, src) // 非 DNS：立即返回空数据
				return
			}
			_, _ = h.udp.WriteToUDP(resp, src)
		}()
	}
}

// ---------- TCP ----------

func (h *hijacker) serveTCP() {
	for {
		c, err := h.tcp.Accept()
		if err != nil {
			return // 监听关闭
		}
		go h.serveTCPConn(c)
	}
}

func (h *hijacker) serveTCPConn(c net.Conn) {
	defer c.Close()
	var lp [2]byte
	for {
		_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
		if _, err := io.ReadFull(c, lp[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(lp[:]))
		if n == 0 || n > 64*1024 {
			return // 非法长度：直接断开
		}
		pkt := make([]byte, n)
		if _, err := io.ReadFull(c, pkt); err != nil {
			return
		}
		resp, isDNS := h.answer(pkt)
		if !isDNS {
			h.emptys.Add(1)
			binary.BigEndian.PutUint16(lp[:], 0)
			_, _ = c.Write(lp[:]) // 非 DNS：立即返回空数据（零长度帧）后断开
			return
		}
		binary.BigEndian.PutUint16(lp[:], uint16(len(resp)))
		if _, err := c.Write(append(lp[:], resp...)); err != nil {
			return
		}
	}
}

// ---------- 查询处理 ----------

// answer 处理一个 DNS wireformat 查询。isDNS=false 表示不是正常 DNS 请求
// （调用方立即回空数据）。
func (h *hijacker) answer(pkt []byte) (resp []byte, isDNS bool) {
	if !validDNSQuery(pkt) {
		return nil, false
	}
	body, err := h.s.resolveWire(pkt)
	if err != nil {
		h.fails.Add(1)
		h.s.log.Debugf("53 劫持：查询失败（回 SERVFAIL）: %v", err)
		return buildDNSError(pkt, 2), true // SERVFAIL
	}
	h.reqs.Add(1)
	return body, true
}

// validDNSQuery 校验报文是正常 DNS 查询：QR=0（查询）、OPCODE=0（标准查询）、
// 有问题区且问题区可解析。任一不满足 = 非正常 DNS 流量。
func validDNSQuery(msg []byte) bool {
	if len(msg) < 12 {
		return false
	}
	if msg[2]&0x80 != 0 { // QR=1 是应答不是查询
		return false
	}
	if msg[2]&0x78 != 0 { // OPCODE != 0（标准查询以外的操作码不接受）
		return false
	}
	if _, err := parseQuestion(msg); err != nil {
		return false
	}
	return true
}

// buildDNSError 构造错误应答（保留事务 ID 与问题区，QR=1 + RCODE）。
func buildDNSError(query []byte, rcode uint8) []byte {
	_, qend, err := decodeName(query, 12)
	if err != nil {
		qend = 12
	}
	qend += 4
	if qend > len(query) {
		qend = len(query)
	}
	out := append([]byte(nil), query[:qend]...)
	flags := binary.BigEndian.Uint16(query[2:4]) | 0x8080 // QR=1 + RA=1，保留 RD 等
	flags = flags&0xFFF0 | uint16(rcode&0x0F)
	binary.BigEndian.PutUint16(out[2:4], flags)
	binary.BigEndian.PutUint16(out[4:6], 1) // QDCOUNT
	binary.BigEndian.PutUint16(out[6:8], 0) // ANCOUNT
	binary.BigEndian.PutUint16(out[8:10], 0)
	binary.BigEndian.PutUint16(out[10:12], 0)
	return out
}

// resolveWire 劫持查询的服务管线（与 /e2e HTTP 入口同一套语义，返回含本次
// 事务 ID 的应答报文）：
//
//  1. 系统 DNS 伺候的域名（命中过 IP 段 / 用户强制）：代管缓存命中即回
//     （过期后台 SWR），未命中现场走系统 DNS；失败不回退上游、不受熔断影响
//  2. 上游域名自身（A/AAAA）：本地 DoT→DoH 链代答（防"连上游先解析上游"死循环）
//  3. 内部缓存命中：直接按现有内容应答；过期后台换新
//  4. 未命中：端到端加密发主备上游竞速；应答 IP 命中 IP 段则转系统 DNS
//     解析并返回系统 DNS 结果（raceUpstream 内完成），未命中直接响应
func (s *Server) resolveWire(payload []byte) ([]byte, error) {
	canon := canonQuery(payload)
	key := cacheKey("DNS", canon)
	q, qErr := parseQuestion(canon)
	isIPQ := qErr == nil && (q.Qtype == dnsTypeA || q.Qtype == dnsTypeAAAA)
	localQ := isIPQ && (q.Name == s.upHost || (s.fbHost != "" && q.Name == s.fbHost))

	// 1. 系统 DNS 域名（强制/已命中标记）：只走系统 DNS
	if isIPQ && s.sysCache != nil && !s.noDivertHas(q.Name) &&
		(s.forceDNSHas(q.Name) || s.markedForSys(key)) {
		if e, ok := s.sysCache.Get(key); ok {
			s.hits.Add(1)
			if e.stale() {
				go s.sysRefreshBG(e.payload, key, e.q)
			}
			return withTID(e.body, payload), nil
		}
		s.misses.Add(1)
		body, err := s.sysResolveAndCache(payload, key, q)
		if err != nil {
			s.sysErr.Add(1)
			return nil, err
		}
		return withTID(body, payload), nil
	}

	// 3. 内部缓存命中（含上游域名代答条目）：按现有内容应答
	if body, ok, fresh := s.cache.Get(key); ok {
		s.hits.Add(1)
		if !fresh {
			go s.cacheRefreshBG("DNS", payload, key, localQ)
		}
		return withTID(body, payload), nil
	}
	s.misses.Add(1)

	// 2. 上游域名自身：本地代答，不碰上游、不受熔断影响
	if localQ {
		body, err := s.resolveLocal(payload, key)
		if err != nil {
			s.fgErr.Add(1)
			return nil, err
		}
		s.localAns.Add(1)
		return body, nil
	}

	// 4. 未命中：端到端加密竞速上游（命中 IP 段的域名在其内部转系统 DNS）
	if s.breakerOpen() { // 熔断中：本地快速失败（系统 DNS 域名不经过这里）
		s.breakSkip.Add(1)
		return nil, errors.New("upstream outage (circuit open)")
	}
	body, _, err := s.fetch("DNS", payload, key, nil)
	if err != nil {
		s.fgErr.Add(1)
		return nil, err
	}
	if len(body) == 0 {
		return nil, errors.New("上游返回空应答")
	}
	return withTID(body, payload), nil
}

// ---------- 平台相关（hijack_linux.go / hijack_desktop.go / hijack_other.go） ----------

// hijackDefaultAddr 返回平台默认监听地址：linux/android 用高端口配合 iptables
// REDIRECT；windows/darwin 直接绑定 :53。
// hijackPlatformSetup 完成平台接管（装 iptables 规则 / 把系统 DNS 指向本机），
// 返回清理函数。两函数在各平台文件中实现。
