package fastime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"runtime/metrics"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// Server 本地加密中继：
//
//	GET  /e2e?dns=<payload>   → 加密 payload，GET  <上游>?e2e=<base64url(帧)>
//	POST /e2e  (body=payload) → 加密 body，   POST <上游>  (body=帧)
//	GET  /                    → 运行状态页（缓存/命中/上游统计）
//	其它路径                  → 404 拒绝
//
// 响应统一：逐帧解密、流式回写、写入 LRU 缓存（仅上游 200 入缓存）。
// 缓存命中立即返回；过保鲜期后后台同步刷新（stale-while-revalidate）。
type Server struct {
	cfg    *Config
	cipher *streamCipher
	client *hybridClient
	cache  *lruCache
	log    *logger

	sfMu sync.Mutex
	sf   map[string]*sfCall // 单飞：相同请求的并发调用共享一次上游往返
	sem  chan struct{}      // 上游并发闸门：高并发下限制同时在飞的请求数
	http *http.Server

	startTime   time.Time
	hits        atomic.Int64 // 缓存命中次数
	misses      atomic.Int64 // 缓存未命中次数
	upstreamOK  atomic.Int64 // 上游 200 成功次数
	upstreamErr atomic.Int64 // 上游失败/非 200 次数

	cpuMu       sync.Mutex // 状态页 CPU 采样：相邻两次访问间求平均
	lastCPUSec  float64
	lastCPUTime time.Time

	watchStop chan struct{}
}

// sfCall 单飞：后来者等待领导者的结果，避免相同请求重复打上游（省电核心）。
type sfCall struct {
	done chan struct{}
	body []byte
	err  error
}

const (
	maxPostBody        = 4 << 20 // POST 负载上限 4MB
	maxUpstreamInflight = 32     // 同时在飞的上游请求上限
)

func NewServer(cfg *Config) (*Server, error) {
	sc, err := newStreamCipher(cfg.Key)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:         cfg,
		cipher:      sc,
		log:         newLogger(cfg.LogLevel),
		cache:       newLRUCache(cfg.CacheSize, cfg.CacheTTL),
		sf:          make(map[string]*sfCall),
		sem:         make(chan struct{}, maxUpstreamInflight),
		startTime:   time.Now(),
		lastCPUTime: time.Now(),
		lastCPUSec:  procCPUSeconds(),
		watchStop: make(chan struct{}),
	}
	s.client = newHybridClient(newFastDialer(cfg.DoTServer, cfg.DialSingle, s.log), s.log, cfg.PreferQUIC)
	// h2c：本地入口同时支持 HTTP/1.1 与 HTTP/2（先验模式）。
	// q/dig 等 DoH 工具对 http:// 地址直接发 HTTP/2 前言，没有 h2c 会被
	// HTTP/1.1 服务器回 400 错误页，客户端解包 DNS 时溢出报错。
	h2s := &http2.Server{
		MaxHandlers:         0,
		MaxConcurrentStreams: 256, // 本地多路复用：单连接并发流上限
		IdleTimeout:         10 * time.Second, // 与上游空闲策略一致，省电
	}
	s.http = &http.Server{
		Addr:              "127.0.0.1:" + cfg.Port,
		Handler:           h2c.NewHandler(s, h2s),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s, nil
}

func (s *Server) Start() error {
	for _, w := range s.cfg.Warns { // 配置告警用 ERROR 级，确保 -log error 下也可见
		s.log.Errorf("%s", w)
	}
	s.log.Infof("fastime 监听于 http://127.0.0.1:%s (上游 %s, 缓存 %d 条, 静默期 %s, 超时 %s, 拨号 %s, 日志 %s)",
		s.cfg.Port, s.cfg.Upstream, s.cfg.CacheSize, s.cfg.CacheTTL, s.cfg.Timeout,
		map[bool]string{true: "single", false: "race"}[s.cfg.DialSingle], s.cfg.LogLevel)
	go s.watchNetwork(s.watchStop)
	// Shutdown 触发时 ListenAndServe 返回 ErrServerClosed——属正常退出，不上抛
	err := s.http.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Shutdown() {
	close(s.watchStop)
	s.client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = s.http.Shutdown(ctx)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// 路径路由：/e2e 中继入口，/ 状态页，其它路径一律拒绝
	switch req.URL.Path {
	case "/e2e":
		// 继续向下走中继逻辑
	case "/":
		if req.Method == http.MethodGet {
			s.serveStatus(w)
			return
		}
		http.NotFound(w, req)
		return
	default:
		http.NotFound(w, req)
		return
	}

	var payload []byte
	switch req.Method {
	case http.MethodGet:
		p := req.URL.Query().Get("dns")
		if p == "" {
			http.Error(w, "missing dns= parameter", http.StatusBadRequest)
			return
		}
		// dns= 约定为 base64(DNS 报文)，与上游 Worker 明文模式一致：
		// 本地先解码成报文字节再加密，Worker 解密后即得原始报文
		b, decErr := decodeB64(p)
		if decErr != nil {
			http.Error(w, "dns= must be base64", http.StatusBadRequest)
			return
		}
		payload = b
	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(req.Body, maxPostBody+1))
		req.Body.Close()
		if err != nil {
			http.Error(w, "read body failed", http.StatusBadRequest)
			return
		}
		if len(body) == 0 {
			http.Error(w, "empty body", http.StatusBadRequest)
			return
		}
		if len(body) > maxPostBody {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		payload = body
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 缓存键 = 方法 + 规范化报文：剔除事务 ID / EDNS Cookie（每次随机），
	// 保留 flags、QNAME(小写)+QTYPE+QCLASS、ECS 等用户设置项
	canon := canonQuery(payload)
	key := cacheKey(req.Method, canon)

	// 命中：立即返回（回写本次查询的事务 ID）；过静默期才后台刷新（省电）
	if body, ok, fresh := s.cache.Get(key); ok {
		s.hits.Add(1)
		s.log.Debugf("%s 缓存命中 fresh=%v key=%s", req.Method, fresh, keyFP(canon))
		w.Header().Set("X-Cache", "HIT")
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(withTID(body, payload))
		if !fresh {
			go func() { _, _, _ = s.fetch(req.Method, normPayload(payload), key, nil) }()
		}
		return
	}
	s.misses.Add(1)
	// 键指纹：同 host 同类型的多次查询应打出完全相同的指纹+键内容，
	// 若不同则说明报文里还有未归一化的差异字段（debug 排障用）
	s.log.Debugf("%s 缓存未命中, 负载 %d 字节, key=%s canon=%s",
		req.Method, len(payload), keyFP(canon), base64.StdEncoding.EncodeToString(canon))

	// 未命中：单飞。领导者边解密边流式回写；并发相同请求共享结果。
	body, streamed, err := s.fetch(req.Method, payload, key, w)
	if err != nil {
		s.log.Errorf("上游请求失败: %v", err)
		if !streamed {
			http.Error(w, "upstream error", http.StatusBadGateway)
		}
		return
	}
	if !streamed {
		w.Header().Set("X-Cache", "MISS-SHARED")
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(withTID(body, payload)) // 单飞共享：回写跟随者自己的事务 ID
	}
}

// cacheKey / splitCacheKey：缓存键 = 方法 + \x00 + 负载。
func cacheKey(method string, payload []byte) string {
	return method + "\x00" + string(payload)
}

// canonQuery 规范化 DNS 查询报文作为缓存键：
//   剔除 —— 事务 ID（每次随机）、EDNS COOKIE 选项（每次随机）；
//   保留 —— flags（DO/CD 等用户设置）、问题区（QNAME 小写+QTYPE+QCLASS，
//          支持全部记录类型）、ECS 等其它 EDNS 选项（用户设置，影响应答内容）。
// 非 DNS 负载（解析失败）回退为 TID 归零的完整报文。
func canonQuery(p []byte) []byte {
	if len(p) < 12 {
		return p
	}
	qd := int(binary.BigEndian.Uint16(p[4:6]))
	an := int(binary.BigEndian.Uint16(p[6:8]))
	ns := int(binary.BigEndian.Uint16(p[8:10]))
	ar := int(binary.BigEndian.Uint16(p[10:12]))

	out := make([]byte, 0, len(p))
	out = append(out, 0, 0)         // 事务 ID 归零
	out = append(out, p[2:12]...)   // flags + 各段计数，原样保留
	i := 12

	// 拷贝域名（小写化，防 0x20 大小写随机化导致键抖动）
	copyName := func() bool {
		start := i
		j, err := skipName(p, i) // dot.go 中已有实现，支持压缩指针
		if err != nil {
			return false
		}
		out = append(out, bytes.ToLower(p[start:j])...)
		i = j
		return true
	}

	for n := 0; n < qd; n++ { // 问题区
		if !copyName() || i+4 > len(p) {
			return normPayload(p)
		}
		out = append(out, p[i:i+4]...) // QTYPE + QCLASS
		i += 4
	}
	for n := 0; n < an+ns; n++ { // 回答/授权段（查询里通常为空），原样保留
		if !copyName() || i+10 > len(p) {
			return normPayload(p)
		}
		end := i + 10 + int(binary.BigEndian.Uint16(p[i+8:i+10]))
		if end > len(p) {
			return normPayload(p)
		}
		out = append(out, p[i:end]...)
		i = end
	}
	for n := 0; n < ar; n++ { // 附加段：OPT 过滤 Cookie，其它原样保留
		if !copyName() || i+10 > len(p) {
			return normPayload(p)
		}
		typ := binary.BigEndian.Uint16(p[i : i+2])
		rdlen := int(binary.BigEndian.Uint16(p[i+8 : i+10]))
		if i+10+rdlen > len(p) {
			return normPayload(p)
		}
		rdata := p[i+10 : i+10+rdlen]
		out = append(out, p[i:i+8]...) // name+type+class+ttl（含 OPT 的 DO 位等）
		if typ == 41 {                 // OPT RR：重建选项列表，剔除 COOKIE(code 10)
			var filtered []byte
			j := 0
			for j+4 <= len(rdata) {
				code := binary.BigEndian.Uint16(rdata[j : j+2])
				l := int(binary.BigEndian.Uint16(rdata[j+2 : j+4]))
				if j+4+l > len(rdata) {
					break
				}
				if code != 10 {
					filtered = append(filtered, rdata[j:j+4+l]...)
				}
				j += 4 + l
			}
			out = append(out, byte(len(filtered)>>8), byte(len(filtered)))
			out = append(out, filtered...)
		} else {
			out = append(out, p[i+8:i+10+rdlen]...)
		}
		i += 10 + rdlen
	}
	return out
}

// normPayload 缓存键归一化：DNS 报文头 2 字节是事务 ID（每次查询随机），
// 归零后才能使「同 Host 同类型」的查询命中同一缓存条目。
// 非 DNS 负载（<12 字节）原样返回，退化为精确匹配。
func normPayload(payload []byte) []byte {
	if len(payload) < 12 {
		return payload
	}
	p := make([]byte, len(payload))
	copy(p, payload)
	p[0], p[1] = 0, 0
	return p
}

// withTID 把响应报文头 2 字节事务 ID 回写为本次查询的 ID。
// 缓存命中 / 单飞共享时响应里的 ID 属于上一次查询，不回写会导致客户端
// 校验“响应 ID != 查询 ID”而报 bad header id。
func withTID(body, query []byte) []byte {
	if len(query) < 12 || len(body) < 12 {
		return body
	}
	if body[0] == query[0] && body[1] == query[1] {
		return body
	}
	out := make([]byte, len(body))
	copy(out, body)
	out[0], out[1] = query[0], query[1]
	return out
}

// keyFP 缓存键指纹：SHA-256 前 8 字节十六进制，便于在日志里肉眼比对多次查询是否同键。
func keyFP(canon []byte) string {
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:8])
}

// decodeB64 容错 base64 解码：兼容标准/base64url、有无填充、空格残留（同 Worker 的 safeAtob）。
func decodeB64(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, " ", "+") // URLSearchParams 会把裸 + 解码成空格
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.StdEncoding.DecodeString(s)
}

func splitCacheKey(key string) (method string, payload []byte, ok bool) {
	i := strings.IndexByte(key, 0)
	if i <= 0 {
		return "", nil, false
	}
	return key[:i], []byte(key[i+1:]), true
}

// fetch 返回 (body, 是否已流式写入 w, err)。
func (s *Server) fetch(method string, payload []byte, key string, w http.ResponseWriter) ([]byte, bool, error) {
	s.sfMu.Lock()
	if c, ok := s.sf[key]; ok { // 跟随者：等待领导者
		s.sfMu.Unlock()
		s.log.Debugf("单飞跟随: %s", method)
		<-c.done
		return c.body, false, c.err
	}
	c := &sfCall{done: make(chan struct{})}
	s.sf[key] = c
	s.sfMu.Unlock()

	body, streamed, err := s.doFetch(method, payload, key, w)
	c.body, c.err = body, err
	close(c.done)
	s.sfMu.Lock()
	delete(s.sf, key)
	s.sfMu.Unlock()
	return body, streamed, err
}

func (s *Server) doFetch(method string, payload []byte, key string, w http.ResponseWriter) ([]byte, bool, error) {
	// 并发闸门：超过上限的相同/不同请求在此排队，
	// 防止瞬间打满射频与 CPU（移动端能耗保护）
	s.sem <- struct{}{}
	defer func() { <-s.sem }()

	var req *http.Request
	var err error

	if method == http.MethodGet {
		// GET：加密 → base64url → 拼 e2e= 参数，GET 上游
		enc, encErr := s.cipher.EncryptForQuery(payload)
		if encErr != nil {
			return nil, false, encErr
		}
		u := s.cfg.Upstream
		sep := "?"
		if strings.Contains(u, "?") {
			sep = "&"
		}
		req, err = http.NewRequest(http.MethodGet, u+sep+"e2e="+url.QueryEscape(enc), nil)
	} else {
		// POST：直接加密 body，POST 上游
		encBody, encErr := s.cipher.Encrypt(payload)
		if encErr != nil {
			return nil, false, encErr
		}
		req, err = http.NewRequest(http.MethodPost, s.cfg.Upstream, bytes.NewReader(encBody))
	}
	if err != nil {
		return nil, false, err
	}
	// 上游请求超时（默认 10s，REQUEST_TIMEOUT_SEC 可调）
	ctx, cancel := context.WithTimeout(req.Context(), s.cfg.Timeout)
	defer cancel()
	req = req.WithContext(ctx)
	start := time.Now()

	// 自定义请求头模式：全新 header，不带 Go 默认的 User-Agent 等任何多余头
	req.Header = make(http.Header)
	if len(s.cfg.Headers) > 0 {
		for k, v := range s.cfg.Headers {
			req.Header.Set(k, v)
		}
	} else {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	req.Header["User-Agent"] = nil // 显式抹除默认 UA

	resp, err := s.client.Do(req)
	if err != nil {
		s.upstreamErr.Add(1)
		return nil, false, err
	}
	defer resp.Body.Close()
	s.log.Debugf("%s 上游响应 %d, 耗时 %s", method, resp.StatusCode, time.Since(start))
	if resp.StatusCode != http.StatusOK {
		// 只缓存 200：非 200 一律视为错误，不进缓存
		s.upstreamErr.Add(1)
		return nil, false, fmt.Errorf("上游返回 %d", resp.StatusCode)
	}

	var buf bytes.Buffer
	out := io.Writer(&buf)
	streamed := false
	var flush func()
	if w != nil {
		w.Header().Set("X-Cache", "MISS")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		out = io.MultiWriter(&buf, w)
		if f, ok := w.(http.Flusher); ok {
			flush = f.Flush // 每解出一帧立即推给客户端
		}
		streamed = true
	}
	if err := s.cipher.DecryptStream(resp.Body, out, flush); err != nil {
		s.upstreamErr.Add(1)
		return nil, streamed, err
	}
	// 空响应不入缓存：上游异常时的 0 字节 200 一旦入缓存，
	// 静默期内会持续毒害客户端（DNS 解包溢出等）
	if buf.Len() > 0 {
		s.cache.Put(key, buf.Bytes())
	}
	s.upstreamOK.Add(1)
	s.log.Debugf("%s 上游完成, 解密 %d 字节, 已写缓存", method, buf.Len())
	return buf.Bytes(), streamed, nil
}

// procCPUSeconds 读取进程累计 CPU 秒（runtime/metrics，全平台可用，无 syscall 依赖）。
// 老 Go 版本无此指标时返回 0，状态页显示 "-"。
func procCPUSeconds() float64 {
	samples := []metrics.Sample{{Name: "/cpu/classes/total:cpu-seconds"}}
	metrics.Read(samples)
	if samples[0].Value.Kind() == metrics.KindFloat64 {
		return samples[0].Value.Float64()
	}
	return 0
}

// serveStatus 输出运行状态页：浏览器直接访问 http://ip:端口/ 时展示。
// 服务只监听 127.0.0.1，状态信息不会暴露到外网。
func (s *Server) serveStatus(w http.ResponseWriter) {
	uptime := time.Since(s.startTime).Round(time.Second)
	hits := s.hits.Load()
	misses := s.misses.Load()
	total := hits + misses
	hitRate := "-"
	if total > 0 {
		hitRate = fmt.Sprintf("%.1f%%", float64(hits)/float64(total)*100)
	}
	dialMode := "race（多 IP 竞速）"
	if s.cfg.DialSingle {
		dialMode = "single（单 IP 直连）"
	}
	netMode := "refresh（保留缓存+强制刷新）"
	if s.cfg.NetSwitchClear {
		netMode = "clear（清空全部缓存）"
	}
	quic := "关闭（Alt-Svc 探测后升级）"
	if s.cfg.PreferQUIC {
		quic = "开启（首请求直连 QUIC 0-RTT）"
	}
	hdrStr := "未配置"
	if n := len(s.cfg.Headers); n > 0 {
		hdrStr = fmt.Sprintf("%d 个", n)
	}
	// 密钥指纹：核对本地与 Worker 密钥是否一致，又不泄露密钥本身
	keyFP := sha256.Sum256(s.cfg.Key)
	dnsN, bestN := s.client.dialer.stats()

	// CPU：相邻两次访问状态页（页面每 5s 自动刷新）之间的进程平均占用
	s.cpuMu.Lock()
	nowCPU, nowT := procCPUSeconds(), time.Now()
	cpuStr := "-"
	if dt := nowT.Sub(s.lastCPUTime).Seconds(); dt > 0.1 {
		cpuStr = fmt.Sprintf("%.1f%%", (nowCPU-s.lastCPUSec)/dt*100)
	}
	s.lastCPUSec, s.lastCPUTime = nowCPU, nowT
	s.cpuMu.Unlock()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	row := func(k, v string) {
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td></tr>", k, html.EscapeString(v))
	}
	grp := func(name string) {
		fmt.Fprintf(w, `<tr class="grp"><td colspan="2">%s</td></tr>`, name)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="5">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>⚡</text></svg>">
<title>Fastime 运行状态</title>
<style>
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;max-width:680px;margin:24px auto;padding:0 16px;color:#1a1a2e;background:#f4f6fa}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.06);overflow:hidden}
.hd{display:flex;align-items:center;gap:10px;padding:16px 20px;background:linear-gradient(135deg,#1a73e8,#0d47a1);color:#fff}
.hd h1{font-size:18px;margin:0;font-weight:600}
.dot{width:9px;height:9px;border-radius:50%;background:#4ade80;box-shadow:0 0 0 0 rgba(74,222,128,.7);animation:p 2s infinite}
@keyframes p{70%{box-shadow:0 0 0 8px rgba(74,222,128,0)}100%{box-shadow:0 0 0 0 rgba(74,222,128,0)}}
.badge{margin-left:auto;font-size:12px;background:rgba(255,255,255,.18);padding:3px 10px;border-radius:999px}
table{border-collapse:collapse;width:100%}
td{padding:8px 14px;font-size:13.5px;border-bottom:1px solid #f0f0f5}
td:first-child{color:#666;width:34%}
td:last-child{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px}
tr.grp td{background:#f7f8fc;color:#1a73e8;font-weight:600;font-size:12px;letter-spacing:.5px;padding:6px 14px}
tr:not(.grp):hover{background:#fafbff}
.tip{color:#999;font-size:12px;margin:12px 4px}
</style></head><body><div class="card">
<div class="hd"><span class="dot"></span><h1>Fastime</h1><span class="badge">运行中 · 127.0.0.1:`, s.cfg.Port, `</span></div>
<table>`)

	grp("运行状态")
	row("运行时长", uptime.String())
	row("CPU 占用", cpuStr+"（按页面刷新间隔平均，多核可超 100%）")
	row("内存占用", fmt.Sprintf("在用 %.1f MB / 申请 %.1f MB · 协程 %d", float64(ms.Alloc)/1048576, float64(ms.Sys)/1048576, runtime.NumGoroutine()))
	row("页面时间", nowT.Format("2006-01-02 15:04:05"))

	grp("缓存与上游")
	row("缓存条数", fmt.Sprintf("%d / %d", s.cache.Len(), s.cfg.CacheSize))
	row("命中 / 未命中", fmt.Sprintf("%d / %d（命中率 %s）", hits, misses, hitRate))
	row("上游 200 / 失败", fmt.Sprintf("%d / %d", s.upstreamOK.Load(), s.upstreamErr.Load()))
	row("在飞上游请求", fmt.Sprintf("%d / %d", len(s.sem), maxUpstreamInflight))

	grp("网络与解析")
	row("上游地址", s.cfg.Upstream)
	row("DNS 解析缓存 / 最快 IP", fmt.Sprintf("%d 条 / %d 条", dnsN, bestN))
	row("解析链", "DoT "+s.cfg.DoTServer+" → 失败自动 DoH(443) → 报错，不回退系统 DNS")
	row("拨号模式", dialMode)
	row("QUIC 优先", quic)

	grp("配置")
	row("静默期 / 超时", fmt.Sprintf("%s / %s", s.cfg.CacheTTL, s.cfg.Timeout))
	row("切网策略", netMode)
	row("日志等级", s.cfg.LogLevel)
	row("自定义请求头", hdrStr)
	row("密钥指纹 (SHA-256 前 8 位)", hex.EncodeToString(keyFP[:4]))
	row("运行时", fmt.Sprintf("%s · %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH))

	fmt.Fprint(w, `</table></div><p class="tip">页面每 5 秒自动刷新 · 仅缓存上游 200 响应 · 密钥指纹用于和 Worker 端核对密钥一致性</p></body></html>`)
}
