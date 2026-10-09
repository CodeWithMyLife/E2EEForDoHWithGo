package fastime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"runtime/metrics"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// Server 本地加密 DNS 中继（唯一运行模式）：
//
//	GET  /e2e?dns=<payload>   → 加密 payload，GET  <上游>?e2e=<base64url(帧)>
//	POST /e2e  (body=payload) → 加密 body，   POST <上游>  (body=帧)
//	GET  /                    → 运行状态页
//	GET  /cache               → 缓存查看页（污染状态 + 覆盖开关）
//	GET  /latency             → 上游延迟曲线（H2/H3 真实协议探测）
//
// 应答管线：主备上游并发竞速取最快（200 + 内容合法才认）→ 读应答第一个 IP
// → 命中污染 IP 段则回虚假 IP（A:169.254.254.254 / AAAA:::ffff:a9fe:fefe），
// 主备双败回空 DNS 应答（NOERROR 0 记录）；成功结果缓存，后续直接返回缓存，
// 后台每 15 分钟逐条向上游换新，每 30s 落盘。
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

	startTime    time.Time
	hits         atomic.Int64 // 缓存命中次数
	misses       atomic.Int64 // 缓存未命中次数
	upstreamOK   atomic.Int64 // 上游 200 成功次数（主备合计）
	fgErr        atomic.Int64 // 前台（首次）请求失败次数
	localAns     atomic.Int64 // 上游域名本地代答次数
	sysdnsQ      atomic.Int64 // system-dns.com 本地应答次数
	raceWinP     atomic.Int64 // 竞速主上游胜出次数
	raceWinF     atomic.Int64 // 竞速后备上游胜出次数
	raceTryP     atomic.Int64 // 竞速主上游发起次数
	raceTryF     atomic.Int64 // 竞速后备上游发起次数
	raceCancelP  atomic.Int64 // 主上游被后备抢先取消次数
	raceCancelF  atomic.Int64 // 后备被主上游抢先取消次数
	raceErr      atomic.Int64 // 竞速双败次数（回空应答）
	breakFails   atomic.Int64 // 当前连续双败计数（≥3 触发熔断）
	breakerUntil atomic.Int64 // 熔断截止（UnixNano，0=未熔断）
	breakerN     atomic.Int64 // 熔断期间拦下的请求数
	raceDurMs    atomic.Int64 // 竞速胜出者累计毫秒（求平均）
	fakeN        atomic.Int64 // 命中 IP 段回虚假 IP 次数
	forceFakeN   atomic.Int64 // 强制污染直接回虚假 IP 次数
	realN        atomic.Int64 // 取消污染放行真实结果次数
	sinkN        atomic.Int64 // 上游正常但无解析 → 回沉没地址（TTL 60s）次数
	sinkFailN    atomic.Int64 // 上游失败/熔断 → 回沉没地址（TTL 0）次数
	upstream429  atomic.Int64 // 上游 429 次数

	rateLimitHint atomic.Bool // 429 限流提示抑制（提示一次后 30 分钟内不再重复）

	// 缓存（持久化 + 定时换新）
	persistLoaded atomic.Int64 // 本次启动从 fastime-cache.json 恢复的条数
	refreshOK     atomic.Int64 // 定时换新累计成功条数
	refreshFail   atomic.Int64 // 定时换新累计失败条数（保留旧值）
	lastRefreshAt atomic.Int64 // 上次换新完成时刻（Unix 秒），0 = 尚未刷新

	lat *latTracker // 主/备上游延迟序列（真实请求 + 探测），/latency 折线图数据源

	lastDemandProbe atomic.Int64 // 折线图页面触发的按需探测节流（Unix 秒，≥2s 一次）

	upHost string // 上游主机名（小写），本地代答匹配用
	fbHost string // 后备上游主机名（小写），空 = 未配置

	iplist    *ipList        // 污染 IP 段表，nil = 未配置（不做污染判定）
	noFake    *overrideStore // 「取消污染」名单
	forceFake *overrideStore // 「强制污染」名单

	cpuMu       sync.Mutex // 状态页 CPU 采样：相邻两次访问间求平均
	lastCPUSec  float64
	lastCPUTime time.Time

	watchStop chan struct{}
	sysdns    *sysdnsHolder // system-dns.com 本地应答：系统真实 DNS 探测结果
}

// sfCall 单飞：后来者等待领导者的结果，避免相同请求重复打上游（省电核心）。
type sfCall struct {
	done chan struct{}
	body []byte
	err  error
}

const (
	maxPostBody         = 4 << 20 // POST 负载上限 4MB
	maxUpstreamInflight = 32      // 同时在飞的上游请求上限
)

func NewServer(cfg *Config) (*Server, error) {
	protectFromOOM() // linux/android：防止 LMK/OOM 杀死进程（移动端常驻关键）
	sc, err := newStreamCipher(cfg.Key)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:         cfg,
		cipher:      sc,
		log:         newLogger(cfg.LogLevel),
		cache:       newLRUCache(cfg.CacheSize),
		sf:          make(map[string]*sfCall),
		sem:         make(chan struct{}, maxUpstreamInflight),
		startTime:   time.Now(),
		lastCPUTime: time.Now(),
		lastCPUSec:  procCPUSeconds(),
		watchStop:   make(chan struct{}),
		lat:         newLatTracker(),
	}
	s.sysdns = newSysdnsHolder(s.log)
	s.noFake = newOverrideStore(noFakeFile, s.log)
	s.forceFake = newOverrideStore(forceFakeFile, s.log)
	s.noFake.load()
	s.forceFake.load()
	if cfg.IPListURL != "" {
		s.iplist = newIPList(cfg.IPListURL, s.log)
	} else {
		s.cfg.Warns = append(s.cfg.Warns, "未配置 IPLIST_URL：污染判定不生效（仅「强制污染」名单可用）")
	}
	fbHost := ""
	if cfg.Fallback != "" {
		if u, err := url.Parse(cfg.Fallback); err == nil {
			fbHost = u.Hostname()
		}
	}
	if u, err := url.Parse(cfg.Upstream); err == nil {
		s.upHost = strings.ToLower(u.Hostname())
	}
	s.fbHost = strings.ToLower(fbHost)
	s.client = newHybridClient(newFastDialer(cfg.DoTServer, s.log), s.log, cfg.QuicPrimary, cfg.QuicFallback, fbHost)
	if s.iplist != nil {
		// IP 段列表的域名解析走与上游相同的 DoT→DoH 链（不回退系统 DNS）
		s.iplist.resolve = s.client.dialer.lookup
	}
	// h2c：本地入口同时支持 HTTP/1.1 与 HTTP/2（先验模式）。
	h2s := &http2.Server{
		MaxHandlers:          0,
		MaxConcurrentStreams: 256,              // 本地多路复用：单连接并发流上限
		IdleTimeout:          10 * time.Second, // 与上游空闲策略一致，省电
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
	s.log.Infof("fastime 监听于 http://127.0.0.1:%s (上游 %s, 缓存 %d 条, 超时 %s, 日志 %s)",
		s.cfg.Port, s.cfg.Upstream, s.cfg.CacheSize, s.cfg.Timeout, s.cfg.LogLevel)
	if s.cfg.Fallback != "" {
		s.log.Infof("后备上游: %s（主备并发竞速取最快，主 %s / 备 %s 超时）", s.cfg.Fallback, s.cfg.Timeout, s.cfg.FbTimeout)
	}
	if s.iplist != nil {
		s.log.Infof("污染 IP 段列表: %s（命中第一个 IP 即回虚假 IP，12h 刷新）", s.cfg.IPListURL)
	}
	// 先恢复上次运行的缓存（前台立即可命中），再加载本地 IP 段表
	s.loadPersistedCache()
	if s.iplist != nil {
		s.iplist.loadLocal()
		go s.iplist.loop(s.watchStop)
	}
	go s.cacheLoop(s.watchStop) // 30s 落盘 + 15 分钟逐条换新
	go s.probeLoop()            // 上游延迟空闲探测（折线图数据源）
	go s.watchNetwork(s.watchStop)
	s.sysdnsStart() // 探测系统真实 DNS（system-dns.com 本地应答的数据源）
	// Shutdown 触发时 ListenAndServe 返回 ErrServerClosed——属正常退出，不上抛
	err := s.http.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Shutdown() {
	close(s.watchStop)
	s.savePersistedCache()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.http.Shutdown(ctx)
	s.client.Close()
}

// ---------- 路由 ----------

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch req.URL.Path {
	case "/e2e":
		// 继续向下走中继逻辑
	case "/":
		if req.Method == http.MethodGet {
			s.serveStatus(w)
			return
		}
	case "/cache":
		if req.Method == http.MethodGet {
			s.serveCache(w)
			return
		}
	case "/latency":
		if req.Method == http.MethodGet {
			s.serveLatency(w)
			return
		}
	case "/latency.json":
		if req.Method == http.MethodGet {
			s.serveLatencyJSON(w, req)
			return
		}
	case "/sysdns-refresh":
		if req.Method == http.MethodGet {
			s.serveSysdnsRefresh(w, req)
			return
		}
	case "/override":
		s.serveOverride(w, req)
		return
	case "/refresh":
		s.serveForceRefresh(w, req)
		return
	}
	if req.URL.Path != "/e2e" {
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
		// dns= 约定为 base64(DNS 报文)，与上游 Worker 明文模式一致
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
	// 保留 flags、QNAME(小写)+QTYPE+QCLASS、ECS 等其它 EDNS 选项
	canon := canonQuery(payload)
	key := cacheKey(req.Method, canon)
	q, qErr := parseQuestion(canon)
	isIPQ := qErr == nil && (q.Qtype == dnsTypeA || q.Qtype == dnsTypeAAAA)
	localQ := isIPQ && (q.Name == s.upHost || (s.fbHost != "" && q.Name == s.fbHost))

	// 「强制污染」域名：直接回虚假 IP——不打上游、不进缓存、不受上游故障影响
	if isIPQ && s.forceFakeHas(q.Name) {
		if body, err := buildFakeAnswer(payload, q.Qtype); err == nil {
			s.forceFakeN.Add(1)
			w.Header().Set("X-Cache", "FORCE-FAKE")
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(body)
			return
		}
	}

	// system-dns.com：本机构造的虚构域名，任何查询类型都直接本地应答，
	// 永远不打上游、不进缓存、不受熔断影响——A→全部 IPv4 DNS、
	// AAAA→全部 IPv6 DNS（TTL=1s），其它类型回空应答。
	// dig @127.0.0.1 -p <port> system-dns.com 即可随时查看当前系统 DNS
	if qErr == nil && q.Name == sysdnsDomain {
		w.Header().Set("X-Cache", "LOCAL-SYSDNS")
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(s.sysdnsAnswer(payload, q))
		return
	}

	// 缓存命中：立即返回。缓存里存的是上游原始应答，污染与否按当前
	// IP 段表 + 覆盖名单在应答时判定——覆盖改动下一次查询立即生效
	if body, ok := s.cache.Get(key); ok {
		s.hits.Add(1)
		w.Header().Set("X-Cache", "HIT")
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(s.decide(payload, body, q, isIPQ))
		return
	}
	s.misses.Add(1)

	// 熔断中（主备连续双败后的短暂保护窗）：未缓存的请求一律回
	// 沉没应答（A/AAAA → 0.0.0.0/::，TTL=0 不缓存），不再打上游——
	// 缓存命中与强制污染（不打上游）不受影响，照常返回
	if s.breakerOpen() {
		s.breakerN.Add(1)
		s.sinkFailN.Add(1)
		w.Header().Set("X-Cache", "BREAKER")
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(s.failAnswer(payload, q, isIPQ))
		return
	}

	// 上游域名本地代答：查询对象是主/备上游主机名本身（A/AAAA）时，
	// 直接走内置 DoT→DoH 链解析并构造应答，不经 Worker——
	// 否则"要连上游得先解析上游"就成死循环了
	if localQ {
		body, err := s.resolveLocal(payload, key)
		if err != nil {
			s.fgErr.Add(1)
			s.sinkFailN.Add(1)
			s.log.Errorf("上游域名本地解析失败: %v", err)
			w.Header().Set("X-Cache", "EMPTY-FAIL")
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(s.failAnswer(payload, q, isIPQ))
			return
		}
		s.localAns.Add(1)
		w.Header().Set("X-Cache", "MISS-LOCAL")
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(body)
		return
	}

	// 未命中：单飞 + 主备并发竞速
	s.log.Debugf("%s 缓存未命中, 负载 %d 字节, key=%s", req.Method, len(payload), keyFP(canon))
	body, err := s.fetch(req.Method, payload, key)
	if err != nil {
		s.fgErr.Add(1)
		s.sinkFailN.Add(1)
		s.log.Errorf("上游请求失败（回沉没应答 0.0.0.0/::，TTL=0）: %v", err)
		// 主备双败：A/AAAA 回沉没地址（TTL=0 不缓存），客户端连接立即失败，
		// 而不是传输层错误或长时间挂起
		w.Header().Set("X-Cache", "EMPTY-FAIL")
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(s.failAnswer(payload, q, isIPQ))
		return
	}
	w.Header().Set("X-Cache", "MISS-SHARED")
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(s.decide(payload, body, q, isIPQ))
}

// decide 应答时的污染判定：缓存/竞速拿到的是上游原始应答，这里决定回真实
// 还是虚假 IP。顺序：取消污染 > 强制污染（已在前面短路） > IP 段命中。
func (s *Server) decide(payload, body []byte, q dnsQuestion, isIPQ bool) []byte {
	if !isIPQ {
		return withTID(body, payload)
	}
	// 上游无解析结果 → 沉没地址 0.0.0.0 / ::：
	// NXDOMAIN → TTL=60s（结果稳定）；SERVFAIL/NODATA → TTL=0（不许缓存，
	// 下次查询立即重试上游）——客户端连接立即失败
	if ttl, noResult := dnsNoResult(body, q.Qtype); noResult {
		if sink, err := buildSinkholeAnswer(payload, q.Qtype, ttl); err == nil {
			s.sinkN.Add(1)
			s.log.Debugf("%s %s 上游无解析结果，回沉没地址 %s（TTL %ds）", q.Name, qtypeName(q.Qtype), sinkIPFor(q.Qtype), ttl)
			return sink
		}
	}
	if s.noFakeHas(q.Name) { // 「取消污染」：命中 IP 段也回真实结果
		s.realN.Add(1)
		return withTID(body, payload)
	}
	if s.cfg.PolluteMode == "off" { // 污染判定关闭：全部原样返回（手动覆盖名单仍生效）
		return withTID(body, payload)
	}
	if s.iplist != nil {
		if ip := firstAnswerIP(body); ip != nil && s.iplist.Contains(ip) {
			if fake, err := buildFakeAnswer(payload, q.Qtype); err == nil {
				s.fakeN.Add(1)
				s.log.Debugf("%s %s 应答第一个 IP %s 命中污染段，回虚假 IP", q.Name, qtypeName(q.Qtype), ip)
				return fake
			}
		}
	}
	return withTID(body, payload)
}

// failAnswer 上游失败/熔断时的应答：A/AAAA 回沉没地址（0.0.0.0 / ::，
// TTL=0——明确不缓存，下次查询立即重试）；其它查询类型回空应答
// （NOERROR + SOA 负缓存 TTL=1s）。
func (s *Server) failAnswer(payload []byte, q dnsQuestion, isIPQ bool) []byte {
	if isIPQ {
		if body, err := buildSinkholeAnswer(payload, q.Qtype, 0); err == nil {
			return body
		}
	}
	return buildEmptyAnswer(payload, 1)
}

// ---------- 上游竞速 ----------

// fetch 单飞 + 竞速：并发相同请求共享一次上游往返。
func (s *Server) fetch(method string, payload []byte, key string) ([]byte, error) {
	s.sfMu.Lock()
	if c, ok := s.sf[key]; ok { // 跟随者：等待领导者
		s.sfMu.Unlock()
		s.log.Debugf("单飞跟随: %s", method)
		<-c.done
		return c.body, c.err
	}
	c := &sfCall{done: make(chan struct{})}
	s.sf[key] = c
	s.sfMu.Unlock()

	var body []byte
	var err error
	if s.cfg.Fallback != "" {
		body, err = s.raceUpstream(method, payload, key) // 主备并发竞速
	} else {
		body, err = s.doFetchCtx(context.Background(), s.cfg.Upstream, s.cfg.Timeout, method, payload, key)
		if err == nil && !dnsRespOK(body) {
			err = errors.New("上游应答内容非法（非有效 DNS 响应）")
		}
	}
	c.body, c.err = body, err
	s.breakerAccount(err)
	close(c.done)
	s.sfMu.Lock()
	delete(s.sf, key)
	s.sfMu.Unlock()
	return body, err
}

// raceUpstream 主/备上游同时出发：谁先返回「200 + 内容合法」用谁，
// 败者立即取消；双败返回错误（调用方回空 DNS 应答）。
func (s *Server) raceUpstream(method string, payload []byte, key string) ([]byte, error) {
	start := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // 胜者已定 → 取消败者的在途请求
	type res struct {
		body    []byte
		primary bool
		err     error
	}
	ch := make(chan res, 2)
	go func() {
		s.raceTryP.Add(1)
		b, e := s.doFetchCtx(ctx, s.cfg.Upstream, s.cfg.Timeout, method, payload, key)
		ch <- res{b, true, e}
	}()
	go func() {
		s.raceTryF.Add(1)
		b, e := s.doFetchCtx(ctx, s.cfg.Fallback, s.cfg.FbTimeout, method, payload, key)
		ch <- res{b, false, e}
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		r := <-ch
		if r.err == nil && dnsRespOK(r.body) {
			cancel()
			if r.primary {
				s.raceWinP.Add(1)
				s.raceCancelF.Add(1) // 后备在途请求被取消（主更快，属正常）
			} else {
				s.raceWinF.Add(1)
				s.raceCancelP.Add(1)
			}
			s.raceDurMs.Add(time.Since(start).Milliseconds())
			return r.body, nil
		}
		if r.err != nil {
			firstErr = r.err
		} else {
			firstErr = errors.New("上游应答内容非法（非有效 DNS 响应）")
		}
	}
	s.raceErr.Add(1)
	return nil, fmt.Errorf("主备上游竞速双败: %w", firstErr)
}

// ---------- 熔断器 ----------
// 连续 3 次主备双败 → 熔断 2 秒：期间未缓存的请求一律回 HTTP 200 +
// 沉没应答（A/AAAA → 0.0.0.0/::，TTL=0 不缓存），不打上游——
// 纯粹快速失败（断网场景省流省电）。
// 缓存命中、强制污染（直接回虚假 IP，不打上游）不受影响，照常返回。
// 任何一次成功立即清零计数；切网时重置（新网络上游可能恢复）。

const (
	breakThreshold = 3
	breakDuration  = 2 * time.Second
)

func (s *Server) breakerAccount(err error) {
	if err == nil {
		s.breakFails.Store(0)
		return
	}
	if s.breakFails.Add(1) >= breakThreshold {
		s.breakerUntil.Store(time.Now().Add(breakDuration).UnixNano())
		s.breakFails.Store(0)
		s.log.Errorf("主备连续 %d 次双败，熔断 %ds：期间未命中请求直接回空应答", breakThreshold, int(breakDuration.Seconds()))
	}
}

func (s *Server) breakerOpen() bool {
	u := s.breakerUntil.Load()
	return u > 0 && time.Now().UnixNano() < u
}

func (s *Server) breakerRemain() time.Duration {
	u := s.breakerUntil.Load()
	if u <= 0 {
		return 0
	}
	d := time.Until(time.Unix(0, u))
	if d < 0 {
		return 0
	}
	return d
}

func (s *Server) resetBreaker() {
	s.breakFails.Store(0)
	s.breakerUntil.Store(0)
}

// dnsRespOK 校验上游应答是合法 DNS 响应（QR=1 且能解析出问题区）。
func dnsRespOK(body []byte) bool {
	if len(body) < 12 || body[2]&0x80 == 0 {
		return false
	}
	_, err := parseQuestion(body)
	return err == nil
}

// ---------- 单次上游请求（加密 + 打点 + 写缓存） ----------

func (s *Server) doFetchCtx(parent context.Context, upstream string, timeout time.Duration, method string, payload []byte, key string) ([]byte, error) {
	// 并发闸门：超过上限的请求在此排队，防止瞬间打满射频与 CPU（移动端能耗保护）
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-parent.Done():
		return nil, parent.Err()
	}

	var req *http.Request
	var err error
	if method == http.MethodGet {
		// GET：加密 → base64url → 拼 e2e= 参数，GET 上游
		enc, encErr := s.cipher.EncryptForQuery(payload)
		if encErr != nil {
			return nil, encErr
		}
		sep := "?"
		if strings.Contains(upstream, "?") {
			sep = "&"
		}
		req, err = http.NewRequest(http.MethodGet, upstream+sep+"e2e="+url.QueryEscape(enc), nil)
	} else {
		encBody, encErr := s.cipher.Encrypt(payload)
		if encErr != nil {
			return nil, encErr
		}
		req, err = http.NewRequest(http.MethodPost, upstream, bytes.NewReader(encBody))
	}
	if err != nil {
		return nil, err
	}
	// 分阶段耗时打点（/latency 延迟曲线）：dialPhases 由拨号器/QUIC 传输回填
	// DNS/TCP/握手耗时，httptrace 补 h2 的 TLS 握手与首字节；连接复用时全为 0
	ph := &dialPhases{}
	parent = context.WithValue(parent, dialPhasesKey{}, ph)
	start := time.Now()
	var tlsStart time.Time
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			if !tlsStart.IsZero() {
				ph.tlsMs, ph.hasDial = time.Since(tlsStart).Milliseconds(), true
			}
		},
		GotFirstResponseByte: func() { ph.ttfbMs = time.Since(start).Milliseconds() },
	}
	ctx, cancel := context.WithTimeout(httptrace.WithClientTrace(parent, trace), timeout)
	defer cancel()
	req = req.WithContext(ctx)

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
		return nil, err
	}
	defer resp.Body.Close()
	if ph.ttfbMs == 0 {
		// h3 等不触发 httptrace 首字节事件的路径：响应头到达≈首字节
		ph.ttfbMs = time.Since(start).Milliseconds()
	}
	ph.proto = protoLabel(resp.Proto) // 实际协商的协议（h2/h3/h1），延迟页展示
	s.log.Debugf("%s 上游响应 %d, 协议 %s, 耗时 %s", method, resp.StatusCode, ph.proto, time.Since(start))
	if resp.StatusCode == http.StatusTooManyRequests {
		// 429 是 Cloudflare 平台层限流（Worker 代码本身只返回 400/405）：
		// 免费版每日 10 万次请求额度耗尽，或突发限流。单独醒目提示一次，
		// 避免被失败日志淹没后误判成"网络不通"
		s.upstream429.Add(1)
		if s.rateLimitHint.CompareAndSwap(false, true) {
			s.log.Errorf("上游被 Cloudflare 限流（429）：免费版额度约 10 万次/日可能已耗尽" +
				"（主备双上游竞速会加倍消耗额度）。对策：升付费版 / 主备分两个账号。UTC 零点重置额度")
			go func() { // 提示抑制定时解除（额度重置后能再次提醒）
				time.Sleep(30 * time.Minute)
				s.rateLimitHint.Store(false)
			}()
		}
		return nil, fmt.Errorf("上游返回 429（Cloudflare 限流）")
	}
	if resp.StatusCode != http.StatusOK {
		// 只缓存 200：非 200 一律视为错误，不进缓存
		return nil, fmt.Errorf("上游返回 %d", resp.StatusCode)
	}

	var buf bytes.Buffer
	if err := s.cipher.DecryptStream(resp.Body, &buf, nil); err != nil {
		return nil, err
	}
	// 延迟打点（/latency 折线图）：总耗时含完整传输，分阶段耗时由 ph 携带；
	// key 为空串 = 空闲/按需探测，曲线标记为探测点且不写缓存
	s.lat.record(upstream == s.cfg.Upstream, float64(time.Since(start).Milliseconds()), key == "", *ph)
	s.upstreamOK.Add(1)
	// 空响应不入缓存：上游异常时的 0 字节 200 一旦入缓存会持续毒害客户端。
	// 只缓存 NOERROR / NXDOMAIN：SERVFAIL 等错误码多为临时故障，
	// 缓存没有 TTL 语义，一次抖动就会把该域名长期毒害成"服务器失败"
	if buf.Len() > 0 && key != "" { // key 空串 = 探测请求，不落缓存
		if r := buf.Bytes(); len(r) >= 4 && (r[3]&0x0f == 0 || r[3]&0x0f == 3) {
			s.cache.Put(key, buf.Bytes())
		} else {
			s.log.Debugf("上游应答 RCODE=%d（非 NOERROR/NXDOMAIN），不写入缓存", r[3]&0x0f)
		}
	}
	s.log.Debugf("%s 上游完成, 解密 %d 字节, 已写缓存", method, buf.Len())
	return buf.Bytes(), nil
}

// protoLabel 把 http.Response.Proto 归一化成短标签（延迟曲线展示用）。
func protoLabel(p string) string {
	switch {
	case strings.HasPrefix(p, "HTTP/3"):
		return "h3"
	case strings.HasPrefix(p, "HTTP/2"):
		return "h2"
	default:
		return "h1"
	}
}

// resolveLocal 上游域名本地代答：绕过 Worker，走内置解析链
// DoT(223.5.5.5:853) → 失败自动阿里 DoH(443) → 两级都失败才报错（绝不回退系统 DNS），
// 用结果构造 DNS 应答并写入缓存。
func (s *Server) resolveLocal(payload []byte, key string) ([]byte, error) {
	q, err := parseQuestion(payload)
	if err != nil {
		return nil, err
	}
	host := strings.ToLower(q.Name)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ips, err := s.client.dialer.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	body, err := buildAnswer(payload, q.Qtype, ips, 60)
	if err != nil {
		return nil, err
	}
	s.cache.Put(key, body)
	matched := 0
	for _, ip := range ips {
		if q.Qtype == dnsTypeA && ip.To4() != nil {
			matched++
		}
		if q.Qtype == dnsTypeAAAA && ip.To4() == nil && ip.To16() != nil {
			matched++
		}
	}
	s.log.Infof("本地代答 %s %s → %d 条记录（解析共 %d 个 IP，DoT/DoH 直连，不经上游）",
		host, qtypeName(q.Qtype), matched, len(ips))
	return body, nil
}

// serveForceRefresh 强制向上游刷新某条缓存（/cache 页每行按钮）。
func (s *Server) serveForceRefresh(w http.ResponseWriter, req *http.Request) {
	key := req.URL.Query().Get("key")
	method, canon, ok := splitCacheKey(key)
	if !ok {
		http.Error(w, "bad key", http.StatusBadRequest)
		return
	}
	go func() { // 后台换新，页面立即跳回
		if _, err := s.fetch(method, canon, key); err != nil {
			s.log.Debugf("手动刷新失败: %v", err)
		}
	}()
	http.Redirect(w, req, "/cache", http.StatusSeeOther)
}

// serveSysdnsRefresh 手动强制重新探测系统 DNS（状态页 🔄 按钮），
// 探测完跳回状态页——下次查询 system-dns.com 就是新结果。
func (s *Server) serveSysdnsRefresh(w http.ResponseWriter, req *http.Request) {
	s.sysdns.detect()
	http.Redirect(w, req, "/", http.StatusSeeOther)
}

// refreshBtn 缓存页"立即刷新"按钮。
func refreshBtn(key string) string {
	return fmt.Sprintf(`<a class="opb rf" href="/refresh?key=%s">♻️ 立即刷新</a>`, urlQueryEscape(key))
}

// ---------- 缓存键与报文规范化 ----------

// cacheKey / splitCacheKey：缓存键 = 方法 + \x00 + 负载。
func cacheKey(method string, payload []byte) string {
	return method + "\x00" + string(payload)
}

func splitCacheKey(key string) (method string, payload []byte, ok bool) {
	i := strings.IndexByte(key, 0)
	if i <= 0 {
		return "", nil, false
	}
	return key[:i], []byte(key[i+1:]), true
}

// canonQuery 规范化 DNS 查询报文作为缓存键：
//
//	剔除 —— 事务 ID（每次随机）、EDNS COOKIE 选项（每次随机）；
//	保留 —— flags（DO/CD 等用户设置）、问题区（QNAME 小写+QTYPE+QCLASS，
//	       支持全部记录类型）、ECS 等其它 EDNS 选项（用户设置，影响应答内容）。
//
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
	out = append(out, 0, 0)       // 事务 ID 归零
	out = append(out, p[2:12]...) // flags + 各段计数，原样保留
	i := 12

	// 拷贝域名（小写化，防 0x20 大小写随机化导致键抖动）
	copyName := func() bool {
		start := i
		j, err := skipName(p, i)
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
// 同时同步问题区：缓存键对 QNAME 做了小写归一，但缓存的响应里问题区是
// 上一次查询的原始大小写——开启 0x20 大小写随机化校验的客户端（Chrome 等）
// 会因大小写不符拒收响应并重试到放弃。QNAME 大小写变化不改变长度，
// 直接把本次查询的问题区覆盖回去即可。
func withTID(body, query []byte) []byte {
	if len(query) < 12 || len(body) < 12 {
		return body
	}
	needTID := body[0] != query[0] || body[1] != query[1]
	_, qe1, err1 := decodeName(query, 12)
	_, qe2, err2 := decodeName(body, 12)
	qe1 += 4
	qe2 += 4
	syncQ := err1 == nil && err2 == nil && qe1 == qe2 &&
		qe1 <= len(query) && qe2 <= len(body) &&
		!bytes.Equal(query[12:qe1], body[12:qe2])
	if !needTID && !syncQ {
		return body
	}
	out := make([]byte, len(body))
	copy(out, body)
	out[0], out[1] = query[0], query[1]
	if syncQ {
		copy(out[12:qe2], query[12:qe1])
	}
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

// procCPUSeconds 读取进程累计 CPU 秒（runtime/metrics，全平台可用，无 syscall 依赖）。
// 老 Go 版本无此指标时返回 0，状态页显示 "-"。
func procCPUSeconds() float64 {
	samples := []metrics.Sample{{Name: "/cpu/classes/total:cpu-seconds"}}
	metrics.Read(samples)
	if len(samples) == 0 || samples[0].Value.Kind() == metrics.KindBad {
		return 0
	}
	return samples[0].Value.Float64()
}

// rcodeText DNS 响应码助记（缓存页展示用）。
func rcodeText(rcode int) string {
	switch rcode {
	case 1:
		return "格式错误"
	case 2:
		return "服务器失败 SERVFAIL"
	case 3:
		return "域名不存在 NXDOMAIN"
	case 4:
		return "不支持"
	case 5:
		return "拒绝 REFUSED"
	}
	return "未知"
}
