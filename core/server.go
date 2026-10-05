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
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"runtime"
	"runtime/metrics"
	"sort"
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

	startTime     time.Time
	hits          atomic.Int64 // 缓存命中次数
	misses        atomic.Int64 // 缓存未命中次数
	upstreamOK    atomic.Int64 // 主上游 200 成功次数
	upDurMs       atomic.Int64 // 主上游成功请求累计毫秒（求平均）
	fgErr         atomic.Int64 // 前台（首次）请求失败次数
	bgErr         atomic.Int64 // 后台刷新失败次数
	fbTry         atomic.Int64 // 后备上游尝试次数
	fbOK          atomic.Int64 // 后备上游成功次数
	fbErr         atomic.Int64 // 后备上游失败次数
	fbDurMs       atomic.Int64 // 后备请求累计毫秒（求平均）
	failStreak    atomic.Int64 // 主备链连续失败次数（成功即清零）
	breakUntil    atomic.Int64 // 熔断截止（UnixNano），0 = 未熔断
	rateLimitHint atomic.Bool  // 429 限流提示抑制（提示一次后 30 分钟内不再重复）
	breakSkip     atomic.Int64 // 熔断期间本地快速跳过的请求数
	localAns      atomic.Int64 // 上游域名本地代答次数

	// 运行缓存（持久化 + 定时批量刷新）
	persistLoaded atomic.Int64 // 本次启动从 fastime-cache.json 恢复的条数
	refreshOK     atomic.Int64 // 定时刷新累计成功条数
	refreshFail   atomic.Int64 // 定时刷新累计失败条数（保留旧值）
	lastRefreshAt atomic.Int64 // 上次批量刷新完成时刻（Unix 秒），0 = 尚未刷新

	lat *latTracker // 主/备上游延迟序列（真实请求 + 空闲探测），/latency 折线图数据源

	lastDemandProbe atomic.Int64 // 折线图页面触发的按需探测节流（Unix 秒，≥2s 一次）

	upHost string // 上游主机名（小写），本地代答匹配用
	fbHost string // 后备上游主机名（小写），空 = 未配置

	// turbo 新模式（RUN_MODE=turbo）
	iplist     *ipList         // IP 段列表（命中 → 系统 DNS 代管），nil = 未配置
	sysres     *sysResolver    // 系统 DNS 解析器
	sysCache   *sysCache       // 系统 DNS 代管缓存（与上游缓存隔离，切网即清）
	raceWinP   atomic.Int64    // 竞速主上游胜出次数
	raceWinF   atomic.Int64    // 竞速后备上游胜出次数
	raceErr    atomic.Int64    // 竞速双败次数
	raceDurMs  atomic.Int64    // 竞速胜出者累计毫秒（求平均）
	sysOK      atomic.Int64    // 系统 DNS 代管解析成功次数
	sysErr     atomic.Int64    // 系统 DNS 代管解析失败次数
	marked     sync.Map        // 缓存键 -> *iplistMark：应答 IP 命中用户段的标记（缓存页徽标；代管失败也可见）
	iplistHitN atomic.Int64    // IP 段累计命中次数
	ndMu       sync.RWMutex    // noDivert 读写锁
	noDivert   map[string]bool // 用户指定"不走系统 DNS 代管"的域名（缓存页按钮切换，持久化到 fastime-nodivert.json）
	fdMu       sync.RWMutex    // forceDNS 读写锁
	forceDNS   map[string]bool // 用户指定"强制走系统 DNS"的域名（缓存页按钮切换，持久化到 fastime-forcedns.json）
	hijack     *hijacker       // 53 端口 DNS 劫持拦截器（HIJACK_DNS=true 且 turbo 时启用），nil = 未启用

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
	maxPostBody         = 4 << 20 // POST 负载上限 4MB
	maxUpstreamInflight = 32      // 同时在飞的上游请求上限
)

func NewServer(cfg *Config) (*Server, error) {
	sc, err := newStreamCipher(cfg.Key)
	if err != nil {
		return nil, err
	}
	cacheTTL := cfg.CacheTTL
	if cfg.Mode == "turbo" {
		cacheTTL = cfg.RaceCache // turbo 模式：上游结果缓存时长由 RACE_CACHE_SEC 控制
	}
	s := &Server{
		cfg:         cfg,
		cipher:      sc,
		log:         newLogger(cfg.LogLevel),
		cache:       newLRUCache(cfg.CacheSize, cacheTTL),
		sf:          make(map[string]*sfCall),
		sem:         make(chan struct{}, maxUpstreamInflight),
		startTime:   time.Now(),
		lastCPUTime: time.Now(),
		lastCPUSec:  procCPUSeconds(),
		watchStop:   make(chan struct{}),
		lat:         newLatTracker(),
		noDivert:    make(map[string]bool),
		forceDNS:    make(map[string]bool),
	}
	s.sysres = newSysResolver(s.log) // 两种模式都创建：状态页展示真实系统 DNS，turbo 另用于代管解析
	s.loadNoDivert()                 // 恢复"不走系统 DNS 代管"的豁免域名列表
	s.loadForceDNS()                 // 恢复"强制走系统 DNS"的域名清单
	if cfg.Mode == "turbo" {
		s.sysCache = newSysCache(cfg.CacheSize)
		if cfg.IPListURL != "" {
			s.iplist = newIPList(cfg.IPListURL, s.log)
			// IP 段列表每次下载成功后补扫一遍缓存：
			// 重启恢复的条目、列表未就绪期间缓存的条目，命中段内的补做系统 DNS 代管
			s.iplist.onUpdate = s.redivertCache
		}
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
	s.client = newHybridClient(newFastDialer(cfg.DoTServer, cfg.DialSingle, s.log), s.log, cfg.QuicPrimary, cfg.QuicFallback, fbHost)
	if s.iplist != nil {
		// IP 段列表的域名解析走与上游相同的 DoT→DoH 链（不回退系统 DNS）；
		// 本地表加载在 Start() 恢复缓存之后进行（见 Start）
		s.iplist.resolve = s.client.dialer.lookup
	}
	// h2c：本地入口同时支持 HTTP/1.1 与 HTTP/2（先验模式）。
	// q/dig 等 DoH 工具对 http:// 地址直接发 HTTP/2 前言，没有 h2c 会被
	// HTTP/1.1 服务器回 400 错误页，客户端解包 DNS 时溢出报错。
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
	s.log.Infof("fastime 监听于 http://127.0.0.1:%s (上游 %s, 缓存 %d 条, 静默期 %s, 超时 %s, 拨号 %s, 日志 %s)",
		s.cfg.Port, s.cfg.Upstream, s.cfg.CacheSize, s.cfg.CacheTTL, s.cfg.Timeout,
		map[bool]string{true: "single", false: "race"}[s.cfg.DialSingle], s.cfg.LogLevel)
	if s.cfg.Fallback != "" {
		s.log.Infof("后备上游: %s（主 %s 失败 → 备 %s）", s.cfg.Fallback, s.cfg.Timeout, s.cfg.FbTimeout)
	}
	if s.cfg.Mode == "turbo" {
		s.log.Infof("turbo 模式：主备并发竞速取最快，竞速结果缓存 %s；IP 段列表: %s（命中段内 IP 的域名改走系统 DNS，12h 刷新）",
			s.cfg.RaceCache, map[bool]string{true: s.cfg.IPListURL, false: "未配置"}[s.cfg.IPListURL != ""])
		if s.iplist != nil {
			go s.iplist.loop(s.watchStop)
		}
	}
	// 运行缓存：先恢复上次运行的上游缓存（前台立即可命中），再开定时批量刷新
	s.loadPersistedCache()
	// IP 段列表本地表在缓存恢复后再加载：onUpdate 补扫才能看到恢复的条目
	//（否则网络不可达时本地表加载早于缓存恢复，补扫扫了个空）
	if s.iplist != nil {
		s.iplist.loadLocal()
	}
	// 「强制走系统DNS」清单在缓存恢复后补建代管（重启自动恢复用户选择）
	for _, h := range s.forceDNSList() {
		s.forceDivertHost(h)
	}
	// 53 劫持（桌面平台接管系统 DNS 前）必须先拿到真实系统 DNS 并缓存住，
	// 否则接管后只能发现 127.0.0.1；iptables 平台不改系统 DNS，无此要求
	if s.cfg.HijackDNS {
		s.sysres.dnsServers()
		s.sysres.hijackGuard.Store(true) // 之后的发现丢弃 127.0.0.1/::1，防止接管后自我污染
	}
	go s.cacheRefreshLoop(s.watchStop)
	go s.cachePersistLoop(s.watchStop) // 定时落盘：强杀进程也最多丢一个间隔的增量
	go s.probeLoop(s.watchStop)        // 上游延迟空闲探测（折线图数据源）
	go s.sysres.dnsServers()           // 启动即发现系统 DNS（状态页可见；按网络缓存，切网重取）
	go s.watchNetwork(s.watchStop)
	if s.cfg.HijackDNS {
		s.startHijack() // 失败只记日志，不影响 HTTP 入口
	}
	// Shutdown 触发时 ListenAndServe 返回 ErrServerClosed——属正常退出，不上抛
	err := s.http.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Shutdown() {
	close(s.watchStop)
	if s.hijack != nil {
		s.hijack.close() // 先撤劫持（iptables 规则/系统 DNS 恢复），再关业务
	}
	s.savePersistedCache() // 退出前落盘：下次启动直接恢复
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
	case "/cache":
		if req.Method == http.MethodGet {
			s.serveCache(w)
			return
		}
		http.NotFound(w, req)
		return
	case "/latency":
		if req.Method == http.MethodGet {
			s.serveLatency(w)
			return
		}
		http.NotFound(w, req)
		return
	case "/latency.json":
		if req.Method == http.MethodGet {
			s.serveLatencyJSON(w)
			return
		}
		http.NotFound(w, req)
		return
	case "/nodivert":
		s.serveNoDivert(w, req)
		return
	case "/refresh":
		s.serveForceRefresh(w, req)
		return
	case "/forcedns":
		s.serveForceDNS(w, req)
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

	// 上游域名本地代答：查询对象是主/备上游主机名本身（A/AAAA）时，
	// 直接走内置 DoT→DoH 链解析并构造应答，不经 Worker——
	// 否则"要连上游得先解析上游"就成死循环了。
	q, qOK := parseQuestion(canon)
	isIPQ := qOK == nil && (q.Qtype == dnsTypeA || q.Qtype == dnsTypeAAAA)
	localQ := isIPQ && (q.Name == s.upHost || (s.fbHost != "" && q.Name == s.fbHost))

	// turbo 模式·系统 DNS 伺候的域名：命中过 IP 段的（marked）与用户「🧭 强制
	// 走系统DNS」的，一律只走系统 DNS——缓存命中即回（过期后台 SWR 刷新），
	// 未命中现场解析；失败不回退上游，也不受上游熔断影响（本分支在熔断检查之前）。
	if isIPQ && s.sysCache != nil && !s.noDivertHas(q.Name) &&
		(s.forceDNSHas(q.Name) || s.markedForSys(key)) {
		if e, ok := s.sysCache.Get(key); ok {
			s.hits.Add(1)
			w.Header().Set("X-Cache", "HIT-SYSDNS")
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(withTID(e.body, payload))
			if e.stale() {
				go s.sysRefreshBG(e.payload, key, e.q)
			}
			return
		}
		s.misses.Add(1)
		body, err := s.sysResolveAndCache(payload, key, q)
		if err != nil {
			s.sysErr.Add(1)
			s.log.Errorf("系统 DNS 解析 %s 失败（按设置不回退上游）: %v", q.Name, err)
			http.Error(w, "system dns failed", http.StatusBadGateway)
			return
		}
		w.Header().Set("X-Cache", "MISS-SYSDNS")
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(withTID(body, payload))
		return
	}

	// 命中：立即返回（回写本次查询的事务 ID）；过静默期才后台刷新（省电）
	if body, ok, fresh := s.cache.Get(key); ok {
		// "不走系统DNS"豁免域名用独立刷新时长（NODIVERT_REFRESH_SEC，默认 3 分钟）：
		// 条目年龄超过该时长即视为不新鲜，本次照常返回旧值 + 后台向上游换新
		if fresh && isIPQ && s.cfg.NoDivertRefresh > 0 && s.noDivertHas(q.Name) {
			if at, ok2 := s.cache.At(key); ok2 && time.Since(at) >= s.cfg.NoDivertRefresh {
				fresh = false
			}
		}
		s.hits.Add(1)
		s.log.Debugf("%s 缓存命中 fresh=%v key=%s", req.Method, fresh, keyFP(canon))
		w.Header().Set("X-Cache", "HIT")
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(withTID(body, payload))
		if !fresh {
			go s.cacheRefreshBG(req.Method, payload, key, localQ)
		}
		return
	}
	s.misses.Add(1)
	// 上游域名代答：未命中时本地解析，绕过熔断（与上游通不通无关）
	if localQ {
		body, err := s.resolveLocal(payload, key)
		if err != nil {
			s.fgErr.Add(1)
			s.log.Errorf("上游域名本地解析失败: %v", err)
			http.Error(w, "local resolve failed", http.StatusBadGateway)
			return
		}
		s.localAns.Add(1)
		w.Header().Set("X-Cache", "MISS-LOCAL")
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(body)
		return
	}
	// 熔断中：本地快速失败，不打上游（断网时保护射频与电量；缓存命中不受熔断影响）
	if s.breakerOpen() {
		s.breakSkip.Add(1)
		s.log.Debugf("%s 熔断中，本地快速失败", req.Method)
		http.Error(w, "upstream outage (circuit open)", http.StatusBadGateway)
		return
	}
	// 键指纹：同 host 同类型的多次查询应打出完全相同的指纹+键内容，
	// 若不同则说明报文里还有未归一化的差异字段（debug 排障用）
	s.log.Debugf("%s 缓存未命中, 负载 %d 字节, key=%s canon=%s",
		req.Method, len(payload), keyFP(canon), base64.StdEncoding.EncodeToString(canon))

	// 未命中：单飞。领导者边解密边流式回写；并发相同请求共享结果。
	body, streamed, err := s.fetch(req.Method, payload, key, w)
	if err != nil {
		s.fgErr.Add(1)
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

// markedForSys 该缓存键是否已被标记"应走系统 DNS"（应答 IP 命中过 IP 段，
// 或用户强制）；标记存在期间查询只走系统 DNS，不回退上游。
func (s *Server) markedForSys(key string) bool {
	_, ok := s.marked.Load(key)
	return ok
}

// sysRefreshBG 系统 DNS 代管条目的后台 SWR 刷新（失败保留旧值，下次再试）。
func (s *Server) sysRefreshBG(payload []byte, key string, q dnsQuestion) {
	if _, err := s.sysResolveAndCache(payload, key, q); err != nil {
		s.sysErr.Add(1)
		s.log.Debugf("系统 DNS 后台刷新失败: %v", err)
	}
}

// cacheRefreshBG 上游缓存条目的后台 SWR 刷新：代答条目走本地解析，
// 熔断中暂停（省流省电），失败保留旧值（bgErr 单独计数）。
func (s *Server) cacheRefreshBG(method string, payload []byte, key string, localQ bool) {
	if localQ { // 代答条目过期：后台重新本地解析，不碰上游、不受熔断影响
		if _, err := s.resolveLocal(payload, key); err != nil {
			s.bgErr.Add(1)
			s.log.Debugf("后台代答刷新失败: %v", err)
		}
		return
	}
	if s.breakerOpen() { // 熔断中暂停后台刷新，省流省电
		s.breakSkip.Add(1)
		return
	}
	// 后台刷新失败单独计数（bgErr），debug 级日志便于排查
	if _, _, err := s.fetch(method, normPayload(payload), key, nil); err != nil {
		s.bgErr.Add(1)
		s.log.Debugf("后台刷新失败: %v", err)
	}
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

	var body []byte
	var streamed bool
	var err error
	if s.cfg.Mode == "turbo" && s.cfg.Fallback != "" {
		body, err = s.raceUpstream(method, payload, key) // 竞速：缓冲模式，不流式
	} else {
		body, streamed, err = s.fetchUpstream(method, payload, key, w)
	}
	c.body, c.err = body, err
	close(c.done)
	s.sfMu.Lock()
	delete(s.sf, key)
	s.sfMu.Unlock()
	return body, streamed, err
}

// raceUpstream turbo 模式：主/备上游同时出发，谁先返回 200 用谁，败者取消。
// 胜出结果由 doFetch 写入上游缓存（时长 RACE_CACHE_SEC）；
// 随后若应答 IP 命中用户 IP 段，改走系统 DNS 解析并按其 TTL 代管缓存。
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
		b, _, e := s.doFetchCtx(ctx, s.cfg.Upstream, s.cfg.Timeout, method, payload, key, nil)
		ch <- res{b, true, e}
	}()
	go func() {
		b, _, e := s.doFetchCtx(ctx, s.cfg.Fallback, s.cfg.FbTimeout, method, payload, key, nil)
		ch <- res{b, false, e}
	}()

	var firstErr error
	var winPri bool
	var body []byte
	for i := 0; i < 2; i++ {
		r := <-ch
		if r.err == nil {
			body, winPri = r.body, r.primary
			break
		}
		firstErr = r.err // 先到的是错误：等另一个
	}
	if body == nil {
		s.raceErr.Add(1)
		s.noteUpstreamFailure()
		return nil, fmt.Errorf("主备上游竞速双败: %w", firstErr)
	}
	cancel()
	s.resetBreaker()
	if winPri {
		s.raceWinP.Add(1)
	} else {
		s.raceWinF.Add(1)
	}
	s.raceDurMs.Add(time.Since(start).Milliseconds())

	// 应答 IP 命中用户 IP 段 → 该域名改由系统 DNS 代管（按系统应答 TTL 缓存）
	if s.iplist != nil {
		if q, qerr := parseQuestion(normPayload(payload)); qerr == nil &&
			(q.Qtype == dnsTypeA || q.Qtype == dnsTypeAAAA) && !s.noDivertHas(q.Name) {
			if mip, ok := s.matchAnswer(body); ok {
				s.iplistHitN.Add(1)
				s.log.Infof("%s %s 应答 IP %s 命中 IP 段，改由系统 DNS 代管", q.Name, qtypeName(q.Qtype), mip)
				if sbody, err := s.sysResolveAndCache(payload, key, q); err == nil {
					s.marked.Store(key, &iplistMark{ip: mip, at: time.Now(), diverted: true})
					return sbody, nil
				} else {
					// 代管失败打标记（缓存页可见原因）后按规则失败返回：
					// 走系统 DNS 的域名失败后继续走系统 DNS，不回退上游竞速结果
					s.marked.Store(key, &iplistMark{ip: mip, at: time.Now(), diverted: false, err: err.Error()})
					s.sysErr.Add(1)
					s.log.Errorf("系统 DNS 解析 %s 失败(%v)，按设置不回退上游，下次查询重试系统 DNS", q.Name, err)
					return nil, fmt.Errorf("系统 DNS 解析失败（不回退上游）: %w", err)
				}
			}
		}
	}
	return body, nil
}

// matchAnswer 检查上游应答中的 A/AAAA 记录是否命中用户 IP 段，返回首个命中的 IP。
func (s *Server) matchAnswer(body []byte) (string, bool) {
	rcode, answers, err := parseResponse(body)
	if err != nil || rcode != 0 {
		return "", false
	}
	for _, a := range answers {
		if a.Type != "A" && a.Type != "AAAA" {
			continue
		}
		if ip := net.ParseIP(a.Data); ip != nil && s.iplist.Contains(ip) {
			return a.Data, true
		}
	}
	return "", false
}

// redivertCache IP 段列表下载/更新成功后补扫上游缓存：
// 重启从磁盘恢复的条目、以及列表未就绪期间缓存的条目，不会经过竞速时的
// 命中判断——这里补做：命中段内且未豁免的，立即补建系统 DNS 代管。
func (s *Server) redivertCache() {
	if s.sysCache == nil || s.iplist == nil {
		return
	}
	for _, it := range s.cache.Snapshot() {
		_, canon, ok := splitCacheKey(it.key)
		if !ok {
			continue
		}
		q, qerr := parseQuestion(canon)
		if qerr != nil || (q.Qtype != dnsTypeA && q.Qtype != dnsTypeAAAA) {
			continue
		}
		if s.noDivertHas(q.Name) {
			continue // 用户指定不走系统 DNS
		}
		if _, ok := s.sysCache.Get(it.key); ok {
			continue // 已在代管中
		}
		if mip, ok := s.matchAnswer(it.body); ok {
			s.iplistHitN.Add(1)
			s.log.Infof("补扫：%s %s 缓存应答 IP %s 命中 IP 段，补建系统 DNS 代管", q.Name, qtypeName(q.Qtype), mip)
			if _, err := s.sysResolveAndCache(canon, it.key, q); err == nil {
				s.marked.Store(it.key, &iplistMark{ip: mip, at: time.Now(), diverted: true})
			} else {
				s.marked.Store(it.key, &iplistMark{ip: mip, at: time.Now(), diverted: false, err: err.Error()})
				s.sysErr.Add(1)
			}
		}
	}
}

// redivertHost 取消某域名"不走系统 DNS"豁免后，立即尝试重新代管。
func (s *Server) redivertHost(host string) {
	if s.sysCache == nil || s.iplist == nil {
		return
	}
	for _, it := range s.cache.Snapshot() {
		_, canon, ok := splitCacheKey(it.key)
		if !ok {
			continue
		}
		q, qerr := parseQuestion(canon)
		if qerr != nil || q.Name != host || (q.Qtype != dnsTypeA && q.Qtype != dnsTypeAAAA) {
			continue
		}
		if _, ok := s.sysCache.Get(it.key); ok {
			continue
		}
		if mip, ok := s.matchAnswer(it.body); ok {
			if _, err := s.sysResolveAndCache(canon, it.key, q); err == nil {
				s.marked.Store(it.key, &iplistMark{ip: mip, at: time.Now(), diverted: true})
			}
		}
	}
}

// sysResolveAndCache 用系统 DNS 解析并构造应答，按应答 TTL 写入代管缓存。
// 后续同域名查询直接命中代管缓存，过期后台刷新也只走系统 DNS（不再碰上游）。
func (s *Server) sysResolveAndCache(payload []byte, key string, q dnsQuestion) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ips, ttl, err := s.sysres.lookup(ctx, q.Name, q.Qtype)
	if err != nil {
		return nil, err
	}
	body, err := buildAnswer(payload, q.Qtype, ips, ttl)
	if err != nil {
		return nil, err
	}
	s.sysCache.Put(&sysEntry{
		key:     key,
		q:       q,
		payload: normPayload(payload),
		body:    body,
		at:      time.Now(),
		ttl:     time.Duration(ttl) * time.Second,
	})
	s.sysOK.Add(1)
	s.log.Debugf("系统 DNS 代管 %s %s → %d 个 IP，TTL %ds", q.Name, qtypeName(q.Qtype), len(ips), ttl)
	return body, nil
}

// breakerOpen 熔断中：请求本地快速失败，不碰射频（断网/弱网省流省电关键）。
// BreakDur = 0 时熔断整体禁用。
func (s *Server) breakerOpen() bool {
	if s.cfg.BreakDur <= 0 {
		return false
	}
	until := s.breakUntil.Load()
	return until > 0 && time.Now().UnixNano() < until
}

// noteUpstreamFailure 主备链最终失败：累计连续失败，达到阈值熔断。
// 熔断期结束后的探测请求若再失败（streak > 阈值），重新熔断（半开语义）。
func (s *Server) noteUpstreamFailure() {
	if s.cfg.BreakDur <= 0 {
		return
	}
	streak := s.failStreak.Add(1)
	if streak == int64(s.cfg.BreakFails) {
		s.log.Infof("上游连续 %d 次失败，熔断 %s（期间缓存照常返回，新请求快速失败）", s.cfg.BreakFails, s.cfg.BreakDur)
	}
	if streak >= int64(s.cfg.BreakFails) {
		s.breakUntil.Store(time.Now().Add(s.cfg.BreakDur).UnixNano())
	}
}

// resetBreaker 任一上游成功：连续失败清零，熔断解除。
func (s *Server) resetBreaker() {
	if s.failStreak.Load() > 0 || s.breakUntil.Load() > 0 {
		s.failStreak.Store(0)
		if s.breakUntil.Load() > 0 {
			s.log.Infof("上游恢复，熔断解除")
		}
		s.breakUntil.Store(0)
	}
}

// fetchUpstream 主备请求逻辑（首次请求与后台刷新共用）：
//
//	主上游（cfg.Timeout，默认 3s）→ 失败 → 后备上游（cfg.FbTimeout，默认 5s）→ 失败 → 报错
//
// 每次请求独立决策：单次失败不影响后续请求，下一个请求仍然先打主上游。
func (s *Server) fetchUpstream(method string, payload []byte, key string, w http.ResponseWriter) ([]byte, bool, error) {
	start := time.Now()
	body, streamed, err := s.doFetch(s.cfg.Upstream, s.cfg.Timeout, method, payload, key, w)
	if err == nil {
		s.resetBreaker()
		s.upstreamOK.Add(1)
		s.upDurMs.Add(time.Since(start).Milliseconds())
		return body, streamed, nil
	}
	// 已流式写出的请求不能重试（客户端已收到部分数据）
	if streamed || s.cfg.Fallback == "" {
		s.noteUpstreamFailure()
		return nil, streamed, err
	}
	s.log.Debugf("主上游失败(%v)，重试后备上游", err)
	body, streamed, err = s.tryFallback(method, payload, key, w)
	if err != nil {
		s.noteUpstreamFailure()
		return nil, streamed, err
	}
	s.resetBreaker()
	return body, streamed, nil
}

// tryFallback 打后备上游并统计次数与耗时。
func (s *Server) tryFallback(method string, payload []byte, key string, w http.ResponseWriter) ([]byte, bool, error) {
	s.fbTry.Add(1)
	fbStart := time.Now()
	body, streamed, err := s.doFetch(s.cfg.Fallback, s.cfg.FbTimeout, method, payload, key, w)
	s.fbDurMs.Add(time.Since(fbStart).Milliseconds())
	if err != nil {
		s.fbErr.Add(1)
		return nil, streamed, err
	}
	s.fbOK.Add(1)
	return body, streamed, nil
}

func (s *Server) doFetch(upstream string, timeout time.Duration, method string, payload []byte, key string, w http.ResponseWriter) ([]byte, bool, error) {
	return s.doFetchCtx(context.Background(), upstream, timeout, method, payload, key, w)
}

// doFetchCtx 与 doFetch 相同，但接受父 context：turbo 模式胜者产生后立即取消败者。
func (s *Server) doFetchCtx(parent context.Context, upstream string, timeout time.Duration, method string, payload []byte, key string, w http.ResponseWriter) ([]byte, bool, error) {
	// 并发闸门：超过上限的相同/不同请求在此排队，
	// 防止瞬间打满射频与 CPU（移动端能耗保护）
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-parent.Done():
		return nil, false, parent.Err()
	}

	var req *http.Request
	var err error

	if method == http.MethodGet {
		// GET：加密 → base64url → 拼 e2e= 参数，GET 上游
		enc, encErr := s.cipher.EncryptForQuery(payload)
		if encErr != nil {
			return nil, false, encErr
		}
		u := upstream
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
		req, err = http.NewRequest(http.MethodPost, upstream, bytes.NewReader(encBody))
	}
	if err != nil {
		return nil, false, err
	}
	// 上游请求超时（主/备分别由 REQUEST_TIMEOUT_SEC / FALLBACK_TIMEOUT_SEC 控制）
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
		return nil, false, err
	}
	defer resp.Body.Close()
	if ph.ttfbMs == 0 {
		// h3 等不触发 httptrace 首字节事件的路径：响应头到达≈首字节
		ph.ttfbMs = time.Since(start).Milliseconds()
	}
	s.log.Debugf("%s 上游响应 %d, 耗时 %s", method, resp.StatusCode, time.Since(start))
	if resp.StatusCode == http.StatusTooManyRequests {
		// 429 是 Cloudflare 平台层限流（Worker 代码本身只返回 400/405）：
		// 免费版每日 10 万次请求额度耗尽，或突发限流。单独醒目提示一次，
		// 避免被熔断日志淹没后误判成"网络不通"
		if s.rateLimitHint.CompareAndSwap(false, true) {
			s.log.Errorf("上游被 Cloudflare 限流（429）：免费版额度约 10 万次/日可能已耗尽" +
				"（劫持整机 DNS + turbo 双上游竞速会加倍消耗额度）。对策：升付费版 / 主备分两个账号 / " +
				"加大 -race-cache / 用 IP 段分流把域名转系统 DNS。UTC 零点重置额度")
			go func() { // 提示抑制定时解除（额度重置后能再次提醒）
				time.Sleep(30 * time.Minute)
				s.rateLimitHint.Store(false)
			}()
		}
		return nil, false, fmt.Errorf("上游返回 429（Cloudflare 限流）")
	}
	if resp.StatusCode != http.StatusOK {
		// 只缓存 200：非 200 一律视为错误，不进缓存
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
		return nil, streamed, err
	}
	// 延迟打点（/latency 折线图）：总耗时含完整传输，分阶段耗时由 ph 携带；
	// key 为空串 = 空闲/按需探测，曲线标记为探测点且不写缓存
	s.lat.record(upstream == s.cfg.Upstream, time.Since(start).Milliseconds(), key == "", ph)
	// 空响应不入缓存：上游异常时的 0 字节 200 一旦入缓存，
	// 静默期内会持续毒害客户端（DNS 解包溢出等）
	if buf.Len() > 0 && key != "" { // key 空串 = 探测请求，不落缓存
		s.cache.Put(key, buf.Bytes())
	}
	s.log.Debugf("%s 上游完成, 解密 %d 字节, 已写缓存", method, buf.Len())
	return buf.Bytes(), streamed, nil
}

// resolveLocal 上游域名本地代答：绕过 Worker，走内置解析链
// DoT(223.5.5.5:853) → 失败自动阿里 DoH(443) → 两级都失败才报错（绝不回退系统 DNS），
// 用结果构造 DNS 应答并写入缓存（后续查询直接命中，过期后台刷新同样走本地）。
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
	matched := 0 // 实际写入应答的记录数（lookup 返回的是 A+AAAA 全集）
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
	quicDesc := func(m string) string {
		switch m {
		case "prefer":
			return "prefer（首请求直连 0-RTT）"
		case "off":
			return "off（禁用，仅 h2/h1）"
		}
		return "auto（Alt-Svc 探测后升级）"
	}
	hdrStr := "未配置"
	if n := len(s.cfg.Headers); n > 0 {
		hdrStr = fmt.Sprintf("%d 个", n)
	}
	// 密钥指纹：核对本地与 Worker 密钥是否一致，又不泄露密钥本身
	keyFP := sha256.Sum256(s.cfg.Key)
	dnsHosts, dnsIPs, bestN := s.client.dialer.stats()

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
.btn{font-size:12px;color:#fff;background:rgba(255,255,255,.16);padding:4px 12px;border-radius:999px;text-decoration:none;border:1px solid rgba(255,255,255,.35)}
.btn:hover{background:rgba(255,255,255,.3)}
table{border-collapse:collapse;width:100%}
td{padding:8px 14px;font-size:13.5px;border-bottom:1px solid #f0f0f5}
td:first-child{color:#666;width:34%}
td:last-child{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px}
tr.grp td{background:#f7f8fc;color:#1a73e8;font-weight:600;font-size:12px;letter-spacing:.5px;padding:6px 14px}
tr:not(.grp):hover{background:#fafbff}
.tip{color:#999;font-size:12px;margin:12px 4px}
</style></head><body><div class="card">
<div class="hd"><span class="dot"></span><h1>Fastime</h1><span class="badge">运行中 · 127.0.0.1:`, s.cfg.Port, `</span><a class="btn" href="/latency">📈 延迟曲线</a><a class="btn" href="/cache">📋 缓存内容</a></div>
<table>`)

	grp("运行状态")
	row("运行时长", uptime.String())
	row("CPU 占用", cpuStr+"（按页面刷新间隔平均，多核可超 100%）")
	row("内存占用", fmt.Sprintf("在用 %.1f MB / 申请 %.1f MB · 协程 %d", float64(ms.Alloc)/1048576, float64(ms.Sys)/1048576, runtime.NumGoroutine()))
	row("页面时间", nowT.Format("2006-01-02 15:04:05"))

	grp("缓存与上游")
	if s.cfg.Mode == "turbo" {
		row("运行模式", "turbo（新模式：主备并发竞速 + IP 段分流 + 系统 DNS 代管）")
	} else {
		row("运行模式", "standard（现有模式：主 → 失败 → 备 顺序重试）")
	}
	row("缓存条数", fmt.Sprintf("%d / %d", s.cache.Len(), s.cfg.CacheSize))
	{ // 运行缓存：持久化恢复 + 定时批量刷新状态
		var persistTxt string
		if n := s.persistLoaded.Load(); n > 0 {
			persistTxt = fmt.Sprintf("本次启动恢复 %d 条", n)
		} else {
			persistTxt = "本次启动无历史缓存可恢复"
		}
		refreshTxt := "定时刷新已关闭（CACHE_REFRESH_SEC=0）"
		if s.cfg.CacheRefresh > 0 {
			last := "尚未刷新"
			if t := s.lastRefreshAt.Load(); t > 0 {
				last = time.Unix(t, 0).Format("15:04:05")
			}
			refreshTxt = fmt.Sprintf("每 %s 批量刷新 · 上次 %s（累计成功 %d / 失败 %d）",
				s.cfg.CacheRefresh, last, s.refreshOK.Load(), s.refreshFail.Load())
		}
		saveTxt := "仅退出时落盘"
		if s.cfg.CachePersist > 0 {
			saveTxt = fmt.Sprintf("每 %s 定时落盘（强杀不丢）", s.cfg.CachePersist)
		}
		row("运行缓存", fmt.Sprintf("持久化 %s · %s · %s · %s", cachePersistFile, persistTxt, saveTxt, refreshTxt))
	}
	if s.cfg.NoDivertRefresh > 0 {
		row("豁免域名独立刷新", fmt.Sprintf("每 %s（🚫 不走系统DNS 的域名走此时长，当前豁免 %d 个）",
			s.cfg.NoDivertRefresh, len(s.noDivertList())))
	}
	row("命中 / 未命中", fmt.Sprintf("%d / %d（命中率 %s）", hits, misses, hitRate))
	if s.cfg.Mode == "turbo" {
		winP, winF, winErr := s.raceWinP.Load(), s.raceWinF.Load(), s.raceErr.Load()
		raceN := winP + winF
		raceAvg := int64(0)
		if raceN > 0 {
			raceAvg = s.raceDurMs.Load() / raceN
		}
		row("竞速 主胜/备胜/双败", fmt.Sprintf("%d / %d / %d", winP, winF, winErr))
		row("竞速胜出平均耗时", fmt.Sprintf("%d ms", raceAvg))
	} else {
		upOK := s.upstreamOK.Load()
		upAvg := int64(0)
		if upOK > 0 {
			upAvg = s.upDurMs.Load() / upOK
		}
		row("主上游 200 / 平均耗时", fmt.Sprintf("%d 次 / %d ms", upOK, upAvg))
	}
	row("前台失败 / 后台刷新失败", fmt.Sprintf("%d / %d", s.fgErr.Load(), s.bgErr.Load()))
	row("本地代答（上游域名）", fmt.Sprintf("%d 次（DoT→DoH，不经上游，不受熔断影响）", s.localAns.Load()))
	if s.iplist != nil {
		n, lastOK, lastErr, fetches, fails, fromLocal := s.iplist.stats()
		v := fmt.Sprintf("%d 条 · 已下载 %d 次 · 命中 %d 次", n, fetches, s.iplistHitN.Load())
		if fromLocal {
			v += " · 当前为本地缓存表（联网更新中）"
		}
		if !lastOK.IsZero() {
			v += fmt.Sprintf(" · 更新于 %s 前", time.Since(lastOK).Round(time.Minute))
		}
		if fails > 0 {
			v += fmt.Sprintf(" · 失败 %d 次（%s）", fails, lastErr)
		}
		row("IP 段列表（12h 刷新）", v)
	}
	if s.sysCache != nil {
		servers, _ := s.sysres.stats()
		srvStr := "（待发现）"
		if len(servers) > 0 {
			srvStr = strings.Join(servers, ", ")
		}
		row("系统 DNS 代管", fmt.Sprintf("%d 个域名 · 解析成功 %d / 失败 %d · 服务器 %s",
			s.sysCache.Len(), s.sysOK.Load(), s.sysErr.Load(), srvStr))
		if n := len(s.forceDNSList()); n > 0 {
			row("强制走系统 DNS", fmt.Sprintf("%d 个域名：%s（跳过上游竞速，失败不回退）",
				n, strings.Join(s.forceDNSList(), ", ")))
		}
	}
	if s.hijack != nil {
		addr, reqs, emptys, fails := s.hijack.stats()
		row("53 端口劫持", fmt.Sprintf("监听 %s（UDP+TCP）· 已应答 %d 次 · 非DNS回空 %d 次 · 失败回SERVFAIL %d 次",
			addr, reqs, emptys, fails))
	} else if s.cfg.HijackDNS {
		row("53 端口劫持", "启动失败（详见日志，HTTP 入口不受影响）")
	}
	breaker := "正常"
	if s.cfg.BreakDur <= 0 {
		breaker = "已禁用"
	} else if until := s.breakUntil.Load(); until > 0 && time.Now().UnixNano() < until {
		breaker = fmt.Sprintf("熔断中（剩余 %ds，已快速跳过 %d 次）",
			int(time.Until(time.Unix(0, until)).Seconds())+1, s.breakSkip.Load())
	} else if streak := s.failStreak.Load(); streak > 0 {
		breaker = fmt.Sprintf("正常（连续失败 %d/%d 次）", streak, s.cfg.BreakFails)
	}
	row("熔断状态", breaker)
	row("在飞上游请求", fmt.Sprintf("%d / %d", len(s.sem), maxUpstreamInflight))

	grp("网络与解析")
	row("上游地址", s.cfg.Upstream)
	if s.cfg.Fallback != "" {
		fbTry := s.fbTry.Load()
		fbAvg := int64(0)
		if fbTry > 0 {
			fbAvg = s.fbDurMs.Load() / fbTry
		}
		row("后备上游", s.cfg.Fallback)
		if s.cfg.Mode == "turbo" {
			row("主备逻辑", fmt.Sprintf("turbo：主备并发竞速（主 %s / 备 %s 超时），取最快；每次请求独立决策", s.cfg.Timeout, s.cfg.FbTimeout))
		} else {
			row("主备逻辑", fmt.Sprintf("主 %s → 失败 → 备 %s → 报错；每次请求独立决策", s.cfg.Timeout, s.cfg.FbTimeout))
		}
		row("后备 尝试/成功/失败", fmt.Sprintf("%d / %d / %d", fbTry, s.fbOK.Load(), s.fbErr.Load()))
		row("后备平均耗时", fmt.Sprintf("%d ms", fbAvg))
	} else {
		row("后备上游", "未配置（设置 Secret FALLBACK_URL 或启动参数 -fallback 后启用并显示统计）")
	}
	row("DNS 解析缓存 / 最快 IP", fmt.Sprintf("%d 个域名（%d 个 IP）/ %d 条", dnsHosts, dnsIPs, bestN))
	if bestN > 0 {
		row("最快 IP 明细", strings.Join(s.client.dialer.bestDetail(), "；"))
	}
	row("解析链", "DoT "+s.cfg.DoTServer+" → 失败自动 DoH(443) → 报错，不回退系统 DNS")
	{ // 系统 DNS（当前网络真实下发的服务器，两种模式都展示）
		servers, sysQueries := s.sysres.stats()
		srvStr := "获取中…"
		if len(servers) > 0 {
			srvStr = strings.Join(servers, ", ")
		} else if s.sysres.discovered() {
			srvStr = "未发现（将回退 Go 系统解析器）"
		}
		if id := sysNetIDValue(); id > 0 {
			srvStr += fmt.Sprintf(" · 代管查询直达物理网络 netId=%d（fwmark 旁路 VPN 隧道）", id)
		}
		row("系统 DNS", fmt.Sprintf("%s（查询 %d 次）", srvStr, sysQueries))
	}
	row("拨号模式", dialMode)
	if s.cfg.Fallback != "" {
		row("QUIC 主/备", quicDesc(s.cfg.QuicPrimary)+" / "+quicDesc(s.cfg.QuicFallback))
	} else {
		row("QUIC", quicDesc(s.cfg.QuicPrimary))
	}

	grp("配置")
	row("静默期", s.cfg.CacheTTL.String())
	if s.cfg.Fallback != "" {
		row("超时 主/备", fmt.Sprintf("%s / %s", s.cfg.Timeout, s.cfg.FbTimeout))
	} else {
		row("超时", s.cfg.Timeout.String())
	}
	row("切网策略", netMode)
	row("日志等级", s.cfg.LogLevel)
	row("自定义请求头", hdrStr)
	row("密钥指纹 (SHA-256 前 8 位)", hex.EncodeToString(keyFP[:4]))
	row("运行时", fmt.Sprintf("%s · %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH))

	fmt.Fprint(w, `</table></div><p class="tip">页面每 5 秒自动刷新 · 仅缓存上游 200 响应 · 密钥指纹用于和 Worker 端核对密钥一致性</p></body></html>`)
}

// serveCache 缓存查看页：把每条缓存还原成 域名 / 查询类型 / 应答 IP / TTL，
// 按 MRU 排序展示，排障时可直接核对某个域名缓存了什么。
// turbo 模式下另有第二张表：命中 IP 段、由系统 DNS 代管的域名（独立缓存）。
func (s *Server) serveCache(w http.ResponseWriter) {
	items := s.cache.Snapshot()
	ttl := s.cache.TTL()
	now := time.Now()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>⚡</text></svg>">
<title>Fastime 缓存内容</title>
<style>
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;max-width:960px;margin:24px auto;padding:0 16px;color:#1a1a2e;background:#f4f6fa}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.06);overflow:hidden;margin-bottom:20px}
.hd{display:flex;align-items:center;gap:10px;padding:16px 20px;background:linear-gradient(135deg,#1a73e8,#0d47a1);color:#fff}
.hd.green{background:linear-gradient(135deg,#059669,#065f46)}
.hd h1{font-size:18px;margin:0;font-weight:600}
.badge{font-size:12px;background:rgba(255,255,255,.18);padding:3px 10px;border-radius:999px}
.btn{margin-left:auto;font-size:12px;color:#fff;background:rgba(255,255,255,.16);padding:4px 12px;border-radius:999px;text-decoration:none;border:1px solid rgba(255,255,255,.35)}
.btn:hover{background:rgba(255,255,255,.3)}
table{border-collapse:collapse;width:100%}
th{padding:8px 10px;font-size:12px;color:#1a73e8;background:#f7f8fc;text-align:left;letter-spacing:.5px}
td{padding:8px 10px;font-size:13px;border-bottom:1px solid #f0f0f5;vertical-align:top;word-break:break-all}
td.mono,.ans{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12.5px}
tr:hover td{background:#fafbff}
.dom{font-weight:600}
.fresh{color:#16a34a}
.stale{color:#d97706}
.bad{color:#dc2626}
.mark{font-size:11.5px;margin-top:3px;padding:2px 8px;border-radius:6px;display:inline-block}
.mark.ok{color:#059669;background:#ecfdf5}
.mark.fail{color:#dc2626;background:#fef2f2}
.opb{font-size:11.5px;color:#b45309;background:#fffbeb;border:1px solid #fcd34d;padding:2px 9px;border-radius:999px;text-decoration:none;white-space:nowrap;display:inline-block;margin:1px 2px}
.opb:hover{background:#fef3c7}
.opb.on{color:#059669;background:#ecfdf5;border-color:#6ee7b7}
.opb.on:hover{background:#d1fae5}
.opb.rf{color:#1a73e8;background:#eff6ff;border-color:#93c5fd}
.opb.rf:hover{background:#dbeafe}
.opb.fd{color:#0e7490;background:#ecfeff;border-color:#67e8f9}
.opb.fd:hover{background:#cffafe}
.ans div{white-space:nowrap}
.empty{padding:40px;text-align:center;color:#999;font-size:14px}
.tip{color:#999;font-size:12px;margin:12px 4px}
@media (max-width:720px){
  body{margin:12px auto;padding:0 8px}
  table,tbody,tr,td{display:block;width:100%}
  tr.hdr{display:none}
  table tr{border-bottom:8px solid #f4f6fa;padding:6px 0}
  table tr:last-child{border-bottom:none}
  td{border:none;padding:3px 12px}
  td::before{content:attr(data-label);display:block;font-size:11px;color:#999;margin-bottom:1px}
  .ans div{white-space:normal}
}
</style></head><body><div class="card">
<div class="hd"><h1>📋 上游缓存</h1><span class="badge">`, len(items), ` / `, s.cfg.CacheSize, ` 条</span><a class="btn" href="/cache">🔄 刷新页面</a><a class="btn" style="margin-left:0" href="/">← 返回状态页</a></div>`)

	if len(items) == 0 {
		fmt.Fprint(w, `<div class="empty">缓存为空 —— 有请求成功打通过上游后，这里会列出每个域名缓存的应答</div>`)
	} else {
		fmt.Fprint(w, `<table><tr class="hdr"><th>域名</th><th>类型</th><th>方法</th><th>应答内容（类型 数据 · TTL）</th><th>大小</th><th>缓存于</th><th>状态</th><th>操作</th></tr>`)
		for _, it := range items {
			method, canon, _ := strings.Cut(it.key, "\x00")
			q, qerr := parseQuestion([]byte(canon))
			rcode, answers, rerr := parseResponse(it.body)

			domain, qtype := "(非 DNS 负载)", "-"
			if qerr == nil {
				domain = q.Name
				if domain == "" {
					domain = "."
				}
				qtype = qtypeName(q.Qtype)
			}

			var ans strings.Builder
			if rerr != nil {
				fmt.Fprintf(&ans, `<span class="bad">应答解析失败: %s</span>`, html.EscapeString(rerr.Error()))
			} else {
				if rcode != 0 {
					fmt.Fprintf(&ans, `<div class="bad">RCODE=%d（%s）</div>`, rcode, rcodeText(rcode))
				}
				if len(answers) == 0 && rcode == 0 {
					ans.WriteString(`<div style="color:#999">无回答记录（NODATA）</div>`)
				}
				for _, a := range answers {
					fmt.Fprintf(&ans, `<div>%s <b>%s</b> · TTL %ds</div>`, a.Type, html.EscapeString(a.Data), a.TTL)
				}
			}

			age := now.Sub(it.at).Round(time.Second)
			// 豁免域名的保鲜期按独立刷新时长显示（与其实际刷新节奏一致）
			rowTTL := ttl
			if qerr == nil && s.cfg.NoDivertRefresh > 0 && s.noDivertHas(domain) {
				rowTTL = s.cfg.NoDivertRefresh
			}
			fresh := rowTTL > 0 && age < rowTTL
			state := fmt.Sprintf(`<span class="stale">已过期（待后台刷新）</span>`)
			if fresh {
				state = fmt.Sprintf(`<span class="fresh">新鲜（剩余 %s）</span>`, (rowTTL - age).Round(time.Second))
			}
			// IP 段命中徽标：无论系统 DNS 代管成功与否都展示（排障关键信息）；
			// 已豁免的域名改标注"已豁免不代管"，避免与豁免徽标语义打架
			if mv, ok := s.marked.Load(it.key); ok {
				m := mv.(*iplistMark)
				switch {
				case m.diverted && qerr == nil && s.noDivertHas(domain):
					state += fmt.Sprintf(`<div class="mark" style="color:#b45309;background:#fffbeb">🎯 命中 IP 段（%s）· 已豁免不代管</div>`, m.ip)
				case m.diverted:
					state += fmt.Sprintf(`<div class="mark ok">🎯 命中 IP 段（%s）→ 已转系统 DNS 代管</div>`, m.ip)
				default:
					state += fmt.Sprintf(`<div class="mark fail">🎯 命中 IP 段（%s）但系统 DNS 失败：%s</div>`, m.ip, html.EscapeString(m.err))
				}
			}
			// 操作列：所有条目都可强制向上游刷新（turbo=主备并发竞速）；
			// A/AAAA 条目另可切换"不走系统 DNS 代管"与"强制走系统 DNS"（互斥，
			// turbo+IP段模式才有意义）
			opBtn := refreshBtn(it.key)
			if qerr == nil && s.noDivertHas(domain) && s.cfg.NoDivertRefresh > 0 {
				// 豁免域名：状态列标注独立刷新周期，一眼看出它在走自己的节奏
				state += fmt.Sprintf(`<div class="mark" style="color:#b45309;background:#fffbeb">🚫 已豁免系统DNS · 每 %s 独立刷新</div>`, s.cfg.NoDivertRefresh)
			}
			if qerr == nil && s.forceDNSHas(domain) {
				state += `<div class="mark" style="color:#0e7490;background:#ecfeff">🧭 已强制走系统DNS · 失败不回退上游</div>`
			}
			if s.sysCache != nil && qerr == nil && (q.Qtype == dnsTypeA || q.Qtype == dnsTypeAAAA) {
				opBtn += s.noDivertBtn(domain)
				opBtn += s.forceDNSBtn(domain)
			}

			fmt.Fprintf(w, `<tr><td data-label="域名" class="dom">%s</td><td data-label="类型">%s</td><td data-label="方法">%s</td><td data-label="应答内容" class="ans">%s</td><td data-label="大小" class="mono">%d B</td><td data-label="缓存于" class="mono">%s 前</td><td data-label="状态">%s</td><td data-label="操作">%s</td></tr>`,
				html.EscapeString(domain), qtype, html.EscapeString(method), ans.String(), len(it.body), age, state, opBtn)
		}
		fmt.Fprint(w, `</table>`)
	}
	fmt.Fprint(w, `</div>`)

	// 第二张表：系统 DNS 代管（turbo 模式且命中过 IP 段的域名）
	if s.sysCache != nil {
		entries := s.sysCache.Snapshot()
		sort.Slice(entries, func(i, j int) bool { return entries[i].at.After(entries[j].at) })
		fmt.Fprint(w, `<div class="card"><div class="hd green"><h1>🛰 系统 DNS 代管（命中 IP 段 / 强制指定）</h1><span class="badge">`, len(entries), ` 条</span></div>`)
		if len(entries) == 0 {
			fmt.Fprint(w, `<div class="empty">暂无 —— 上游应答 IP 命中 IP 段后，或点「🧭 强制走系统DNS」后，对应域名会改由系统 DNS 解析并列在这里；切网时此表清空（上游缓存保留，强制名单持久化重启自动恢复）</div>`)
		} else {
			fmt.Fprint(w, `<table><tr class="hdr"><th>域名</th><th>类型</th><th>应答内容（系统 DNS）</th><th>大小</th><th>缓存于</th><th>状态</th><th>操作</th></tr>`)
			for _, e := range entries {
				_, answers, _ := parseResponse(e.body)
				var ans strings.Builder
				for _, a := range answers {
					fmt.Fprintf(&ans, `<div>%s <b>%s</b> · TTL %ds</div>`, a.Type, html.EscapeString(a.Data), a.TTL)
				}
				if ans.Len() == 0 {
					ans.WriteString(`<div style="color:#999">无回答记录</div>`)
				}
				age := now.Sub(e.at).Round(time.Second)
				state := `<span class="stale">已过期（待后台系统 DNS 刷新）</span>`
				if !e.stale() {
					state = fmt.Sprintf(`<span class="fresh">新鲜（剩余 %s）</span>`, (e.ttl - age).Round(time.Second))
				}
				if s.forceDNSHas(e.q.Name) {
					state += `<div class="mark" style="color:#0e7490;background:#ecfeff">🧭 已强制走系统DNS · 失败不回退上游</div>`
				}
				fmt.Fprintf(w, `<tr><td data-label="域名" class="dom">%s</td><td data-label="类型">%s</td><td data-label="应答内容" class="ans">%s</td><td data-label="大小" class="mono">%d B</td><td data-label="缓存于" class="mono">%s 前</td><td data-label="状态">%s</td><td data-label="操作">%s</td></tr>`,
					html.EscapeString(e.q.Name), qtypeName(e.q.Qtype), ans.String(), len(e.body), age, state, s.forceDNSBtn(e.q.Name))
			}
			fmt.Fprint(w, `</table>`)
		}
		fmt.Fprint(w, `</div>`)
	}
	fmt.Fprint(w, `<p class="tip">页面不自动刷新（浏览不跳顶），点右上角「🔄 刷新页面」手动更新 · 按最近使用排序（最上=最新）· 过静默期的条目会在下次访问时后台刷新</p></body></html>`)
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
