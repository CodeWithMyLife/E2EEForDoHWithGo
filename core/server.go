package fastime

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Server 本地加密中继，双协议入口：
//
//	GET  /?dns=<payload>   → 加密 payload，GET  <上游>?time=<base64url(帧)>
//	POST /  (body=payload) → 加密 body，   POST <上游>  (body=帧)
//
// 响应统一：逐帧解密、流式回写、写入 LRU 缓存。
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
		cfg:       cfg,
		cipher:    sc,
		log:       newLogger(cfg.LogLevel),
		cache:     newLRUCache(cfg.CacheSize, cfg.CacheTTL),
		sf:        make(map[string]*sfCall),
		sem:       make(chan struct{}, maxUpstreamInflight),
		watchStop: make(chan struct{}),
	}
	s.client = newHybridClient(newFastDialer(cfg.DoTServer, cfg.DialSingle, s.log), s.log, cfg.PreferQUIC)
	s.http = &http.Server{
		Addr:              "127.0.0.1:" + cfg.Port,
		Handler:           s,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s, nil
}

func (s *Server) Start() error {
	s.log.Infof("fastime 监听于 http://127.0.0.1:%s (上游 %s, 缓存 %d 条, 静默期 %s, 超时 %s, 拨号 %s, 日志 %s)",
		s.cfg.Port, s.cfg.Upstream, s.cfg.CacheSize, s.cfg.CacheTTL, s.cfg.Timeout,
		map[bool]string{true: "single", false: "race"}[s.cfg.DialSingle], s.cfg.LogLevel)
	go s.watchNetwork(s.watchStop)
	return s.http.ListenAndServe()
}

func (s *Server) Shutdown() {
	close(s.watchStop)
	s.client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = s.http.Shutdown(ctx)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var payload []byte
	switch req.Method {
	case http.MethodGet:
		p := req.URL.Query().Get("dns")
		if p == "" {
			http.Error(w, "missing dns= parameter", http.StatusBadRequest)
			return
		}
		payload = []byte(p)
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

	// 缓存键 = 方法 + 负载（GET/POST 相同内容不串缓存）
	key := cacheKey(req.Method, payload)

	// 命中：立即返回；过静默期才后台刷新（省电）
	if body, ok, fresh := s.cache.Get(key); ok {
		s.log.Debugf("%s 缓存命中 fresh=%v", req.Method, fresh)
		w.Header().Set("X-Cache", "HIT")
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(body)
		if !fresh {
			go func() { _, _, _ = s.fetch(req.Method, payload, key, nil) }()
		}
		return
	}
	s.log.Debugf("%s 缓存未命中, 负载 %d 字节", req.Method, len(payload))

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
		_, _ = w.Write(body)
	}
}

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
		// GET：加密 → base64url → 拼 time= 参数，GET 上游
		enc, encErr := s.cipher.EncryptForQuery(payload)
		if encErr != nil {
			return nil, false, encErr
		}
		u := s.cfg.Upstream
		sep := "?"
		if strings.Contains(u, "?") {
			sep = "&"
		}
		req, err = http.NewRequest(http.MethodGet, u+sep+"time="+url.QueryEscape(enc), nil)
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
		return nil, false, err
	}
	defer resp.Body.Close()
	s.log.Debugf("%s 上游响应 %d, 耗时 %s", method, resp.StatusCode, time.Since(start))
	if resp.StatusCode != http.StatusOK {
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
	s.cache.Put(key, buf.Bytes())
	s.log.Debugf("%s 上游完成, 解密 %d 字节, 已写缓存", method, buf.Len())
	return buf.Bytes(), streamed, nil
}
