package fastime

import (
	"crypto/tls"
	"net/http"
	"strings"
	"sync"
	"time"
)

// hybridClient 同时持有 HTTP/2（回退 HTTP/1.1）与可选的 HTTP/3(QUIC) 传输：
//   - 默认走 HTTP/2，单连接多路复用（多个并发请求共享一条 TCP+TLS 连接）
//   - 若上游响应带 Alt-Svc 声明支持 h3，后续请求自动升级到 QUIC
//   - QUIC 失败自动回退 h2，保证弱网可用性
//
// 用 -tags noquic 编译可完全裁掉 HTTP/3（lite 版，体积更小）。
// TLS 版本覆盖 1.1 / 1.2 / 1.3（h3 强制 1.3，由 QUIC 规范决定）。
type hybridClient struct {
	dialer *fastDialer
	h12    *http.Transport
	h3     h3RoundTripper // noquic 版恒为 nil
	log    *logger

	// 共享的 TLS 1.3 会话票据缓存：
	//   - TCP 侧 → 会话恢复（PSK 恢复，免完整握手，省 1-RTT 与证书验证功耗）
	//   - QUIC 侧 → 0-RTT：重连时首个数据包即携带请求，无需等待握手
	// 注意：0-RTT 在理论上可被重放。本程序的请求本质是幂等查询，
	// 且 body 已加密（上游可校验），风险可接受。
	sessionCache tls.ClientSessionCache
	preferQUIC   bool // 首次联系即尝试 QUIC

	mu    sync.Mutex
	h3ok  map[string]bool      // host -> Alt-Svc 声明支持 h3
	h3bad map[string]time.Time // host -> QUIC 失败时间（5 分钟内不再尝试）
}

// h3RoundTripper 抽象 HTTP/3 传输，便于编译期裁剪。
type h3RoundTripper interface {
	RoundTrip(*http.Request) (*http.Response, error)
	Close() error
}

func newHybridClient(dialer *fastDialer, log *logger, preferQUIC bool) *hybridClient {
	c := &hybridClient{
		dialer:       dialer,
		log:          log,
		preferQUIC:   preferQUIC,
		h3ok:         make(map[string]bool),
		h3bad:        make(map[string]time.Time),
		sessionCache: tls.NewLRUClientSessionCache(64),
	}

	c.h12 = &http.Transport{
		DialContext: dialer.DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS11, // 兼容 TLS 1.1；协商时优先 1.3
			MaxVersion:         tls.VersionTLS13,
			ClientSessionCache: c.sessionCache, // TLS 1.3 会话恢复
		},
		ForceAttemptHTTP2:     true, // 自定义 Dial 下仍启用内置 h2（ALPN 自动协商）
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       10 * time.Second, // 空闲 10 秒即释放：射频尽快回休眠
		TLSHandshakeTimeout:   8 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	c.h3 = newH3RT(dialer, c.sessionCache, log)
	return c
}

func (c *hybridClient) Do(req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()

	// 尝试 QUIC 的条件：Alt-Svc 已知支持，或 PREFER_QUIC 开启且近期未失败
	c.mu.Lock()
	useH3 := c.h3 != nil && (c.h3ok[host] ||
		(c.preferQUIC && time.Since(c.h3bad[host]) > 5*time.Minute))
	c.mu.Unlock()

	if useH3 {
		resp, err := c.h3.RoundTrip(req.Clone(req.Context()))
		if err == nil {
			c.log.Debugf("%s 走 QUIC(h3)", host)
			return resp, nil
		}
		// QUIC 路径失效（运营商封 UDP 等），记黑名单 5 分钟并降级
		c.log.Infof("%s QUIC 失败回退 h2: %v", host, err)
		c.mu.Lock()
		c.h3ok[host] = false
		c.h3bad[host] = time.Now()
		c.mu.Unlock()
	}

	resp, err := c.h12.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	// 标准 Alt-Svc 探测：上游声明支持 h3 则下次升级 QUIC
	if !useH3 && c.h3 != nil && strings.Contains(resp.Header.Get("Alt-Svc"), "h3") {
		c.log.Infof("%s 上游支持 h3, 后续升级 QUIC", host)
		c.mu.Lock()
		c.h3ok[host] = true
		c.mu.Unlock()
	}
	return resp, nil
}

func (c *hybridClient) Close() {
	c.h12.CloseIdleConnections()
	if c.h3 != nil {
		_ = c.h3.Close()
	}
}
