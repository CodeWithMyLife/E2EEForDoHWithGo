package fastime

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// fastDialer 通过 DoT（默认 tls:223.5.5.5:853，阿里公共 DNS）解析域名，
// 并对全部候选 IP 做 Happy-Eyeballs 式竞速拨号，胜出的 IP 会被记住，
// 后续连接直达最优 IP，不再重复竞速。
type fastDialer struct {
	dotAddr string
	dotName string // DoT 证书 ServerName，阿里 DNS 证书 SAN 含 223.5.5.5，可直接校验 IP
	single  bool   // DIAL_MODE=single：跳过竞速，直连首个解析 IP（最省资源）
	log     *logger

	dialer *net.Dialer

	mu      sync.Mutex
	ipCache map[string]*ipEntry // host -> 解析结果（带 TTL）
	best    map[string]*bestIP  // host -> 竞速胜出的 IP
}

type ipEntry struct {
	ips     []net.IP
	expires time.Time
}

type bestIP struct {
	ip      net.IP
	expires time.Time
}

const (
	dnsCacheTTL = 5 * time.Minute
	bestIPTTL   = 1 * time.Minute // 竞速胜出 IP 的记忆时长，到期后重新竞速
	raceStagger = 250 * time.Millisecond // 每个候选 IP 的出发间隔
	perDialTMO  = 5 * time.Second
)

func newFastDialer(dotAddr string, single bool, log *logger) *fastDialer {
	host, _, err := net.SplitHostPort(dotAddr)
	if err != nil {
		host = dotAddr
	}
	return &fastDialer{
		dotAddr: dotAddr,
		dotName: host,
		single:  single,
		log:     log,
		dialer:  &net.Dialer{Timeout: perDialTMO, KeepAlive: 30 * time.Second},
		ipCache: make(map[string]*ipEntry),
		best:    make(map[string]*bestIP),
	}
}

// lookup 走 DoT（手写 DNS wire 协议，零依赖）查询 A + AAAA 记录，
// 带 5 分钟内存缓存；DoT 失败回退系统解析。
func (f *fastDialer) lookup(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	f.mu.Lock()
	if e, ok := f.ipCache[host]; ok && time.Now().Before(e.expires) {
		ips := e.ips
		f.mu.Unlock()
		return ips, nil
	}
	f.mu.Unlock()

	ips, err := dotQuery(ctx, f.dotAddr, f.dotName, host)
	if err != nil || len(ips) == 0 {
		f.log.Debugf("DoT 查询 %s 失败(%v)，回退系统解析", host, err)
		ips, err = net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
	}
	f.mu.Lock()
	f.ipCache[host] = &ipEntry{ips: ips, expires: time.Now().Add(dnsCacheTTL)}
	f.mu.Unlock()
	return ips, nil
}

// DialContext 供 http.Transport 使用：优先直达记忆中的最快 IP，
// 否则对所有候选 IP 竞速，第一个连通的胜出并被记住。
func (f *fastDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	f.mu.Lock()
	b, hasBest := f.best[host]
	f.mu.Unlock()
	if hasBest && time.Now().Before(b.expires) {
		conn, err := f.dialer.DialContext(ctx, network, net.JoinHostPort(b.ip.String(), port))
		if err == nil {
			return conn, nil
		}
		f.mu.Lock()
		delete(f.best, host) // 记忆失效，重新竞速
		f.mu.Unlock()
	}

	ips, err := f.lookup(ctx, host)
	if err != nil {
		return nil, err
	}

	// 单 IP 模式：不竞速，直连首个（优先 IPv4），资源开销最低
	if f.single {
		ip := pickIPv4(ips)
		f.log.Debugf("dial single %s -> %s:%s", host, ip, port)
		return f.dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}

	f.log.Debugf("dial race %s: %d candidates", host, len(ips))
	type result struct {
		conn net.Conn
		ip   net.IP
		err  error
	}
	resCh := make(chan result, len(ips))
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	for i, ip := range ips {
		ip := ip
		go func(delay time.Duration) {
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-raceCtx.Done():
					return
				}
			}
			conn, err := f.dialer.DialContext(raceCtx, network, net.JoinHostPort(ip.String(), port))
			select {
			case resCh <- result{conn, ip, err}:
			case <-raceCtx.Done():
				if conn != nil {
					conn.Close()
				}
			}
		}(time.Duration(i) * raceStagger)
	}

	var lastErr error
	for range ips {
		r := <-resCh
		if r.err == nil {
			cancel()
			f.mu.Lock()
			f.best[host] = &bestIP{ip: r.ip, expires: time.Now().Add(bestIPTTL)}
			f.mu.Unlock()
			f.log.Debugf("race winner %s -> %s", host, r.ip)
			return r.conn, nil
		}
		lastErr = r.err
	}
	if lastErr == nil {
		lastErr = context.DeadlineExceeded
	}
	return nil, fmt.Errorf("所有候选 IP 拨号失败: %w", lastErr)
}

func pickIPv4(ips []net.IP) net.IP {
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip
		}
	}
	return ips[0]
}

// pickIP 为 QUIC(UDP) 选一个目标 IP：复用 TCP 竞速记忆，否则取解析结果首个 IPv4。
// UDP 无法低成本做连接竞速，复用 TCP 侧结论在实践中足够准。
func (f *fastDialer) pickIP(ctx context.Context, host string) (net.IP, error) {
	f.mu.Lock()
	b, hasBest := f.best[host]
	f.mu.Unlock()
	if hasBest && time.Now().Before(b.expires) {
		return b.ip, nil
	}
	ips, err := f.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	return pickIPv4(ips), nil
}
