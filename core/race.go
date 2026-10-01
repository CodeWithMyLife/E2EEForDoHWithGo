// turbo 新模式（RUN_MODE=turbo）配套设施：
//
//	ipList   —— 用户指定 URL 的 IP 段列表（IPv4/IPv6 CIDR），下载后内存缓存，每 12h 刷新
//	sysCache —— 命中 IP 段的域名改由系统 DNS 解析后的独立缓存（按应答 TTL，与上游缓存隔离）
package fastime

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// iplistRefresh IP 段列表固定刷新间隔（12 小时）。
const iplistRefresh = 12 * time.Hour

// ipList IP 段匹配表：从指定 URL 下载 txt（一行一个 CIDR 或裸 IP，支持 # 注释）。
type ipList struct {
	url string
	log *logger

	mu      sync.RWMutex
	nets    []*net.IPNet
	lastOK  time.Time
	lastErr string

	onUpdate func() // 下载成功回调（补扫缓存做代管），由 Server 装配

	fetches atomic.Int64 // 下载成功次数
	fails   atomic.Int64 // 下载失败次数
}

func newIPList(url string, log *logger) *ipList {
	return &ipList{url: url, log: log}
}

// loop 启动时立即下载一次，之后每 12h 刷新；下载失败沿用旧表（不为空时）。
func (l *ipList) loop(stop <-chan struct{}) {
	l.refresh()
	// 首次成功前每 60s 重试（启动时网络未就绪/URL 临时失败很常见，
	// 否则一次失败要等 12h 才有表，段内域名一直不被代管——用户难以察觉）
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		l.mu.RLock()
		ok := !l.lastOK.IsZero()
		l.mu.RUnlock()
		if !ok {
			l.refresh() // 尚未成功过：每分钟重试
			continue
		}
		l.mu.RLock()
		due := time.Since(l.lastOK) >= iplistRefresh
		l.mu.RUnlock()
		if due {
			l.refresh() // 正常节奏：每 12h 刷新
		}
	}
}

func (l *ipList) refresh() {
	c := &http.Client{Timeout: 20 * time.Second}
	resp, err := c.Get(l.url)
	if err != nil {
		l.fails.Add(1)
		l.mu.Lock()
		l.lastErr = err.Error()
		l.mu.Unlock()
		l.log.Errorf("IP 段列表下载失败: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		l.fails.Add(1)
		l.mu.Lock()
		l.lastErr = fmt.Sprintf("HTTP %d", resp.StatusCode)
		l.mu.Unlock()
		l.log.Errorf("IP 段列表下载失败: HTTP %d", resp.StatusCode)
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // 上限 8MB
	if err != nil {
		l.fails.Add(1)
		l.mu.Lock()
		l.lastErr = err.Error()
		l.mu.Unlock()
		return
	}
	nets := parseIPList(string(data))
	if len(nets) == 0 {
		l.fails.Add(1)
		l.mu.Lock()
		l.lastErr = "解析结果为空"
		l.mu.Unlock()
		l.log.Errorf("IP 段列表解析为空，沿用旧表（%s）", l.url)
		return
	}
	l.mu.Lock()
	l.nets = nets
	l.lastOK = time.Now()
	l.lastErr = ""
	l.mu.Unlock()
	l.fetches.Add(1)
	l.log.Infof("IP 段列表已更新：%d 条（%s）", len(nets), l.url)
	if l.onUpdate != nil {
		go l.onUpdate() // 补扫已有缓存：命中段的补建系统 DNS 代管（含重启恢复的条目）
	}
}

// parseIPList 解析 txt：一行一个 CIDR（10.0.0.0/8）或裸 IP（自动补 /32、/128），
// 支持 # 与 ; 注释与空行，IPv4/IPv6 混合。
func parseIPList(text string) []*net.IPNet {
	var nets []*net.IPNet
	for _, line := range strings.Split(text, "\n") {
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "/") {
			if _, n, err := net.ParseCIDR(line); err == nil {
				nets = append(nets, n)
			}
			continue
		}
		if ip := net.ParseIP(line); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return nets
}

// Contains 判断 ip 是否落在任一 IP 段内。
func (l *ipList) Contains(ip net.IP) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, n := range l.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// iplistMark 记录"该缓存键的上游应答 IP 命中了用户 IP 段"，
// 供缓存页打徽标：无论系统 DNS 代管成功与否都可见，便于排障。
type iplistMark struct {
	ip       string    // 命中的应答 IP
	at       time.Time // 命中时刻
	diverted bool      // true = 已转系统 DNS 代管；false = 代管失败暂用上游结果
	err      string    // 代管失败原因（diverted=false 时）
}

// stats 供状态页展示。
func (l *ipList) stats() (n int, lastOK time.Time, lastErr string, fetches, fails int64) {
	l.mu.RLock()
	n, lastOK, lastErr = len(l.nets), l.lastOK, l.lastErr
	l.mu.RUnlock()
	return n, lastOK, lastErr, l.fetches.Load(), l.fails.Load()
}

// ---------- 系统 DNS 代管缓存 ----------

// sysEntry 一条系统 DNS 代管缓存：命中 IP 段的域名按系统 DNS 应答 TTL 缓存。
// payload/q 留存用于 TTL 到期后的后台刷新（无需再碰上游）。
type sysEntry struct {
	key     string
	q       dnsQuestion
	payload []byte // 规范化查询报文（后台刷新重建应答用）
	body    []byte
	at      time.Time
	ttl     time.Duration
}

func (e *sysEntry) stale() bool { return time.Since(e.at) > e.ttl }

// sysCache 系统 DNS 代管缓存，与上游结果缓存完全隔离：
// 切网时只清它（运营商 DNS 结果随网络位置变化），上游缓存保留。
type sysCache struct {
	mu   sync.Mutex
	cap  int
	data map[string]*sysEntry
}

func newSysCache(capacity int) *sysCache {
	if capacity <= 0 {
		capacity = 256
	}
	return &sysCache{cap: capacity, data: make(map[string]*sysEntry)}
}

func (c *sysCache) Get(key string) (*sysEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.data[key]
	return e, ok
}

func (c *sysCache) Put(e *sysEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[e.key] = e
	if len(c.data) > c.cap { // 简单淘汰：删最旧的一条
		var oldestKey string
		var oldest time.Time
		first := true
		for k, v := range c.data {
			if first || v.at.Before(oldest) {
				oldestKey, oldest, first = k, v.at, false
			}
		}
		delete(c.data, oldestKey)
	}
}

func (c *sysCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = make(map[string]*sysEntry)
}

func (c *sysCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.data)
}

// DeleteByHost 删除某域名的全部代管条目（用户设置"不走系统 DNS"时调用，
// 下次查询立即回到上游结果）。
func (c *sysCache) DeleteByHost(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.data {
		if e.q.Name == host {
			delete(c.data, k)
		}
	}
}

// Snapshot 返回全部条目快照（缓存查看页用）。
func (c *sysCache) Snapshot() []*sysEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*sysEntry, 0, len(c.data))
	for _, e := range c.data {
		out = append(out, e)
	}
	return out
}
