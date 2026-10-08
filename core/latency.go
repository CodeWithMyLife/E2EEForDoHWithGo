package fastime

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// dialPhases 一次真实上游请求的各阶段耗时（毫秒）。
// 探测与真实查询共用同一条加密链路（H2/H3 依 QUIC 策略自动协商），
// 协议版本记录在 proto 字段（"h3"/"h2"/"h1"）。
type dialPhasesKey struct{}

type dialPhases struct {
	dnsMs, tcpMs, tlsMs, ttfbMs int64  // 毫秒
	proto                       string // 实际协商出的协议：h3 / h2 / h1
	hasDial                     bool
}

// totalMs 优先用真实首字节时间，缺失时退化为阶段和。
func (d dialPhases) totalMs(fallback float64) float64 {
	if d.ttfbMs > 0 {
		return float64(d.ttfbMs)
	}
	sum := d.dnsMs + d.tcpMs + d.tlsMs
	if sum > 0 {
		return float64(sum)
	}
	return fallback
}

// dialDetail 渲染阶段明细：协议 · DNS · TCP · TLS · TTFB。
func (d dialPhases) dialDetail() string {
	if !d.hasDial {
		return ""
	}
	s := "· "
	if d.proto != "" {
		s += d.proto + " "
	}
	s += fmt.Sprintf("dns %d tcp %d", d.dnsMs, d.tcpMs)
	if d.tlsMs > 0 {
		s += fmt.Sprintf(" tls %d", d.tlsMs)
	}
	if d.ttfbMs > 0 {
		s += fmt.Sprintf(" ttfb %d", d.ttfbMs)
	}
	return s
}

type latPoint struct {
	T     int64   `json:"t"`
	Ms    float64 `json:"ms"`
	Probe bool    `json:"p,omitempty"`
	Reuse bool    `json:"r,omitempty"`
	Proto string  `json:"pr,omitempty"` // h3 / h2 / h1
	Dns   float64 `json:"d,omitempty"`
	Tcp   float64 `json:"c,omitempty"`
	Tls   float64 `json:"l,omitempty"`
	Tfb   float64 `json:"f,omitempty"`
}

func newLatTracker() *latTracker { return &latTracker{} }

type latTracker struct {
	mu         sync.Mutex
	primary    []latPoint
	fallback   []latPoint
	lastRealAt time.Time
}

const latKeep = 400

func (t *latTracker) record(primary bool, ms float64, probe bool, ph dialPhases) {
	p := latPoint{T: time.Now().Unix(), Ms: ms, Probe: probe, Reuse: !ph.hasDial,
		Proto: ph.proto, Dns: float64(ph.dnsMs), Tcp: float64(ph.tcpMs), Tls: float64(ph.tlsMs), Tfb: float64(ph.ttfbMs)}
	t.mu.Lock()
	if primary {
		t.primary = appendTrim(t.primary, p)
	} else {
		t.fallback = appendTrim(t.fallback, p)
	}
	t.mu.Unlock()
	if !probe {
		t.mu.Lock()
		t.lastRealAt = time.Now()
		t.mu.Unlock()
	}
}

func appendTrim(s []latPoint, p latPoint) []latPoint {
	s = append(s, p)
	if len(s) > latKeep {
		s = append(s[:0], s[len(s)-latKeep:]...)
	}
	return s
}

func (t *latTracker) lastReal() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastRealAt
}

func (t *latTracker) snapshot() (p, f []latPoint) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]latPoint(nil), t.primary...), append([]latPoint(nil), t.fallback...)
}

// probeIdleAfter：距上次真实查询超过该间隔才补探测，省电优先。
const probeIdleAfter = 45 * time.Second

// probeDomain 探测用的真实域名：真实解析、真实链路，仅不入缓存。
const probeDomain = "www.cloudflare.com"

func (s *Server) probeLoop() {
	tk := time.NewTicker(30 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-tk.C:
			s.maybeProbe()
		case <-s.watchStop:
			return
		}
	}
}

// maybeProbe 空闲时向真实域名发一条真实查询测量链路（结果丢弃不缓存）。
func (s *Server) maybeProbe() {
	if time.Since(s.lat.lastReal()) < probeIdleAfter {
		return
	}
	q := buildQuery(probeDomain, 1)
	if s.cfg.Fallback == "" {
		s.doFetchCtx(context.Background(), s.cfg.Upstream, s.cfg.Timeout, http.MethodGet, q, "")
		return
	}
	up := s.cfg.Upstream
	timeout := s.cfg.Timeout
	if s.raceWinF.Load() > s.raceWinP.Load() {
		up, timeout = s.cfg.Fallback, s.cfg.FbTimeout
	}
	s.doFetchCtx(context.Background(), up, timeout, http.MethodGet, q, "")
}

func (s *Server) probeNow(primary bool) {
	up, timeout := s.cfg.Upstream, s.cfg.Timeout
	if !primary {
		if s.cfg.Fallback == "" {
			return
		}
		up, timeout = s.cfg.Fallback, s.cfg.FbTimeout
	}
	q := buildQuery(probeDomain, 1)
	s.doFetchCtx(context.Background(), up, timeout, http.MethodGet, q, "")
}

func writeLatSeries(w interface{ Write([]byte) (int, error) }, name string, pts []latPoint) {
	fmt.Fprintf(w, "%s:[", name)
	for i, p := range pts {
		if i > 0 {
			fmt.Fprint(w, ",")
		}
		fmt.Fprintf(w, "{t:%d,ms:%.1f,p:%v,r:%v,pr:%q,d:%.1f,c:%.1f,l:%.1f,f:%.1f}",
			p.T, p.Ms, p.Probe, p.Reuse, p.Proto, p.Dns, p.Tcp, p.Tls, p.Tfb)
	}
	fmt.Fprint(w, "]")
}

func latStats(pts []latPoint) (avg, p95 float64, n int) {
	n = len(pts)
	if n == 0 {
		return
	}
	vals := make([]float64, n)
	var sum float64
	for i, p := range pts {
		vals[i] = p.Ms
		sum += p.Ms
	}
	avg = sum / float64(n)
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if vals[j] < vals[i] {
				vals[i], vals[j] = vals[j], vals[i]
			}
		}
	}
	return avg, vals[int(float64(n)*0.95)-1], n
}

func protoCounts(pts []latPoint) (h3, h2, other int) {
	for _, p := range pts {
		switch p.Proto {
		case "h3":
			h3++
		case "h2":
			h2++
		default:
			other++
		}
	}
	return
}
