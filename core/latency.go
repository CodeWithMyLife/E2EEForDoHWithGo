package fastime

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// 上游延迟折线图（/latency）：
//
// 数据来自两处 ——
//  1. 真实请求：doFetchCtx 每次拿到上游响应时记录耗时（主/备分开记账）；
//  2. 空闲探测：某上游 45s 无真实请求时，每 30s 发一次加密探测查询
//     （固定问 probe.fastime.invalid A，NXDOMAIN 也是 200，不影响统计与缓存），
//     保证 standard 模式下后备上游即使长期无流量也有延迟曲线。
//
// 探测结果只进折线图，不进命中/失败统计，不写缓存（key 为空串即探测标记）。
const (
	latCap         = 240              // 每序列最多保留的点数（30s 探测 ≈ 2 小时）
	probeInterval  = 30 * time.Second // 空闲探测间隔
	probeIdleAfter = 45 * time.Second // 超过此时长无真实请求才探测
)

type latPoint struct {
	T     int64 `json:"t"`  // Unix 秒
	Ms    int64 `json:"ms"` // 往返毫秒
	Probe bool  `json:"p,omitempty"`
}

type latTracker struct {
	mu       sync.Mutex
	cap      int
	primary  []latPoint
	fallback []latPoint
}

func newLatTracker() *latTracker { return &latTracker{cap: latCap} }

// record 记录一次上游往返耗时。primary=true 主上游，false 后备；probe=探测产生。
func (t *latTracker) record(primary bool, ms int64, probe bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p := latPoint{T: time.Now().Unix(), Ms: ms, Probe: probe}
	if primary {
		t.primary = append(t.primary, p)
		if len(t.primary) > t.cap {
			t.primary = t.primary[len(t.primary)-t.cap:]
		}
	} else {
		t.fallback = append(t.fallback, p)
		if len(t.fallback) > t.cap {
			t.fallback = t.fallback[len(t.fallback)-t.cap:]
		}
	}
}

// lastRealAt 最近一次真实（非探测）请求时刻，0 = 从未有过。
func (t *latTracker) lastRealAt(primary bool) int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	series := t.primary
	if !primary {
		series = t.fallback
	}
	for i := len(series) - 1; i >= 0; i-- {
		if !series[i].Probe {
			return series[i].T
		}
	}
	return 0
}

func (t *latTracker) snapshot() (p, f []latPoint) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p = append([]latPoint(nil), t.primary...)
	f = append([]latPoint(nil), t.fallback...)
	return
}

// probeLoop 空闲探测：两个上游各自独立判断，断流 45s 后每 30s 探测一次。
// 熔断期间暂停探测（断网保护射频电量）。
func (s *Server) probeLoop(stop chan struct{}) {
	tk := time.NewTicker(probeInterval)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tk.C:
		}
		if s.breakerOpen() {
			continue
		}
		s.maybeProbe(true)
		if s.cfg.Fallback != "" {
			s.maybeProbe(false)
		}
	}
}

func (s *Server) maybeProbe(primary bool) {
	up, timeout := s.cfg.Upstream, s.cfg.Timeout
	if !primary {
		up, timeout = s.cfg.Fallback, s.cfg.FbTimeout
	}
	if time.Now().Unix()-s.lat.lastRealAt(primary) < int64(probeIdleAfter.Seconds()) {
		return // 近期有真实流量，延迟曲线已有数据
	}
	// key="" = 探测标记：doFetchCtx 不写缓存、打点标记为探测
	q := buildQuery("probe.fastime.invalid", dnsTypeA)
	_, _, _ = s.doFetchCtx(context.Background(), up, timeout, http.MethodGet, q, "", nil)
}

// probeNow 按需探测：延迟曲线页打开期间由 /latency.json 轮询触发（节流 ≥2s 一次），
// 页面活跃时每 2 秒主动打一次两个上游，曲线实时走动；页面关闭后自动停。
func (s *Server) probeNow() {
	now := time.Now().Unix()
	last := s.lastDemandProbe.Load()
	if now-last < 2 || !s.lastDemandProbe.CompareAndSwap(last, now) {
		return
	}
	if s.breakerOpen() {
		return
	}
	// key="" = 探测标记：不写缓存，曲线标记为空心探测点
	go func() {
		q := buildQuery("probe.fastime.invalid", dnsTypeA)
		_, _, _ = s.doFetchCtx(context.Background(), s.cfg.Upstream, s.cfg.Timeout, http.MethodGet, q, "", nil)
	}()
	if s.cfg.Fallback != "" {
		go func() {
			q := buildQuery("probe.fastime.invalid", dnsTypeA)
			_, _, _ = s.doFetchCtx(context.Background(), s.cfg.Fallback, s.cfg.FbTimeout, http.MethodGet, q, "", nil)
		}()
	}
}

// serveLatencyJSON 折线图数据接口。页面每 2s 轮询本接口 → 顺带触发一次按需探测，
// 下一次轮询即可拿到新点（页面关闭后轮询停止，只剩 30s 空闲探测）。
func (s *Server) serveLatencyJSON(w http.ResponseWriter) {
	s.probeNow()
	p, f := s.lat.snapshot()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"primaryName":%q,"fallbackName":%q,"now":%d,"primary":`,
		s.upHost, s.fbHost, time.Now().Unix())
	writeLatSeries(w, p)
	fmt.Fprint(w, `,"fallback":`)
	writeLatSeries(w, f)
	fmt.Fprint(w, `}`)
}

func writeLatSeries(w http.ResponseWriter, pts []latPoint) {
	fmt.Fprint(w, "[")
	for i, p := range pts {
		if i > 0 {
			fmt.Fprint(w, ",")
		}
		fmt.Fprintf(w, `{"t":%d,"ms":%d,"p":%v}`, p.T, p.Ms, p.Probe)
	}
	fmt.Fprint(w, "]")
}
