package fastime

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"
)

// ================= 缓存页 /cache =================
//
// 顶部是「覆盖名单」置顶区：取消污染 🚫 / 强制污染 🎯 的域名，
// 按更改时间倒序，最新改的排最前，附状态徽标与一键恢复按钮。
// 下方是缓存条目表（MRU 在前）：每条显示当前判定状态、应答内容、
// 缓存时间，以及 取消污染 / 强制污染 / 立即刷新 按钮。

func (s *Server) serveCache(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	items := s.cache.Snapshot()
	noFakeList := s.noFake.list()
	forceFakeList := s.forceFake.list()

	fmt.Fprint(w, pageHead)
	fmt.Fprintf(w, `<div class="card"><div class="hd"><h1>📋 DNS 缓存</h1><span class="badge">%d / %d 条</span><span class="sp"></span>
<a class="btn" href="/">← 返回状态页</a><a class="btn" style="margin-left:0" href="/latency">📈 延迟</a></div>`,
		len(items), s.cfg.CacheSize)

	// ---------- 置顶：覆盖名单 ----------
	if len(noFakeList)+len(forceFakeList) > 0 {
		fmt.Fprint(w, `<div class="kv"><table><tr class="hdr"><th>置顶 · 覆盖名单</th><th>状态</th><th>操作</th></tr>`)
		// 两名单按各自设置时间合并倒序（list() 已各自倒序，这里按置顶语义直接 取消污染 在前、强制污染 在后逐条输出，
		// 每条内部已是时间倒序，最新改的在该组最前）
		writeOverrideRow := func(host string) {
			fmt.Fprintf(w, `<tr><td data-label="域名"><span class="dom mono">%s</span></td><td data-label="状态">%s</td><td data-label="操作">%s</td></tr>`,
				html.EscapeString(host), s.overrideBadges(host), s.overrideBtns(host))
		}
		for _, h := range noFakeList {
			writeOverrideRow(h)
		}
		for _, h := range forceFakeList {
			writeOverrideRow(h)
		}
		fmt.Fprint(w, `</table></div>`)
	}

	// ---------- 缓存条目 ----------
	if len(items) == 0 {
		fmt.Fprint(w, `<div class="empty">暂无缓存条目</div></div>
<p class="tip">查询成功后会自动缓存：15 分钟内直接回缓存，后台到点逐条换新；每 30 秒落盘，重启自动恢复。</p></body></html>`)
		return
	}

	fmt.Fprint(w, `<div class="kv"><table><tr class="hdr"><th>域名 / 类型</th><th>当前判定</th><th>应答（原始上游结果）</th><th>缓存</th><th>操作</th></tr>`)
	for _, it := range items {
		method, payload, ok := splitCacheKey(it.key)
		if !ok {
			continue
		}
		q, qerr := parseQuestion(payload)
		dom := "?"
		var qtype uint16
		if qerr == nil {
			dom, qtype = q.Name, q.Qtype
		}

		// 应答内容（原始上游结果，未套用污染判定）
		var ansHTML string
		if rcode, answers, perr := parseResponse(withTID(it.body, payload)); perr == nil {
			var b strings.Builder
			fmt.Fprintf(&b, `<div><span class="%s">%s</span></div>`, map[bool]string{true: "fresh", false: "bad"}[rcode == 0], rcodeText(rcode))
			for _, a := range answers {
				fmt.Fprintf(&b, `<div>%s → %s <span style="color:#999">TTL %d</span></div>`,
					html.EscapeString(a.Type), html.EscapeString(a.Data), a.TTL)
			}
			ansHTML = b.String()
		} else {
			ansHTML = `<span class="bad">解析失败</span>`
		}

		fmt.Fprintf(w, `<tr><td data-label="域名"><span class="dom">%s</span> <span style="color:#999">%s · %s</span></td>`+
			`<td data-label="判定">%s%s</td>`+
			`<td data-label="应答" class="ans">%s</td>`+
			`<td data-label="缓存">%s 前<br><span style="color:#999">%d 字节</span></td>`+
			`<td data-label="操作">%s%s</td></tr>`,
			html.EscapeString(dom), qtypeName(qtype), method,
			s.cacheDecision(dom, qtype, it.body), s.overrideBadges(dom),
			ansHTML,
			fmtDur(time.Since(it.at)), len(it.body),
			refreshBtn(it.key), s.overrideBtns(dom))
	}
	fmt.Fprint(w, `</table></div></div>
<p class="tip">判定在应答时实时计算：改覆盖名单立刻生效，不用等缓存过期 · 应答列展示的是上游原始结果，污染判定只影响发给客户端的最终应答</p></body></html>`)
}

// cacheDecision 该缓存条目「此刻」会被如何判定（与 decide() 同规则，仅展示用）。
func (s *Server) cacheDecision(host string, qtype uint16, body []byte) string {
	isIPQ := qtype == 1 || qtype == 28
	switch {
	case s.forceFakeHas(host):
		return `<span class="bad">🎯 强制污染 · 直接回虚假 IP</span>`
	case s.noFakeHas(host):
		return `<span class="fresh">🚫 取消污染 · 始终回真实 IP</span>`
	case isIPQ && s.iplist != nil:
		if ip := firstAnswerIP(body); ip != nil && s.iplist.Contains(ip) {
			return `<span class="stale">🎯 命中污染段 · 回虚假 IP</span>`
		}
		return `<span class="fresh">真实 IP</span>`
	default:
		return `<span class="fresh">真实 IP</span>`
	}
}

// ================= /latency.json =================
//
// 延迟曲线页的数据源。页面打开期间每 2s 轮询一次，同时触发一次
// 真实链路的按需探测（节流 ≥2s），让曲线实时反映当前网络下的真实耗时。

func (s *Server) serveLatencyJSON(w http.ResponseWriter, _ *http.Request) {
	// 页面打开期间的按需探测：模拟真实访问（H2 就按 H2，H3 就按 H3）
	if now := time.Now().Unix(); now-s.lastDemandProbe.Load() >= 2 && s.lastDemandProbe.CompareAndSwap(s.lastDemandProbe.Load(), now) {
		go s.probeNow(true)
		if s.cfg.Fallback != "" {
			go s.probeNow(false)
		}
	}

	pri, fbk := s.lat.snapshot()
	type point struct {
		T   int64   `json:"t"`
		Ms  float64 `json:"ms"`
		P   bool    `json:"p,omitempty"`
		R   bool    `json:"r,omitempty"`
		Pr  string  `json:"pr,omitempty"`
		Dns float64 `json:"dns,omitempty"`
		Tcp float64 `json:"tcp,omitempty"`
		Tls float64 `json:"tls,omitempty"`
		Tfb float64 `json:"tfb,omitempty"`
	}
	conv := func(in []latPoint) []point {
		out := make([]point, len(in))
		for i, p := range in {
			out[i] = point{p.T, p.Ms, p.Probe, p.Reuse, p.Proto, p.Dns, p.Tcp, p.Tls, p.Tfb}
		}
		return out
	}
	resp := struct {
		PrimaryName  string  `json:"primaryName"`
		FallbackName string  `json:"fallbackName,omitempty"`
		Primary      []point `json:"primary"`
		Fallback     []point `json:"fallback"`
	}{PrimaryName: s.cfg.Upstream, FallbackName: s.cfg.Fallback, Primary: conv(pri), Fallback: conv(fbk)}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}
