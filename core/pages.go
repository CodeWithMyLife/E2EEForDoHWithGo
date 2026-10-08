package fastime

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// 状态页 / 缓存页共享的现代卡片风格（纯服务端渲染无外部依赖）。

const pageHead = `<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>⚡</text></svg>">
<style>
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;max-width:1060px;margin:0 auto;padding:20px 16px 40px;color:#1e293b;background:#eef2f9}
.hero{background:linear-gradient(135deg,#4f46e5 0%,#2563eb 55%,#0ea5e9 100%);border-radius:20px;padding:22px 24px;color:#fff;box-shadow:0 8px 24px rgba(37,99,235,.25);margin-bottom:18px}
.hero .top{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.hero h1{font-size:21px;margin:0;font-weight:700;letter-spacing:.3px}
.dot{width:9px;height:9px;border-radius:50%;background:#4ade80;box-shadow:0 0 0 4px rgba(74,222,128,.25);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 4px rgba(74,222,128,.25)}50%{box-shadow:0 0 0 7px rgba(74,222,128,.12)}}
.badge{font-size:12px;background:rgba(255,255,255,.18);border:1px solid rgba(255,255,255,.25);padding:3px 11px;border-radius:999px;backdrop-filter:blur(4px)}
.hero .sp{flex:1}
.btn{font-size:12.5px;color:#fff;background:rgba(255,255,255,.16);padding:6px 15px;border-radius:999px;text-decoration:none;border:1px solid rgba(255,255,255,.35);white-space:nowrap;transition:background .15s}
.btn:hover{background:rgba(255,255,255,.32)}
.hero .sub{font-size:12px;opacity:.85;margin-top:10px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.card{background:#fff;border-radius:16px;box-shadow:0 2px 14px rgba(15,23,42,.07);overflow:hidden;transition:box-shadow .2s,transform .2s}
.card:hover{box-shadow:0 6px 22px rgba(15,23,42,.11);transform:translateY(-1px)}
.card.wide{grid-column:1/-1}
.ct{padding:13px 20px;font-size:14px;font-weight:650;color:#1e293b;border-bottom:1px solid #f1f5f9;display:flex;align-items:center;gap:8px}
.ct .ico{font-size:15px}
.ct .hint{margin-left:auto;font-size:11.5px;color:#94a3b8;font-weight:400}
.kv{padding:6px 20px 14px}
.kv table{border-collapse:collapse;width:100%}
.kv td{padding:8px 4px;font-size:13px;border-bottom:1px dashed #eef2f7;vertical-align:top}
.kv tr:last-child td{border-bottom:none}
.kv td:first-child{color:#64748b;white-space:nowrap;width:7.5em;padding-right:10px}
.kv td:last-child{color:#0f172a;word-break:break-all}
.mono,.ans{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12.5px}
.ok{color:#059669}.warn{color:#d97706}.bad{color:#dc2626}
.pill{display:inline-block;font-size:11.5px;padding:2px 10px;border-radius:999px;font-weight:600}
.pill.g{color:#047857;background:#d1fae5}
.pill.y{color:#b45309;background:#fef3c7}
.pill.r{color:#b91c1c;background:#fee2e2}
.pill.b{color:#1d4ed8;background:#dbeafe}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:4px}
.chip{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;background:#f1f5f9;border:1px solid #e2e8f0;padding:4px 11px;border-radius:8px;color:#0f172a}
.chip.v6{background:#f5f3ff;border-color:#ddd6fe}
.subt{font-size:11.5px;color:#94a3b8;margin:10px 0 2px;font-weight:600;letter-spacing:.4px}
table.list{border-collapse:collapse;width:100%}
table.list th{padding:9px 12px;font-size:11.5px;color:#6366f1;background:#f8faff;text-align:left;letter-spacing:.6px;text-transform:uppercase}
table.list td{padding:9px 12px;font-size:13px;border-bottom:1px solid #f1f5f9;vertical-align:top;word-break:break-all}
table.list tr:hover td{background:#fafbff}
.dom{font-weight:650}
.mark{font-size:11.5px;margin-top:3px;padding:2px 8px;border-radius:6px;display:inline-block}
.opb{font-size:11.5px;color:#b45309;background:#fffbeb;border:1px solid #fcd34d;padding:2px 9px;border-radius:999px;text-decoration:none;white-space:nowrap;display:inline-block;margin:1px 2px;transition:background .15s}
.opb:hover{background:#fef3c7}
.opb.on{color:#059669;background:#ecfdf5;border-color:#6ee7b7}
.opb.on:hover{background:#d1fae5}
.opb.rf{color:#1d4ed8;background:#eff6ff;border-color:#93c5fd}
.opb.rf:hover{background:#dbeafe}
.opb.fd{color:#dc2626;background:#fef2f2;border-color:#fca5a5}
.opb.fd:hover{background:#fee2e2}
.ans div{white-space:nowrap}
.empty{padding:36px;text-align:center;color:#94a3b8;font-size:13.5px}
.tip{color:#94a3b8;font-size:12px;margin:14px 4px 0;line-height:1.7}
@media (max-width:760px){
  body{padding:10px 8px 28px}
  .grid{grid-template-columns:1fr;gap:12px}
  .hero{padding:16px 16px;border-radius:16px}
  .hero h1{font-size:17px}
  table.list,tbody,tr,td{display:block;width:100%}
  tr.hdr{display:none}
  table.list tr{border-bottom:8px solid #eef2f9;padding:6px 0}
  table.list tr:last-child{border-bottom:none}
  table.list td{border:none;padding:3px 14px}
  table.list td::before{content:attr(data-label);display:block;font-size:10.5px;color:#94a3b8;margin-bottom:1px}
  .ans div{white-space:normal}
  .kv td:first-child{width:auto}
}
</style></head><body>`

// fmtDur 人性化时长（状态页用）。
func fmtDur(d time.Duration) string {
	switch {
	case d >= time.Hour:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}

func chipList(ips []string, v6 bool) string {
	if len(ips) == 0 {
		return `<span style="color:#94a3b8;font-size:12.5px">无</span>`
	}
	var b strings.Builder
	cls := "chip"
	if v6 {
		cls = "chip v6"
	}
	b.WriteString(`<div class="chips">`)
	for _, ip := range ips {
		fmt.Fprintf(&b, `<span class="%s">%s</span>`, cls, html.EscapeString(ip))
	}
	b.WriteString(`</div>`)
	return b.String()
}

// durText 把整小时/整分钟的周期格式化为短文本（12h0m0s→12h，15m0s→15m）。
func durText(d time.Duration) string {
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", d/time.Hour)
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.String()
}

// serveStatus 运行状态页。
func (s *Server) serveStatus(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	up := time.Since(s.startTime).Round(time.Second)

	// CPU：相邻两次访问间求平均（%）；内存：当前堆占用
	s.cpuMu.Lock()
	cpuNow := procCPUSeconds()
	cpuPct := 0.0
	if d := time.Since(s.lastCPUTime); d > 0 && cpuNow > s.lastCPUSec {
		cpuPct = (cpuNow - s.lastCPUSec) / d.Seconds() * 100
	}
	s.lastCPUSec, s.lastCPUTime = cpuNow, time.Now()
	s.cpuMu.Unlock()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	fmt.Fprint(w, pageHead)

	// ---------- Hero ----------
	polluteBadge := `<span class="badge">污染 fake</span>`
	if s.cfg.PolluteMode == "off" {
		polluteBadge = `<span class="badge">污染 off</span>`
	}
	fmt.Fprintf(w, `<div class="hero"><div class="top"><span class="dot"></span><h1>⚡ Fastime 加密 DNS 中继</h1>%s<span class="badge">运行 %s</span><span class="sp"></span>
<a class="btn" href="/cache">📋 缓存</a><a class="btn" style="margin-left:0" href="/latency">📈 延迟</a></div>
<div class="sub">监听 <b>http://127.0.0.1:%s/e2e</b>（GET dns= / POST）· 加密 → 上游竞速 → 解密 → 应答时污染判定</div></div>`,
		polluteBadge, fmtDur(up), html.EscapeString(s.cfg.Port))

	fmt.Fprint(w, `<div class="grid">`)

	// ---------- 卡 1：系统 DNS（system-dns.com 本地应答） ----------
	v4, v6, via, at := s.sysdns.snapshot()
	fmt.Fprint(w, `<div class="card"><div class="ct"><span class="ico">🧭</span>系统 DNS · system-dns.com<span class="hint">dig @127.0.0.1 -p `+html.EscapeString(s.cfg.Port)+` system-dns.com</span><a class="opb rf" href="/sysdns-refresh" title="强制重新探测系统 DNS 并立即生效">🔄 重新探测</a></div><div class="kv">`)
	if len(v4)+len(v6) > 0 {
		fmt.Fprintf(w, `<div class="subt">IPv4（A 查询应答 · TTL 1s）</div>%s`, chipList(v4, false))
		fmt.Fprintf(w, `<div class="subt">IPv6（AAAA 查询应答 · TTL 1s）</div>%s`, chipList(v6, true))
		src := ""
		if via != "" {
			src = fmt.Sprintf("来源 %s · 更新于 %s（%s 前）", html.EscapeString(via), at.Format("15:04:05"), fmtDur(time.Since(at)))
		}
		fmt.Fprintf(w, `<div class="subt" style="font-weight:400">%s · 已应答 %d 次 · 切网自动更新</div>`, src, s.sysdnsQ.Load())
	} else {
		fmt.Fprint(w, `<div class="empty">尚未探测到系统 DNS（切网或稍候自动重试）</div>`)
	}
	fmt.Fprint(w, `</div></div>`)

	// ---------- 卡 2：概览 ----------
	fmt.Fprint(w, `<div class="card"><div class="ct"><span class="ico">📊</span>概览</div><div class="kv"><table>`)
	row := func(k, v string) { fmt.Fprintf(w, `<tr><td>%s</td><td>%s</td></tr>`, k, v) }
	if s.cfg.PolluteMode == "off" {
		row("污染模式", `<span class="pill b">off</span> 不匹配 IP 段，全部原样返回（覆盖名单仍生效）· 缓存 5 分钟换新 · 切网立刻全量换新`)
	} else {
		row("污染模式", `<span class="pill y">fake</span> 命中段回虚假 IP <span class="mono">169.254.254.254 / ::ffff:a9fe:fefe</span> · 缓存 15 分钟换新 · 切网不动缓存`)
	}
	if d := s.breakerRemain(); d > 0 {
		row("熔断", fmt.Sprintf(`<span class="pill r">熔断中</span> 剩余 %.1fs · 已拦 %d 次（未缓存请求回 200 空应答，缓存照常）`, d.Seconds(), s.breakerN.Load()))
	} else {
		row("熔断", fmt.Sprintf(`<span class="pill g">未触发</span> 连续 %d 次主备双败 → 熔断 %ds`, breakThreshold, int(breakDuration.Seconds())))
	}
	row("CPU / 内存", fmt.Sprintf("最近间隔均值 %.1f%% · 堆 %.1f MB", cpuPct, float64(ms.HeapAlloc)/1048576))
	fmt.Fprint(w, `</table></div></div>`)

	// ---------- 卡 3：上游与竞速 ----------
	pri, fbk := s.lat.snapshot()
	lastDesc := func(pts []latPoint) string {
		if len(pts) == 0 {
			return `<span style="color:#94a3b8">暂无请求</span>`
		}
		p := pts[len(pts)-1]
		proto := p.Proto
		if proto == "" {
			proto = "?"
		}
		kind := "真实"
		if p.Probe {
			kind = "探测"
		}
		return fmt.Sprintf(`<span class="pill b">%s</span> 最近 %.0fms（%s）`, proto, p.Ms, kind)
	}
	fmt.Fprint(w, `<div class="card"><div class="ct"><span class="ico">🌐</span>上游与竞速</div><div class="kv"><table>`)
	row("主上游", fmt.Sprintf(`<span class="mono">%s</span><br>QUIC %s · 超时 %s · %s`, html.EscapeString(s.cfg.Upstream), s.cfg.QuicPrimary, s.cfg.Timeout, lastDesc(pri)))
	if s.cfg.Fallback != "" {
		row("后备上游", fmt.Sprintf(`<span class="mono">%s</span><br>QUIC %s · 超时 %s · %s`, html.EscapeString(s.cfg.Fallback), s.cfg.QuicFallback, s.cfg.FbTimeout, lastDesc(fbk)))
	} else {
		row("后备上游", `<span class="warn">未配置（单上游）</span>`)
	}
	wins := s.raceWinP.Load() + s.raceWinF.Load()
	avgRace := int64(0)
	if wins > 0 {
		avgRace = s.raceDurMs.Load() / wins
	}
	row("竞速统计", fmt.Sprintf("主胜 <b>%d</b> · 备胜 <b>%d</b> · 双败（回空应答） <b>%d</b> · 胜者平均 %dms",
		s.raceWinP.Load(), s.raceWinF.Load(), s.raceErr.Load(), avgRace))
	row("上游请求", fmt.Sprintf("成功 %d · 前台失败 %d · 429 限流 %d · 本地代答上游域名 %d",
		s.upstreamOK.Load(), s.fgErr.Load(), s.upstream429.Load(), s.localAns.Load()))
	fmt.Fprint(w, `</table></div></div>`)

	// ---------- 卡 4：缓存与污染 ----------
	fmt.Fprint(w, `<div class="card"><div class="ct"><span class="ico">🗄️</span>缓存与污染</div><div class="kv"><table>`)
	row("缓存", fmt.Sprintf("<b>%d</b> / %d 条 · 启动恢复 %d 条 · 命中 %d / 未命中 %d · 每 %s 落盘",
		s.cache.Len(), s.cfg.CacheSize, s.persistLoaded.Load(), s.hits.Load(), s.misses.Load(), cachePersistEvery))
	if t := s.lastRefreshAt.Load(); t > 0 {
		row("上次换新", fmt.Sprintf("%s 前（成功累计 %d / 失败 %d，失败保留旧值）",
			fmtDur(time.Since(time.Unix(t, 0))), s.refreshOK.Load(), s.refreshFail.Load()))
	}
	if s.cfg.PolluteMode != "off" {
		if s.iplist != nil {
			n, lastOK, lastErr, fetches, fails, fromLocal := s.iplist.stats()
			src := "联网下载"
			if fromLocal {
				src = "本地文件（待联网更新）"
			}
			v := fmt.Sprintf("%d 条 · 来源 %s · 下载成功 %d / 失败 %d", n, src, fetches, fails)
			if !lastOK.IsZero() {
				v += fmt.Sprintf(" · 上次更新 %s 前", fmtDur(time.Since(lastOK)))
			}
			if lastErr != "" {
				v += fmt.Sprintf(` · <span class="bad">%s</span>`, html.EscapeString(lastErr))
			}
			row("污染 IP 段表", v)
		} else {
			row("污染 IP 段表", `<span class="warn">未配置 IPLIST_URL（仅「强制污染」名单生效）</span>`)
		}
		noFakeN, forceFakeN := s.overrideStats()
		row("污染判定", fmt.Sprintf("命中回虚假 IP %d 次 · 强制污染 %d 条（直接回假 %d 次） · 取消污染 %d 条（放行真实 %d 次）",
			s.fakeN.Load(), forceFakeN, s.forceFakeN.Load(), noFakeN, s.realN.Load()))
	}
	fmt.Fprint(w, `</table></div></div>`)

	// ---------- 卡 5：运行配置（编译注入 + 启动参数快照） ----------
	keyFP := "-"
	if len(s.cfg.Key) > 0 {
		sum := sha256.Sum256(s.cfg.Key)
		keyFP = hex.EncodeToString(sum[:4])
	}
	hdrN := len(s.cfg.Headers)
	hdrDesc := fmt.Sprintf("%d 个（加密管道随请求发往上游）", hdrN)
	if hdrN == 0 {
		hdrDesc = "未配置"
	}
	fmt.Fprint(w, `<div class="card wide"><div class="ct"><span class="ico">⚙️</span>运行配置<span class="hint">编译注入 + 启动参数快照</span></div><div class="kv"><table>`)
	row("运行环境", fmt.Sprintf("<b>%s/%s</b> · %s · 协程 %d · 启动于 %s",
		runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.NumGoroutine(), s.startTime.Format("01-02 15:04:05")))
	row("日志等级", fmt.Sprintf(`<span class="pill b">%s</span>`, html.EscapeString(s.cfg.LogLevel)))
	row("加密密钥", fmt.Sprintf("AES-128-GCM · 指纹 <span class=\"mono\">%s</span>（sha256 前 8 位，用于核对两端一致）", keyFP))
	row("请求头", hdrDesc)
	row("DoT 引导", fmt.Sprintf("上游域名本地代答 · 引导服务器 <span class=\"mono\">%s</span>", html.EscapeString(s.cfg.DoTServer)))
	row("缓存策略", fmt.Sprintf("容量 %d 条 LRU · 无过期 · 每 %s 串行换新 · 每 %s 落盘（强杀最多丢 %s 增量）",
		s.cfg.CacheSize, durText(s.cfg.RefreshEvery), durText(cachePersistEvery), durText(cachePersistEvery)))
	if s.cfg.IPListURL != "" {
		row("污染 IP 段表", fmt.Sprintf("每 %s 联网更新 · 优先读本地文件 · 地址 <span class=\"mono\">%s</span>",
			durText(iplistRefresh), html.EscapeString(s.cfg.IPListURL)))
	}
	row("系统 DNS 探测", fmt.Sprintf("启动即探测 · 切网立刻重探 · 无变化每 %s 周期探测", durText(sysdnsDetectEvery)))
	fmt.Fprint(w, `</table></div></div>`)

	fmt.Fprint(w, `</div>
<p class="tip">💡 查询 <b>system-dns.com</b>（A / AAAA）可随时获取当前网络真实下发的 DNS，TTL=1s，切网自动更新 ·
熔断期间未缓存请求回 HTTP 200 空应答 · 覆盖名单改动即时生效，无需等缓存过期</p>
</body></html>`)
}
