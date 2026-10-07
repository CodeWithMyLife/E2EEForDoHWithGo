package fastime

import (
	"fmt"
	"html"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// 状态页 / 缓存页（统一的浅色卡片风格，纯服务端渲染无外部依赖）。

const pageHead = `<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>⚡</text></svg>">
<style>
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;max-width:960px;margin:24px auto;padding:0 16px;color:#1a1a2e;background:#f4f6fa}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.06);overflow:hidden;margin-bottom:20px}
.hd{display:flex;align-items:center;gap:10px;padding:16px 20px;background:linear-gradient(135deg,#1a73e8,#0d47a1);color:#fff;flex-wrap:wrap}
.hd.red{background:linear-gradient(135deg,#dc2626,#7f1d1d)}
.hd h1{font-size:18px;margin:0;font-weight:600}
.badge{font-size:12px;background:rgba(255,255,255,.18);padding:3px 10px;border-radius:999px}
.btn{font-size:12px;color:#fff;background:rgba(255,255,255,.16);padding:4px 12px;border-radius:999px;text-decoration:none;border:1px solid rgba(255,255,255,.35);white-space:nowrap;cursor:pointer}
.btn:hover{background:rgba(255,255,255,.3)}
.hd .sp{flex:1}
table{border-collapse:collapse;width:100%}
th{padding:8px 10px;font-size:12px;color:#1a73e8;background:#f7f8fc;text-align:left;letter-spacing:.5px}
td{padding:8px 10px;font-size:13px;border-bottom:1px solid #f0f0f5;vertical-align:top;word-break:break-all}
td.mono,.ans{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12.5px}
tr:hover td{background:#fafbff}
.dom{font-weight:600}
.kv{padding:6px 20px 16px}
.kv table td:first-child{color:#666;white-space:nowrap;width:9em}
.fresh{color:#16a34a}
.stale{color:#d97706}
.bad{color:#dc2626}
.mark{font-size:11.5px;margin-top:3px;padding:2px 8px;border-radius:6px;display:inline-block}
.opb{font-size:11.5px;color:#b45309;background:#fffbeb;border:1px solid #fcd34d;padding:2px 9px;border-radius:999px;text-decoration:none;white-space:nowrap;display:inline-block;margin:1px 2px}
.opb:hover{background:#fef3c7}
.opb.on{color:#059669;background:#ecfdf5;border-color:#6ee7b7}
.opb.on:hover{background:#d1fae5}
.opb.rf{color:#1a73e8;background:#eff6ff;border-color:#93c5fd}
.opb.rf:hover{background:#dbeafe}
.opb.fd{color:#dc2626;background:#fef2f2;border-color:#fca5a5}
.opb.fd:hover{background:#fee2e2}
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
  .kv table td:first-child{width:auto}
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

// serveStatus 运行状态页：只保留排障/监控真正有用的信息。
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
	fmt.Fprint(w, `<div class="card"><div class="hd"><h1>⚡ Fastime 加密 DNS 中继</h1><span class="badge">运行中</span><span class="sp"></span>
<a class="btn" href="/cache">📋 缓存</a><a class="btn" style="margin-left:0" href="/latency">📈 延迟</a></div><div class="kv"><table>`)
	row := func(k, v string) { fmt.Fprintf(w, `<tr><td>%s</td><td>%s</td></tr>`, k, v) }

	row("监听", fmt.Sprintf("http://127.0.0.1:%s/e2e （GET dns= / POST · 加密→上游→解密→响应）", html.EscapeString(s.cfg.Port)))

	// 污染模式：决定判定行为与缓存节奏
	if s.cfg.PolluteMode == "off" {
		row("污染模式", `off · 不匹配 IP 段，全部原样返回真实结果（手动覆盖名单仍生效）· 缓存 5 分钟换新 · 切网立刻全量换新`)
	} else {
		row("污染模式", `fake · 命中 IP 段回虚假 IP（A→169.254.254.254 / AAAA→::ffff:a9fe:fefe）· 缓存 15 分钟换新 · 切网不动缓存`)
	}

	// 上游行：附最近一次真实请求的耗时与实际协议（h2/h3/h1）
	pri, fbk := s.lat.snapshot()
	lastDesc := func(pts []latPoint) string {
		if len(pts) == 0 {
			return "暂无请求"
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
		return fmt.Sprintf("最近 %.0fms · %s · %s", p.Ms, proto, kind)
	}
	row("主上游", fmt.Sprintf("%s （QUIC %s · 超时 %s · %s）", html.EscapeString(s.cfg.Upstream), s.cfg.QuicPrimary, s.cfg.Timeout, lastDesc(pri)))
	if s.cfg.Fallback != "" {
		row("后备上游", fmt.Sprintf("%s （QUIC %s · 超时 %s · %s）——主备并发竞速取最快", html.EscapeString(s.cfg.Fallback), s.cfg.QuicFallback, s.cfg.FbTimeout, lastDesc(fbk)))
	} else {
		row("后备上游", `<span class="stale">未配置（单上游）</span>`)
	}

	// 熔断状态
	if d := s.breakerRemain(); d > 0 {
		row("熔断", fmt.Sprintf(`<span class="bad">熔断中 · 剩余 %.1fs · 已拦下 %d 次</span>（连续 %d 次主备双败触发，期间未缓存请求回 200 空应答，缓存照常）`, d.Seconds(), s.breakerN.Load(), breakThreshold))
	} else {
		row("熔断", fmt.Sprintf("未触发（连续 %d 次主备双败 → 熔断 %ds，未缓存请求回 200 空应答）", breakThreshold, int(breakDuration.Seconds())))
	}

	// 识别到的系统 DNS（Android root 代管时才取得到）
	if dnsList, via := s.resolvDNSList(); len(dnsList) > 0 {
		row("系统 DNS（识别）", fmt.Sprintf("%s · 来源 %s · %s", html.EscapeString(strings.Join(dnsList, "、")), html.EscapeString(via), html.EscapeString(s.resolvStatus())))
	} else if v := s.resolvStatus(); v != "" {
		row("系统 DNS（识别）", html.EscapeString(v))
	}

	// 缓存
	row("缓存", fmt.Sprintf("%d / %d 条 · 启动恢复 %d 条 · 命中 %d / 未命中 %d · 每 %s 落盘",
		s.cache.Len(), s.cfg.CacheSize, s.persistLoaded.Load(), s.hits.Load(), s.misses.Load(), cachePersistEvery))
	if t := s.lastRefreshAt.Load(); t > 0 {
		row("上次换新", fmt.Sprintf("%s 前（成功累计 %d / 失败 %d，失败保留旧值）",
			fmtDur(time.Since(time.Unix(t, 0))), s.refreshOK.Load(), s.refreshFail.Load()))
	}

	// IP 段表 + 污染判定计数（fake 模式才有意义）
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
			row("污染 IP 段表", `<span class="stale">未配置 IPLIST_URL（仅「强制污染」名单生效）</span>`)
		}
		noFakeN, forceFakeN := s.overrideStats()
		row("污染判定", fmt.Sprintf("命中回虚假 IP %d 次 · 强制污染 %d 条（直接回假 %d 次） · 取消污染 %d 条（放行真实 %d 次）",
			s.fakeN.Load(), forceFakeN, s.forceFakeN.Load(), noFakeN, s.realN.Load()))
	}

	// 竞速与上游请求
	wins := s.raceWinP.Load() + s.raceWinF.Load()
	avgRace := int64(0)
	if wins > 0 {
		avgRace = s.raceDurMs.Load() / wins
	}
	row("竞速统计", fmt.Sprintf("主胜 %d · 备胜 %d · 双败（回空应答） %d · 胜者平均 %dms",
		s.raceWinP.Load(), s.raceWinF.Load(), s.raceErr.Load(), avgRace))
	row("上游请求", fmt.Sprintf("成功 %d · 前台失败 %d · 429 限流 %d · 本地代答上游域名 %d",
		s.upstreamOK.Load(), s.fgErr.Load(), s.upstream429.Load(), s.localAns.Load()))

	row("运行时长 / 资源", fmt.Sprintf("%s · CPU 最近间隔均值 %.1f%% · 堆 %.1f MB", fmtDur(up), cpuPct, float64(ms.HeapAlloc)/1048576))
	fmt.Fprint(w, `</table></div></div>
</body></html>`)
}
