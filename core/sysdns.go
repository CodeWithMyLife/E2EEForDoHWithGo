package fastime

import (
	"net"
	"sync"
	"time"
)

// ================= system-dns.com：系统真实 DNS 本地应答 =================
//
// 程序启动时（以及每次网络切换后）探测本机「真实网络」下发的 DNS：
//   - Android APK：Java 侧写入 filesDir/sysdns.txt，这里读取
//   - Android root：dumpsys connectivity 块解析（INTERNET 能力 +
//     WIFI/CELLULAR 分类），Private DNS 开启时改取 DoT(853) 连接对端
//   - Android 兜底：getprop
//   - Windows：PowerShell Get-DnsClientServerAddress（过滤 VPN/TAP/虚拟网卡）
//   - macOS：scutil --dns 的默认解析器
//   - iOS：读 /etc/resolv.conf（沙盒内可能为空，静默降级）
//   - Linux：/etc/resolv.conf（systemd-resolved 桩 127.0.0.53 时改读 resolvectl）
//
// 探测结果用于应答特殊域名 system-dns.com：
// A 查询回全部 IPv4 DNS、AAAA 回全部 IPv6 DNS，TTL=1s——
// 客户端 dig @127.0.0.1 -p <port> system-dns.com 即可随时看到当前网络的
// 真实 DNS，切网后下一次查询就是新结果。

const sysdnsDomain = "system-dns.com"

type sysdnsHolder struct {
	log *logger

	mu  sync.RWMutex
	v4  []string
	v6  []string
	via string
	at  time.Time

	kick     chan struct{}
	detectMu sync.Mutex // 探测串行化：连续切网只留最后一次
	lastRun  time.Time  // 最近一次探测完成时刻（detectMu 保护）
}

func newSysdnsHolder(log *logger) *sysdnsHolder {
	return &sysdnsHolder{log: log, kick: make(chan struct{}, 1)}
}

// sysdnsDetectEvery：网络无变化时的周期重探测间隔（用户指定 30s）。
// 探测开销已通过「来源粘性」控制：上次成功的来源优先重试。
const sysdnsDetectEvery = 30 * time.Second

// sysdnsStart 启动探测循环：启动时立即探测一次 → 之后每 30s 一次 →
// 切网即时插队（去抖 1.2s 等系统 DNS 下发）。
// 非强制探测带 2s 最小间隔：切网抖动期 kick 与周期 tick 可能同时到，
// 合并掉重复探测（省电，日志也不会被刷屏）。
func (s *Server) sysdnsStart() {
	h := s.sysdns
	go func() {
		h.detect()
		tk := time.NewTicker(sysdnsDetectEvery)
		defer tk.Stop()
		for {
			select {
			case <-s.watchStop:
				return
			case <-tk.C:
				h.detectThrottled(2 * time.Second)
			case <-h.kick:
				time.Sleep(1200 * time.Millisecond)
				h.detectThrottled(2 * time.Second)
			}
		}
	}()
}

// detectThrottled 带最小间隔的探测：距上次探测不足 min 时跳过。
// 网页「重新探测」按钮走 detect() 强制路径，不受此限。
func (h *sysdnsHolder) detectThrottled(min time.Duration) {
	h.detectMu.Lock()
	fresh := time.Since(h.lastRun) < min
	h.detectMu.Unlock()
	if !fresh {
		h.detect()
	}
}

// sysdnsKick 切网时触发重新探测（非阻塞）。
func (s *Server) sysdnsKick() {
	select {
	case s.sysdns.kick <- struct{}{}:
	default:
	}
}

// detect 调平台探测并更新结果；空结果保留旧值。
// 仅在结果真正变化（DNS 列表/来源）时更新并打 INFO 日志——
// 30s 周期探测无变化时静默，不刷屏。
func (h *sysdnsHolder) detect() {
	h.detectMu.Lock()
	defer h.detectMu.Unlock()
	h.lastRun = time.Now()
	servers, via := detectSystemDNS(h.log)
	// 剔除公共 DNS（114/阿里/腾讯/谷歌/Cloudflare/360/OneDNS/CNNIC/CFIEC 等）：
	// 它们基本是代理 App 改写或手工设置的残留，不是网络真实下发的。
	servers, dropped := filterPublicDNS(servers)
	if len(dropped) > 0 {
		h.log.Infof("系统 DNS 探测（%s）：已剔除公共 DNS %v", via, dropped)
	}
	if len(servers) == 0 {
		h.log.Debugf("系统 DNS 探测为空（via=%s），保留旧值", via)
		return
	}
	var v4, v6 []string
	for _, ip := range servers {
		if p := net.ParseIP(ip); p != nil {
			if p.To4() != nil {
				v4 = append(v4, ip)
			} else {
				v6 = append(v6, ip)
			}
		}
	}
	h.mu.Lock()
	changed := via != h.via || !equalStrings(v4, h.v4) || !equalStrings(v6, h.v6)
	if changed {
		h.v4, h.v6, h.via, h.at = v4, v6, via, time.Now()
	}
	h.mu.Unlock()
	if changed {
		h.log.Infof("系统 DNS 已更新（%s）：IPv4 %d 个 · IPv6 %d 个", via, len(v4), len(v6))
		h.log.Debugf("系统 DNS 明细（%s）：IPv4 %v · IPv6 %v", via, v4, v6)
	} else {
		h.log.Debugf("系统 DNS 无变化（%s）：IPv4 %v · IPv6 %v", via, v4, v6)
	}
}

// equalStrings 比较两个字符串切片是否逐元素相等。
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// snapshot 当前探测结果。
func (h *sysdnsHolder) snapshot() (v4, v6 []string, via string, at time.Time) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return append([]string(nil), h.v4...), append([]string(nil), h.v6...), h.via, h.at
}

// sysdnsAnswer 构造 system-dns.com 的本地应答：A → 全部 IPv4 DNS，
// AAAA → 全部 IPv6 DNS，TTL=1s（客户端几乎不缓存，切网立刻可见新结果）。
// 虚构域名绝不出本机：其它查询类型（TXT/MX/…）一律回空应答，
// 任何情况下都不打上游、不进缓存。
func (s *Server) sysdnsAnswer(payload []byte, q dnsQuestion) []byte {
	s.sysdnsQ.Add(1)
	if q.Qtype != dnsTypeA && q.Qtype != dnsTypeAAAA {
		return buildEmptyAnswer(payload, 1) // 非 IP 查询：空应答，绝不转发上游
	}
	v4, v6, _, _ := s.sysdns.snapshot()
	var ips []net.IP
	if q.Qtype == dnsTypeAAAA {
		for _, v := range v6 {
			if ip := net.ParseIP(v); ip != nil {
				ips = append(ips, ip)
			}
		}
	} else {
		for _, v := range v4 {
			if ip := net.ParseIP(v); ip != nil {
				ips = append(ips, ip)
			}
		}
	}
	if len(ips) == 0 {
		return buildEmptyAnswer(payload, 1) // 尚未探测到：空应答而不是错误
	}
	body, err := buildAnswer(payload, q.Qtype, ips, 1) // TTL=1s
	if err != nil {
		return buildEmptyAnswer(payload, 1)
	}
	return body
}

// dedupStrings 去重保序。
func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
