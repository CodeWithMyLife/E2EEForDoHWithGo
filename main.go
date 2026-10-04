package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	fastime "fastime/core"
)

// fatal 同时把错误写进 stderr 和 fastime.log，再退出。
// 配置加载失败发生在文件日志器初始化之前，
// 若不写文件，Windows 双击运行时窗口一闪而过，错误无处可查。
// 日志位置：当前目录 → 失败则回退用户主目录（macOS .app 的 cwd 是 / 不可写）。
func fatal(err error) {
	msg := "[FATAL] " + err.Error()
	log.Println(msg)
	line := fmt.Sprintf("%s %s\n", time.Now().Format("15:04:05.000000"), msg)
	if f, ferr := os.OpenFile("fastime.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); ferr == nil {
		f.WriteString(line)
		f.Close()
	} else if home, herr := os.UserHomeDir(); herr == nil {
		if f, ferr2 := os.OpenFile(filepath.Join(home, "fastime.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); ferr2 == nil {
			f.WriteString(line)
			f.Close()
		}
	}
	os.Exit(1)
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	// 全部配置项均可命令行覆盖，优先级：命令行 > 环境变量 > 编译注入值。
	// 括号内为对应的 GitHub Secret / 环境变量名。
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "fastime 运行参数（全部可选，括号内为对应的环境变量/Secret）：\n\n")
		flag.PrintDefaults()
	}
	fPort := flag.String("port", "", "本地监听端口 (LISTEN_PORT)")
	fUpstream := flag.String("upstream", "", "上游地址，例 https://api.example.com (UPSTREAM_URL)")
	fFallback := flag.String("fallback", "", "后备上游域名，主上游失败后重试 (FALLBACK_URL)")
	fPath := flag.String("path", "", "上游路径，例 /gateway (UPSTREAM_PATH)")
	fKey := flag.String("key", "", "base64 的 16 字节 AES-128 密钥 (ENC_KEY_B64)")
	fCacheSize := flag.String("cache-size", "", "内存缓存条数 (CACHE_SIZE)")
	fCacheTTL := flag.String("cache-ttl", "", "缓存静默期秒数 (CACHE_TTL_SEC)")
	fDot := flag.String("dot", "", "DoT 服务器，例 223.5.5.5:853 (DOT_SERVER)")
	fHeaders := flag.String("headers", "", "自定义请求头，JSON 或其 base64 (CUSTOM_HEADERS)")
	fNetSwitch := flag.String("net-switch", "", "切网策略 refresh/clear (NET_SWITCH_MODE)")
	fTimeout := flag.String("timeout", "", "主上游请求超时秒数 (REQUEST_TIMEOUT_SEC)")
	fbTimeout := flag.String("fallback-timeout", "", "后备上游请求超时秒数 (FALLBACK_TIMEOUT_SEC)")
	fBreakFails := flag.String("break-fails", "", "连续失败几次触发熔断 (BREAK_FAILS)")
	fBreakDur := flag.String("break-duration", "", "熔断时长秒数，0=禁用 (BREAK_DURATION_SEC)")
	fLog := flag.String("log", "", "日志等级 debug/info/error (LOG_LEVEL)")
	fDial := flag.String("dial", "", "拨号模式 race/single (DIAL_MODE)")
	fQuic := flag.String("quic", "", "旧版 QUIC 开关 true/false，等价 -quic-primary=prefer (PREFER_QUIC)")
	fQuicP := flag.String("quic-primary", "", "主上游 QUIC 策略 auto/prefer/off (QUIC_PRIMARY)")
	fQuicF := flag.String("quic-fallback", "", "后备上游 QUIC 策略 auto/prefer/off (QUIC_FALLBACK)")
	fMode := flag.String("run-mode", "", "运行模式 standard/turbo（turbo=主备并发竞速+IP段分流+系统DNS代管）(RUN_MODE)")
	fRaceCache := flag.String("race-cache", "", "turbo 模式上游竞速结果缓存秒数 (RACE_CACHE_SEC)")
	fIPList := flag.String("iplist-url", "", "IP 段列表 txt 下载地址，命中段内 IP 的域名改走系统 DNS (IPLIST_URL)")
	fCacheRefresh := flag.String("cache-refresh", "", "运行缓存定时刷新间隔秒数：到期把已有缓存逐条向上游换新，0=关闭定时刷新 (CACHE_REFRESH_SEC)")
	fNDRefresh := flag.String("nodivert-refresh", "", "\"不走系统DNS\"豁免域名的独立刷新秒数，默认180，0=跟随全局 (NODIVERT_REFRESH_SEC)")
	fPersist := flag.String("cache-persist", "", "缓存定时落盘间隔秒数，默认30，0=仅退出时保存 (CACHE_PERSIST_SEC)")
	fHijack := flag.String("hijack-dns", "", "turbo 模式劫持本机53端口全部UDP/TCP DNS流量 true/false，需root/管理员 (HIJACK_DNS)")
	fHijackListen := flag.String("hijack-listen", "", "拦截器自定义监听地址（高级/调试，设置后不装iptables、不改系统DNS）(HIJACK_LISTEN)")
	flag.Parse()

	// 枚举参数先校验，拼写错误立即给出明确提示而不是静默走默认值
	check := func(name, val string, allowed ...string) {
		if val == "" {
			return
		}
		for _, a := range allowed {
			if val == a {
				return
			}
		}
		fatal(fmt.Errorf("无效的 %s 值 %q（可选 %s）", name, val, strings.Join(allowed, "/")))
	}
	check("-log", *fLog, "debug", "info", "error")
	check("-dial", *fDial, "race", "single")
	check("-quic", *fQuic, "true", "false")
	check("-quic-primary", *fQuicP, "auto", "prefer", "off")
	check("-quic-fallback", *fQuicF, "auto", "prefer", "off")
	check("-net-switch", *fNetSwitch, "refresh", "clear")
	check("-run-mode", *fMode, "standard", "turbo")
	check("-hijack-dns", *fHijack, "true", "false")

	ov := make(map[string]string)
	add := func(env, val string) {
		if val != "" {
			ov[env] = val
		}
	}
	add("LISTEN_PORT", *fPort)
	add("UPSTREAM_URL", *fUpstream)
	add("FALLBACK_URL", *fFallback)
	add("UPSTREAM_PATH", *fPath)
	add("ENC_KEY_B64", *fKey)
	add("CACHE_SIZE", *fCacheSize)
	add("CACHE_TTL_SEC", *fCacheTTL)
	add("DOT_SERVER", *fDot)
	add("CUSTOM_HEADERS", *fHeaders)
	add("NET_SWITCH_MODE", *fNetSwitch)
	add("REQUEST_TIMEOUT_SEC", *fTimeout)
	add("FALLBACK_TIMEOUT_SEC", *fbTimeout)
	add("BREAK_FAILS", *fBreakFails)
	add("BREAK_DURATION_SEC", *fBreakDur)
	add("LOG_LEVEL", *fLog)
	add("DIAL_MODE", *fDial)
	add("PREFER_QUIC", *fQuic)
	add("QUIC_PRIMARY", *fQuicP)
	add("QUIC_FALLBACK", *fQuicF)
	add("RUN_MODE", *fMode)
	add("RACE_CACHE_SEC", *fRaceCache)
	add("IPLIST_URL", *fIPList)
	add("CACHE_REFRESH_SEC", *fCacheRefresh)
	add("NODIVERT_REFRESH_SEC", *fNDRefresh)
	add("CACHE_PERSIST_SEC", *fPersist)
	add("HIJACK_DNS", *fHijack)
	add("HIJACK_LISTEN", *fHijackListen)

	cfg, err := fastime.LoadConfigWith(ov)
	if err != nil {
		fatal(err)
	}
	srv, err := fastime.NewServer(cfg)
	if err != nil {
		fatal(err)
	}

	// 优雅退出：收到 SIGINT/SIGTERM 时关闭连接与监听
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		srv.Shutdown()
	}()

	if err := srv.Start(); err != nil {
		fatal(err)
	}
}
