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
	fFallback := flag.String("fallback", "", "后备上游域名，与主上游并发竞速取最快 (FALLBACK_URL)")
	fPath := flag.String("path", "", "上游路径，例 /gateway (UPSTREAM_PATH)")
	fKey := flag.String("key", "", "base64 的 16 字节 AES-128 密钥 (ENC_KEY_B64)")
	fCacheSize := flag.String("cache-size", "", "内存缓存条数 (CACHE_SIZE)")
	fDot := flag.String("dot", "", "DoT 服务器，例 223.5.5.5:853 (DOT_SERVER)")
	fHeaders := flag.String("headers", "", "自定义请求头，JSON 或其 base64 (CUSTOM_HEADERS)")
	fTimeout := flag.String("timeout", "", "主上游请求超时秒数 (REQUEST_TIMEOUT_SEC)")
	fbTimeout := flag.String("fallback-timeout", "", "后备上游请求超时秒数 (FALLBACK_TIMEOUT_SEC)")
	fLog := flag.String("log", "", "日志等级 debug/info/error (LOG_LEVEL)")
	fQuicP := flag.String("quic-primary", "", "主上游 QUIC 策略 auto/prefer/off (QUIC_PRIMARY)")
	fQuicF := flag.String("quic-fallback", "", "后备上游 QUIC 策略 auto/prefer/off (QUIC_FALLBACK)")
	fIPList := flag.String("iplist-url", "", "污染 IP 段列表 txt 下载地址，命中段内 IP 的域名回虚假 IP (IPLIST_URL)")
	fPollute := flag.String("pollute", "", "污染模式 fake/off：fake=命中段回虚假IP(缓存15min换新) off=全部原样返回(缓存5min换新,切网立刻更新) (POLLUTE_MODE)")
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
	check("-quic-primary", *fQuicP, "auto", "prefer", "off")
	check("-quic-fallback", *fQuicF, "auto", "prefer", "off")
	check("-pollute", *fPollute, "fake", "off")

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
	add("DOT_SERVER", *fDot)
	add("CUSTOM_HEADERS", *fHeaders)
	add("REQUEST_TIMEOUT_SEC", *fTimeout)
	add("FALLBACK_TIMEOUT_SEC", *fbTimeout)
	add("LOG_LEVEL", *fLog)
	add("QUIC_PRIMARY", *fQuicP)
	add("QUIC_FALLBACK", *fQuicF)
	add("IPLIST_URL", *fIPList)
	add("POLLUTE_MODE", *fPollute)

	cfg, err := fastime.LoadConfigWith(ov)
	if err != nil {
		fatal(err)
	}
	srv, err := fastime.NewServer(cfg)
	if err != nil {
		fatal(err)
	}

	// 优雅退出：收到 SIGINT/SIGTERM 时保存缓存、关闭连接与监听
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
