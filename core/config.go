package fastime

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// 以下默认值在构建时通过 -ldflags -X 注入（来源为 GitHub Secrets），
// 例如: -X fastime/core.cfgPort=8080
// 运行时可用同名环境变量临时覆盖，便于本地调试。
var (
	cfgPort         = "8080"          // Secret: LISTEN_PORT      —— 本地监听端口
	cfgUpstream     = ""              // Secret: UPSTREAM_URL    —— 例: https://api.example.com
	cfgFallback     = ""              // Secret: FALLBACK_URL    —— 后备上游域名，主备并发竞速（可选）
	cfgPath         = "/"             // Secret: UPSTREAM_PATH   —— 例: /gateway
	cfgKeyB64       = ""              // Secret: ENC_KEY_B64     —— base64 的 16 字节 AES-128 密钥
	cfgCacheSize    = "128"           // Secret: CACHE_SIZE      —— 内存缓存条数（LRU 淘汰）
	cfgDoT          = "223.5.5.5:853" // Secret: DOT_SERVER      —— DoT 服务器（上游域名引导解析用）
	cfgHeaders      = ""              // Secret: CUSTOM_HEADERS  —— base64(JSON) 或纯 JSON，例: eyJYLUF1dGgiOiJhYmMifQ==
	cfgTimeoutSec   = "3"             // Secret: REQUEST_TIMEOUT_SEC —— 主上游请求超时秒数
	cfgFbTimeoutSec = "5"             // Secret: FALLBACK_TIMEOUT_SEC —— 后备上游请求超时秒数
	cfgLogLevel     = "info"          // Secret: LOG_LEVEL       —— debug / info / error
	cfgQuicPrimary  = ""              // Secret: QUIC_PRIMARY    —— 主上游 QUIC: auto(默认)/prefer/off
	cfgQuicFallback = ""              // Secret: QUIC_FALLBACK   —— 后备上游 QUIC: auto(默认)/prefer/off
	cfgIPListURL    = ""              // Secret: IPLIST_URL      —— 污染 IP 段列表 txt 下载地址（12h 刷新）
	cfgDnsDexB64    = ""              // CI 注入: android/tools/FastimeDns.dex 的 base64（root 取系统真实 DNS 用）
	cfgPolluteMode  = "fake"          // Secret: POLLUTE_MODE    —— fake(默认):命中段回虚假IP / off:不做污染判定全部原样返回
)

// 运行节奏（固定值，按需求硬编码，不占配置项）：
const (
	cacheRefreshFake  = 15 * time.Minute // 污染模式 fake：15 分钟换新，切网不动缓存
	cacheRefreshOff   = 5 * time.Minute  // 污染模式 off：5 分钟换新，切网立刻全量换新
	cachePersistEvery = 30 * time.Second // 缓存定时落盘间隔（强杀最多丢 30s 增量）
	iplistRefresh     = 12 * time.Hour   // IP 段列表联网更新周期
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type Config struct {
	Port         string
	Upstream     string // URL + Path 已拼接
	Fallback     string // 后备上游（URL + Path 已拼接），空 = 不启用
	Key          []byte
	CacheSize    int
	DoTServer    string
	Headers      map[string]string // 发往上游的自定义请求头；非空时不再发送任何默认头（含 User-Agent）
	Timeout      time.Duration     // 主上游请求超时
	FbTimeout    time.Duration     // 后备上游请求超时
	LogLevel     string            // debug / info / error
	QuicPrimary  string            // 主上游 QUIC 策略: auto / prefer / off
	QuicFallback string            // 后备上游 QUIC 策略: auto / prefer / off
	IPListURL    string            // 污染 IP 段列表 txt 下载地址，空 = 不做污染判断
	PolluteMode  string            // fake（命中回虚假 IP）/ off（不判定，原样返回）
	RefreshEvery time.Duration     // 缓存换新周期：fake=15min，off=5min
	Warns        []string          // 非致命配置问题，启动时以 ERROR 级输出
}

// LoadConfig 保持旧签名，等价于无命令行覆盖。
func LoadConfig() (*Config, error) { return LoadConfigWith(nil) }

// LoadConfigWith 支持命令行覆盖：overrides 以环境变量名为键（如 "LISTEN_PORT"），
// 优先级：命令行参数 > 环境变量 > 编译注入值 > 代码默认值。
func LoadConfigWith(overrides map[string]string) (*Config, error) {
	pick := func(key, fallback string) string {
		if v := overrides[key]; v != "" {
			return v
		}
		return envOr(key, fallback)
	}
	key, err := base64.StdEncoding.DecodeString(pick("ENC_KEY_B64", cfgKeyB64))
	if err != nil || len(key) != 16 {
		return nil, errors.New("ENC_KEY_B64 必须是 base64 编码的 16 字节 AES-128 密钥")
	}
	upstream := pick("UPSTREAM_URL", cfgUpstream)
	if upstream == "" {
		return nil, errors.New("缺少 UPSTREAM_URL")
	}
	fallback := pick("FALLBACK_URL", cfgFallback)
	if fallback != "" {
		fallback += pick("UPSTREAM_PATH", cfgPath)
	}
	cacheN, _ := strconv.Atoi(pick("CACHE_SIZE", cfgCacheSize))
	if cacheN <= 0 {
		cacheN = 128
	}
	dot := pick("DOT_SERVER", cfgDoT)
	if dot == "" {
		dot = "223.5.5.5:853"
	}
	var headers map[string]string
	var warns []string
	if h := strings.TrimSpace(pick("CUSTOM_HEADERS", cfgHeaders)); h != "" {
		if m, err := parseHeaders(h); err == nil {
			headers = m
		} else {
			// 自定义头是增强项：解析失败只告警，绝不让整个程序起不来
			warns = append(warns, fmt.Sprintf("CUSTOM_HEADERS 无法解析，已忽略（本次不带自定义头运行）。传入值: %q", h))
		}
	}
	timeoutSec, _ := strconv.Atoi(pick("REQUEST_TIMEOUT_SEC", cfgTimeoutSec))
	if timeoutSec <= 0 {
		timeoutSec = 3
	}
	fbTimeoutSec, _ := strconv.Atoi(pick("FALLBACK_TIMEOUT_SEC", cfgFbTimeoutSec))
	if fbTimeoutSec <= 0 {
		fbTimeoutSec = 5
	}
	// QUIC 策略：主/备独立三档（auto=Alt-Svc 探测 / prefer=首请求直连 / off=禁用）
	normQUIC := func(v string) string {
		switch v {
		case "off", "prefer":
			return v
		}
		return "auto"
	}
	cfg := &Config{
		Port:         pick("LISTEN_PORT", cfgPort),
		Upstream:     upstream + pick("UPSTREAM_PATH", cfgPath),
		Fallback:     fallback,
		Key:          key,
		CacheSize:    cacheN,
		DoTServer:    dot,
		Headers:      headers,
		Timeout:      time.Duration(timeoutSec) * time.Second,
		FbTimeout:    time.Duration(fbTimeoutSec) * time.Second,
		LogLevel:     pick("LOG_LEVEL", cfgLogLevel),
		QuicPrimary:  normQUIC(pick("QUIC_PRIMARY", cfgQuicPrimary)),
		QuicFallback: normQUIC(pick("QUIC_FALLBACK", cfgQuicFallback)),
		IPListURL:    strings.TrimSpace(pick("IPLIST_URL", cfgIPListURL)),
		PolluteMode:  normPollute(pick("POLLUTE_MODE", cfgPolluteMode)),
		Warns:        warns,
	}
	if cfg.PolluteMode == "off" {
		cfg.RefreshEvery = cacheRefreshOff
	} else {
		cfg.RefreshEvery = cacheRefreshFake
	}
	return cfg, nil
}

// normPollute 校验污染模式：fake（默认，命中 IP 段回虚假 IP）/ off（不判定，原样返回）。
func normPollute(v string) string {
	if v == "off" {
		return "off"
	}
	return "fake"
}

// parseHeaders 尽力解析 CUSTOM_HEADERS，容忍各种来源的变形：
// 纯 JSON、base64 标准/URL 安全字母表、有/无填充、首尾空白或引号。
func parseHeaders(h string) (map[string]string, error) {
	h = strings.TrimSpace(h)
	h = strings.Trim(h, `"'`)
	tryJSON := func(s string) (map[string]string, error) {
		var m map[string]string
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			return nil, err
		}
		return m, nil
	}
	if strings.HasPrefix(h, "{") {
		return tryJSON(h)
	}
	for _, dec := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	} {
		if raw, err := dec(h); err == nil {
			if m, err := tryJSON(string(raw)); err == nil {
				return m, nil
			}
		}
	}
	return nil, errors.New("既不是 JSON 也不是 base64(JSON)")
}
