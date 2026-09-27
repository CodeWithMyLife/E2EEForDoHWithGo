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
	cfgPort        = "8080"          // Secret: LISTEN_PORT      —— 本地监听端口
	cfgUpstream    = ""              // Secret: UPSTREAM_URL    —— 例: https://api.example.com
	cfgFallback    = ""              // Secret: FALLBACK_URL    —— 后备上游域名，主上游失败后重试（可选）
	cfgPath        = "/"             // Secret: UPSTREAM_PATH   —— 例: /gateway
	cfgKeyB64      = ""              // Secret: ENC_KEY_B64     —— base64 的 16 字节 AES-128 密钥
	cfgCacheSize   = "128"           // Secret: CACHE_SIZE      —— 内存缓存条数（LRU 淘汰）
	cfgCacheTTLSec = "10"            // Secret: CACHE_TTL_SEC   —— 静默期：期内命中零网络，过期返回缓存+后台刷新
	cfgDoT         = "223.5.5.5:853" // Secret: DOT_SERVER      —— DoT 服务器
	cfgHeaders     = ""              // Secret: CUSTOM_HEADERS  —— base64(JSON) 或纯 JSON，例: eyJYLUF1dGgiOiJhYmMifQ==
	cfgNetSwitch   = "refresh"       // Secret: NET_SWITCH_MODE —— 切网策略: refresh(保留缓存+强制刷新) / clear(清空)
	cfgTimeoutSec  = "3"             // Secret: REQUEST_TIMEOUT_SEC —— 主上游请求超时秒数
	cfgFbTimeoutSec = "5"            // Secret: FALLBACK_TIMEOUT_SEC —— 后备上游请求超时秒数
	cfgBreakFails  = "3"             // Secret: BREAK_FAILS      —— 连续失败几次触发熔断
	cfgBreakSec    = "3"             // Secret: BREAK_DURATION_SEC —— 熔断时长秒数，0 = 禁用熔断
	cfgLogLevel    = "info"          // Secret: LOG_LEVEL       —— debug / info / error
	cfgDialMode    = "race"          // Secret: DIAL_MODE       —— race(多IP竞速) / single(单IP直连)
	cfgPreferQUIC  = "false"         // Secret: PREFER_QUIC     —— 旧版开关，true 等价于 QUIC_PRIMARY=prefer
	cfgQuicPrimary = ""              // Secret: QUIC_PRIMARY    —— 主上游 QUIC: auto(默认)/prefer/off
	cfgQuicFallback = ""             // Secret: QUIC_FALLBACK   —— 后备上游 QUIC: auto(默认)/prefer/off
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type Config struct {
	Port       string
	Upstream   string // URL + Path 已拼接
	Fallback   string // 后备上游（URL + Path 已拼接），空 = 不启用
	Key        []byte
	CacheSize  int
	CacheTTL   time.Duration // 0 = 每次命中都后台刷新
	DoTServer  string
	Headers    map[string]string // 发往上游的自定义请求头；非空时不再发送任何默认头（含 User-Agent）
	NetSwitchClear bool          // 切网时清空缓存（false = 保留缓存并强制逐条刷新）
	Timeout    time.Duration // 主上游请求超时
	FbTimeout  time.Duration // 后备上游请求超时
	BreakFails int           // 连续失败熔断阈值（次）
	BreakDur   time.Duration // 熔断时长，0 = 禁用熔断
	LogLevel   string        // debug / info / error
	DialSingle bool          // true = 单 IP 直连不竞速
	PreferQUIC bool          // 旧版字段：PREFER_QUIC == true（等价 QuicPrimary=prefer）
	QuicPrimary  string      // 主上游 QUIC 策略: auto / prefer / off
	QuicFallback string      // 后备上游 QUIC 策略: auto / prefer / off
	Warns      []string      // 非致命配置问题，启动时以 ERROR 级输出
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
	// 后备上游：主上游请求失败后自动重试的备用域名（可选，路径与主上游一致）
	fallback := pick("FALLBACK_URL", cfgFallback)
	if fallback != "" {
		fallback += pick("UPSTREAM_PATH", cfgPath)
	}
	cacheN, _ := strconv.Atoi(pick("CACHE_SIZE", cfgCacheSize))
	if cacheN <= 0 {
		cacheN = 128
	}
	ttlSec, _ := strconv.Atoi(pick("CACHE_TTL_SEC", cfgCacheTTLSec))
	if ttlSec < 0 {
		ttlSec = 0
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
	netMode := pick("NET_SWITCH_MODE", cfgNetSwitch)
	timeoutSec, _ := strconv.Atoi(pick("REQUEST_TIMEOUT_SEC", cfgTimeoutSec))
	if timeoutSec <= 0 {
		timeoutSec = 3
	}
	fbTimeoutSec, _ := strconv.Atoi(pick("FALLBACK_TIMEOUT_SEC", cfgFbTimeoutSec))
	if fbTimeoutSec <= 0 {
		fbTimeoutSec = 5
	}
	breakFails, _ := strconv.Atoi(pick("BREAK_FAILS", cfgBreakFails))
	if breakFails <= 0 {
		breakFails = 3
	}
	breakSec, _ := strconv.Atoi(pick("BREAK_DURATION_SEC", cfgBreakSec))
	if breakSec < 0 { // 0 是合法值：禁用熔断
		breakSec = 3
	}
	// QUIC 策略：主/备独立三档（auto=Alt-Svc 探测 / prefer=首请求直连 / off=禁用）。
	// 旧版 PREFER_QUIC=true 映射为主上游 prefer，保持兼容。
	quicP := pick("QUIC_PRIMARY", cfgQuicPrimary)
	if quicP == "" {
		if pick("PREFER_QUIC", cfgPreferQUIC) == "true" {
			quicP = "prefer"
		} else {
			quicP = "auto"
		}
	}
	quicF := pick("QUIC_FALLBACK", cfgQuicFallback)
	normQUIC := func(v string) string {
		switch v {
		case "off", "prefer":
			return v
		}
		return "auto"
	}
	return &Config{
		Port:      pick("LISTEN_PORT", cfgPort),
		Upstream:  upstream + pick("UPSTREAM_PATH", cfgPath),
		Fallback:  fallback,
		Key:       key,
		CacheSize: cacheN,
		CacheTTL:  time.Duration(ttlSec) * time.Second,
		DoTServer: dot,
		Headers:   headers,
		NetSwitchClear: netMode == "clear",
		Timeout:    time.Duration(timeoutSec) * time.Second,
		FbTimeout:  time.Duration(fbTimeoutSec) * time.Second,
		BreakFails: breakFails,
		BreakDur:   time.Duration(breakSec) * time.Second,
		LogLevel:   pick("LOG_LEVEL", cfgLogLevel),
		DialSingle: pick("DIAL_MODE", cfgDialMode) == "single",
		PreferQUIC: pick("PREFER_QUIC", cfgPreferQUIC) == "true",
		QuicPrimary:  normQUIC(quicP),
		QuicFallback: normQUIC(quicF),
		Warns:      warns,
	}, nil
}

// parseHeaders 尽力解析 CUSTOM_HEADERS，容忍各种来源的变形：
// 纯 JSON、base64 标准/URL 安全字母表、有/无填充、首尾空白或引号。
func parseHeaders(h string) (map[string]string, error) {
	h = strings.Trim(strings.TrimSpace(h), "\ufeff")
	if unq, err := strconv.Unquote(h); err == nil { // 容忍被多余引号包住的情况
		h = unq
	}
	candidates := [][]byte{[]byte(h)}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if dec, err := enc.DecodeString(h); err == nil {
			candidates = append(candidates, dec)
		}
	}
	for _, raw := range candidates {
		var m map[string]string
		if err := json.Unmarshal(raw, &m); err == nil && m != nil {
			return m, nil
		}
	}
	return nil, errors.New("不是 JSON 对象，也不是其 base64")
}
