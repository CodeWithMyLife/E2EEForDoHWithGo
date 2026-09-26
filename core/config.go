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
	cfgPath        = "/"             // Secret: UPSTREAM_PATH   —— 例: /gateway
	cfgKeyB64      = ""              // Secret: ENC_KEY_B64     —— base64 的 16 字节 AES-128 密钥
	cfgCacheSize   = "128"           // Secret: CACHE_SIZE      —— 内存缓存条数（LRU 淘汰）
	cfgCacheTTLSec = "10"            // Secret: CACHE_TTL_SEC   —— 静默期：期内命中零网络，过期返回缓存+后台刷新
	cfgDoT         = "223.5.5.5:853" // Secret: DOT_SERVER      —— DoT 服务器
	cfgHeaders     = ""              // Secret: CUSTOM_HEADERS  —— base64(JSON) 或纯 JSON，例: eyJYLUF1dGgiOiJhYmMifQ==
	cfgNetSwitch   = "refresh"       // Secret: NET_SWITCH_MODE —— 切网策略: refresh(保留缓存+强制刷新) / clear(清空)
	cfgTimeoutSec  = "10"            // Secret: REQUEST_TIMEOUT_SEC —— 上游请求超时秒数
	cfgLogLevel    = "info"          // Secret: LOG_LEVEL       —— debug / info / error
	cfgDialMode    = "race"          // Secret: DIAL_MODE       —— race(多IP竞速) / single(单IP直连)
	cfgPreferQUIC  = "false"         // Secret: PREFER_QUIC     —— true: 首请求直连 QUIC(0-RTT)，失败回退 h2
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
	Key        []byte
	CacheSize  int
	CacheTTL   time.Duration // 0 = 每次命中都后台刷新
	DoTServer  string
	Headers    map[string]string // 发往上游的自定义请求头；非空时不再发送任何默认头（含 User-Agent）
	NetSwitchClear bool          // 切网时清空缓存（false = 保留缓存并强制逐条刷新）
	Timeout    time.Duration // 上游请求超时
	LogLevel   string        // debug / info / error
	DialSingle bool          // true = 单 IP 直连不竞速
	PreferQUIC bool          // true = 首次联系即尝试 QUIC，跳过 Alt-Svc 探测
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
		timeoutSec = 10
	}
	return &Config{
		Port:      pick("LISTEN_PORT", cfgPort),
		Upstream:  upstream + pick("UPSTREAM_PATH", cfgPath),
		Key:       key,
		CacheSize: cacheN,
		CacheTTL:  time.Duration(ttlSec) * time.Second,
		DoTServer: dot,
		Headers:   headers,
		NetSwitchClear: netMode == "clear",
		Timeout:    time.Duration(timeoutSec) * time.Second,
		LogLevel:   pick("LOG_LEVEL", cfgLogLevel),
		DialSingle: pick("DIAL_MODE", cfgDialMode) == "single",
		PreferQUIC: pick("PREFER_QUIC", cfgPreferQUIC) == "true",
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
