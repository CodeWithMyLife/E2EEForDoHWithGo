package fastime

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strconv"
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
}

func LoadConfig() (*Config, error) {
	key, err := base64.StdEncoding.DecodeString(envOr("ENC_KEY_B64", cfgKeyB64))
	if err != nil || len(key) != 16 {
		return nil, errors.New("ENC_KEY_B64 必须是 base64 编码的 16 字节 AES-128 密钥")
	}
	upstream := envOr("UPSTREAM_URL", cfgUpstream)
	if upstream == "" {
		return nil, errors.New("缺少 UPSTREAM_URL")
	}
	cacheN, _ := strconv.Atoi(envOr("CACHE_SIZE", cfgCacheSize))
	if cacheN <= 0 {
		cacheN = 128
	}
	ttlSec, _ := strconv.Atoi(envOr("CACHE_TTL_SEC", cfgCacheTTLSec))
	if ttlSec < 0 {
		ttlSec = 0
	}
	dot := envOr("DOT_SERVER", cfgDoT)
	if dot == "" {
		dot = "223.5.5.5:853"
	}
	var headers map[string]string
	if h := envOr("CUSTOM_HEADERS", cfgHeaders); h != "" {
		raw := []byte(h)
		if !json.Valid(raw) {
			// CI 注入时为避免 shell/YAML 吃掉 JSON 引号，Secret 里存 base64(JSON)
			if dec, err := base64.StdEncoding.DecodeString(h); err == nil {
				raw = dec
			}
		}
		if err := json.Unmarshal(raw, &headers); err != nil {
			return nil, errors.New("CUSTOM_HEADERS 必须是 JSON 对象或其 base64，例: {\"X-Auth\":\"abc\"}")
		}
	}
	netMode := envOr("NET_SWITCH_MODE", cfgNetSwitch)
	timeoutSec, _ := strconv.Atoi(envOr("REQUEST_TIMEOUT_SEC", cfgTimeoutSec))
	if timeoutSec <= 0 {
		timeoutSec = 10
	}
	return &Config{
		Port:      envOr("LISTEN_PORT", cfgPort),
		Upstream:  upstream + envOr("UPSTREAM_PATH", cfgPath),
		Key:       key,
		CacheSize: cacheN,
		CacheTTL:  time.Duration(ttlSec) * time.Second,
		DoTServer: dot,
		Headers:   headers,
		NetSwitchClear: netMode == "clear",
		Timeout:    time.Duration(timeoutSec) * time.Second,
		LogLevel:   envOr("LOG_LEVEL", cfgLogLevel),
		DialSingle: envOr("DIAL_MODE", cfgDialMode) == "single",
		PreferQUIC: envOr("PREFER_QUIC", cfgPreferQUIC) == "true",
	}, nil
}
