package fastime

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ---------- 虚假 IP 应答 ----------

func TestBuildFakeAnswerV4(t *testing.T) {
	q := buildQuery("example.com", 1)
	body, err := buildFakeAnswer(q, 1)
	if err != nil {
		t.Fatal(err)
	}
	ip := firstAnswerIP(withTID(body, q))
	if !ip.Equal(net.IP{169, 254, 254, 254}) {
		t.Fatalf("A 虚假 IP = %v，期望 169.254.254.254", ip)
	}
	// QR=1 且 ANCOUNT=1
	if body[2]&0x80 == 0 || binary.BigEndian.Uint16(body[6:8]) != 1 {
		t.Fatal("应答标志/条数不对")
	}
}

func TestBuildFakeAnswerV6(t *testing.T) {
	q := buildQuery("example.com", 28)
	body, err := buildFakeAnswer(q, 28)
	if err != nil {
		t.Fatal(err)
	}
	ip := firstAnswerIP(withTID(body, q))
	if !ip.Equal(net.ParseIP("::ffff:a9fe:fefe")) {
		t.Fatalf("AAAA 虚假 IP = %v，期望 ::ffff:a9fe:fefe", ip)
	}
}

func TestBuildEmptyAnswer(t *testing.T) {
	q := buildQuery("example.com", 1)
	body := buildEmptyAnswer(q)
	if body[2]&0x80 == 0 {
		t.Fatal("QR 位应为 1")
	}
	if body[3]&0x0f != 0 {
		t.Fatal("RCODE 应为 NOERROR(0)")
	}
	if binary.BigEndian.Uint16(body[6:8]) != 0 {
		t.Fatal("ANCOUNT 应为 0")
	}
	// 问题区保留
	question, err := parseQuestion(body)
	if err != nil || question.Name != "example.com" {
		t.Fatalf("问题区丢失: %v %+v", err, question)
	}
}

// ---------- IP 段表 ----------

func TestIPListContains(t *testing.T) {
	nets := parseIPList("93.184.216.0/24\n# 注释\n2001:db8::/32\n\n无效行\n1.2.3.4\n")
	if len(nets) != 3 {
		t.Fatalf("解析条数 = %d，期望 3（CIDR×2 + 裸 IP×1）", len(nets))
	}
	l := &ipList{nets: nets}
	if !l.Contains(net.ParseIP("93.184.216.34")) {
		t.Fatal("93.184.216.34 应命中 93.184.216.0/24")
	}
	if l.Contains(net.ParseIP("93.184.217.1")) {
		t.Fatal("93.184.217.1 不应命中")
	}
	if !l.Contains(net.ParseIP("2001:db8::1")) {
		t.Fatal("2001:db8::1 应命中 2001:db8::/32")
	}
	if !l.Contains(net.ParseIP("1.2.3.4")) {
		t.Fatal("裸 IP 1.2.3.4 应解析为 /32 并命中自身")
	}
}

// ---------- 覆盖名单 ----------

func TestOverrideMutualExclusiveAndPersist(t *testing.T) {
	dir := t.TempDir()
	log := newLogger("error")
	s := &Server{
		noFake:    newOverrideStore(filepath.Join(dir, "nf.json"), log),
		forceFake: newOverrideStore(filepath.Join(dir, "ff.json"), log),
		log:       log,
	}
	s.overrideSet("nofake", "A.COM ", true)
	if !s.noFakeHas("a.com") {
		t.Fatal("nofake 未生效（大小写/空白应被归一化）")
	}
	s.overrideSet("forcefake", "a.com", true)
	if s.noFakeHas("a.com") || !s.forceFakeHas("a.com") {
		t.Fatal("互斥失败：设强制污染后取消污染应被清除")
	}
	s.overrideSet("forcefake", "a.com", false)
	if s.forceFakeHas("a.com") {
		t.Fatal("关闭后仍有强制污染")
	}

	// 落盘 + 重载
	s.overrideSet("nofake", "b.com", true)
	nf2 := newOverrideStore(filepath.Join(dir, "nf.json"), log)
	nf2.load()
	if !nf2.has("b.com") {
		t.Fatal("重启后未从 JSON 恢复取消污染名单")
	}
}

// ---------- decide：应答时实时判定 ----------

func TestDecide(t *testing.T) {
	log := newLogger("error")
	nets := parseIPList("93.184.216.0/24")
	s := &Server{
		cfg:       &Config{PolluteMode: "fake"},
		noFake:    newOverrideStore(filepath.Join(t.TempDir(), "nf.json"), log),
		forceFake: newOverrideStore(filepath.Join(t.TempDir(), "ff.json"), log),
		iplist:    &ipList{nets: nets},
		log:       log,
	}
	q := buildQuery("example.com", 1)
	real, err := buildAnswer(q, 1, []net.IP{net.ParseIP("93.184.216.34")}, 300)
	if err != nil {
		t.Fatal(err)
	}
	question, _ := parseQuestion(q)

	// 命中污染段 → 虚假 IP
	out := s.decide(q, real, question, true)
	if ip := firstAnswerIP(out); !ip.Equal(net.IP{169, 254, 254, 254}) {
		t.Fatalf("命中污染段应回虚假 IP，实际 %v", ip)
	}
	// 取消污染 → 真实 IP
	s.overrideSet("nofake", "example.com", true)
	out = s.decide(q, real, question, true)
	if ip := firstAnswerIP(out); !ip.Equal(net.ParseIP("93.184.216.34")) {
		t.Fatalf("取消污染应回真实 IP，实际 %v", ip)
	}
	s.overrideSet("nofake", "example.com", false)
	// 未命中段 → 真实 IP
	real2, _ := buildAnswer(q, 1, []net.IP{net.ParseIP("8.8.8.8")}, 300)
	out = s.decide(q, real2, question, true)
	if ip := firstAnswerIP(out); !ip.Equal(net.ParseIP("8.8.8.8")) {
		t.Fatalf("未命中污染段应回真实 IP，实际 %v", ip)
	}
	// 非 A/AAAA 查询不判定
	q2 := buildQuery("example.com", 16) // TXT
	real3, _ := buildAnswer(q2, 1, []net.IP{net.ParseIP("93.184.216.34")}, 300)
	question2, _ := parseQuestion(q2)
	out = s.decide(q2, real3, question2, false)
	if len(out) != len(withTID(real3, q2)) {
		t.Fatal("非 IP 查询应原样返回（仅换 TID）")
	}
}

// ---------- 缓存落盘往返 ----------

func TestPersistRoundtrip(t *testing.T) {
	dir := t.TempDir()
	old := cachePersistFile
	cachePersistFile = filepath.Join(dir, "c.json")
	defer func() { cachePersistFile = old }()

	log := newLogger("error")
	c := newLRUCache(8)
	at := time.Now().Add(-3 * time.Minute)
	c.PutWithAt("GET\x00abc", []byte("payload-1"), at)
	c.Put("GET\x00def", []byte("payload-2"))

	s := &Server{cache: c, log: log}
	s.savePersistedCache()

	c2 := newLRUCache(8)
	s2 := &Server{cache: c2, log: log}
	s2.loadPersistedCache()
	if c2.Len() != 2 {
		t.Fatalf("恢复条数 = %d，期望 2", c2.Len())
	}
	body, ok := c2.Get("GET\x00abc")
	if !ok || string(body) != "payload-1" {
		t.Fatal("恢复内容不符")
	}
	items := c2.Snapshot()
	var found bool
	for _, it := range items {
		if it.key == "GET\x00abc" && it.at.Equal(at) {
			found = true
		}
	}
	if !found {
		t.Fatal("缓存时间戳未随落盘保留（影响 15 分钟换新节奏）")
	}
	if s2.persistLoaded.Load() != 2 {
		t.Fatalf("persistLoaded = %d，期望 2", s2.persistLoaded.Load())
	}
}

// ---------- 缓存无过期（LRU 只管容量） ----------

func TestCacheNoExpiry(t *testing.T) {
	c := newLRUCache(2)
	c.PutWithAt("a", []byte("1"), time.Now().Add(-time.Hour)) // 一小时前的也照样命中
	if _, ok := c.Get("a"); !ok {
		t.Fatal("缓存不应有过期概念")
	}
	c.Put("b", []byte("2"))
	c.Put("c", []byte("3")) // 挤掉最久未用的
	if c.Len() != 2 {
		t.Fatalf("LRU 容量 = %d，期望 2", c.Len())
	}
}

// ---------- 15 分钟换新跳过逻辑 ----------

func TestRefreshSkipFresh(t *testing.T) {
	// refreshCache 里跳过 <15min 的条目与强制污染域名——
	// 这里单测判定条件本身（避免起整个 Server）。
	fresh := cacheItem{at: time.Now().Add(-5 * time.Minute)}
	stale := cacheItem{at: time.Now().Add(-16 * time.Minute)}
	if time.Since(fresh.at) >= cacheRefreshFake {
		t.Fatal("5 分钟前的条目不应触发换新（fake 模式 15min 周期）")
	}
	if time.Since(stale.at) < cacheRefreshFake {
		t.Fatal("16 分钟前的条目应触发换新（fake 模式 15min 周期）")
	}
}

// ---------- 空应答 / dnsRespOK ----------

func TestDNSRespOK(t *testing.T) {
	q := buildQuery("x.com", 1)
	if dnsRespOK(q) {
		t.Fatal("查询报文 QR=0，不应判为合法应答")
	}
	ok, _ := buildAnswer(q, 1, []net.IP{net.ParseIP("1.1.1.1")}, 60)
	if !dnsRespOK(ok) {
		t.Fatal("正常应答应通过 dnsRespOK")
	}
	if dnsRespOK([]byte("short")) {
		t.Fatal("过短报文不应通过")
	}
}

// ---------- 熔断器：连续 3 次双败 → 熔断 2 秒回空 ----------

func TestBreaker(t *testing.T) {
	s := &Server{log: newLogger("error")}
	if s.breakerOpen() {
		t.Fatal("初始不应熔断")
	}
	for i := 0; i < breakThreshold-1; i++ {
		s.breakerAccount(assertErr{})
		if s.breakerOpen() {
			t.Fatalf("第 %d 次双败不应触发熔断", i+1)
		}
	}
	s.breakerAccount(assertErr{})
	if !s.breakerOpen() {
		t.Fatal("连续 3 次双败应触发熔断")
	}
	if s.breakerRemain() <= 0 || s.breakerRemain() > breakDuration {
		t.Fatalf("熔断剩余时间异常: %v", s.breakerRemain())
	}
	// 成功后清零
	s.resetBreaker()
	if s.breakerOpen() {
		t.Fatal("resetBreaker 后不应熔断")
	}
	s.breakerAccount(assertErr{})
	s.breakerAccount(nil) // 一次成功立即清零连续计数
	if s.breakFails.Load() != 0 {
		t.Fatal("成功后连续失败计数应清零")
	}
}

type assertErr struct{}

func (assertErr) Error() string { return "test" }

// ---------- 污染模式 off：不做 IP 段判定 ----------

func TestDecidePolluteOff(t *testing.T) {
	log := newLogger("error")
	nets := parseIPList("93.184.216.0/24")
	s := &Server{
		cfg:       &Config{PolluteMode: "off"},
		noFake:    newOverrideStore(filepath.Join(t.TempDir(), "nf.json"), log),
		forceFake: newOverrideStore(filepath.Join(t.TempDir(), "ff.json"), log),
		iplist:    &ipList{nets: nets},
		log:       log,
	}
	q := buildQuery("example.com", 1)
	real, _ := buildAnswer(q, 1, []net.IP{net.ParseIP("93.184.216.34")}, 300)
	question, _ := parseQuestion(q)
	out := s.decide(q, real, question, true)
	if ip := firstAnswerIP(out); !ip.Equal(net.ParseIP("93.184.216.34")) {
		t.Fatalf("off 模式命中段也应原样返回真实 IP，实际 %v", ip)
	}
}

// ---------- 污染模式决定缓存换新周期 ----------

func TestPolluteModeRefreshEvery(t *testing.T) {
	fakeCfg, err := LoadConfigWith(map[string]string{
		"UPSTREAM_URL": "https://a.example.com", "ENC_KEY_B64": "AAAAAAAAAAAAAAAAAAAAAA==",
	})
	if err != nil {
		t.Fatal(err)
	}
	if fakeCfg.PolluteMode != "fake" || fakeCfg.RefreshEvery != cacheRefreshFake {
		t.Fatalf("默认应为 fake/15min，实际 %s/%v", fakeCfg.PolluteMode, fakeCfg.RefreshEvery)
	}
	offCfg, err := LoadConfigWith(map[string]string{
		"UPSTREAM_URL": "https://a.example.com", "ENC_KEY_B64": "AAAAAAAAAAAAAAAAAAAAAA==",
		"POLLUTE_MODE": "off",
	})
	if err != nil {
		t.Fatal(err)
	}
	if offCfg.PolluteMode != "off" || offCfg.RefreshEvery != cacheRefreshOff {
		t.Fatalf("off 应为 off/5min，实际 %s/%v", offCfg.PolluteMode, offCfg.RefreshEvery)
	}
}

// ---------- resolv.conf 代管的 DNS 过滤 ----------

func TestValidDNSFilter(t *testing.T) {
	bad := []string{"::", "0.0.0.0", "::1", "127.0.0.1", "169.254.254.254", "fe80::1", "垃圾", ""}
	for _, v := range bad {
		if validDNS(v) {
			t.Fatalf("%q 不应通过 DNS 有效性过滤", v)
		}
	}
	good := []string{"223.5.5.5", "8.8.8.8", "2400:3200::1", "192.168.1.1"}
	for _, v := range good {
		if !validDNS(v) {
			t.Fatalf("%q 应通过过滤", v)
		}
	}
}

func TestParseDNSLines(t *testing.T) {
	out := "223.5.5.5\n::\n0.0.0.0\n223.5.5.5\n  119.29.29.29 \n"
	ips := parseDNSLines(out)
	if len(ips) != 2 || ips[0] != "223.5.5.5" || ips[1] != "119.29.29.29" {
		t.Fatalf("解析结果 = %v，期望 [223.5.5.5 119.29.29.29]（去重+过滤占位地址）", ips)
	}
}

func TestParseDumpsysDNS(t *testing.T) {
	dump := `
Active default network: 102
NetworkAgentInfo{ ni{WIFI} 101}
   Transports: WIFI
   DnsAddresses: [ /192.168.1.1, /:: ]
NetworkAgentInfo{ ni{MOBILE} 102}
   Transports: CELLULAR
   DnsAddresses: [ /10.200.192.253, /0.0.0.0, /211.136.20.203 ]
NetworkAgentInfo{ ni{VPN} 103}
   Transports: VPN
   DnsAddresses: [ /172.16.0.1 ]
`
	ips := parseDumpsysDNS(dump)
	// 活动网络 102（蜂窝）：收 10.200.192.253 与 211.136.20.203，滤掉 0.0.0.0；VPN 块跳过
	want := map[string]bool{"10.200.192.253": true, "211.136.20.203": true}
	if len(ips) != 2 {
		t.Fatalf("解析结果 = %v，期望恰好 2 条", ips)
	}
	for _, ip := range ips {
		if !want[ip] {
			t.Fatalf("解析结果含意外地址 %s（全集 %v）", ip, ips)
		}
	}
}

// ---------- system-dns.com 本地应答 ----------

func TestSysdnsAnswer(t *testing.T) {
	log := newLogger("error")
	h := newSysdnsHolder(log)
	s := &Server{cfg: &Config{}, log: log, sysdns: h}

	// 模拟探测结果
	h.mu.Lock()
	h.v4 = []string{"192.168.1.1", "223.5.5.5"}
	h.v6 = []string{"2400:3200::1"}
	h.mu.Unlock()

	// A 查询 → 两个 IPv4，TTL=1
	q := buildQuery("system-dns.com", 1)
	question, _ := parseQuestion(q)
	body := s.sysdnsAnswer(q, question)
	rcode, answers, err := parseResponse(withTID(body, q))
	if err != nil || rcode != 0 {
		t.Fatalf("应答解析失败: %v rcode=%d", err, rcode)
	}
	if len(answers) != 2 || answers[0].Data != "192.168.1.1" || answers[1].Data != "223.5.5.5" {
		t.Fatalf("A 应答 = %+v，期望两个 IPv4", answers)
	}
	if answers[0].TTL != 1 {
		t.Fatalf("TTL = %d，期望 1s", answers[0].TTL)
	}

	// AAAA 查询 → 一个 IPv6
	q6 := buildQuery("system-dns.com", 28)
	question6, _ := parseQuestion(q6)
	body6 := s.sysdnsAnswer(q6, question6)
	_, answers6, _ := parseResponse(withTID(body6, q6))
	if len(answers6) != 1 || answers6[0].Type != "AAAA" {
		t.Fatalf("AAAA 应答 = %+v，期望 1 条 AAAA", answers6)
	}

	// 空结果 → 空应答（不是错误）
	h2 := newSysdnsHolder(log)
	s2 := &Server{cfg: &Config{}, log: log, sysdns: h2}
	body9 := s2.sysdnsAnswer(q, question)
	if binary.BigEndian.Uint16(body9[6:8]) != 0 {
		t.Fatal("未探测到时响应为 ANCOUNT=0 的空应答")
	}
}

// ---------- 平台 DNS 解析器 ----------

func TestParseResolvConf(t *testing.T) {
	text := "# comment\nnameserver 192.168.1.1\nnameserver 127.0.0.53\nnameserver fe80::1\nsearch lan\nnameserver 223.5.5.5\n"
	ips := parseResolvConf(text)
	// 127.0.0.53（回环）与 fe80::1（链路本地）被过滤
	if len(ips) != 2 || ips[0] != "192.168.1.1" || ips[1] != "223.5.5.5" {
		t.Fatalf("parseResolvConf = %v", ips)
	}
}

func TestParseScutilDNS(t *testing.T) {
	out := `DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : fd00::1
  if_index : 5 (en0)
  flags    : Request A records

resolver #2
  domain   : corp.example.com
  nameserver[0] : 10.0.0.1
`
	ips := parseScutilDNS(out)
	if len(ips) != 2 || ips[0] != "192.168.1.1" || ips[1] != "fd00::1" {
		t.Fatalf("parseScutilDNS = %v，期望只取 resolver #1", ips)
	}
}

func TestParseResolvectl(t *testing.T) {
	out := "Global: 1.1.1.1\nLink 2 (wlan0): 192.168.1.1 fd00::1\nLink 3 (tun0): 10.8.0.1\n"
	ips := parseResolvectl(out)
	if len(ips) != 4 {
		t.Fatalf("parseResolvectl = %v（条数不对）", ips)
	}
}

var _ = os.Getenv // 保持 os 导入（后续平台测试用）
