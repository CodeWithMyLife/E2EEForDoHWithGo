package fastime

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
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
	body := buildEmptyAnswer(q, 1)
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

// 空应答必须带 SOA 授权记录做负缓存（RFC 2308），TTL=1s：
// 防止客户端/中间解析器把空结果长时间缓存。
func TestBuildEmptyAnswerSOA(t *testing.T) {
	q := buildQuery("example.com", 1)
	body := buildEmptyAnswer(q, 1)
	if binary.BigEndian.Uint16(body[8:10]) != 1 {
		t.Fatal("NSCOUNT 应为 1（SOA 负缓存记录）")
	}
	// SOA 记录紧跟问题区：压缩指针 0xC00C + TYPE=SOA(6) + CLASS=IN(1) + TTL=1
	_, qend, err := decodeName(body, 12)
	if err != nil {
		t.Fatal(err)
	}
	soa := qend + 4
	if body[soa] != 0xC0 || body[soa+1] != 0x0C {
		t.Fatal("SOA owner 应为指向 QNAME 的压缩指针")
	}
	if binary.BigEndian.Uint16(body[soa+2:soa+4]) != 6 {
		t.Fatal("记录类型应为 SOA(6)")
	}
	if binary.BigEndian.Uint32(body[soa+6:soa+10]) != 1 {
		t.Fatal("SOA TTL 应为 1s")
	}
	if binary.BigEndian.Uint16(body[soa+10:soa+12]) != 22 {
		t.Fatal("SOA RDLENGTH 应为 22")
	}
	// minimum（RDATA 最后一个 uint32，RDATA 内偏移 18）也应为 1
	rd := soa + 12
	if binary.BigEndian.Uint32(body[rd+18:rd+22]) != 1 {
		t.Fatal("SOA minimum 应为 1s")
	}
	// 完整性：报文长度 = SOA 记录结束
	if len(body) != rd+22 {
		t.Fatalf("报文长度 %d，期望 %d", len(body), rd+22)
	}
}

// ---------- 公共 DNS / 占位地址过滤 ----------

func TestFilterPublicDNS(t *testing.T) {
	in := []string{
		"192.168.5.1", "202.103.24.68", // 真实下发（保留）
		"114.114.114.114", "223.5.5.5", "119.29.29.29", "8.8.8.8", "1.1.1.1", // 公共 v4
		"240c::6666", "2001:4860:4860::8888", "2400:3200::1", "2402:4e00::", "2606:4700:4700::1111", // 公共 v6
		"fdfe:dcba:9876::2", // ULA 路由器 DNS（保留）
	}
	kept, dropped := filterPublicDNS(in)
	if len(kept) != 3 || kept[0] != "192.168.5.1" || kept[1] != "202.103.24.68" || kept[2] != "fdfe:dcba:9876::2" {
		t.Fatalf("保留列表错误: %v", kept)
	}
	if len(dropped) != 10 {
		t.Fatalf("剔除数 = %d，期望 10: %v", len(dropped), dropped)
	}
	// 名单抽查：各家代表性地址必须命中
	for _, s := range []string{
		"114.114.115.115", "223.6.6.6", "182.254.116.116", "8.8.4.4", "1.0.0.1",
		"180.76.76.76", "101.226.4.6", "218.30.118.6", "117.50.11.11", "52.80.66.66",
		"1.2.4.8", "210.2.4.8",
		"2400:3200:baba::1", "2001:4860:4860::8844", "2606:4700:4700::1001",
		"2400:da00::6666", "2001:dc7:1000::1", "240c::6644",
	} {
		if !isPublicDNS(net.ParseIP(s)) {
			t.Fatalf("%s 应被识别为公共 DNS", s)
		}
	}
}

// Windows「自动获取」网卡的 IPv6 占位 DNS（fec0:0:0:ffff::1/2/3 等）全平台过滤。
func TestValidDNSFiltersSiteLocal(t *testing.T) {
	for _, s := range []string{"fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3", "fec0::abcd"} {
		if validDNS(s) {
			t.Fatalf("%s（site-local 占位）应被过滤", s)
		}
	}
	// 真实 ULA 路由器 DNS 不过滤
	if !validDNS("fdfe:dcba:9876::2") {
		t.Fatal("fdfe:dcba:9876::2（ULA 真实 DNS）不应被过滤")
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
	bad := []string{"::", "0.0.0.0", "::1", "127.0.0.1", "169.254.254.254", "fe80::1", "垃圾", "",
		"198.18.0.2", "198.18.1.1", "198.19.255.254"} // TUN 假 DNS（sing-box/Clash 198.18.0.0/15）
	for _, v := range bad {
		if validDNS(v) {
			t.Fatalf("%q 不应通过 DNS 有效性过滤", v)
		}
	}
	good := []string{"223.5.5.5", "8.8.8.8", "2400:3200::1", "192.168.1.1", "198.17.0.1", "198.20.0.1"}
	for _, v := range good {
		if !validDNS(v) {
			t.Fatalf("%q 应通过过滤", v)
		}
	}
}

func TestParseGetpropDNS(t *testing.T) {
	out := `[net.dns1]: [10.200.192.253]
[net.dns2]: [0.0.0.0]
[net.rmnet_data0.dns1]: [211.136.112.50]
[net.rmnet_data0.dns2]: [211.136.150.66]
[dhcp.wlan0.dns1]: [192.168.1.1]
[dhcp.wlan0.dns2]: [198.18.0.2]
[net.wlan0.dns1]: [2409:8088::1]
[ro.build.version.sdk]: [34]
[net.rmnet_data0.dns1]: [211.136.112.50]
`
	ips := parseGetpropDNS(out)
	// 期望：无效地址（0.0.0.0）与 TUN 假 DNS（198.18.0.2）被滤掉、去重、全局优先
	want := []string{"10.200.192.253", "211.136.112.50", "211.136.150.66", "192.168.1.1", "2409:8088::1"}
	if len(ips) != len(want) {
		t.Fatalf("解析结果 = %v，期望 %v", ips, want)
	}
	for i := range want {
		if ips[i] != want[i] {
			t.Fatalf("解析结果 = %v，期望 %v", ips, want)
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

// ---------- dumpsys 块解析（Android root 主来源） ----------

// 真实风格的 dumpsys connectivity 输出：WIFI + CELLULAR（双通道）+ IMS（无 INTERNET，应丢弃）
// + VPN（Transports 不含 WIFI/CELLULAR，应丢弃）+ 块内 NetworkRequest 干扰行。
const dumpsysSample = `
Active default network: 103
NetworkAgentInfo{ ni{[type: Wifi[], state: CONNECTED/CONNECTED, extra: "office"]} network{103} nlp{{InterfaceName: wlan0 LinkAddresses: [ 192.168.31.5/24 ] DnsAddresses: [ /192.168.31.1,/fe80::1%wlan0 ]} Transports: WIFI Capabilities: INTERNET&NOT_RESTRICTED&TRUSTED}
    NetworkRequest [ id=5 [ Capabilities: INTERNET Transports: CELLULAR|WIFI] ]
NetworkAgentInfo{ ni{[type: Cellular[], state: CONNECTED/CONNECTED]} network{102} nlp{{InterfaceName: rmnet_data1 DnsAddresses: [ /120.196.165.24,/211.136.112.50,/2409:8088:5020:1:ffff::11 ]} Transports: CELLULAR Capabilities: INTERNET&NOT_RESTRICTED}
NetworkAgentInfo{ ni{[type: Cellular[], state: CONNECTED/CONNECTED]} network{104} nlp{{InterfaceName: rmnet_ims0 DnsAddresses: [ /10.10.10.10 ]} Transports: CELLULAR Capabilities: IMS&NOT_RESTRICTED}
NetworkAgentInfo{ ni{[type: Vpn[], state: CONNECTED/CONNECTED]} network{110} nlp{{InterfaceName: tun0 DnsAddresses: [ /198.18.0.2,/10.2.0.1 ]} Transports: VPN Capabilities: INTERNET&NOT_RESTRICTED}
`

func TestParseDumpsysNets(t *testing.T) {
	nets := parseDumpsysNets(dumpsysSample)
	if len(nets) != 2 {
		t.Fatalf("应解析出 2 个可上网网络（WIFI+MOBILE，IMS/VPN 被丢弃），实际 %d: %+v", len(nets), nets)
	}
	w, m := nets[0], nets[1]
	if w.kind != "WIFI" || w.netID != "103" || w.iface != "wlan0" {
		t.Fatalf("WIFI 块解析错误: %+v", w)
	}
	// fe80::1%wlan0：链路本地被滤 + %后缀剥离（双保险）
	if len(w.dns) != 1 || w.dns[0] != "192.168.31.1" {
		t.Fatalf("WIFI DNS = %v，期望 [192.168.31.1]", w.dns)
	}
	if m.kind != "MOBILE" || m.netID != "102" || m.iface != "rmnet_data1" {
		t.Fatalf("MOBILE 块解析错误: %+v", m)
	}
	if len(m.dns) != 3 || m.dns[0] != "120.196.165.24" || m.dns[2] != "2409:8088:5020:1:ffff::11" {
		t.Fatalf("MOBILE DNS = %v", m.dns)
	}
}

func TestSelectDumpsysDNS(t *testing.T) {
	nets := parseDumpsysNets(dumpsysSample)

	// 双通道：两个网络的 DNS 都输出，desc 带归属
	ips, desc := selectDumpsysDNS(nets)
	if len(ips) != 4 || ips[0] != "192.168.31.1" || ips[1] != "120.196.165.24" {
		t.Fatalf("双通道输出 = %v", ips)
	}
	if !strings.Contains(desc, "wlan0#103") || !strings.Contains(desc, "rmnet_data1#102") {
		t.Fatalf("desc 缺 netId/iface 归属: %s", desc)
	}

	// 只有 WIFI
	ips, _ = selectDumpsysDNS(nets[:1])
	if len(ips) != 1 || ips[0] != "192.168.31.1" {
		t.Fatalf("仅 WIFI 输出 = %v", ips)
	}
	// 只有 MOBILE
	ips, _ = selectDumpsysDNS(nets[1:])
	if len(ips) != 3 || ips[0] != "120.196.165.24" {
		t.Fatalf("仅 MOBILE 输出 = %v", ips)
	}
	// 无网络
	ips, _ = selectDumpsysDNS(nil)
	if len(ips) != 0 {
		t.Fatalf("无网络应为空，实际 %v", ips)
	}
}

// TestParseDumpsysNetsOldFormat 老格式/部分 ROM：netId 用 ni{[数字} 形式。
func TestParseDumpsysNetsOldFormat(t *testing.T) {
	dump := `NetworkAgentInfo{ ni{[102 type: CELLULAR[] state: CONNECTED/CONNECTED] extra: cmnet} lp{{InterfaceName: rmnet_data0 DnsAddresses: [ /211.136.112.50 ]} Transports: CELLULAR Capabilities: INTERNET}
`
	nets := parseDumpsysNets(dump)
	if len(nets) != 1 || nets[0].netID != "102" || nets[0].dns[0] != "211.136.112.50" {
		t.Fatalf("老格式 netId 解析 = %+v", nets)
	}
}

// TestParseDumpsysNetsFirstLineOnly 首行无 INTERNET/Transports 的块必须丢弃——
// 即使块内后面的行有 CELLULAR|WIFI 字样（NetworkRequest 干扰）也不行。
func TestParseDumpsysNetsFirstLineOnly(t *testing.T) {
	dump := `NetworkAgentInfo{ ni{[type: Cellular[]]} network{105}
   Transports: CELLULAR Capabilities: IMS
   NetworkRequest [ id=9 [ Capabilities: INTERNET Transports: CELLULAR|WIFI] ]
   DnsAddresses: [ /10.0.0.1 ]
`
	if nets := parseDumpsysNets(dump); len(nets) != 0 {
		t.Fatalf("首行无 INTERNET/Transports 的块应丢弃，实际 %+v", nets)
	}
}

func TestScanAllDnsAddrs(t *testing.T) {
	dump := "custom: DnsAddresses: [ /120.196.165.24,/198.18.0.2,/fe80::1,/0.0.0.0 ]\nagain: DnsAddresses: [ /211.136.112.50 ]"
	ips := scanAllDnsAddrs(dump)
	if len(ips) != 2 || ips[0] != "120.196.165.24" || ips[1] != "211.136.112.50" {
		t.Fatalf("全文扫描兜底 = %v", ips)
	}
}

// ---------- /proc/net/tcp 的 DoT(853) 对端 ----------

func TestParseProcNetTCP853(t *testing.T) {
	// 本地 192.168.31.5:54321 → 对端 1.1.1.1:853 ESTABLISHED（01）
	// 1.1.1.1 小端 hex = 01010101；另有一条 8.8.8.8:853 但状态是 TIME_WAIT(06) 应跳过；
	// 还有一条 853 监听/非 ESTABLISHED 与一条非 853 端口连接。
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0501A8C0:D431 01010101:0215 01 00000000:00000000 00:00000000 00000000     0        0 12345
   1: 0501A8C0:D432 08080808:0215 06 00000000:00000000 00:00000000 00000000     0        0 12346
   2: 0501A8C0:D433 01010101:0050 01 00000000:00000000 00:00000000 00000000     0        0 12347
`
	ips := parseProcNetTCP853(tcp, false)
	if len(ips) != 1 || ips[0] != "1.1.1.1" {
		t.Fatalf("853 对端(v4) = %v，期望 [1.1.1.1]", ips)
	}

	// v6：2606:4700:4700::1111 的 /proc 小端字格式（字内字节逆序）
	tcp6 := `  sl  local_address                         rem_address                        st
   0: 00000000000000000000000000000000:0000 00470626000000470000000011110000:0215 01
`
	ips6 := parseProcNetTCP853(tcp6, true)
	if len(ips6) != 1 || ips6[0] != "2606:4700:4700::1111" {
		t.Fatalf("853 对端(v6) = %v，期望 [2606:4700:4700::1111]", ips6)
	}
}

// TestDNSAddrTokens 逗号/空白/方括号混合分隔的 DnsAddresses 行。
func TestDNSAddrTokens(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"DnsAddresses: [ /120.196.165.24,/211.136.112.50 ]", []string{"120.196.165.24", "211.136.112.50"}},
		{"DnsAddresses: [ /192.168.1.1, /:: ]", []string{"192.168.1.1", "::"}},
		{"DnsAddresses: []", nil},
		{"Routes: [ fe80::/64 -> :: wlan0 ]", nil},
	}
	for _, c := range cases {
		got := dnsAddrTokens(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("dnsAddrTokens(%q) = %v，期望 %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("dnsAddrTokens(%q) = %v，期望 %v", c.in, got, c.want)
			}
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

	// 非 IP 查询（TXT=16）：即使已有探测结果也必须回空——
	// 虚构域名任何类型都不允许携带数据或转发上游
	qt := buildQuery("system-dns.com", 16)
	questionT, _ := parseQuestion(qt)
	bodyT := s.sysdnsAnswer(qt, questionT)
	if binary.BigEndian.Uint16(bodyT[6:8]) != 0 {
		t.Fatal("TXT 查询必须是 ANCOUNT=0 的空应答（虚构域名不出本机）")
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
