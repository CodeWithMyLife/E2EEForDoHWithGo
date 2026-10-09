//go:build android

package fastime

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// detectSystemDNS Android 平台真实网络 DNS 探测，回退链：
//  1. sysdns.txt——APK 运行时 Java 侧（ConnectivityManager 回调）实时写入，
//     装了 APK 的 root 机直接读其私有目录复用结果（APK 走 Java 层，最准）
//  2. dumpsys connectivity 块解析（root 主来源）：
//     按 NetworkAgentInfo 切块 → 首行分类（INTERNET 能力 + WIFI/CELLULAR）→
//     提取 netId/iface/DnsAddresses → 单网络取其 DNS，Wi-Fi+蜂窝同在则双通道都输出；
//     块结构异常时全文扫描兜底；Private DNS 开启时改取 netd 的 853(DoT) 连接对端
//  3. getprop 全量扫描（老设备兜底）
//
// 来源粘性：上次成功的来源下一轮最先尝试。
var androidLastSource atomic.Int32 // 上次成功的来源序号（androidSources 索引）

type androidSource struct {
	name string
	fn   func(log *logger) ([]string, error)
}

func androidSources() []androidSource {
	return []androidSource{
		{"APK Java 推送", dnsFromSysdnsTxt},
		{"dumpsys", dnsViaDumpsys},
		{"getprop", dnsViaGetprops},
	}
}

// quietNotExist：sysdns.txt 候选路径全部不存在时的静默错误——
// 纯二进制/未装 APK 的用户这是常态，不值得每 30s 刷一条 INFO 日志。
type quietNotExist struct{ err error }

func (e quietNotExist) Error() string { return e.err.Error() }

func detectSystemDNS(log *logger) (servers []string, via string) {
	srcs := androidSources()
	order := make([]int, len(srcs)) // 尝试顺序（值为原始索引）
	for i := range order {
		order[i] = i
	}
	// 粘性：上次成功的来源最先尝试
	if last := int(androidLastSource.Load()); last > 0 && last < len(srcs) {
		order = append([]int{last}, append(order[:last:last], order[last+1:]...)...)
		log.Debugf("系统 DNS 探测开始：上次成功来源为 %s，本轮顺序 %v",
			srcs[last].name, sourceNames(srcs, order))
	} else {
		log.Debugf("系统 DNS 探测开始：来源顺序 %v", sourceNames(srcs, order))
	}
	for _, oi := range order {
		src := srcs[oi]
		log.Debugf("系统 DNS 探测：尝试来源「%s」…", src.name)
		start := time.Now()
		ips, err := src.fn(log)
		cost := time.Since(start).Round(time.Millisecond)
		if err == nil && len(ips) > 0 {
			androidLastSource.Store(int32(oi))
			log.Debugf("系统 DNS 探测成功[%s]（耗时 %s）：%v", src.name, cost, ips)
			return ips, src.name
		}
		if err != nil {
			if _, quiet := err.(quietNotExist); quiet {
				log.Debugf("系统 DNS 探测[%s]（耗时 %s）: %v", src.name, cost, err)
			} else {
				log.Infof("系统 DNS 探测[%s]失败（耗时 %s）: %v", src.name, cost, err)
			}
		} else {
			log.Infof("系统 DNS 探测[%s]结果为空（耗时 %s）", src.name, cost)
		}
	}
	return nil, ""
}

// sourceNames 仅用于日志：按尝试顺序列出来源名。
func sourceNames(srcs []androidSource, order []int) []string {
	names := make([]string, len(order))
	for i, oi := range order {
		names[i] = srcs[oi].name
	}
	return names
}

// dnsFromSysdnsTxt 读 APK Java 侧推送的 DNS 列表。
// 候选路径：cwd（APK 运行时即 filesDir）→ 可执行文件旁 →
// APK 私有目录（装了 APK 又跑 root 二进制时，root 可直接读
// /data/data/com.fastime.app/files/sysdns.txt——这是有意为之的
// 复用通道：APK 的 Java 层探测结果免费共享给 root 二进制）。
// 全部不存在（纯二进制用户的常态）时返回 quietNotExist，不刷日志。
func dnsFromSysdnsTxt(log *logger) ([]string, error) {
	var lastErr error
	exists := false
	for _, p := range sysdnsTxtCandidates() {
		raw, err := os.ReadFile(p)
		if err != nil {
			if !os.IsNotExist(err) {
				exists = true // 文件在但读不了（权限等）——值得报出来
				log.Debugf("sysdns.txt 候选 %s 读取失败: %v", p, err)
			} else {
				log.Debugf("sysdns.txt 候选 %s 不存在", p)
			}
			lastErr = err
			continue
		}
		exists = true
		if ips := parseDNSLines(string(raw)); len(ips) > 0 {
			log.Debugf("sysdns.txt 命中 %s：%v", p, ips)
			return ips, nil
		}
		log.Debugf("sysdns.txt 候选 %s 存在但无有效地址（%d 字节）", p, len(raw))
		lastErr = fmt.Errorf("%s 内容为空或无有效地址", p)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("无可用 sysdns.txt")
	}
	if !exists {
		log.Debugf("sysdns.txt：所有候选路径均不存在（纯二进制运行的常态）")
		return nil, quietNotExist{lastErr}
	}
	return nil, lastErr
}

// sysdnsTxtCandidates sysdns.txt 候选读取路径。
func sysdnsTxtCandidates() []string {
	paths := []string{"sysdns.txt"}
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, filepath.Join(filepath.Dir(exe), "sysdns.txt"))
	}
	// APK（com.fastime.app）的私有 filesDir——装了 APK 时 root 可读
	paths = append(paths, "/data/data/com.fastime.app/files/sysdns.txt")
	return paths
}

// sysdnsDebugMu/lastDumpHash：dumpsys 原文留档按内容哈希去重，
// 避免 30s 周期探测失败时反复写盘。
var (
	sysdnsDebugMu sync.Mutex
	lastDumpHash  [32]byte
)

// saveDumpsysDebug 解析失败时把 dumpsys 原文存到二进制旁，供发回分析。
// 内容没变化时不重复写（省电省闪存）。
func saveDumpsysDebug(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	sysdnsDebugMu.Lock()
	defer sysdnsDebugMu.Unlock()
	if sum == lastDumpHash {
		return ""
	}
	for _, dir := range sysdnsDebugDirs() {
		p := filepath.Join(dir, "sysdns-dumpsys.txt")
		if err := os.WriteFile(p, []byte(raw), 0644); err == nil {
			lastDumpHash = sum
			return p
		}
	}
	return ""
}

func sysdnsDebugDirs() []string {
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		dirs = append(dirs, wd)
	}
	return dirs
}

// dnsViaDumpsys root 主来源：解析 dumpsys connectivity。
//  1. 块解析：NetworkAgentInfo 切块 → 首行 INTERNET/Transports 分类 →
//     WIFI/MOBILE 网络各取 DNS（双通道同在则都输出，desc 带 netId/iface）
//  2. 块结构对不上（ROM 定制）→ 全文扫描所有 DnsAddresses 兜底
//  3. 仍为空 → Private DNS 附加校验：开启时真实出口是 DoT，
//     以 netd 的 853 连接对端（/proc/net/tcp{,6}）为准
//  4. 全部失败 → 原文存 sysdns-dumpsys.txt 供发回分析
func dnsViaDumpsys(log *logger) ([]string, error) {
	start := time.Now()
	out, via, err := dumpsysConnectivity()
	if err != nil {
		return nil, fmt.Errorf("执行 %s connectivity 失败: %w", via, err)
	}
	log.Debugf("dumpsys（%s）输出 %d 字节，耗时 %s", via, len(out), time.Since(start).Round(time.Millisecond))
	text := string(out)
	nets := parseDumpsysNets(text)
	if len(nets) > 0 {
		log.Debugf("dumpsys 块解析：共 %d 个可上网网络块", len(nets))
		for _, n := range nets {
			log.Debugf("  网络块: 类型=%s netId=%s iface=%s DNS=%v", n.kind, n.netID, n.iface, n.dns)
		}
		if ips, desc := selectDumpsysDNS(nets); len(ips) > 0 {
			log.Infof("dumpsys 解析：%s", desc)
			log.Debugf("dumpsys 块解析选中 DNS：%v（%s）", ips, desc)
			return ips, nil
		}
		log.Debugf("dumpsys 块解析：网络块存在但 WIFI/MOBILE 均未取到 DNS，转全文扫描")
	} else {
		log.Debugf("dumpsys 块解析：无 NetworkAgentInfo 可上网块，转全文扫描")
	}
	// ROM 定制格式兜底：全文扫描
	if ips := scanAllDnsAddrs(text); len(ips) > 0 {
		log.Debugf("dumpsys 全文扫描兜底命中 %d 个 DNS：%v", len(ips), ips)
		return ips, nil
	}
	log.Debugf("dumpsys 全文扫描也无 DnsAddresses，进入 Private DNS 校验")
	// 附加校验：Private DNS(DoT) 开启时，真实出口以 netd 的 853 连接对端为准
	if ips, hint := privateDNSFallback(log); len(ips) > 0 {
		return ips, nil
	} else if hint != "" {
		log.Infof("系统 DNS 探测: %s", hint)
	}
	dbg := ""
	if p := saveDumpsysDebug(text); p != "" {
		dbg = fmt.Sprintf("（原文已存 %s，可发回分析）", p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("dumpsys 输出为空，当前无活动网络？%s", dbg)
	}
	return nil, fmt.Errorf("dumpsys 未解析到可上网网络的 DNS（输出 %d 字节）%s", len(out), dbg)
}

// dumpsysConnectivity 执行 dumpsys connectivity，优先 /system/bin/dumpsys。
// 返回实际使用的可执行文件路径，便于日志定位权限问题。
func dumpsysConnectivity() ([]byte, string, error) {
	if _, err := exec.LookPath("dumpsys"); err == nil {
		out, err := exec.Command("dumpsys", "connectivity").Output()
		return out, "dumpsys", err
	}
	out, err := exec.Command("/system/bin/dumpsys", "connectivity").Output()
	return out, "/system/bin/dumpsys", err
}

// privateDNSFallback Private DNS 附加校验：hostname/opportunistic 模式下
// 系统 DNS 实际走 DoT，从 /proc/net/tcp{,6} 找 netd 的 853 连接对端。
func privateDNSFallback(log *logger) ([]string, string) {
	mode := execOutTrim("settings", "get", "global", "private_dns_mode")
	log.Debugf("Private DNS 校验：private_dns_mode=%q", mode)
	if mode != "hostname" && mode != "opportunistic" {
		return nil, ""
	}
	spec := execOutTrim("settings", "get", "global", "private_dns_specifier")
	log.Debugf("Private DNS 已开启（mode=%s specifier=%q），扫描 853(DoT) 连接对端", mode, spec)
	var peers []string
	for _, f := range []struct {
		path string
		v6   bool
	}{{"/proc/net/tcp", false}, {"/proc/net/tcp6", true}} {
		raw, err := os.ReadFile(f.path)
		if err != nil {
			log.Debugf("Private DNS 校验：读取 %s 失败: %v", f.path, err)
			continue
		}
		hit := parseProcNetTCP853(string(raw), f.v6)
		log.Debugf("Private DNS 校验：%s（%d 字节）命中 853 对端 %v", f.path, len(raw), hit)
		peers = append(peers, hit...)
	}
	if len(peers) > 0 {
		log.Infof("Private DNS（%s %s）已开启：实际走加密 DNS，以 853 连接对端为准 %v", mode, spec, peers)
		return peers, ""
	}
	return nil, fmt.Sprintf("Private DNS（%s %s）已开启：实际走加密 DNS（DoT），未发现活动的 853 连接", mode, spec)
}

func execOutTrim(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return string(bytes.TrimSpace(out))
}

// dnsViaGetprops 兜底：getprop 全量扫描。
// 优先全局 net.dns1/2，其次各接口属性（net.<if>.dnsN、dhcp.<if>.dnsN）——
// 移动数据（rmnet_data*）与 Wi-Fi（wlan*）的 DNS 都能拿到。
func dnsViaGetprops(log *logger) ([]string, error) {
	out, err := exec.Command("getprop").Output()
	if err != nil {
		return nil, err
	}
	ips := parseGetpropDNS(string(out))
	log.Debugf("getprop 输出 %d 字节，命中 DNS 属性 %d 个：%v", len(out), len(ips), ips)
	if len(ips) == 0 {
		return nil, fmt.Errorf("getprop 无有效 DNS 属性")
	}
	return ips, nil
}
