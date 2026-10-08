//go:build android

package fastime

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
)

// detectSystemDNS Android 平台真实网络 DNS 探测，完整回退链：
//  1. filesDir/sysdns.txt——APK 运行时 Java 侧（ConnectivityManager 回调）实时写入，
//     无 root 也能拿到当前默认网络的真实 DNS（与系统同源同精度）
//  2. root/shell：内嵌 dex 经 app_process 直调 IConnectivityManager
//     （getActiveLinkProperties + 双通道合并 + VPN 跳过，全反射兼容各版本签名）
//  3. dumpsys connectivity 文本解析（过滤 VPN 块与占位地址）
//  4. getprop 全量扫描（net.dnsN + 各接口 net.<if>.dnsN / dhcp.<if>.dnsN）
//
// 来源粘性：上次成功的来源下一轮最先尝试，避免 30s 周期探测时
// 每次都跑重的 app_process（约几百毫秒 CPU）。
var androidLastSource atomic.Int32 // 上次成功的来源序号（detectAndriodSources 索引）

type androidSource struct {
	name string
	fn   func(log *logger) ([]string, error)
}

func androidSources() []androidSource {
	return []androidSource{
		{"APK Java 推送", func(_ *logger) ([]string, error) { return dnsFromSysdnsTxt() }},
		{"Java 层", dnsViaJavaDex},
		{"dumpsys", func(_ *logger) ([]string, error) { return dnsViaDumpsys() }},
		{"getprop", func(_ *logger) ([]string, error) { return dnsViaGetprops() }},
	}
}

func detectSystemDNS(log *logger) (servers []string, via string) {
	srcs := androidSources()
	order := make([]int, len(srcs)) // 尝试顺序（值为原始索引）
	for i := range order {
		order[i] = i
	}
	// 粘性：上次成功的来源最先尝试
	if last := int(androidLastSource.Load()); last > 0 && last < len(srcs) {
		order = append([]int{last}, append(order[:last:last], order[last+1:]...)...)
	}
	for _, oi := range order {
		src := srcs[oi]
		ips, err := src.fn(log)
		if err == nil && len(ips) > 0 {
			androidLastSource.Store(int32(oi))
			return ips, src.name
		}
		if err != nil {
			log.Infof("系统 DNS 探测[%s]失败: %v", src.name, err)
		} else {
			log.Infof("系统 DNS 探测[%s]结果为空", src.name)
		}
	}
	return nil, ""
}

// dnsFromSysdnsTxt 读 APK Java 侧推送的 DNS 列表。
// 候选路径：cwd（APK 运行时即 filesDir）→ 可执行文件旁 →
// APK 私有目录（装了 APK 又跑 root 二进制时，root 可直接读）。
func dnsFromSysdnsTxt() ([]string, error) {
	var lastErr error
	for _, p := range sysdnsTxtCandidates() {
		raw, err := os.ReadFile(p)
		if err != nil {
			lastErr = err
			continue
		}
		if ips := parseDNSLines(string(raw)); len(ips) > 0 {
			return ips, nil
		}
		lastErr = fmt.Errorf("%s 内容为空或无有效地址", p)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("无可用 sysdns.txt")
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

// dexCandidates 可用的 fastime-dns.dex 查找路径（按优先级）。
// Magisk 模块包内附带 dex（与二进制同目录）；内嵌 dex 也优先释放到
// 可执行文件旁（cwd 可能是 / 等只读目录）。
func dexCandidates() []string {
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		dirs = append(dirs, wd)
	}
	dirs = append(dirs, "/data/adb/modules/fastime", os.TempDir())
	var paths []string
	seen := map[string]bool{}
	for _, d := range dirs {
		p := filepath.Join(d, "fastime-dns.dex")
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	return paths
}

// ensureDexFile 找到或释放 fastime-dns.dex，返回路径。
// 优先用磁盘上已有的（Magisk 模块包内附带 / 用户手动放置），
// 否则从内嵌 base64（CI 注入）释放到第一个可写候选目录。
func ensureDexFile() (string, error) {
	for _, p := range dexCandidates() {
		if st, err := os.Stat(p); err == nil && st.Size() > 0 {
			return p, nil
		}
	}
	if cfgDnsDexB64 == "" {
		return "", dexError("无内嵌 DNS_DEX 且未在二进制旁找到 fastime-dns.dex（可用 CI 构建产物，或把 dex 放到 fastime 同目录）")
	}
	raw, err := base64.StdEncoding.DecodeString(cfgDnsDexB64)
	if err != nil {
		return "", fmt.Errorf("dex base64 解码失败: %w", err)
	}
	var lastErr error
	for _, p := range dexCandidates() {
		if err := os.WriteFile(p, raw, 0644); err == nil {
			return p, nil
		} else {
			lastErr = err
		}
	}
	return "", fmt.Errorf("dex 无处可写: %w", lastErr)
}

// dnsViaJavaDex 用 dex 经 app_process 直调 Java 层（需 root/shell）。
// dex 两个来源：磁盘已有（模块包内附带）或 CI 注入的内嵌 base64。
// 注意 su 环境常常缺少 ANDROID_DATA/ANDROID_ROOT 等变量，app_process 会直接
// 起不来——这里显式补齐；并按 64/32 位依次尝试 app_process 变体。
func dnsViaJavaDex(log *logger) ([]string, error) {
	dexPath, err := ensureDexFile()
	if err != nil {
		return nil, err
	}
	env := append(os.Environ(),
		"ANDROID_DATA=/data", "ANDROID_ROOT=/system", "ANDROID_I18N_ROOT=/apex/com.android.i18n",
		"ANDROID_TZDATA_ROOT=/apex/com.android.tzdata", "BOOTCLASSPATH="+os.Getenv("BOOTCLASSPATH"))
	var lastErr error
	for _, bin := range []string{"app_process", "/system/bin/app_process64", "/system/bin/app_process32", "/system/bin/app_process"} {
		if _, err := exec.LookPath(bin); err != nil {
			continue
		}
		cmd := exec.Command(bin, "-Djava.class.path="+dexPath, "/system/bin", "FastimeDns")
		cmd.Env = env
		out, err := cmd.Output()
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", bin, err)
			continue
		}
		if ips := parseDNSLines(string(out)); len(ips) > 0 {
			return ips, nil
		}
		lastErr = fmt.Errorf("%s 输出为空或无有效地址", bin)
	}
	if lastErr == nil {
		lastErr = dexError("找不到 app_process")
	}
	return nil, lastErr
}

// dnsViaDumpsys 回退：解析 dumpsys connectivity 中活动网络的 DnsAddresses。
func dnsViaDumpsys() ([]string, error) {
	out, err := exec.Command("dumpsys", "connectivity").Output()
	if err != nil {
		return nil, err
	}
	ips := parseDumpsysDNS(string(out))
	if len(ips) == 0 {
		return nil, fmt.Errorf("dumpsys 中未解析到活动网络 DNS")
	}
	return ips, nil
}

// dnsViaGetprops 兜底：getprop 全量扫描。
// 优先全局 net.dns1/2，其次各接口属性（net.<if>.dnsN、dhcp.<if>.dnsN）——
// 移动数据（rmnet_data*）与 Wi-Fi（wlan*）的 DNS 都能拿到。
func dnsViaGetprops() ([]string, error) {
	out, err := exec.Command("getprop").Output()
	if err != nil {
		return nil, err
	}
	ips := parseGetpropDNS(string(out))
	if len(ips) == 0 {
		return nil, fmt.Errorf("getprop 无有效 DNS 属性")
	}
	return ips, nil
}

type dexError string

func (e dexError) Error() string { return string(e) }
