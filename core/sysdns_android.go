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

// dnsFromSysdnsTxt 读 APK Java 侧推送的 DNS 列表（cwd 即 filesDir）。
func dnsFromSysdnsTxt() ([]string, error) {
	raw, err := os.ReadFile("sysdns.txt")
	if err != nil {
		return nil, err
	}
	ips := parseDNSLines(string(raw))
	if len(ips) == 0 {
		return nil, fmt.Errorf("sysdns.txt 内容为空")
	}
	return ips, nil
}

// dnsViaJavaDex 用内嵌 dex 经 app_process 直调 Java 层（需 root/shell）。
// dex 由 CI 编译 android/tools/FastimeDns.java 后 base64 注入（cfgDnsDexB64）。
// 注意 su 环境常常缺少 ANDROID_DATA/ANDROID_ROOT 等变量，app_process 会直接
// 起不来——这里显式补齐；并按 64/32 位依次尝试 app_process 变体。
func dnsViaJavaDex(log *logger) ([]string, error) {
	if cfgDnsDexB64 == "" {
		return nil, dexError("未注入 DNS_DEX（非 CI Android 构建）")
	}
	dir, err := os.Getwd()
	if err != nil {
		dir = "."
	}
	dexPath := filepath.Join(dir, "fastime-dns.dex")
	if _, err := os.Stat(dexPath); err != nil {
		raw, err := base64.StdEncoding.DecodeString(cfgDnsDexB64)
		if err != nil {
			return nil, fmt.Errorf("dex base64 解码失败: %w", err)
		}
		if err := os.WriteFile(dexPath, raw, 0644); err != nil {
			return nil, err
		}
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
