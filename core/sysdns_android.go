//go:build android

package fastime

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// detectSystemDNS Android 平台真实网络 DNS 探测：
//  1. filesDir/sysdns.txt——APK 运行时 Java 侧（ConnectivityManager 回调）实时写入，
//     无 root 也能拿到当前默认网络的真实 DNS（与系统同源同精度）
//  2. root：内嵌 dex 经 app_process 直调 ConnectivityManager（含双通道合并、VPN 跳过）
//  3. dumpsys connectivity 文本解析（过滤 VPN 块与占位地址）
//  4. getprop net.dns1/net.dns2 兜底
func detectSystemDNS(log *logger) (servers []string, via string) {
	if ips, err := dnsFromSysdnsTxt(); err == nil && len(ips) > 0 {
		return ips, "APK Java 推送"
	}
	if ips, err := dnsViaJavaDex(); err == nil && len(ips) > 0 {
		return ips, "Java 层"
	} else if err != nil {
		log.Debugf("Java 层取 DNS 失败: %v（回退 dumpsys）", err)
	}
	if out, err := exec.Command("dumpsys", "connectivity").Output(); err == nil {
		if ips := parseDumpsysDNS(string(out)); len(ips) > 0 {
			return ips, "dumpsys"
		}
	}
	var ips []string
	for _, prop := range []string{"net.dns1", "net.dns2"} {
		if out, err := exec.Command("getprop", prop).Output(); err == nil {
			if v := strings.TrimSpace(string(out)); validDNS(v) {
				ips = append(ips, v)
			}
		}
	}
	if len(ips) > 0 {
		return dedupStrings(ips), "getprop"
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
		return nil, os.ErrNotExist
	}
	return ips, nil
}

// dnsViaJavaDex 用内嵌 dex 经 app_process 调 ConnectivityManager 取 DNS（需 root/shell）。
// dex 由 CI 编译 android/tools/FastimeDns.java 后 base64 注入（cfgDnsDexB64）。
func dnsViaJavaDex() ([]string, error) {
	if cfgDnsDexB64 == "" {
		return nil, errNoDex
	}
	dir, err := os.Getwd()
	if err != nil {
		dir = "."
	}
	dexPath := filepath.Join(dir, "fastime-dns.dex")
	if _, err := os.Stat(dexPath); err != nil {
		raw, err := base64.StdEncoding.DecodeString(cfgDnsDexB64)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(dexPath, raw, 0644); err != nil {
			return nil, err
		}
	}
	out, err := exec.Command("app_process",
		"-Djava.class.path="+dexPath, "/system/bin", "FastimeDns").Output()
	if err != nil {
		return nil, err
	}
	return parseDNSLines(string(out)), nil
}

type dexError string

func (e dexError) Error() string { return string(e) }

const errNoDex = dexError("未注入 DNS_DEX（非 CI Android 构建）")
