//go:build android

package fastime

import (
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// systemDNSServers Android 获取当前网络真实下发的 DNS（运营商/企业 DHCP 推送的），
// 四级来源按序尝试：
//
//  1. sysdns.txt —— APK 的 Java 层通过 ConnectivityManager.NetworkCallback
//     监听默认网络，把 LinkProperties.getDnsServers() 实时写入应用私有目录
//     （Go 核心以该目录为工作目录运行）。这是最准确、免 root 的途径。
//  2. app_process + 内嵌 dex（root/shell 直跑二进制时）—— 直接经 binder 调
//     Java 层 IConnectivityManager.getActiveLinkProperties()，与 ① 同源同精度。
//  3. dumpsys connectivity / netd —— 需要 root/shell 权限；从系统服务 dump 中
//     解析当前默认网络的 DnsAddresses（逐网络精确）。
//  4. getprop net.dns1/2/3/4 —— Magisk(root) 下可读的全局兜底属性；
//     Android 8+ 对普通进程禁用，且可能滞后于当前网络，故排在最后。
//
// 全部失败返回空，由 sysResolver 回退 Go 系统解析器。
// 列表随"当前网络"缓存；切网后 netwatch 触发 Rediscover 重新执行本函数。
func systemDNSServers() []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.Trim(strings.TrimSpace(s), "[]/,")
		if net.ParseIP(s) != nil && !seen[s] {
			seen[s] = true
			out = append(out, net.JoinHostPort(s, "53"))
		}
	}

	// 1. APK Java 层推送的真实网络 DNS
	if data, err := os.ReadFile("sysdns.txt"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			add(line)
		}
	}
	if len(out) > 0 {
		return out
	}

	// 2. app_process 直调 Java 层（root/shell 无 APK 时与 ① 同精度）
	for _, s := range dnsViaAppProcess(nil) {
		add(s)
	}
	if len(out) > 0 {
		return out
	}

	// 3. dumpsys 解析（root/shell，逐网络精确）：
	//    connectivity 行形如 "DnsAddresses: [ /192.168.1.1,/10.0.0.2 ]"
	//    只取含 DnsAddresses（connectivity）或 DNS（netd）的行，避免误抓
	//    同输出里的路由/接口地址。有 root 时这条路径最精准。
	ipRe := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|([0-9a-fA-F:]{3,})`)
	for _, cmd := range [][]string{{"dumpsys", "connectivity"}, {"dumpsys", "netd"}} {
		b, err := exec.Command(cmd[0], cmd[1]).Output()
		if err != nil {
			continue
		}
		marker := "DnsAddresses"
		if cmd[1] == "netd" {
			marker = "DNS"
		}
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.Contains(line, marker) {
				continue
			}
			for _, m := range ipRe.FindAllString(line, -1) {
				add(m)
			}
		}
		if len(out) > 0 {
			return out
		}
	}

	// 4. 系统属性兜底（root）：全局属性可能滞后于当前网络，放最后
	for _, prop := range []string{"net.dns1", "net.dns2", "net.dns3", "net.dns4"} {
		if b, err := exec.Command("getprop", prop).Output(); err == nil {
			add(string(b))
		}
	}
	return out
}
