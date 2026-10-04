//go:build android

package fastime

import (
	"net"
	"os"
	"os/exec"
	"strings"
)

// systemDNSServers Android 获取当前网络真实下发的 DNS（运营商/企业 DHCP 推送的），
// 四级来源按序尝试，全部只取「当前默认网络」——连 Wi-Fi 就是 Wi-Fi 的 DNS，
// 切移动数据就是流量卡的 DNS，其它网络（VPN/热点/历史网络）的一律不混入：
//
//  1. sysdns.txt —— APK 的 Java 层通过 ConnectivityManager.NetworkCallback
//     监听默认网络，把 LinkProperties.getDnsServers() 实时写入应用私有目录
//     （Go 核心以该目录为工作目录运行）。这是最准确、免 root 的途径。
//  2. app_process + 内嵌 dex（root/shell 直跑二进制时）—— 直接经 binder 调
//     Java 层 IConnectivityManager.getActiveLinkProperties()，与 ① 同源同精度。
//  3. dumpsys connectivity（root/shell）—— 按 "Active default network" 的
//     netId 精确提取该网络的 DnsAddresses 行；若活跃网络是 VPN 虚拟网络
//     （Clash/VPN 类程序接管全局流量），跳过它改取底层 Wi-Fi/蜂窝/有线
//     网络的 DNS；解析失败才宽松回退（可能混入其它网络的 DNS），
//     再不行退 dumpsys netd（同样过滤无效地址）。
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
		// 过滤 0.0.0.0 / :: 等占位地址（dumpsys 里未就绪网络的残留），
		// 以及重复项——保证喂给解析器的每一个地址都是当前网络真实可用的
		if validDNSIP(s) && !seen[s] {
			seen[s] = true
			out = append(out, net.JoinHostPort(s, "53"))
		}
	}

	// 1. APK Java 层推送的真实网络 DNS（ConnectivityManager 默认网络回调，
	//    天然只含当前网络：Wi-Fi 即 Wi-Fi 的，移动数据即流量的）
	if data, err := os.ReadFile("sysdns.txt"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			add(line)
		}
	}
	if len(out) > 0 {
		return out
	}

	// 2. app_process 直调 Java 层（root/shell 无 APK 时与 ① 同精度，
	//    getActiveLinkProperties 同样只返回当前默认网络）
	for _, s := range dnsViaAppProcess(nil) {
		add(s)
	}
	if len(out) > 0 {
		return out
	}

	// 3. dumpsys 解析（root/shell）：先按「Active default network」的 netId
	//    精确提取当前默认网络的 DnsAddresses（只含当前网络），
	//    解析失败才回退宽松匹配（历史行为，可能混入其它网络的 DNS）
	b, err := exec.Command("dumpsys", "connectivity").Output()
	if err == nil {
		for _, ip := range dnsFromConnectivityDump(string(b)) {
			add(ip)
		}
		if len(out) == 0 { // 精确匹配失败：宽松回退
			for _, ip := range dnsFromDumpAny(string(b), "DnsAddresses") {
				add(ip)
			}
		}
	}
	if len(out) == 0 {
		if b, err := exec.Command("dumpsys", "netd").Output(); err == nil {
			for _, ip := range dnsFromDumpAny(string(b), "DNS") {
				add(ip)
			}
		}
	}
	if len(out) > 0 {
		return out
	}

	// 4. 系统属性兜底（root）：全局属性可能滞后于当前网络，放最后
	for _, prop := range []string{"net.dns1", "net.dns2", "net.dns3", "net.dns4"} {
		if b, err := exec.Command("getprop", prop).Output(); err == nil {
			add(string(b))
		}
	}
	return out
}
