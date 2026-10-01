//go:build android

package fastime

import (
	"context"
	"encoding/base64"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// cfgDnsDexB64 构建期注入（CI 用 android/tools/build_dns_dex.sh 把
// FastimeDns.java 编译成 dex 后 base64 经 -ldflags -X 写入）。
// 该 dex 通过 binder 直接调用 Java 层 IConnectivityManager，打印当前默认网络
// LinkProperties.getDnsServers() —— 与 APK Java 推送同源同精度。
var cfgDnsDexB64 = ""

// dnsViaAppProcess 以 root/shell 身份直接运行（无 APK）时的 Java 层获取途径：
// 把内嵌 dex 落盘后由 app_process 起 Java 进程调系统服务，输出当前网络 DNS。
// 普通 uid 无 connectivity binder 权限时会静默失败，由调用方继续回退 dumpsys。
func dnsViaAppProcess(log *logger) []string {
	if cfgDnsDexB64 == "" {
		return nil // 未注入 dex（本地手工构建），跳过本途径
	}
	dex, err := base64.StdEncoding.DecodeString(cfgDnsDexB64)
	if err != nil || len(dex) == 0 {
		return nil
	}
	// dex 落盘：优先工作目录（APK=私有目录 / Termux=cwd / Magisk=模块目录），
	// 写不进再试 /data/local/tmp（root 可写）。工作目录副本保留复用，临时副本用后删。
	path := "fastime_dns.dex"
	tmpCopy := false
	if err := os.WriteFile(path, dex, 0o600); err != nil {
		path = "/data/local/tmp/fastime_dns.dex"
		if err := os.WriteFile(path, dex, 0o600); err != nil {
			return nil
		}
		tmpCopy = true
	}
	if tmpCopy {
		defer os.Remove(path)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "app_process",
		"-Djava.class.path="+path, "/system/bin", "FastimeDns").Output()
	if err != nil {
		if log != nil {
			log.Debugf("app_process Java 层 DNS 获取失败: %v", err)
		}
		return nil
	}
	// 逐行输出的是裸 IP（不带端口），交由调用方统一加 :53
	var servers []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		s := strings.Trim(strings.TrimSpace(line), "[]/,")
		if net.ParseIP(s) != nil && !seen[s] {
			seen[s] = true
			servers = append(servers, s)
		}
	}
	return servers
}
