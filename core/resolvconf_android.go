//go:build android

package fastime

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ================= Android root：/system/etc/resolv.conf 代管 =================
//
// 背景：Android 没有 /etc/resolv.conf，但绝大多数命令行工具（dig/curl/wget/
// 终端模拟器里的几乎所有程序）走的 Bionic DNS 以外的解析路径（以及 Termux/
// 各种静态二进制）都读 /system/etc/resolv.conf。/system 分区只读，
// 有 root 也不能直接改——用 bind mount 把运行目录下的文件挂上去即可，
// 原地改写（同一 inode）内容会自动传播到挂载点，无需重新挂载。
//
// DNS 来源（按优先级，全部成功则取第一个）：
//  1. Java 层：内嵌 FastimeDns.dex 经 app_process 调用 ConnectivityManager，
//     只取「当前在用网络」的 DNS（Wi-Fi 归 Wi-Fi、蜂窝归蜂窝，双通道则合并）
//  2. dumpsys connectivity 文本解析（Java 层不可用时的回退）
//  3. getprop net.dns1/net.dns2（最后兜底）
//
// 刷新时机：网络切换（OnNetworkChanged → resolvKick）+ 每 5 分钟强制刷新。

const (
	resolvLocalFile  = "fastime-resolv.conf" // 运行目录下的源文件（原地改写）
	resolvSystemPath = "/system/etc/resolv.conf"
	resolvRefresh    = 5 * time.Minute
)

type resolvKeeper struct {
	log     *logger
	dir     string // 运行目录
	src     string // dir/fastime-resolv.conf
	target  string // /system/etc/resolv.conf 的 realpath
	stop    chan struct{}
	kick    chan struct{}
	mu      sync.Mutex
	status  string   // 状态页展示
	lastDNS []string // 最近一次识别到的系统 DNS（状态页展示）
	via     string   // 识别来源（Java 层 / dumpsys / getprop）
	mounted bool
}

func (s *Server) startResolvKeeper() {
	if os.Geteuid() != 0 {
		return // 非 root：无权限挂载，静默关闭（桌面/Android 非 root 场景）
	}
	dir, err := os.Getwd()
	if err != nil {
		dir = "."
	}
	k := &resolvKeeper{
		log:    s.log,
		dir:    dir,
		src:    filepath.Join(dir, resolvLocalFile),
		stop:   make(chan struct{}),
		kick:   make(chan struct{}, 1),
		status: "初始化中",
	}
	if t, err := filepath.EvalSymlinks(resolvSystemPath); err == nil {
		k.target = t
	} else {
		k.target = resolvSystemPath
	}
	s.resolv = k
	go k.loop()
}

func (s *Server) stopResolvKeeper() {
	if s.resolv == nil {
		return
	}
	close(s.resolv.stop)
	s.resolv.unmount()
}

// resolvKick 网络切换时触发立即刷新（非阻塞）。
func (s *Server) resolvKick() {
	if s.resolv == nil {
		return
	}
	select {
	case s.resolv.kick <- struct{}{}:
	default:
	}
}

func (s *Server) resolvStatus() string {
	if s.resolv == nil {
		return ""
	}
	s.resolv.mu.Lock()
	defer s.resolv.mu.Unlock()
	return s.resolv.status
}

// resolvDNSList 最近一次识别到的系统 DNS（状态页展示用）。
func (s *Server) resolvDNSList() (servers []string, via string) {
	if s.resolv == nil {
		return nil, ""
	}
	s.resolv.mu.Lock()
	defer s.resolv.mu.Unlock()
	return append([]string(nil), s.resolv.lastDNS...), s.resolv.via
}

func (k *resolvKeeper) setStatus(format string, args ...interface{}) {
	k.mu.Lock()
	k.status = fmt.Sprintf(format, args...)
	k.mu.Unlock()
}

func (k *resolvKeeper) loop() {
	k.refresh()
	tk := time.NewTicker(resolvRefresh)
	defer tk.Stop()
	for {
		select {
		case <-k.stop:
			return
		case <-tk.C:
			k.refresh()
		case <-k.kick:
			// 切网后系统 DNS 下发有短暂延迟，稍等再取
			time.Sleep(1200 * time.Millisecond)
			k.refresh()
		}
	}
}

// refresh 取当前在用网络的 DNS → 原地写入源文件 → 确保 bind mount 生效。
func (k *resolvKeeper) refresh() {
	servers, via := k.currentDNS()
	if len(servers) == 0 {
		k.setStatus("未取到系统 DNS（保留现有配置）")
		return
	}
	k.mu.Lock()
	k.lastDNS, k.via = servers, via
	k.mu.Unlock()
	content := "# fastime resolv keeper（随网络切换自动更新）\n"
	for _, ip := range servers {
		content += "nameserver " + ip + "\n"
	}

	// 内容没变就不写盘（省电、减少闪存磨损）
	if old, err := os.ReadFile(k.src); err == nil && string(old) == content {
		k.ensureMount()
		return
	}
	// 原地改写：open+truncate，保持 inode 不变，bind mount 那头立即看到新内容
	f, err := os.OpenFile(k.src, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		k.setStatus("写入 %s 失败: %v", k.src, err)
		return
	}
	if _, err = f.WriteString(content); err == nil {
		err = f.Sync()
	}
	f.Close()
	if err != nil {
		k.setStatus("写入失败: %v", err)
		return
	}
	k.ensureMount()
	k.mu.Lock()
	mounted := k.mounted
	k.mu.Unlock()
	if mounted {
		k.setStatus("已代管（%s · %d 个 DNS · %s）", via, len(servers), time.Now().Format("15:04:05"))
	} else {
		k.setStatus("已写入源文件，但挂载未生效（%s）", via)
	}
	k.log.Infof("resolv.conf 已更新（%s）: %s", via, strings.Join(servers, ", "))
}

// ensureMount 确保 bind mount 生效；已挂载则跳过。
func (k *resolvKeeper) ensureMount() {
	if k.isMounted() {
		k.mu.Lock()
		k.mounted = true
		k.mu.Unlock()
		return
	}
	// 挂载目标不存在（极少数 ROM 没有该文件）：无法 bind mount 到不存在的路径，
	// 尝试创建会触碰只读 /system，失败则提示用户用 Magisk 模块方式
	if _, err := os.Stat(k.target); err != nil {
		k.setStatus("目标 %s 不存在，无法挂载；请用 Magisk 模块放置 resolv.conf", k.target)
		k.log.Errorf("resolv 代管：%s 不存在，放弃挂载", k.target)
		return
	}
	out, err := exec.Command("mount", "--bind", k.src, k.target).CombinedOutput()
	if err != nil {
		k.setStatus("mount --bind 失败: %v %s", err, strings.TrimSpace(string(out)))
		k.log.Errorf("resolv bind mount 失败: %v %s", err, out)
		return
	}
	k.mu.Lock()
	k.mounted = true
	k.mu.Unlock()
	k.log.Infof("已挂载 %s → %s", k.src, k.target)
}

func (k *resolvKeeper) isMounted() bool {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[1] == k.target {
			return true
		}
	}
	return false
}

func (k *resolvKeeper) unmount() {
	k.mu.Lock()
	mounted := k.mounted
	k.mu.Unlock()
	if !mounted {
		return
	}
	if out, err := exec.Command("umount", k.target).CombinedOutput(); err != nil {
		k.log.Errorf("umount %s 失败: %v %s", k.target, err, out)
	} else {
		k.log.Infof("已卸载 %s 的 resolv.conf 挂载", k.target)
	}
	k.mu.Lock()
	k.mounted = false
	k.mu.Unlock()
}

// currentDNS 返回「当前在用网络」的 DNS 列表与来源说明。
// 只包含正在使用的网络：Wi-Fi 连上就只要 Wi-Fi 的，蜂窝在用就只要蜂窝的；
// 双通道（Wi-Fi+蜂窝同时承载流量）时两者都要。不含 VPN 自己的 DNS。
func (k *resolvKeeper) currentDNS() (servers []string, via string) {
	if ips, err := k.dnsViaJava(); err == nil && len(ips) > 0 {
		return ips, "Java 层"
	}
	if ips, err := k.dnsViaDumpsys(); err == nil && len(ips) > 0 {
		return ips, "dumpsys"
	}
	if ips, err := k.dnsViaGetprop(); err == nil && len(ips) > 0 {
		return ips, "getprop"
	}
	return nil, ""
}

// dnsViaJava 用内嵌 dex 经 app_process 调 ConnectivityManager 取 DNS。
// dex 由 CI 编译 android/tools/FastimeDns.java 后 base64 注入（cfgDnsDexB64）。
func (k *resolvKeeper) dnsViaJava() ([]string, error) {
	if cfgDnsDexB64 == "" {
		return nil, fmt.Errorf("未注入 DNS_DEX")
	}
	dexPath := filepath.Join(k.dir, "fastime-dns.dex")
	if _, err := os.Stat(dexPath); err != nil {
		raw, err := base64.StdEncoding.DecodeString(cfgDnsDexB64)
		if err != nil {
			return nil, fmt.Errorf("dex base64 解码失败: %w", err)
		}
		if err := os.WriteFile(dexPath, raw, 0644); err != nil {
			return nil, err
		}
	}
	out, err := exec.Command("app_process",
		"-Djava.class.path="+dexPath, "/system/bin", "FastimeDns").Output()
	if err != nil {
		return nil, fmt.Errorf("app_process 执行失败: %w", err)
	}
	return parseDNSLines(string(out)), nil
}

// dnsViaDumpsys 回退：解析 dumpsys connectivity 中活动网络的 DnsAddresses。
func (k *resolvKeeper) dnsViaDumpsys() ([]string, error) {
	out, err := exec.Command("dumpsys", "connectivity").Output()
	if err != nil {
		return nil, err
	}
	return parseDumpsysDNS(string(out)), nil
}

// dnsViaGetprop 最后兜底：net.dns1/net.dns2 全局属性。
func (k *resolvKeeper) dnsViaGetprop() ([]string, error) {
	var ips []string
	for _, prop := range []string{"net.dns1", "net.dns2"} {
		out, err := exec.Command("getprop", prop).Output()
		if err == nil {
			if v := strings.TrimSpace(string(out)); net.ParseIP(v) != nil {
				ips = append(ips, v)
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("getprop 无有效 DNS")
	}
	return ips, nil
}

// parseDNSLines 解析每行一个 IP 的输出，去重、过滤非法值。
func parseDNSLines(out string) []string {
	seen := map[string]bool{}
	var ips []string
	for _, line := range strings.Split(out, "\n") {
		v := strings.TrimSpace(line)
		if v == "" || seen[v] {
			continue
		}
		if ip := net.ParseIP(v); ip != nil {
			seen[v] = true
			ips = append(ips, v)
		}
	}
	return ips
}

// parseDumpsysDNS 从 dumpsys connectivity 文本提取活动网络的 DNS。
// 只取「Active default network」所在块及其同 transport 的 LinkProperties，
// 避免把没连上的网络（如关掉的蜂窝）DNS 混进来。
func parseDumpsysDNS(text string) []string {
	// 找活动网络 ID，形如: "Active default network: 101"
	activeID := ""
	for _, line := range strings.Split(text, "\n") {
		if i := strings.Index(line, "Active default network:"); i >= 0 {
			activeID = strings.TrimSpace(line[i+len("Active default network:"):])
			break
		}
	}
	seen := map[string]bool{}
	var ips []string
	var curBlock strings.Builder
	flush := func() {
		blk := curBlock.String()
		curBlock.Reset()
		// 只要活动网络的块（块头含 "NetworkAgentInfo{ ... 101 ..." 形式不易精确匹配，
		// 宽松处理：活动 ID 未知时全收，已知时只收包含该 ID 引用的块）
		if activeID != "" && !strings.Contains(blk, " "+activeID+" ") && !strings.Contains(blk, "("+activeID+")") {
			return
		}
		for _, line := range strings.Split(blk, "\n") {
			if i := strings.Index(line, "DnsAddresses:"); i >= 0 {
				seg := line[i+len("DnsAddresses:"):]
				seg = strings.Trim(seg, " []")
				for _, tok := range strings.Fields(seg) {
					tok = strings.Trim(tok, "[], ")
					tok = strings.TrimSuffix(tok, ",")
					// 可能带 / 前缀，形如 /223.5.5.5
					tok = strings.TrimPrefix(tok, "/")
					if ip := net.ParseIP(tok); ip != nil && !seen[tok] {
						seen[tok] = true
						ips = append(ips, tok)
					}
				}
			}
		}
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "NetworkAgentInfo{") && curBlock.Len() > 0 {
			flush()
		}
		curBlock.WriteString(line)
		curBlock.WriteByte('\n')
	}
	flush()
	return ips
}
