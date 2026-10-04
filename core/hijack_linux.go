//go:build linux

// Linux / Android（android 构建标签满足 linux）的 53 劫持平台接管：
// iptables/ip6tables 的 nat 表把 53 端口 UDP/TCP 流量 REDIRECT 到本拦截器
// 监听端口；本进程自己的系统 DNS 代管查询带 SO_MARK（见 sockmark_linux.go），
// OUTPUT 规则对其放行——劫持全机 53 但不劫持自己。
//
// 覆盖范围：
//
//	· OUTPUT     —— 本机进程发出的 53 流量（任意出口网卡 Wi-Fi/蜂窝/有线、
//	  硬编码外部 DNS 的程序都在此被截获；多网卡无需逐个处理）
//	· PREROUTING —— 经本机转发的 53 流量（Android 热点/USB 共享网络下，
//	  下游设备的 DNS 也一并接管）
//	· 看门狗每 5s 复查规则还在不在：VPN 类 App / netd 重建或冲刷 nat 规则
//	  后静默丢失会立刻补回（规则被外部抢先 ACCEPT 的情形无法检测，见 README）
//
// Android 需 Magisk root 环境运行（iptables 可用）；桌面 Linux 需 root。
package fastime

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// hijackDefaultAddr iptables REDIRECT 的目标监听地址（高端口，不占 53）。
func hijackDefaultAddr() string { return ":10053" }

// hijackPlatformSetup 安装 iptables 重定向规则并启动看门狗，返回清理函数。
func (s *Server) hijackPlatformSetup(addr string) (func(), error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("需要 root 权限安装 iptables 规则（当前 uid=%d）", os.Geteuid())
	}
	// 无 CAP_NET_ADMIN 时 SO_MARK 必失败，规则一旦生效自己的代管查询会
	// 被打回自己形成死循环——先验证再装规则
	if err := sockMarkVerify(); err != nil {
		return nil, err
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if _, err := strconv.Atoi(port); err != nil {
		return nil, fmt.Errorf("监听地址端口无效: %s", port)
	}

	mark := fmt.Sprintf("0x%x", hijackSockMark)

	// OUTPUT 规则集：① 目标是本机回环的不碰（127.0.0.53 之类的本地 stub
	// 服务正常用，它向上游的转发仍会经 OUTPUT 被接管）；② 带本进程
	// SO_MARK 的放行（自己的代管查询）；③ 其余 53 流量全部重定向
	outV4 := [][]string{
		{"-p", "udp", "-d", "127.0.0.0/8", "--dport", "53", "-j", "RETURN"},
		{"-p", "tcp", "-d", "127.0.0.0/8", "--dport", "53", "-j", "RETURN"},
		{"-p", "udp", "--dport", "53", "-m", "mark", "!", "--mark", mark, "-j", "REDIRECT", "--to-ports", port},
		{"-p", "tcp", "--dport", "53", "-m", "mark", "!", "--mark", mark, "-j", "REDIRECT", "--to-ports", port},
	}
	outV6 := [][]string{
		{"-p", "udp", "-d", "::1/128", "--dport", "53", "-j", "RETURN"},
		{"-p", "tcp", "-d", "::1/128", "--dport", "53", "-j", "RETURN"},
		{"-p", "udp", "--dport", "53", "-m", "mark", "!", "--mark", mark, "-j", "REDIRECT", "--to-ports", port},
		{"-p", "tcp", "--dport", "53", "-m", "mark", "!", "--mark", mark, "-j", "REDIRECT", "--to-ports", port},
	}
	// PREROUTING 规则集：接管经本机转发的 53 流量（热点/共享网络的下游设备）。
	// 本机发出的包不走 PREROUTING，无需 mark 豁免
	preV4 := [][]string{
		{"-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", port},
		{"-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", port},
	}
	preV6 := [][]string{
		{"-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", port},
		{"-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", port},
	}

	type ruleSet struct {
		bin   string // iptables / ip6tables
		chain string // OUTPUT / PREROUTING
		rules [][]string
	}
	sets := []ruleSet{
		{"iptables", "OUTPUT", outV4},
		{"iptables", "PREROUTING", preV4},
		{"ip6tables", "OUTPUT", outV6},
		{"ip6tables", "PREROUTING", preV6},
	}

	iptRun := func(bin, op, chain string, r []string) error {
		args := append([]string{"-t", "nat", op, chain}, r...)
		out, err := exec.Command(bin, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s -t nat %s %s %s: %v (%s)", bin, op, chain, strings.Join(r, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	var installed []ruleSet // 至少装上一条规则的集合（清理/看门狗用）
	var v6Failed bool
	for _, st := range sets {
		ok := false
		for _, r := range st.rules {
			_ = iptRun(st.bin, "-D", st.chain, r) // 先删后加：重复启动不产生重复规则
			if err := iptRun(st.bin, "-A", st.chain, r); err != nil {
				s.log.Infof("53 劫持：规则安装失败（忽略）: %v", err)
				continue
			}
			ok = true
		}
		if ok {
			installed = append(installed, st)
		} else if st.bin == "ip6tables" {
			v6Failed = true
		}
	}
	if len(installed) == 0 {
		return nil, fmt.Errorf("iptables 规则全部安装失败")
	}
	hijackSockMarkOn.Store(true) // 规则已生效 → 代管查询开始打 SO_MARK
	if v6Failed {
		s.log.Errorf("53 劫持：ip6tables NAT 不可用，IPv6 的 53 流量未被接管（泄漏面！可禁用 IPv6 规避）")
	}
	s.log.Infof("53 劫持：iptables 已把本机+转发 53 端口 UDP/TCP 重定向到 %s（自身代管查询打 mark 放行，看门狗 5s 复查）", port)

	// 看门狗：VPN 类 App / netd / 其他 root 程序可能冲刷或重建 nat 规则导致
	// 劫持静默失效——每 5s 用 -C 复查每条规则，丢失立即补回
	stop := make(chan struct{})
	go func() {
		tk := time.NewTicker(5 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
			}
			for _, st := range installed {
				for _, r := range st.rules {
					if err := iptRun(st.bin, "-C", st.chain, r); err != nil {
						if err2 := iptRun(st.bin, "-A", st.chain, r); err2 == nil {
							s.log.Infof("53 劫持：检测到规则被移除（%s %s），已补回", st.bin, st.chain)
						}
					}
				}
			}
		}
	}()

	return func() {
		close(stop)
		hijackSockMarkOn.Store(false)
		for _, st := range installed {
			for _, r := range st.rules {
				_ = iptRun(st.bin, "-D", st.chain, r)
			}
		}
		s.log.Infof("53 劫持：iptables 重定向规则已撤除")
	}, nil
}
