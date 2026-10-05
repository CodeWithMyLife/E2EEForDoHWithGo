//go:build linux

package fastime

import (
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"syscall"
)

// 本进程发往 53 的系统 DNS 代管查询的 SO_MARK 设计（Android fwmark 兼容）：
//
//	标记值 = 0xfa560000 | netId
//
// Android 的 socket fwmark 是策略路由键，不是自由值：低 16 位 = netId，
// bit16 = explicitlySelected、bit17 = protectedFromVpn（VpnService.protect()
// 同款机制）。VPN 全隧道接管时默认路由指向 tun0，运营商 DNS（如
// 211.138.x.x）拒绝回答来自 VPN 出口 IP 的查询——代管查询被灌进隧道即
// 全部超时。打上 protectedFromVpn + 物理网络 netId 后，Android ip rule
// 把查询直接路由到蜂窝/Wi-Fi 物理网络，绕过 VPN 隧道。
// netId 未知（0）时 bit16=0 使报文回落到默认网络规则，行为与旧版一致。
//
// iptables 豁免按掩码匹配高位（低 18 位让给 netId 与路由标志位）：
// 0xfa560000 & 0xfffc0000 = 0xfa540000。
const (
	hijackSockMarkBase = 0xfa560000              // SO_MARK 基值（bit17=protectedFromVpn）
	hijackSockMarkRule = "0xfa540000/0xfffc0000" // iptables -m mark 匹配串（掩码高位）
)

// hijackSockMarkOn 劫持（iptables 重定向）生效后才打开：平时拨号不带标记，
// 避免无 CAP_NET_ADMIN 环境下无意义的 setsockopt 调用。
var hijackSockMarkOn atomic.Bool

// sysNetID 系统 DNS 代管查询要直达的物理网络 netId（Android dumpsys 发现，
// 见 sysdns_parse.go physicalNetIDFromDump）；0 = 未知（按默认网络路由）。
// 桌面 Linux 无 fwmark 策略路由，该值不影响行为。
var sysNetID atomic.Int32

// setSysNetID 更新代管查询的物理网络 netId（空串/非法值 = 清除）。
func setSysNetID(id string) {
	n, err := strconv.Atoi(id)
	if err != nil || n <= 0 || n > 0xffff {
		sysNetID.Store(0)
		return
	}
	sysNetID.Store(int32(n))
}

// sysNetIDValue 状态页展示用：当前代管查询直达的物理网络 netId（0=未知）。
func sysNetIDValue() int { return int(sysNetID.Load()) }

// sockMarkValue 当前应打的 SO_MARK 完整值（基值 | netId）。
func sockMarkValue() int {
	return hijackSockMarkBase | int(sysNetID.Load())
}

// sockMarkControl net.Dialer.Control 钩子：劫持生效期间给出站的 UDP/TCP
// socket 打 SO_MARK（仅系统 DNS 代管查询使用，见 sysdns.go exchange）。
func sockMarkControl(network, address string, c syscall.RawConn) error {
	if !hijackSockMarkOn.Load() {
		return nil
	}
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, sockMarkValue())
	}); err != nil {
		return err
	}
	return serr
}

// sockMarkVerify 装 iptables 规则前验证本进程有 CAP_NET_ADMIN：
// 无权限时 SO_MARK 必然 EPERM，一旦重定向生效，代管查询会被打回自己形成死循环，
// 所以宁可拒绝启动劫持。
func sockMarkVerify() error {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer pc.Close()
	sc, ok := pc.(*net.UDPConn)
	if !ok {
		return fmt.Errorf("unexpected packet conn type")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, sockMarkValue())
	}); err != nil {
		return err
	}
	if serr != nil {
		return fmt.Errorf("SO_MARK 设置失败（需要 root/CAP_NET_ADMIN）: %w", serr)
	}
	return nil
}
