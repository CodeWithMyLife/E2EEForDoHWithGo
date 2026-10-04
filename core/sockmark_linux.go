//go:build linux

package fastime

import (
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
)

// hijackSockMark 本进程发往 53 的系统 DNS 代管查询的 SO_MARK 标记：
// iptables REDIRECT 规则放行带该标记的报文——劫持全机 53 流量的同时，
// 自己的代管查询不被重定向回自己（防死循环的关键）。
const hijackSockMark = 0xfa57

// hijackSockMarkOn 劫持（iptables 重定向）生效后才打开：平时拨号不带标记，
// 避免无 CAP_NET_ADMIN 环境下无意义的 setsockopt 调用。
var hijackSockMarkOn atomic.Bool

// sockMarkControl net.Dialer.Control 钩子：劫持生效期间给出站的 UDP/TCP
// socket 打 SO_MARK（仅系统 DNS 代管查询使用，见 sysdns.go exchange）。
func sockMarkControl(network, address string, c syscall.RawConn) error {
	if !hijackSockMarkOn.Load() {
		return nil
	}
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, hijackSockMark)
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
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, hijackSockMark)
	}); err != nil {
		return err
	}
	if serr != nil {
		return fmt.Errorf("SO_MARK 设置失败（需要 root/CAP_NET_ADMIN）: %w", serr)
	}
	return nil
}
