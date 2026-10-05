//go:build windows || darwin

// Windows / macOS 的 53 劫持平台接管：没有 iptables 可用，采用
// 「直接绑定 :53 + 把系统 DNS 指向 127.0.0.1」的接管方式（dnscrypt-proxy 同款）：
// 系统解析器发出的全部 UDP/TCP 53 查询都打到本拦截器；本进程自己的系统 DNS
// 代管查询直接拨真实服务器 IP（接管前已发现缓存，hijackGuard 过滤回环地址），
// 天然不经过本机监听器——不劫持自己。退出时恢复原 DNS 设置。
// 局限：硬编码外部 DNS（如 8.8.8.8）且不经过系统解析器的程序无法被接管。
// 接管/恢复的具体实现分平台，见 hijack_takeover_windows.go / hijack_takeover_darwin.go。
package fastime

// hijackDefaultAddr 桌面平台直接绑定 53 端口。
func hijackDefaultAddr() string { return ":53" }

// hijackPlatformSetup 接管系统解析，返回清理函数（恢复原设置）。
func (s *Server) hijackPlatformSetup(addr string) (func(), error) {
	return s.takeoverSystemDNS()
}
