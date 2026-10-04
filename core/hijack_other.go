//go:build !linux && !windows && !darwin

package fastime

import "errors"

// 其余平台（iOS 等）：53 劫持未实现——iOS 沙箱不允许绑定特权端口也不允许
// 修改系统 DNS，使用方请走 /e2e HTTP 入口或 IKEv2/DoH 方式。
func hijackDefaultAddr() string { return ":53" }

func (s *Server) hijackPlatformSetup(addr string) (func(), error) {
	return nil, errors.New("当前平台不支持 53 端口劫持（支持 linux/android(magisk)/windows/macos）")
}
