//go:build !linux

package fastime

import "syscall"

// 非 linux 平台（windows/darwin/ios）：53 劫持靠直接绑定 :53 + 接管系统解析，
// 自己的代管查询直接拨真实服务器地址，天然不经过本机监听器，无需 SO_MARK。
// 注意：android 的构建标签满足 linux，走 sockmark_linux.go。

func sockMarkControl(_, _ string, _ syscall.RawConn) error { return nil }

func sockMarkVerify() error { return nil }

func sysNetIDValue() int { return 0 }
