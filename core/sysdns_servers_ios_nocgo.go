//go:build ios && !cgo

package fastime

// systemDNSServers iOS 无 cgo 的兜底（gomobile 构建始终开 cgo，正常不会走到）：
// 返回空，由 sysResolver 回退 Go 系统解析器。
func systemDNSServers() []string { return nil }
