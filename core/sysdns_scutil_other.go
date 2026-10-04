//go:build !darwin

package fastime

// darwinPhysicalDNS 非 macOS 平台的占位实现（macOS 见 sysdns_scutil_darwin.go）。
func darwinPhysicalDNS() []string { return nil }
