// Package bind 是 gomobile 绑定入口，供 Android(APK) / iOS(IPA) 调用。
// gomobile 只导出本包的公开函数，因此 Start/Stop 签名保持简单。
package bind

import (
	"runtime/debug"
	"sync"

	fastime "fastime/core"
)

var (
	mu  sync.Mutex
	srv *fastime.Server
)

// Start 启动本地中继；重复调用幂等。配置已在构建期注入。
func Start() error {
	mu.Lock()
	defer mu.Unlock()
	if srv != nil {
		return nil
	}
	// 移动端内存保护：限制堆峰值，防 Android LMK / iOS jetsam 杀进程
	debug.SetMemoryLimit(48 << 20)
	cfg, err := fastime.LoadConfig()
	if err != nil {
		return err
	}
	s, err := fastime.NewServer(cfg)
	if err != nil {
		return err
	}
	srv = s
	go func() {
		_ = s.Start() // 退出由 Stop 触发
	}()
	return nil
}

// Stop 停止中继并释放连接。
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if srv != nil {
		srv.Shutdown()
		srv = nil
	}
}

// OnNetworkChanged 供系统网络回调调用（Android ConnectivityManager /
// iOS NWPathMonitor）：切网后清空全部缓存与连接记忆。
// 内置的接口指纹 watcher 也会自动触发，二者幂等共存。
func OnNetworkChanged() {
	mu.Lock()
	defer mu.Unlock()
	if srv != nil {
		srv.OnNetworkChanged()
	}
}
