package fastime

import (
	"container/list"
	"net"
	"sort"
	"strings"
	"time"
)

// 网络切换感知：轮询本机活动网络接口 + IP 地址指纹，变化即视为切网
// （Wi-Fi ↔ 蜂窝 ↔ 有线、VPN 开关、换热点都会改变指纹）。
// 切网后调用 OnNetworkChanged：清空全部缓存与连接记忆。
//
// 桌面/CLI 场景靠本 watcher 自动感知；Android/iOS 另有系统回调
// （ConnectivityManager / NWPathMonitor），通过 bind.OnNetworkChanged 直接触发，
// 两者共存，先到先清，幂等无害。
const netWatchInterval = 2 * time.Second

func netFingerprint() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var parts []string
	for _, ifa := range ifaces {
		if ifa.Flags&net.FlagUp == 0 || ifa.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifa.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			parts = append(parts, ifa.Name+"/"+a.String())
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

func (s *Server) watchNetwork(stop <-chan struct{}) {
	last := netFingerprint()
	t := time.NewTicker(netWatchInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			fp := netFingerprint()
			if fp != last {
				last = fp
				s.log.Infof("检测到网络切换，重建连接与缓存策略")
				s.OnNetworkChanged()
			}
		}
	}
}

// OnNetworkChanged 切网后的复位：
//   - DNS 解析缓存、最快 IP 记忆清空（下一跳拓扑变了，重新解析重新竞速）
//   - HTTP/3 能力记忆清空，空闲连接关闭（旧连接绑在旧网络通道上，不可用）
//   - 业务缓存按 NET_SWITCH_MODE 处理：
//     clear   → 全部清空
//     refresh → 保留缓存继续可用，同时逐条强制后台刷新
func (s *Server) OnNetworkChanged() {
	s.client.dialer.reset()
	s.client.reset()
	if s.cfg.NetSwitchClear {
		s.cache.Clear()
		return
	}
	// refresh 模式：逐条强制刷新，间隔 100ms 防止瞬间打满射频
	keys := s.cache.Keys()
	go func() {
		for _, key := range keys {
			method, payload, ok := splitCacheKey(key)
			if !ok {
				continue
			}
			_, _, _ = s.fetch(method, payload, key, nil)
			time.Sleep(100 * time.Millisecond)
		}
	}()
}

func (c *lruCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll.Init()
	c.data = make(map[string]*list.Element)
}

func (f *fastDialer) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ipCache = make(map[string]*ipEntry)
	f.best = make(map[string]*bestIP)
}

func (c *hybridClient) reset() {
	c.mu.Lock()
	c.h3ok = make(map[string]bool)
	c.mu.Unlock()
	c.h12.CloseIdleConnections()
	// h3 RoundTripper 无法单独清空闲连接，直接整体替换
	c.mu.Lock()
	old := c.h3
	c.h3 = newH3RT(c.dialer, c.sessionCache, c.log)
	c.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
}
