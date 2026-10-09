package fastime

import (
	"net"
	"sort"
	"strings"
	"time"
)

// 网络切换感知：轮询本机活动网络接口 + IP 地址指纹，变化即视为切网
// （Wi-Fi ↔ 蜂窝 ↔ 有线、VPN 开关、换热点都会改变指纹）。
// 切网后调用 OnNetworkChanged：重建连接记忆，并触发 resolv.conf 代管刷新。
//
// 桌面/CLI 场景靠本 watcher 自动感知；Android/iOS 另有系统回调
// （ConnectivityManager / NWPathMonitor），通过 bind.OnNetworkChanged 直接触发，
// 两者共存，幂等无害。
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
				s.log.Infof("检测到网络切换，重建连接记忆")
				s.OnNetworkChanged()
			}
		}
	}
}

// OnNetworkChanged 切网后的复位：
//   - 上游 DNS 解析缓存、最快 IP 记忆清空（下一跳拓扑变了，重新竞速）
//   - HTTP/3 能力记忆清空，空闲连接关闭（旧连接绑在旧网络通道上）
//   - resolv.conf 代管立即刷新（新网络的真实 DNS 变了）
//
// 业务缓存保留：污染判定与缓存内容不随网络位置失效，
// 后台 15 分钟换新会自然收敛到新网络的上游结果。
func (s *Server) OnNetworkChanged() {
	s.client.dialer.reset()
	s.client.reset()
	s.resetBreaker() // 新网络上游可能恢复，熔断立即解除
	s.sysdnsKick()   // 切网后重新探测系统真实 DNS（system-dns.com 应答随之更新）
	if s.cfg.PolluteMode == "off" {
		// off 模式：缓存换新周期短（5min）且切网立刻全量换新——
		// 无污染判定时结果应尽量贴近当前网络
		go s.refreshCache(true)
	}
	// fake 模式：缓存不受切网影响（15min 换新节奏不变）
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
	old := c.h3
	c.h3 = newH3RT(c.dialer, c.sessionCache, c.log)
	c.mu.Unlock()
	c.h12.CloseIdleConnections()
	if old != nil {
		_ = old.Close()
	}
}
