//go:build !noquic

package fastime

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// newH3RT 构造 QUIC 传输。省电关键决策：
//   - KeepAlivePeriod = 0：不发保活 ping。周期 ping 会持续唤醒射频，
//     是移动端 QUIC 最大的耗电来源；宁可让连接空闲超时，用时靠 0-RTT 秒建
//   - ClientSessionCache：QUIC 会话票据使 0-RTT 重连成为可能
func newH3RT(dialer *fastDialer, sc tls.ClientSessionCache, log *logger) h3RoundTripper {
	return &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			ClientSessionCache: sc, // 0-RTT 的前提
		},
		QUICConfig: &quic.Config{
			MaxIdleTimeout:  10 * time.Second, // 与 TCP 对齐：空闲 10 秒释放
			KeepAlivePeriod: 0,                // 关保活 ping，省电
		},
		// QUIC 走 UDP，Dial 里复用 DoT 解析 + 最快 IP 结论
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ip, err := dialer.pickIP(ctx, host)
			if err != nil {
				return nil, err
			}
			p := 443
			fmt.Sscanf(port, "%d", &p)
			conn, err := net.ListenUDP("udp", nil)
			if err != nil {
				return nil, err
			}
			return quic.DialEarly(ctx, conn, &net.UDPAddr{IP: ip, Port: p}, tlsCfg, cfg)
		},
	}
}
