//go:build noquic

package fastime

import "crypto/tls"

// newH3RT noquic 版：不含 HTTP/3，砍掉 quic-go 依赖以精简体积。
func newH3RT(_ *fastDialer, _ tls.ClientSessionCache, _ *logger) h3RoundTripper {
	return nil
}
