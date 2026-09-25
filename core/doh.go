// 阿里 DoH 备用解析（RFC 8484，POST wireformat）。
// 当 DoT(853) 被封锁/故障时使用：443 端口通常更难被一刀切。
// server 为 IP 字面量（如 223.5.5.5），阿里 DNS 证书 SAN 含该 IP，
// 可直接校验证书，全程无需任何域名解析，不产生"解析依赖解析"的死循环。
package fastime

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// dohQuery 通过 https://<server>/dns-query 查询 host 的 A + AAAA 记录。
func dohQuery(ctx context.Context, server, host string) ([]net.IP, error) {
	client := &http.Client{
		Timeout:  (6 * time.Second),
		Transport: &http.Transport{
			TLSClientConfig:    &tls.Config{ServerName: server, MinVersion: tls.VersionTLS12},
			DisableCompression: true,
			ForceAttemptHTTP2:  true,
		},
	}
	url := "https://" + server + "/dns-query"

	var ips []net.IP
	var lastErr error
	for _, qtype := range []uint16{dnsTypeA, dnsTypeAAAA} {
		r, err := dohExchange(ctx, client, url, host, qtype)
		if err != nil {
			lastErr = err
			continue
		}
		ips = append(ips, r...)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("DoH 查询失败: %w", lastErr)
	}
	return ips, nil
}

func dohExchange(ctx context.Context, client *http.Client, url, host string, qtype uint16) ([]net.IP, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buildQuery(host, qtype)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH 状态码 %d", resp.StatusCode)
	}
	return parseAnswers(body, qtype)
}
