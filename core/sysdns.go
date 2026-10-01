// 系统 DNS（运营商 DNS）解析器：turbo 模式下，应答 IP 命中用户 IP 段的域名
// 改用系统配置的 DNS 服务器解析，以获得运营商按真实网络位置调度的最优 IP。
//
// 实现：直接以 UDP/53 wireformat 查询系统 DNS 服务器（可拿到真实 TTL），
// 服务器地址分平台发现（Linux/macOS 读 resolv.conf，Windows 读注册表，
// 见 sysdns_servers_*.go）；发现失败时回退 Go 系统解析器（无 TTL，按 60s 缓存）。
package fastime

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

type sysResolver struct {
	log *logger

	mu       sync.Mutex
	servers  []string // 系统 DNS 服务器（IP:53），懒发现
	tried    bool
	lastErr  string
	queryCnt int64
}

func newSysResolver(log *logger) *sysResolver { return &sysResolver{log: log} }

// dnsServers 懒发现系统 DNS 服务器列表。结果按"当前网络"缓存：
// 网络不变时一直复用；切网后由 Invalidate/Rediscover 触发重新获取。
func (r *sysResolver) dnsServers() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.tried {
		r.discoverLocked()
	}
	return r.servers
}

// discoverLocked 实际执行发现（调用方须持锁）。
func (r *sysResolver) discoverLocked() {
	r.tried = true
	r.servers = systemDNSServers() // 分平台实现：resolv.conf / 注册表 / Android 真实网络下发
	if len(r.servers) > 0 {
		r.log.Infof("系统 DNS 服务器：%v", r.servers)
	} else {
		r.log.Infof("未能发现系统 DNS 服务器，系统 DNS 代管将回退 Go 系统解析器")
	}
}

// Invalidate 使已发现的服务器列表失效，下次解析时重新获取（切网时调用）。
func (r *sysResolver) Invalidate() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tried = false
}

// Rediscover 立即重新获取系统 DNS 服务器（切网时主动调用，日志立即可见新列表）。
func (r *sysResolver) Rediscover() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tried = false
	r.discoverLocked()
}

// stats 供状态页展示。
func (r *sysResolver) stats() (servers []string, queries int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.servers, r.queryCnt
}

// lookup 经系统 DNS 解析 host 的指定类型记录，返回 IP 列表与最小 TTL（秒）。
// CNAME 链最多追 3 层；TTL 钳制在 [5s, 24h]。
func (r *sysResolver) lookup(ctx context.Context, host string, qtype uint16) ([]net.IP, uint32, error) {
	r.mu.Lock()
	r.queryCnt++
	r.mu.Unlock()

	servers := r.dnsServers()
	if len(servers) == 0 { // 无服务器列表（如 Android）：回退 Go 系统解析器
		return r.lookupViaGo(ctx, host, qtype)
	}
	ips, ttl, err := r.queryServers(ctx, servers, host, qtype, 0)
	if err == nil && len(ips) == 0 {
		err = errors.New("系统 DNS 无匹配记录")
	}
	return ips, ttl, err
}

// queryServers 依次尝试各 DNS 服务器（UDP 优先，截断转 TCP）。
func (r *sysResolver) queryServers(ctx context.Context, servers []string, host string, qtype uint16, depth int) ([]net.IP, uint32, error) {
	var lastErr error
	for _, srv := range servers {
		msg, err := r.exchange(ctx, srv, host, qtype)
		if err != nil {
			lastErr = err
			continue
		}
		rcode, answers, err := parseResponse(msg)
		if err != nil {
			lastErr = err
			continue
		}
		if rcode == 3 {
			return nil, 0, errors.New("NXDOMAIN")
		}
		if rcode != 0 {
			lastErr = fmt.Errorf("RCODE=%d", rcode)
			continue
		}
		var ips []net.IP
		var minTTL uint32 = 86400
		want := "A"
		if qtype == dnsTypeAAAA {
			want = "AAAA"
		}
		cname := ""
		for _, a := range answers {
			switch a.Type {
			case want:
				if ip := net.ParseIP(a.Data); ip != nil {
					ips = append(ips, ip)
					if a.TTL < minTTL {
						minTTL = a.TTL
					}
				}
			case "CNAME":
				cname = a.Data
			}
		}
		if len(ips) > 0 {
			if minTTL < 5 {
				minTTL = 5
			}
			return ips, minTTL, nil
		}
		// 只有 CNAME：追一层目标（运营商 DNS 通常同包带齐 A，追到是兜底）
		if cname != "" && depth < 3 {
			sub, subTTL, err := r.queryServers(ctx, servers, cname, qtype, depth+1)
			if err == nil && len(sub) > 0 {
				if subTTL < minTTL {
					minTTL = subTTL
				}
				if minTTL < 5 {
					minTTL = 5
				}
				return sub, minTTL, nil
			}
		}
		lastErr = errors.New("无 A/AAAA 记录")
	}
	if lastErr == nil {
		lastErr = errors.New("无可用系统 DNS 服务器")
	}
	return nil, 0, lastErr
}

// exchange 向单个服务器发一次查询：UDP/53，3s 超时；应答截断（TC）时转 TCP。
func (r *sysResolver) exchange(ctx context.Context, server, host string, qtype uint16) ([]byte, error) {
	q := buildQuery(host, qtype)
	dl := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(dl) {
		dl = d
	}
	uc, err := net.DialTimeout("udp", server, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer uc.Close()
	_ = uc.SetDeadline(dl)
	if _, err = uc.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := uc.Read(buf)
	if err != nil {
		return nil, err
	}
	msg := buf[:n]
	if len(msg) >= 4 && msg[2]&0x02 == 0 { // TC=0：完整应答
		return msg, nil
	}
	// 截断 → TCP 重试（2 字节长度前缀）
	tc, err := net.DialTimeout("tcp", server, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer tc.Close()
	_ = tc.SetDeadline(dl)
	var lp [2]byte
	binary.BigEndian.PutUint16(lp[:], uint16(len(q)))
	if _, err = tc.Write(append(lp[:], q...)); err != nil {
		return nil, err
	}
	if _, err = readFull(tc, lp[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(lp[:]))
	if _, err = readFull(tc, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// lookupViaGo 无服务器列表时的兜底：Go 系统解析器（内部走 OS 配置），
// 拿不到 TTL，按 60s 缓存。
func (r *sysResolver) lookupViaGo(ctx context.Context, host string, qtype uint16) ([]net.IP, uint32, error) {
	network := "ip4"
	if qtype == dnsTypeAAAA {
		network = "ip6"
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, network, host)
	if err != nil {
		return nil, 0, err
	}
	return ips, 60, nil
}
