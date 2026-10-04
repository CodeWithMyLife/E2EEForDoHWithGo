package fastime

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"
	"sort"
	"time"
)

// 指定 host 强制走系统 DNS（/cache 页每行按钮切换，与「🚫 不走系统DNS」互斥）：
// 无论其应答 IP 是否命中 IPLIST_URL 段内，该域名都直接交给系统 DNS 解析并代管
// 缓存，跳过上游竞速；失败后继续走系统 DNS（不回退上游、不受熔断影响）。
// 设置持久化到 fastime-forcedns.json（工作目录），重启后自动恢复并立即补建代管。
const forceDNSFile = "fastime-forcedns.json"

// forceDNSHas 查询某域名是否被用户设为"强制走系统 DNS"。
func (s *Server) forceDNSHas(host string) bool {
	s.fdMu.RLock()
	defer s.fdMu.RUnlock()
	return s.forceDNS[host]
}

// forceDNSSet 设置/取消某域名的"强制走系统 DNS"，并立即生效：
//
//	设为强制 → 清除该域名的"不走系统DNS"豁免（两者互斥），并把上游缓存中
//	          该域名的条目立即转为系统 DNS 代管（无需命中 IP 段）；
//	取消强制 → 删除该域名的系统 DNS 代管缓存与命中标记（下次查询回上游竞速，
//	          若应答仍命中 IP 段则按普通规则重新代管）。
func (s *Server) forceDNSSet(host string, on bool) {
	s.fdMu.Lock()
	if on {
		s.forceDNS[host] = true
	} else {
		delete(s.forceDNS, host)
	}
	s.fdMu.Unlock()
	s.saveForceDNS()
	if on {
		// 与豁免互斥：强制走系统 DNS 的域名不可能同时豁免系统 DNS
		if s.noDivertHas(host) {
			s.noDivertSet(host, false)
		}
		s.forceDivertHost(host)
		s.log.Infof("%s 已设为强制走系统 DNS（跳过上游竞速，失败不回退）", host)
	} else {
		if s.sysCache != nil {
			s.sysCache.DeleteByHost(host)
		}
		s.unmarkHost(host)
		s.log.Infof("%s 已取消强制走系统 DNS（恢复普通分流规则）", host)
	}
}

// forceDivertHost 把上游缓存中属于 host 的 A/AAAA 条目立即转为系统 DNS 代管
// （不检查 IP 段命中——用户已明确强制）。启动恢复清单时对每个域名执行一次。
func (s *Server) forceDivertHost(host string) {
	if s.sysCache == nil {
		return
	}
	for _, it := range s.cache.Snapshot() {
		_, canon, ok := splitCacheKey(it.key)
		if !ok {
			continue
		}
		q, qerr := parseQuestion(canon)
		if qerr != nil || q.Name != host || (q.Qtype != dnsTypeA && q.Qtype != dnsTypeAAAA) {
			continue
		}
		if _, ok := s.sysCache.Get(it.key); ok {
			continue
		}
		if _, err := s.sysResolveAndCache(canon, it.key, q); err == nil {
			s.marked.Store(it.key, &iplistMark{ip: "强制", at: time.Now(), diverted: true})
			s.log.Infof("强制代管：%s %s 已转系统 DNS", q.Name, qtypeName(q.Qtype))
		} else {
			s.marked.Store(it.key, &iplistMark{ip: "强制", at: time.Now(), diverted: false, err: err.Error()})
			s.sysErr.Add(1)
		}
	}
}

// unmarkHost 删除某域名的全部 IP 段命中标记（取消强制/豁免状态变化时用）。
func (s *Server) unmarkHost(host string) {
	s.marked.Range(func(k, _ any) bool {
		key := k.(string)
		_, canon, ok := splitCacheKey(key)
		if !ok {
			return true
		}
		if q, err := parseQuestion(canon); err == nil && q.Name == host {
			s.marked.Delete(key)
		}
		return true
	})
}

func (s *Server) loadForceDNS() {
	data, err := os.ReadFile(forceDNSFile)
	if err != nil {
		return
	}
	var hosts []string
	if json.Unmarshal(data, &hosts) != nil {
		return
	}
	s.fdMu.Lock()
	for _, h := range hosts {
		s.forceDNS[h] = true
	}
	n := len(s.forceDNS)
	s.fdMu.Unlock()
	if n > 0 {
		s.log.Infof("已从 %s 恢复 %d 条\"强制走系统 DNS\"清单", forceDNSFile, n)
	}
}

func (s *Server) saveForceDNS() {
	s.fdMu.RLock()
	hosts := make([]string, 0, len(s.forceDNS))
	for h := range s.forceDNS {
		hosts = append(hosts, h)
	}
	s.fdMu.RUnlock()
	sort.Strings(hosts)
	data, err := json.Marshal(hosts)
	if err != nil {
		return
	}
	tmp := forceDNSFile + ".tmp"
	if os.WriteFile(tmp, data, 0o600) != nil {
		return
	}
	_ = os.Rename(tmp, forceDNSFile)
}

// forceDNSList 供状态页展示与启动补建代管。
func (s *Server) forceDNSList() []string {
	s.fdMu.RLock()
	defer s.fdMu.RUnlock()
	out := make([]string, 0, len(s.forceDNS))
	for h := range s.forceDNS {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// serveForceDNS 缓存页按钮入口：GET /forcedns?host=xx&on=1|0，处理完跳回 /cache。
func (s *Server) serveForceDNS(w http.ResponseWriter, req *http.Request) {
	host := req.URL.Query().Get("host")
	if host != "" {
		s.forceDNSSet(host, req.URL.Query().Get("on") == "1")
	}
	w.Header().Set("Location", "/cache")
	w.WriteHeader(http.StatusSeeOther)
}

// forceDNSBtn 渲染缓存行"强制走系统DNS"按钮（与豁免按钮互斥共存）。
func (s *Server) forceDNSBtn(domain string) string {
	if s.forceDNSHas(domain) {
		return fmt.Sprintf(`<a class="opb on" href="/forcedns?host=%s&on=0">↩️ 取消强制系统DNS</a>`,
			html.EscapeString(domain))
	}
	return fmt.Sprintf(`<a class="opb fd" href="/forcedns?host=%s&on=1">🧭 强制走系统DNS</a>`,
		html.EscapeString(domain))
}
