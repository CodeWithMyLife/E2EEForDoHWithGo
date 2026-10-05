package fastime

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"
	"sort"
	"time"
)

// 指定 host 不走系统 DNS 代管（/cache 页每行按钮切换）：
// 即便其应答 IP 命中 IPLIST_URL 段内，也始终返回两个上游的解析结果。
// 设置持久化到 fastime-nodivert.json（工作目录），重启后保留。
const noDivertFile = "fastime-nodivert.json"

// noDivertHas 查询某域名是否被用户设为"不走系统 DNS 代管"。
func (s *Server) noDivertHas(host string) bool {
	s.ndMu.RLock()
	defer s.ndMu.RUnlock()
	return s.noDivert[host]
}

// noDivertSet 设置/取消某域名的代管豁免，并立即生效：
//
//	设为豁免 → 删掉该域名已代管的系统 DNS 缓存（下次查询回上游结果）；
//	取消豁免 → 立即尝试重新代管（若上游缓存应答仍命中 IP 段）。
func (s *Server) noDivertSet(host string, bypass bool) {
	s.ndMu.Lock()
	if bypass {
		s.noDivert[host] = true
	} else {
		delete(s.noDivert, host)
	}
	s.ndMu.Unlock()
	s.saveNoDivert()
	if bypass {
		if s.sysCache != nil {
			s.sysCache.DeleteByHost(host)
		}
		s.log.Infof("%s 已设为不走系统 DNS 代管（始终返回上游结果）", host)
	} else {
		s.log.Infof("%s 已恢复系统 DNS 代管资格", host)
		s.redivertHost(host)
	}
}

func (s *Server) loadNoDivert() {
	data, err := os.ReadFile(noDivertFile)
	if err != nil {
		return
	}
	var hosts []string
	if json.Unmarshal(data, &hosts) != nil {
		return
	}
	s.ndMu.Lock()
	for _, h := range hosts {
		s.noDivert[h] = true
	}
	n := len(s.noDivert)
	s.ndMu.Unlock()
	if n > 0 {
		s.log.Infof("已从 %s 恢复 %d 条\"不走系统 DNS\"豁免", noDivertFile, n)
	}
}

func (s *Server) saveNoDivert() {
	s.ndMu.RLock()
	hosts := make([]string, 0, len(s.noDivert))
	for h := range s.noDivert {
		hosts = append(hosts, h)
	}
	s.ndMu.RUnlock()
	sort.Strings(hosts)
	data, err := json.Marshal(hosts)
	if err != nil {
		return
	}
	tmp := noDivertFile + ".tmp"
	if os.WriteFile(tmp, data, 0o600) != nil {
		return
	}
	_ = os.Rename(tmp, noDivertFile)
}

// noDivertList 供状态页/缓存页展示。
func (s *Server) noDivertList() []string {
	s.ndMu.RLock()
	defer s.ndMu.RUnlock()
	out := make([]string, 0, len(s.noDivert))
	for h := range s.noDivert {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// serveNoDivert 缓存页按钮入口：GET /nodivert?host=xx&off=1|0，处理完跳回 /cache。
func (s *Server) serveNoDivert(w http.ResponseWriter, req *http.Request) {
	host := req.URL.Query().Get("host")
	if host != "" {
		s.noDivertSet(host, req.URL.Query().Get("off") == "1")
	}
	w.Header().Set("Location", "/cache")
	w.WriteHeader(http.StatusSeeOther)
}

// noDivertBtn 渲染缓存行操作按钮（豁免/恢复）。
func (s *Server) noDivertBtn(domain string) string {
	if s.noDivertHas(domain) {
		return fmt.Sprintf(`<a class="opb on" href="/nodivert?host=%s&off=0">↩️ 恢复系统DNS托管</a>`,
			html.EscapeString(domain))
	}
	return fmt.Sprintf(`<a class="opb" href="/nodivert?host=%s&off=1">🚫 不走系统DNS</a>`,
		html.EscapeString(domain))
}

// serveForceRefresh 缓存页按钮入口：GET /refresh?key=<base64url(缓存键)>。
// 无视新鲜度与静默期，立即把该条目向上游强制换新，完成后跳回 /cache。
func (s *Server) serveForceRefresh(w http.ResponseWriter, req *http.Request) {
	if raw, err := base64.RawURLEncoding.DecodeString(req.URL.Query().Get("key")); err == nil {
		key := string(raw)
		if method, canon, ok := splitCacheKey(key); ok {
			s.forceRefresh(method, canon, key)
		}
	}
	w.Header().Set("Location", "/cache")
	w.WriteHeader(http.StatusSeeOther)
}

// forceRefresh 强制刷新单条缓存：turbo 模式经 s.fetch 走主备并发竞速（取最快、
// 败者立即取消），standard 模式走主→备顺序链；上游域名代答条目走本地 DoT→DoH。
// 失败保留旧值。不受熔断与新鲜度影响——用户点击即明确意图。
func (s *Server) forceRefresh(method string, canon []byte, key string) {
	start := time.Now()
	q, qErr := parseQuestion(canon)
	desc := key
	if qErr == nil {
		desc = q.Name + " " + qtypeName(q.Qtype)
	}
	localQ := qErr == nil && (q.Qtype == dnsTypeA || q.Qtype == dnsTypeAAAA) &&
		(q.Name == s.upHost || (s.fbHost != "" && q.Name == s.fbHost))
	var err error
	if localQ {
		_, err = s.resolveLocal(canon, key)
	} else {
		_, _, err = s.fetch(method, canon, key, nil)
	}
	if err != nil {
		s.log.Errorf("强制刷新 %s 失败（保留旧值）: %v", desc, err)
		return
	}
	s.log.Infof("强制刷新 %s 完成，耗时 %s", desc, time.Since(start).Round(time.Millisecond))
}

// refreshBtn 渲染缓存行"强制刷新"按钮（key 含 \x00，base64url 编码后入参）。
func refreshBtn(key string) string {
	return fmt.Sprintf(`<a class="opb rf" href="/refresh?key=%s">🔄 强制刷新</a>`,
		base64.RawURLEncoding.EncodeToString([]byte(key)))
}
