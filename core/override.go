package fastime

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// 污染覆盖名单（/cache 页每行按钮切换，互斥）：
//
//	取消污染 noFake    —— 即便应答 IP 命中 IP 段，也返回真实结果
//	强制污染 forceFake —— 即便应答 IP 没命中 IP 段，也返回虚假 IP
//	                     （强制污染的域名完全不打上游：查询直接回虚假 IP）
//
// 两份名单分别持久化到运行目录的 fastime-nofake.json / fastime-forcefake.json，
// 重启后自动恢复；判定在应答时进行（缓存里存的是上游原始应答），
// 因此点击后下一次查询立即生效，无需等缓存过期。
const (
	noFakeFile    = "fastime-nofake.json"
	forceFakeFile = "fastime-forcefake.json"
)

// overrideStore 一组域名名单 + 持久化文件 + 变更时刻（置顶排序用）。
type overrideStore struct {
	mu    sync.RWMutex
	hosts map[string]time.Time // host -> 设置时刻
	file  string
	log   *logger
}

func newOverrideStore(file string, log *logger) *overrideStore {
	return &overrideStore{hosts: make(map[string]time.Time), file: file, log: log}
}

func (o *overrideStore) has(host string) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	_, ok := o.hosts[host]
	return ok
}

// set 加入/移出名单，立即落盘。返回是否发生了变更。
func (o *overrideStore) set(host string, on bool) bool {
	o.mu.Lock()
	_, had := o.hosts[host]
	if on == had {
		o.mu.Unlock()
		return false
	}
	if on {
		o.hosts[host] = time.Now()
	} else {
		delete(o.hosts, host)
	}
	o.mu.Unlock()
	o.save()
	return true
}

func (o *overrideStore) load() {
	data, err := os.ReadFile(o.file)
	if err != nil {
		return
	}
	var hosts []string
	if json.Unmarshal(data, &hosts) != nil {
		return
	}
	o.mu.Lock()
	for _, h := range hosts {
		o.hosts[h] = time.Now()
	}
	n := len(o.hosts)
	o.mu.Unlock()
	if n > 0 {
		o.log.Infof("已从 %s 恢复 %d 条覆盖名单", o.file, n)
	}
}

func (o *overrideStore) save() {
	o.mu.RLock()
	hosts := make([]string, 0, len(o.hosts))
	for h := range o.hosts {
		hosts = append(hosts, h)
	}
	o.mu.RUnlock()
	sort.Strings(hosts)
	data, err := json.Marshal(hosts)
	if err != nil {
		return
	}
	tmp := o.file + ".tmp"
	if os.WriteFile(tmp, data, 0o600) != nil {
		return
	}
	_ = os.Rename(tmp, o.file)
}

// list 返回名单（设置时间倒序，最新改的排最前）。
func (o *overrideStore) list() []string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	out := make([]string, 0, len(o.hosts))
	for h := range o.hosts {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return o.hosts[out[i]].After(o.hosts[out[j]]) })
	return out
}

func (o *overrideStore) count() int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return len(o.hosts)
}

// ---------- Server 接线 ----------

func (s *Server) noFakeHas(host string) bool    { return s.noFake.has(host) }
func (s *Server) forceFakeHas(host string) bool { return s.forceFake.has(host) }

// overrideSet 切换某域名的覆盖状态。kind: "nofake" / "forcefake"。
// 两者互斥：设置一个自动清掉另一个。
func (s *Server) overrideSet(kind, host string, on bool) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return
	}
	switch kind {
	case "nofake":
		if s.noFake.set(host, on) {
			if on {
				s.forceFake.set(host, false)
				s.log.Infof("%s 已设为取消污染（即便命中 IP 段也返回真实结果）", host)
			} else {
				s.log.Infof("%s 已恢复默认污染判定", host)
			}
		}
	case "forcefake":
		if s.forceFake.set(host, on) {
			if on {
				s.noFake.set(host, false)
				s.log.Infof("%s 已设为强制污染（即便没命中 IP 段也返回虚假 IP）", host)
			} else {
				s.log.Infof("%s 已恢复默认污染判定", host)
			}
		}
	}
}

// serveOverride 覆盖开关 HTTP 接口：/override?kind=nofake&host=xxx&on=1
// 处理完跳回 /cache 页。
func (s *Server) serveOverride(w http.ResponseWriter, req *http.Request) {
	kind := req.URL.Query().Get("kind")
	host := req.URL.Query().Get("host")
	on := req.URL.Query().Get("on") == "1"
	if kind != "nofake" && kind != "forcefake" {
		http.Error(w, "kind must be nofake or forcefake", http.StatusBadRequest)
		return
	}
	s.overrideSet(kind, host, on)
	http.Redirect(w, req, "/cache", http.StatusSeeOther)
}

// overrideBadges 缓存页状态列徽标：该域名的覆盖状态。
func (s *Server) overrideBadges(host string) string {
	var b strings.Builder
	if s.noFakeHas(host) {
		b.WriteString(`<div class="mark" style="color:#059669;background:#ecfdf5">🚫 已取消污染 · 命中 IP 段也返回真实 IP</div>`)
	}
	if s.forceFakeHas(host) {
		b.WriteString(`<div class="mark" style="color:#dc2626;background:#fef2f2">🎯 已强制污染 · 没命中也返回虚假 IP（不打上游）</div>`)
	}
	return b.String()
}

// overrideBtns 缓存页操作列按钮（按当前状态显示开/关）。
func (s *Server) overrideBtns(host string) string {
	q := func(v string) string { return urlQueryEscape(v) }
	var b strings.Builder
	if s.noFakeHas(host) {
		fmt.Fprintf(&b, `<a class="opb on" href="/override?kind=nofake&host=%s&on=0">🚫 取消污染中 · 点按恢复</a>`, q(host))
	} else {
		fmt.Fprintf(&b, `<a class="opb" href="/override?kind=nofake&host=%s&on=1">🚫 取消污染</a>`, q(host))
	}
	if s.forceFakeHas(host) {
		fmt.Fprintf(&b, `<a class="opb fd" href="/override?kind=forcefake&host=%s&on=0">🎯 强制污染中 · 点按恢复</a>`, q(host))
	} else {
		fmt.Fprintf(&b, `<a class="opb fd" href="/override?kind=forcefake&host=%s&on=1">🎯 强制污染</a>`, q(host))
	}
	return b.String()
}

// urlQueryEscape URL 查询参数转义（覆盖名单按钮用）。
func urlQueryEscape(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// 覆盖名单统计（状态页用）。
func (s *Server) overrideStats() (noFakeN, forceFakeN int) {
	return s.noFake.count(), s.forceFake.count()
}
