package fastime

import (
	"encoding/json"
	"os"
	"time"
)

// 运行缓存（持久化 + 定时刷新）：
//
// 持久化 —— 上游结果缓存每次定时刷新后写入 fastime-cache.json（工作目录），
//
//	重启时整体恢复，前台查询直接命中旧结果（过期则先返回旧值 + 后台刷新，
//	即既有 SWR 语义），不再从 0 开始请求上游。
//
// 定时刷新 —— 每 CACHE_REFRESH_SEC（默认 1800s）把已有缓存逐条向上游换新：
//
//	普通条目重发原查询（熔断中跳过，省电）；上游域名本地代答条目走本地
//	DoT→DoH 链重新解析。刷新完成后落盘。前台在整个过程中始终先用旧结果。
//
// 系统 DNS 代管缓存（turbo）不参与持久化：它绑定当前网络，切网即清。
const cachePersistFile = "fastime-cache.json"

type persistedCache struct {
	Entries []persistedEntry `json:"entries"`
}

type persistedEntry struct {
	Key  string `json:"k"`
	Body []byte `json:"b"` // encoding/json 自动 base64
	At   int64  `json:"t"` // UnixNano 缓存时刻
}

// loadPersistedCache 启动时恢复上次运行的上游缓存。文件不存在/损坏静默跳过。
func (s *Server) loadPersistedCache() {
	data, err := os.ReadFile(cachePersistFile)
	if err != nil {
		return
	}
	var pc persistedCache
	if json.Unmarshal(data, &pc) != nil {
		return
	}
	n := 0
	for _, e := range pc.Entries {
		if e.Key == "" || len(e.Body) == 0 || e.At <= 0 {
			continue
		}
		s.cache.PutWithAt(e.Key, e.Body, time.Unix(0, e.At))
		n++
	}
	if n > 0 {
		s.persistLoaded.Store(int64(n))
		s.log.Infof("已从 %s 恢复 %d 条上游缓存（重启不从 0 开始）", cachePersistFile, n)
	}
}

// savePersistedCache 缓存快照落盘（先写临时文件再改名，避免写一半留下坏文件）。
func (s *Server) savePersistedCache() {
	items := s.cache.Snapshot()
	pc := persistedCache{Entries: make([]persistedEntry, 0, len(items))}
	for _, it := range items {
		pc.Entries = append(pc.Entries, persistedEntry{Key: it.key, Body: it.body, At: it.at.UnixNano()})
	}
	data, err := json.Marshal(&pc)
	if err != nil {
		return
	}
	tmp := cachePersistFile + ".tmp"
	if os.WriteFile(tmp, data, 0o600) != nil {
		return
	}
	if err := os.Rename(tmp, cachePersistFile); err != nil {
		s.log.Debugf("缓存持久化改名失败: %v", err)
	}
}

// cachePersistLoop 定时落盘：每 CACHE_PERSIST_SEC（默认 30s）把运行缓存写入
// fastime-cache.json——进程被强杀（kill -9 / 断电 / 系统清理）也最多丢一个
// 间隔的增量，不再只有优雅退出才保存。<=0 时关闭（退回仅退出时保存）。
func (s *Server) cachePersistLoop(stop chan struct{}) {
	iv := s.cfg.CachePersist
	if iv <= 0 {
		return
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.savePersistedCache()
			s.log.Debugf("缓存定时落盘完成（间隔 %s）", iv)
		}
	}
}

// cacheRefreshLoop 定时批量刷新已有缓存：首轮在启动 15s 后（恢复的持久化
// 缓存可能已过期，全量换新），之后按条目分别到期判定——普通条目按
// CACHE_REFRESH_SEC，"不走系统DNS"豁免条目按独立的 NODIVERT_REFRESH_SEC
// （默认 3 分钟，远短于全局，保证豁免域名的上游结果足够新鲜）；每轮结束落盘。
func (s *Server) cacheRefreshLoop(stop chan struct{}) {
	iv, nd := s.cfg.CacheRefresh, s.cfg.NoDivertRefresh
	if iv <= 0 && nd <= 0 {
		return // 两者都关 = 不做任何定时刷新（持久化照常，过期条目仍按 SWR 按需刷新）
	}
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	first := true
	for {
		select {
		case <-stop:
			return
		case <-timer.C:
		}
		s.refreshAllCache(first)
		s.savePersistedCache()
		first = false
		// 唤醒间隔取两者中较短者（豁免条目通常要求更频繁的检查），下限 10s 防热循环
		tick := iv
		if tick <= 0 || (nd > 0 && nd < tick) {
			tick = nd
		}
		if tick < 10*time.Second {
			tick = 10 * time.Second
		}
		timer.Reset(tick)
	}
}

// refreshAllCache 逐条把缓存向上游换新。失败保留旧值，下次再试。
// all=true（启动首轮）：无视年龄全量换新；all=false：只刷新已到期的条目
// （普通条目按 CacheRefresh 到期，豁免条目按 NoDivertRefresh 到期）。
func (s *Server) refreshAllCache(all bool) {
	items := s.cache.Snapshot()
	if len(items) == 0 {
		return
	}
	start := time.Now()
	var okN, failN, skipN int64
	for _, it := range items {
		method, canon, ok := splitCacheKey(it.key)
		if !ok {
			skipN++
			continue
		}
		q, qErr := parseQuestion(canon)
		if !all {
			// 到期判定：豁免域名（始终用上游结果）走独立时长，其余走全局时长
			iv := s.cfg.CacheRefresh
			if qErr == nil && s.noDivertHas(q.Name) && s.cfg.NoDivertRefresh > 0 {
				iv = s.cfg.NoDivertRefresh
			}
			if iv <= 0 || time.Since(it.at) < iv {
				skipN++
				continue
			}
		}
		// 上游域名本地代答条目：走本地 DoT→DoH 链重新解析，不碰上游、不受熔断影响
		localQ := qErr == nil && (q.Qtype == dnsTypeA || q.Qtype == dnsTypeAAAA) &&
			(q.Name == s.upHost || (s.fbHost != "" && q.Name == s.fbHost))
		if localQ {
			if _, err := s.resolveLocal(canon, it.key); err != nil {
				failN++
			} else {
				okN++
			}
			continue
		}
		if s.breakerOpen() { // 熔断中暂停批量刷新（省流省电），旧值继续服役
			skipN++
			continue
		}
		// canon 的事务 ID 已归零，本身就是合法 DNS 查询报文，直接作为重发负载；
		// turbo 模式下 fetch 内部走竞速，胜出结果写回缓存（含 IP 段分流判断）
		if _, _, err := s.fetch(method, canon, it.key, nil); err != nil {
			failN++
		} else {
			okN++
		}
	}
	s.refreshOK.Add(okN)
	s.refreshFail.Add(failN)
	s.lastRefreshAt.Store(time.Now().Unix())
	s.pruneMarks()
	s.log.Infof("运行缓存定时刷新：更新 %d 条，失败 %d 条（保留旧值），跳过 %d 条，耗时 %s",
		okN, failN, skipN, time.Since(start).Round(time.Millisecond))
}

// pruneMarks 清理已不在缓存中的 IP 段命中标记（标记随条目生灭，不无限增长）。
func (s *Server) pruneMarks() {
	alive := make(map[string]bool)
	for _, k := range s.cache.Keys() {
		alive[k] = true
	}
	s.marked.Range(func(k, _ any) bool {
		if !alive[k.(string)] {
			s.marked.Delete(k)
		}
		return true
	})
}
