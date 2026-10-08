package fastime

import (
	"encoding/json"
	"os"
	"time"
)

// 缓存持久化与定时换新：
//
// 持久化 —— 每 30s 把运行缓存整体写入 fastime-cache.json（运行目录），
//
//	强杀进程也最多丢 30s 增量；下次启动先整体恢复，前台查询立即返回
//	旧内容，再由换新调度器逐条向上游更新。
//
// 换新 —— 每 60s 扫一遍：取回时刻超过 15 分钟的条目重新竞速上游，
//
//	成功即覆盖缓存；这期间前台一直返回旧内容（换新旧值不中断服务）。
//	启动首轮（15s 后）把恢复出来的条目全量换新一遍。
var cachePersistFile = "fastime-cache.json" // var 便于测试重定向

type persistedCache struct {
	Entries []persistedEntry `json:"entries"`
}

type persistedEntry struct {
	Key  string `json:"k"`
	Body []byte `json:"b"` // encoding/json 自动 base64
	At   int64  `json:"t"` // UnixNano 取回时刻
}

// loadPersistedCache 启动时恢复上次运行的缓存。文件不存在/损坏静默跳过。
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
		s.log.Infof("已从 %s 恢复 %d 条缓存（重启不从 0 开始）", cachePersistFile, n)
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

// cacheLoop 缓存后台调度：30s 落盘 + 15 分钟逐条向上游换新。
// 首轮换新在启动 15s 后进行（恢复的条目可能已经很旧，全量换一遍）。
func (s *Server) cacheLoop(stop chan struct{}) {
	persistTk := time.NewTicker(cachePersistEvery)
	defer persistTk.Stop()
	refreshTk := time.NewTicker(60 * time.Second)
	defer refreshTk.Stop()
	first := time.NewTimer(15 * time.Second)
	defer first.Stop()
	for {
		select {
		case <-stop:
			return
		case <-persistTk.C:
			s.savePersistedCache()
		case <-first.C:
			s.refreshCache(true) // 首轮：恢复的条目全量换新
			s.savePersistedCache()
		case <-refreshTk.C:
			s.refreshCache(false) // 常规：只换超过换新周期（fake 15min / off 5min）的条目
			s.savePersistedCache()
		}
	}
}

// refreshCache 逐条把缓存向上游换新。all=true 全量（启动首轮 / off 模式切网）；
// all=false 只换超过 cfg.RefreshEvery 的条目。
// 失败保留旧值，下次再试；「强制污染」域名不打上游（直接回虚假 IP），跳过。
func (s *Server) refreshCache(all bool) {
	if !all && s.breakerOpen() {
		return // 熔断中：暂停批量换新（省电省流）
	}
	items := s.cache.Snapshot()
	if len(items) == 0 {
		return
	}
	start := time.Now()
	var okN, failN, skipN int64
	for _, it := range items { // 串行逐条换新：移动端省电，避免瞬时打满射频
		method, canon, ok := splitCacheKey(it.key)
		if !ok {
			skipN++
			continue
		}
		if !all && time.Since(it.at) < s.cfg.RefreshEvery {
			skipN++
			continue
		}
		if q, qErr := parseQuestion(canon); qErr == nil && s.forceFakeHas(q.Name) {
			skipN++ // 强制污染域名不走上游
			continue
		}
		// canon 的事务 ID 已归零，本身就是合法 DNS 查询报文，直接作为重发负载
		if _, err := s.fetch(method, canon, it.key); err != nil {
			failN++
		} else {
			okN++
		}
	}
	s.refreshOK.Add(okN)
	s.refreshFail.Add(failN)
	s.lastRefreshAt.Store(time.Now().Unix())
	if okN+failN > 0 {
		s.log.Infof("缓存定时换新：更新 %d 条，失败 %d 条（保留旧值），跳过 %d 条，耗时 %s",
			okN, failN, skipN, time.Since(start).Round(time.Millisecond))
	}
}
