package fastime

import (
	"container/list"
	"sync"
	"time"
)

// lruCache 纯内存 LRU，容量由 CACHE_SIZE 注入。
// 条目没有"过期"概念：命中即返回旧内容，由后台调度器每 15 分钟逐条
// 向上游换新（见 persist.go）；只进内存，不碰磁盘、不用数据库。
type lruCache struct {
	mu   sync.Mutex
	cap  int
	ll   *list.List
	data map[string]*list.Element
}

// cacheItem 一条缓存：key=方法+规范化查询，body=上游原始应答（污染与否在
// 应答时按当前 IP 段表与覆盖名单动态判定——覆盖改动立即生效，无需清缓存）。
type cacheItem struct {
	key  string
	body []byte
	at   time.Time // 上次从上游取回的时刻（15 分钟换新调度的依据）
}

func newLRUCache(capacity int) *lruCache {
	if capacity <= 0 {
		capacity = 128
	}
	return &lruCache{cap: capacity, ll: list.New(), data: make(map[string]*list.Element)}
}

// Get 返回缓存体。命中即有效（无保鲜期概念），换新由后台调度器负责。
func (c *lruCache) Get(key string) (body []byte, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, hit := c.data[key]
	if !hit {
		return nil, false
	}
	c.ll.MoveToFront(e)
	return e.Value.(*cacheItem).body, true
}

// Keys 返回全部缓存键的快照（MRU 在前）。
func (c *lruCache) Keys() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	keys := make([]string, 0, c.ll.Len())
	for e := c.ll.Front(); e != nil; e = e.Next() {
		keys = append(keys, e.Value.(*cacheItem).key)
	}
	return keys
}

// Snapshot 返回全部缓存条目的快照（MRU 在前），供缓存查看页/落盘用。
func (c *lruCache) Snapshot() []cacheItem {
	c.mu.Lock()
	defer c.mu.Unlock()
	items := make([]cacheItem, 0, c.ll.Len())
	for e := c.ll.Front(); e != nil; e = e.Next() {
		it := e.Value.(*cacheItem)
		items = append(items, cacheItem{key: it.key, body: it.body, at: it.at})
	}
	return items
}

// Len 返回当前缓存条数（状态页用）。
func (c *lruCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

func (c *lruCache) Put(key string, body []byte) {
	c.PutWithAt(key, body, time.Now())
}

// PutWithAt 持久化恢复专用：保留条目原本的取回时刻（老条目的 15 分钟换新
// 周期连续计算，重启不打乱节奏）。已有同键条目时覆盖更新。
func (c *lruCache) PutWithAt(key string, body []byte, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.data[key]; ok {
		c.ll.MoveToFront(e)
		it := e.Value.(*cacheItem)
		it.body = body
		it.at = at
		return
	}
	c.data[key] = c.ll.PushFront(&cacheItem{key: key, body: body, at: at})
	if c.ll.Len() > c.cap {
		oldest := c.ll.Back()
		if oldest != nil {
			c.ll.Remove(oldest)
			delete(c.data, oldest.Value.(*cacheItem).key)
		}
	}
}
