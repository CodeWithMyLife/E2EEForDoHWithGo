package fastime

import (
	"container/list"
	"sync"
	"time"
)

// lruCache 纯内存 LRU，容量由 CACHE_SIZE 注入。
// 只进内存，不碰磁盘、不用数据库。条目带时间戳以支持保鲜期（TTL）。
type lruCache struct {
	mu   sync.Mutex
	cap  int
	ttl  time.Duration // 0 = 每次命中都视为过期（触发后台刷新）
	ll   *list.List
	data map[string]*list.Element
}

type cacheItem struct {
	key  string
	body []byte
	at   time.Time
}

func newLRUCache(capacity int, ttl time.Duration) *lruCache {
	if capacity <= 0 {
		capacity = 128
	}
	return &lruCache{cap: capacity, ttl: ttl, ll: list.New(), data: make(map[string]*list.Element)}
}

// Get 返回缓存体和是否仍在保鲜期内。fresh=false 时应后台刷新（SWR）。
func (c *lruCache) Get(key string) (body []byte, ok, fresh bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, hit := c.data[key]
	if !hit {
		return nil, false, false
	}
	c.ll.MoveToFront(e)
	it := e.Value.(*cacheItem)
	return it.body, true, c.ttl > 0 && time.Since(it.at) < c.ttl
}

// Keys 返回全部缓存键的快照（MRU 在前），供切网后强制逐条刷新。
func (c *lruCache) Keys() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	keys := make([]string, 0, c.ll.Len())
	for e := c.ll.Front(); e != nil; e = e.Next() {
		keys = append(keys, e.Value.(*cacheItem).key)
	}
	return keys
}

func (c *lruCache) Put(key string, body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.data[key]; ok {
		c.ll.MoveToFront(e)
		it := e.Value.(*cacheItem)
		it.body = body
		it.at = time.Now()
		return
	}
	c.data[key] = c.ll.PushFront(&cacheItem{key: key, body: body, at: time.Now()})
	if c.ll.Len() > c.cap {
		oldest := c.ll.Back()
		if oldest != nil {
			c.ll.Remove(oldest)
			delete(c.data, oldest.Value.(*cacheItem).key)
		}
	}
}
