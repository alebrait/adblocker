package cache

import (
	"github.com/miekg/dns"
	"strings"
	"sync"
	"time"
)

type key struct {
	name       string
	typ, class uint16
	rd, cd     bool
}
type entry struct {
	msg            *dns.Msg
	saved, expires time.Time
}
type Cache struct {
	mu       sync.Mutex
	entries  map[key]entry
	MaxTTL   time.Duration
	Capacity int
}

func New(ttl time.Duration, capacity int) *Cache {
	return &Cache{entries: map[key]entry{}, MaxTTL: ttl, Capacity: capacity}
}

// EDNS and authenticated requests bypass this minimal cache to avoid mixing options.
func cacheKey(q *dns.Msg) (key, bool) {
	if len(q.Question) != 1 || len(q.Extra) != 0 || len(q.Answer) != 0 || len(q.Ns) != 0 {
		return key{}, false
	}
	v := q.Question[0]
	return key{strings.ToLower(v.Name), v.Qtype, v.Qclass, q.RecursionDesired, q.CheckingDisabled}, true
}
func (c *Cache) Get(q *dns.Msg) *dns.Msg {
	k, ok := cacheKey(q)
	if !ok || c.MaxTTL <= 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[k]
	if !ok {
		return nil
	}
	now := time.Now()
	if !now.Before(e.expires) {
		delete(c.entries, k)
		return nil
	}
	m := e.msg.Copy()
	m.Id = q.Id
	m.Question = append([]dns.Question(nil), q.Question...)
	age := uint32(now.Sub(e.saved) / time.Second)
	for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype != dns.TypeOPT {
				if rr.Header().Ttl > age {
					rr.Header().Ttl -= age
				} else {
					rr.Header().Ttl = 0
				}
			}
		}
	}
	return m
}
func (c *Cache) Put(q, m *dns.Msg) {
	k, ok := cacheKey(q)
	if !ok || c.MaxTTL <= 0 || c.Capacity <= 0 || m.Truncated || m.Rcode != dns.RcodeSuccess || len(m.Answer) == 0 || m.IsTsig() != nil {
		return
	}
	ttl := c.MaxTTL
	for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == dns.TypeOPT {
				return
			}
			if d := time.Duration(rr.Header().Ttl) * time.Second; d < ttl {
				ttl = d
			}
		}
	}
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if len(c.entries) >= c.Capacity {
		for k, e := range c.entries {
			if !now.Before(e.expires) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= c.Capacity {
			for k := range c.entries {
				delete(c.entries, k)
				break
			}
		}
	}
	c.entries[k] = entry{m.Copy(), now, now.Add(ttl)}
}
