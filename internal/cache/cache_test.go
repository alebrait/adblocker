package cache

import (
	"github.com/miekg/dns"
	"testing"
	"time"
)

func pair() (*dns.Msg, *dns.Msg) {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	m := new(dns.Msg)
	m.SetReply(q)
	rr, _ := dns.NewRR("example.com. 60 IN A 192.0.2.1")
	m.Answer = []dns.RR{rr}
	return q, m
}
func TestCache(t *testing.T) {
	c := New(300*time.Second, 2)
	q, m := pair()
	c.Put(q, m)
	q.Id++
	got := c.Get(q)
	if got == nil || got.Id != q.Id {
		t.Fatal("missing hit or wrong ID")
	}
	got.Answer[0].Header().Ttl = 0
	if c.Get(q).Answer[0].Header().Ttl == 0 {
		t.Fatal("shared mutable message")
	}
	k, _ := cacheKey(q)
	e := c.entries[k]
	e.saved = e.saved.Add(-2 * time.Second)
	c.entries[k] = e
	if c.Get(q).Answer[0].Header().Ttl > 58 {
		t.Fatal("TTL did not age")
	}
	e.expires = time.Now().Add(-time.Second)
	c.entries[k] = e
	if c.Get(q) != nil {
		t.Fatal("expired response served")
	}
}
func TestIsolationAndAdmission(t *testing.T) {
	c := New(time.Minute, 1)
	q, m := pair()
	c.Put(q, m)
	other := q.Copy()
	other.Question[0].Qtype = dns.TypeAAAA
	if c.Get(other) != nil {
		t.Fatal("type collision")
	}
	other = q.Copy()
	other.CheckingDisabled = true
	if c.Get(other) != nil {
		t.Fatal("CD collision")
	}
	other = q.Copy()
	other.SetEdns0(1232, true)
	if c.Get(other) != nil {
		t.Fatal("EDNS should bypass")
	}
	for _, kind := range []string{"zero", "truncated", "failure", "empty"} {
		q, m = pair()
		switch kind {
		case "zero":
			m.Answer[0].Header().Ttl = 0
		case "truncated":
			m.Truncated = true
		case "failure":
			m.Rcode = dns.RcodeServerFailure
		case "empty":
			m.Answer = nil
		}
		fresh := New(time.Minute, 1)
		fresh.Put(q, m)
		if fresh.Get(q) != nil {
			t.Errorf("cached %s", kind)
		}
	}
	q, m = pair()
	q.Question[0].Name = "other.example."
	c.Put(q, m)
	if len(c.entries) > 1 {
		t.Fatal("capacity exceeded")
	}
}
