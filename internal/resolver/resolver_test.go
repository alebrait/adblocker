package resolver

import (
	"github.com/miekg/dns"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T, network, addr string, h dns.HandlerFunc) string {
	t.Helper()
	s := &dns.Server{Handler: h}
	var err error
	if network == "udp" {
		s.PacketConn, err = net.ListenPacket(network, addr)
		if err == nil {
			addr = s.PacketConn.LocalAddr().String()
		}
	} else {
		s.Listener, err = net.Listen(network, addr)
		if err == nil {
			addr = s.Listener.Addr().String()
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	s.NotifyStartedFunc = func() { close(ready) }
	done := make(chan error, 1)
	go func() { done <- s.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() {
		if err := s.Shutdown(); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return addr
}
func TestFailoverAndTCPFallback(t *testing.T) {
	var tcpCalls atomic.Int32
	bad := fixture(t, "udp", "127.0.0.1:0", func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(q, dns.RcodeServerFailure)
		w.WriteMsg(m)
	})
	good := fixture(t, "udp", "127.0.0.1:0", func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		m.Truncated = true
		w.WriteMsg(m)
	})
	fixture(t, "tcp", good, func(w dns.ResponseWriter, q *dns.Msg) {
		tcpCalls.Add(1)
		m := new(dns.Msg)
		m.SetReply(q)
		rr, _ := dns.NewRR("example.com. 60 IN A 192.0.2.1")
		m.Answer = []dns.RR{rr}
		w.WriteMsg(m)
	})
	r := &Resolver{[]string{bad, good}, time.Second}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	m, up, err := r.Resolve(q)
	if err != nil || up != good || m.Truncated || len(m.Answer) != 1 || tcpCalls.Load() != 1 {
		t.Fatalf("m=%v upstream=%s err=%v TCP=%d", m, up, err, tcpCalls.Load())
	}
}
func TestTimeout(t *testing.T) {
	addr := fixture(t, "udp", "127.0.0.1:0", func(dns.ResponseWriter, *dns.Msg) {})
	r := &Resolver{[]string{addr}, 30 * time.Millisecond}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	start := time.Now()
	if _, _, err := r.Resolve(q); err == nil {
		t.Fatal("expected timeout")
	}
	if time.Since(start) > time.Second {
		t.Fatal("timeout not bounded")
	}
}
