package dnsserver

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"

	"personal-blocker/internal/rules"
	"testing"
	"time"
)

type fakeResolver struct {
	calls int
	fail  bool
}

func (f *fakeResolver) Resolve(q *dns.Msg) (*dns.Msg, string, error) {
	f.calls++
	if f.fail {
		return nil, "", errors.New("timeout")
	}
	m := new(dns.Msg)
	m.SetReply(q)
	rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.10")
	m.Answer = []dns.RR{rr}
	return m, "fixture", nil
}

type writer struct{ m *dns.Msg }

func (w *writer) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (w *writer) RemoteAddr() net.Addr        { return &net.UDPAddr{} }
func (w *writer) WriteMsg(m *dns.Msg) error   { w.m = m; return nil }
func (w *writer) Write(b []byte) (int, error) { return len(b), nil }
func (w *writer) Close() error                { return nil }
func (w *writer) TsigStatus() error           { return nil }
func (w *writer) TsigTimersOnly(bool)         {}
func (w *writer) Hijack()                     {}
func handler(t *testing.T) (*Handler, *fakeResolver) {
	t.Helper()
	d := t.TempDir()
	b := filepath.Join(d, "block")
	a := filepath.Join(d, "allow")
	for p, s := range map[string]string{b: "doubleclick.net", a: "safe.doubleclick.net"} {
		if err := os.WriteFile(p, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := rules.Load([]string{b}, []string{a}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeResolver{}
	return New(r, f, time.Minute, 10, slog.New(slog.NewTextHandler(io.Discard, nil)), true), f
}
func TestDecisions(t *testing.T) {
	h, f := handler(t)
	for _, tc := range []struct {
		name string
		typ  uint16
		want string
	}{{"doubleclick.net.", dns.TypeA, "0.0.0.0"}, {"ads.doubleclick.net.", dns.TypeAAAA, "::"}, {"doubleclick.net.", dns.TypeTXT, ""}, {"safe.doubleclick.net.", dns.TypeA, "192.0.2.10"}, {"example.com.", dns.TypeA, "192.0.2.10"}, {"example.com.", dns.TypeA, "192.0.2.10"}} {
		q := new(dns.Msg)
		q.SetQuestion(tc.name, tc.typ)
		w := &writer{}
		h.ServeDNS(w, q)
		if w.m.Rcode != 0 {
			t.Fatal(w.m)
		}
		if tc.want == "" {
			if len(w.m.Answer) != 0 {
				t.Fatal(w.m)
			}
			continue
		}
		var ip string
		switch rr := w.m.Answer[0].(type) {
		case *dns.A:
			ip = rr.A.String()
		case *dns.AAAA:
			ip = rr.AAAA.String()
		}
		if ip != tc.want {
			t.Errorf("%s: %s", tc.name, ip)
		}
	}
	if f.calls != 2 {
		t.Fatalf("forwarded %d times", f.calls)
	}
}
func TestErrors(t *testing.T) {
	h, f := handler(t)
	f.fail = true
	for _, tc := range []struct {
		kind  string
		rcode int
	}{{"timeout", dns.RcodeServerFailure}, {"multiple", dns.RcodeFormatError}, {"empty", dns.RcodeFormatError}, {"opcode", dns.RcodeNotImplemented}, {"transfer", dns.RcodeRefused}} {
		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeA)
		switch tc.kind {
		case "multiple":
			q.Question = append(q.Question, q.Question[0])
		case "empty":
			q.Question = nil
		case "opcode":
			q.Opcode = dns.OpcodeUpdate
		case "transfer":
			q.Question[0].Qtype = dns.TypeAXFR
		}
		w := &writer{}
		h.ServeDNS(w, q)
		if w.m.Rcode != tc.rcode {
			t.Errorf("%s: %d", tc.kind, w.m.Rcode)
		}
	}
}
func TestRunAndShutdown(t *testing.T) {
	h, _ := handler(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, addr, h) }()
	q := new(dns.Msg)
	q.SetQuestion("doubleclick.net.", dns.TypeA)
	for _, network := range []string{"udp", "tcp"} {
		client := &dns.Client{Net: network, Timeout: 100 * time.Millisecond}
		deadline := time.Now().Add(3 * time.Second)
		for {
			m, _, err := client.Exchange(q, addr)
			if err == nil {
				if len(m.Answer) != 1 {
					t.Fatal(m)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatal(err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("shutdown hung")
	}
}

func TestReloadPreservesOnFailureAndClearsCache(t *testing.T) {
	h, f := handler(t)
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	h.ServeDNS(&writer{}, q)
	h.ServeDNS(&writer{}, q)
	if f.calls != 1 {
		t.Fatal("cache not primed")
	}
	old := h.state.Load()
	path := filepath.Join(t.TempDir(), "rules")
	if err := os.WriteFile(path, []byte("example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := h.Reload([]string{path}, nil); err != nil {
		t.Fatal(err)
	}
	if h.state.Load() == old || h.state.Load().cache.Get(q) != nil {
		t.Fatal("snapshot/cache not replaced")
	}
	// A delayed old request cannot write into the replacement cache.
	m, _, _ := f.Resolve(q)
	old.cache.Put(q, m)
	if h.state.Load().cache.Get(q) != nil {
		t.Fatal("old response entered new cache")
	}
	w := &writer{}
	h.ServeDNS(w, q)
	if w.m.Answer[0].(*dns.A).A.String() != "0.0.0.0" {
		t.Fatal("new block not active")
	}
	current := h.state.Load()
	for _, data := range []string{"bad rule\n", "||invalid.example^\n"} {
		os.WriteFile(path, []byte(data), 0600)
		if err := h.Reload([]string{path}, nil); err == nil {
			t.Fatal("accepted malformed reload")
		}
		if h.state.Load() != current {
			t.Fatal("failed reload changed active state")
		}
	}
	if err := h.Reload([]string{path + "-missing"}, nil); err == nil {
		t.Fatal("accepted missing file")
	}
	// Intentional empty local lists are valid and remove existing blocks.
	os.WriteFile(path, nil, 0600)
	if err := h.Reload([]string{path}, nil); err != nil {
		t.Fatal(err)
	}
	w = &writer{}
	h.ServeDNS(w, q)
	if w.m.Answer[0].(*dns.A).A.String() == "0.0.0.0" {
		t.Fatal("empty reload failed")
	}
}

func TestConcurrentReload(t *testing.T) {
	h, _ := handler(t)
	path := filepath.Join(t.TempDir(), "rules")
	os.WriteFile(path, []byte("doubleclick.net\n"), 0600)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			q := new(dns.Msg)
			q.SetQuestion("doubleclick.net.", dns.TypeA)
			h.ServeDNS(&writer{}, q)
		}
	}()
	for i := 0; i < 100; i++ {
		if err := h.Reload([]string{path}, nil); err != nil {
			t.Fatal(err)
		}
	}
	<-done
}
