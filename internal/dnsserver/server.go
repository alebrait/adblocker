package dnsserver

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"log/slog"
	"net"
	"os"
	"personal-blocker/internal/cache"
	"personal-blocker/internal/rules"
	"sync/atomic"
	"time"
)

type Resolver interface {
	Resolve(*dns.Msg) (*dns.Msg, string, error)
}
type Handler struct {
	state    atomic.Pointer[ruleState]
	Resolver Resolver
	Logger   *slog.Logger
	QueryLog bool
}

type ruleState struct {
	rules *rules.Engine
	cache *cache.Cache
}

func New(engine *rules.Engine, resolver Resolver, ttl time.Duration, capacity int, logger *slog.Logger, queryLog bool) *Handler {
	h := &Handler{Resolver: resolver, Logger: logger, QueryLog: queryLog}
	h.state.Store(&ruleState{engine, cache.New(ttl, capacity)})
	return h
}

// Reload builds off-path and swaps rules and an empty cache together. In-flight
// requests finish on their old snapshot and cannot populate the new cache.
func (h *Handler) Reload(blockPaths, allowPaths []string) error {
	engine, err := rules.LoadStrict(blockPaths, allowPaths)
	if err != nil {
		return err
	}
	old := h.state.Load()
	h.state.Store(&ruleState{engine, cache.New(old.cache.MaxTTL, old.cache.Capacity)})
	return nil
}

func (h *Handler) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(q)
	m.RecursionAvailable = true
	send := func() {
		if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
			size := uint16(512)
			if opt := q.IsEdns0(); opt != nil {
				size = opt.UDPSize()
				if size < 512 {
					size = 512
				}
				if size > 4096 {
					size = 4096
				}
			}
			m.Truncate(int(size))
		}
		if err := w.WriteMsg(m); err != nil {
			h.Logger.Warn("response failed", "error", err)
		}
	}
	if q.Opcode != dns.OpcodeQuery {
		m.Rcode = dns.RcodeNotImplemented
		send()
		return
	}
	if len(q.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		send()
		return
	}
	v := q.Question[0]
	if v.Qclass != dns.ClassINET || v.Qtype == dns.TypeAXFR || v.Qtype == dns.TypeIXFR || q.IsTsig() != nil {
		m.Rcode = dns.RcodeRefused
		send()
		return
	}
	state := h.state.Load()
	blocked, source := state.rules.Decide(v.Name)
	logDecision := func(decision string, args ...any) {
		if h.QueryLog {
			attrs := []any{"domain", v.Name, "type", dns.TypeToString[v.Qtype]}
			h.Logger.Info(decision, append(attrs, args...)...)
		}
	}
	if blocked {
		header := dns.RR_Header{Name: v.Name, Rrtype: v.Qtype, Class: v.Qclass, Ttl: 60}
		switch v.Qtype {
		case dns.TypeA:
			m.Answer = []dns.RR{&dns.A{Hdr: header, A: net.IPv4zero}}
		case dns.TypeAAAA:
			m.Answer = []dns.RR{&dns.AAAA{Hdr: header, AAAA: net.IPv6zero}}
		}
		logDecision("BLOCK", "matched", source.Domain, "source", fmt.Sprintf("%s:%d", source.File, source.Line))
		send()
		return
	}
	if answer := state.cache.Get(q); answer != nil {
		m = answer
		logDecision("CACHE")
		send()
		return
	}
	start := time.Now()
	answer, upstream, err := h.Resolver.Resolve(q)
	if err != nil {
		m.Rcode = dns.RcodeServerFailure
		logDecision("ERROR", "error", err)
		send()
		return
	}
	state.cache.Put(q, answer)
	m = answer
	logDecision("ALLOW", "upstream", upstream, "duration", time.Since(start), "matched", source.Domain)
	send()
}

// Run acquires both sockets before serving and shuts both down on cancellation.
func Run(ctx context.Context, addr string, h *Handler) error {
	udp, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	tcp, err := net.Listen("tcp", addr)
	if err != nil {
		udp.Close()
		return err
	}
	ready := make(chan struct{}, 2)
	done := make(chan error, 2)
	servers := []*dns.Server{{PacketConn: udp, Handler: h, NotifyStartedFunc: func() { ready <- struct{}{} }}, {Listener: tcp, Handler: h, NotifyStartedFunc: func() { ready <- struct{}{} }}}
	for _, s := range servers {
		go func() { done <- s.ActivateAndServe() }()
	}
	// Sockets have already been validated; wait until shutdown is safe.
	for range servers {
		<-ready
	}
	h.Logger.Info("listening", "address", addr, "transports", "udp,tcp", "pid", os.Getpid())
	var result error
	finished := 0
	select {
	case <-ctx.Done():
	case result = <-done:
		finished++
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		if err := s.ShutdownContext(shutdown); err != nil && result == nil {
			result = err
		}
	}
	for finished < 2 {
		err := <-done
		finished++
		if err != nil && result == nil {
			result = err
		}
	}
	return result
}
