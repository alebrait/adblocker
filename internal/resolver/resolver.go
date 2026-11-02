package resolver

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"time"
)

type Resolver struct {
	Upstreams []string
	Timeout   time.Duration
}

func (r *Resolver) Resolve(q *dns.Msg) (*dns.Msg, string, error) {
	var last error
	for _, addr := range r.Upstreams {
		ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
		client := &dns.Client{Net: "udp", Timeout: r.Timeout, UDPSize: 4096}
		answer, _, err := client.ExchangeContext(ctx, q, addr)
		if err == nil && answer.Truncated {
			client.Net = "tcp"
			answer, _, err = client.ExchangeContext(ctx, q, addr)
		}
		cancel()
		if err == nil && (answer.Rcode == dns.RcodeServerFailure || answer.Rcode == dns.RcodeRefused) {
			err = fmt.Errorf("upstream returned %s", dns.RcodeToString[answer.Rcode])
		}
		if err == nil {
			return answer, addr, nil
		}
		last = fmt.Errorf("%s: %w", addr, err)
	}
	return nil, "", fmt.Errorf("all upstreams failed: %w", last)
}
