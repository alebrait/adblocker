package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"personal-blocker/internal/dnsserver"
	"personal-blocker/internal/listupdate"
	"personal-blocker/internal/resolver"
	"personal-blocker/internal/rules"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func Execute(ctx context.Context, args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: personal-blocker <run|test|update-lists> [flags] [domain]")
	}
	if args[0] == "help" || args[0] == "--help" {
		fmt.Fprintln(out, "Usage: personal-blocker <run|test|update-lists> [flags] [domain]\nUse <command> --help for flags.")
		return nil
	}
	command := args[0]
	if command == "update-lists" {
		return updateLists(ctx, args[1:], out, errOut)
	}
	if command != "run" && command != "test" {
		return fmt.Errorf("unknown command %q", command)
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(errOut)
	blocks := fs.String("blocklists", "blocklists/ads.txt,blocklists/trackers.txt", "comma-separated blocklist paths")
	allows := fs.String("allowlists", "blocklists/allow.txt", "comma-separated allowlist paths (empty disables)")
	var addr, upstreams *string
	var timeout, ttl *time.Duration
	var capacity *int
	var queryLog *bool
	if command == "run" {
		addr = fs.String("listen", "127.0.0.1:5353", "UDP/TCP listen address")
		upstreams = fs.String("upstreams", "1.1.1.1:53,9.9.9.9:53", "comma-separated upstream IP:port addresses")
		timeout = fs.Duration("timeout", 2*time.Second, "timeout per upstream including TCP fallback")
		ttl = fs.Duration("cache-ttl", 300*time.Second, "maximum cache lifetime (0 disables)")
		capacity = fs.Int("cache-size", 4096, "maximum cache entries")
		queryLog = fs.Bool("query-log", true, "log domain decisions to stderr")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if command == "run" && fs.NArg() != 0 || command == "test" && fs.NArg() != 1 {
		return fmt.Errorf("usage: personal-blocker %s [flags]%s", command, map[bool]string{true: " <domain>", false: ""}[command == "test"])
	}
	logger := slog.New(slog.NewTextHandler(errOut, nil))
	engine, err := rules.Load(split(*blocks), split(*allows), func(s string) { logger.Warn(s) })
	if err != nil {
		return err
	}
	if command == "test" {
		host, err := rules.Normalize(fs.Arg(0))
		if err != nil {
			return err
		}
		blocked, source := engine.Decide(host)
		decision := "ALLOW"
		if blocked {
			decision = "BLOCK"
		}
		fmt.Fprintf(out, "%s %s", decision, host)
		if source.Domain != "" {
			fmt.Fprintf(out, " matched=%s source=%s:%d", source.Domain, source.File, source.Line)
		}
		fmt.Fprintln(out)
		return nil
	}
	if *timeout <= 0 || *ttl < 0 || *capacity < 0 {
		return fmt.Errorf("timeout must be positive; cache settings must be nonnegative")
	}
	if err := validateAddress(*addr); err != nil {
		return err
	}
	list := split(*upstreams)
	if len(list) == 0 {
		return fmt.Errorf("at least one upstream is required")
	}
	for _, a := range list {
		if err := validateAddress(a); err != nil {
			return err
		}
		if a == *addr {
			return fmt.Errorf("upstream cannot be the listen address")
		}
	}
	h := dnsserver.New(engine, &resolver.Resolver{Upstreams: list, Timeout: *timeout}, *ttl, *capacity, logger, *queryLog)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)
	defer signal.Stop(signals)
	reloadCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	defer func() { cancel(); <-done }()
	go func() {
		defer close(done)
		for {
			select {
			case <-reloadCtx.Done():
				return
			case <-signals:
				if err := h.Reload(split(*blocks), split(*allows)); err != nil {
					logger.Error("RELOAD failed; keeping current rules", "error", err)
				} else {
					logger.Info("RELOAD complete; cache cleared")
				}
			}
		}
	}()
	return dnsserver.Run(ctx, *addr, h)
}
func split(s string) []string {
	var result []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			result = append(result, v)
		}
	}
	return result
}
func validateAddress(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", s, err)
	}
	p, err := strconv.Atoi(port)
	if net.ParseIP(host) == nil || err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("address must use an IP and port 1-65535: %q", s)
	}
	return nil
}

func updateLists(ctx context.Context, args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("update-lists", flag.ContinueOnError)
	fs.SetOutput(errOut)
	source := fs.String("url", listupdate.DefaultURL, "HTTPS domain/hosts list source")
	destination := fs.String("output", "blocklists/hagezi-light.txt", "download destination (parent directory must exist)")
	timeout := fs.Duration("timeout", 30*time.Second, "total download timeout")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: personal-blocker update-lists [flags]")
	}
	result, err := listupdate.Update(ctx, *source, *destination, *timeout)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Updated %s domains=%d bytes=%d sha256=%s\n", *destination, result.Domains, result.Bytes, result.SHA256)
	fmt.Fprintln(out, "Send SIGHUP to a running server that includes this file, or start run with --blocklists including this path.")
	return nil
}
