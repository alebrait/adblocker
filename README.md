# Personal Blocker

A personal Linux DNS ad/tracker domain blocker written in Go. It listens on
`127.0.0.1:5353` over UDP and TCP, blocks listed domains and their subdomains,
and forwards other queries to configured resolvers.

DNS blocking cannot remove page elements, distinguish ads served from the same
domain as useful content, or prevent all tracking. The included lists are small
starter examples, not comprehensive protection.

## Quick start

Requires Go 1.26.2 or newer and `dig` (usually provided by `dnsutils` or
`bind-utils`). Run from the repository root:

```sh
go test ./...
go build ./cmd/personal-blocker
./personal-blocker test doubleclick.net
./personal-blocker run --listen=127.0.0.1:5533
```

If Go is installed at `/usr/local/go/bin` but missing from your PATH:

```sh
export PATH=/usr/local/go/bin:$PATH
```

In restricted workspaces where Git metadata is inaccessible, build and test with
`GOFLAGS=-buildvcs=false`. Go's dependency and build caches also need writable
locations; this development session used `GOMODCACHE=/tmp/personal-blocker-go-mod`
and `GOCACHE=/tmp/personal-blocker-go-cache`.

The executable default is port 5353, which can conflict with multicast DNS.
The examples below use `--listen=127.0.0.1:5533` to avoid that common conflict.

Stop with Ctrl-C. This development mode requires no root privileges and does not
change system or browser DNS settings. Starting it alone does not route browser
traffic through it.

## Test the running server

From another terminal:

```sh
dig @127.0.0.1 -p 5533 example.com A +noedns
dig @127.0.0.1 -p 5533 example.com A +noedns # expect CACHE in logs
dig @127.0.0.1 -p 5533 doubleclick.net A
dig @127.0.0.1 -p 5533 ads.doubleclick.net A
dig @127.0.0.1 -p 5533 doubleclick.net AAAA
dig @127.0.0.1 -p 5533 doubleclick.net A +tcp
dig @127.0.0.1 -p 5533 doubleclick.net TXT
```

Expected: a real upstream answer for example.com; `0.0.0.0` for blocked A;
`::` for blocked AAAA; an empty successful answer for other blocked types.
Logs report `BLOCK`, `ALLOW`, `CACHE`, or `ERROR`.

To verify an exception, add `example.com` to a temporary blocklist and use the
same domain in a temporary allowlist:

```sh
printf 'example.com\n' > /tmp/personal-blocker-test-block.txt
printf 'example.com\n' > /tmp/personal-blocker-test-allow.txt
# Stop the existing server first.
./personal-blocker run --listen=127.0.0.1:5533 \
  --blocklists=blocklists/ads.txt,/tmp/personal-blocker-test-block.txt \
  --allowlists=/tmp/personal-blocker-test-allow.txt
# From another terminal:
dig @127.0.0.1 -p 5533 example.com A +noedns
```

The real answer and `ALLOW ... matched=example.com` confirm allowlist precedence.

## Configuration

Use flags before the domain argument in `test`. Paths are relative to the current
working directory. `run --help` and `test --help` list supported flags.

```sh
./personal-blocker run \
  --listen=127.0.0.1:5533 \
  --upstreams=1.1.1.1:53,9.9.9.9:53 \
  --blocklists=blocklists/ads.txt,blocklists/trackers.txt \
  --allowlists=blocklists/allow.txt \
  --timeout=2s --cache-ttl=5m --cache-size=4096
```

Upstreams use numeric IP:port addresses, with brackets for IPv6. They are tried
in order on network errors, SERVFAIL, or REFUSED. Truncated UDP replies trigger
TCP fallback within the same per-upstream timeout. If all fail, clients receive
SERVFAIL. Zone transfers, non-IN classes, and TSIG requests are refused. The
handler rejects multiple questions with FORMERR; the DNS library also rejects
malformed messages before dispatch.

Successful positive responses are cached up to the smallest record TTL or the
configured maximum, whichever is shorter. TTLs age on retrieval; the cache is
bounded to 4096 entries by default. Requests with EDNS options bypass this basic
cache, which is why cache demonstrations use `+noedns`. Negative answers are
not cached. Use `--cache-ttl=0` to disable caching.

Logs go to stderr only; the app creates no persistent query log. Use
`--query-log=false` to disable query decision logs, including query errors.
Startup and operational errors remain visible.

## Lists

```text
# Comments and blank lines are accepted.
doubleclick.net
0.0.0.0 tracker.example another-tracker.example
127.0.0.1 telemetry.example # inline comment
```

Names are lowercased and a trailing dot is removed. Rules match complete domain
labels: `doubleclick.net` also blocks `ads.doubleclick.net`, but not
`notdoubleclick.net` or `doubleclick.net.evil.com`. Allowlist rules always win
and also cover subdomains. Diagnostics include the matching file and line.
Use ASCII/punycode names. Malformed entries warn and are skipped; missing files
fail startup. Empty lists are valid. Pass `--allowlists=` for no allowlist.

Send SIGHUP to reload after editing lists (see below). EasyList/Adblock Plus URL rules, wildcard
syntax, and cosmetic filters are not supported.

## Troubleshooting and next steps

- If an upstream times out, verify your network permits UDP/TCP port 53 or choose
  a reachable resolver with `--upstreams`.
- If a site breaks, add the needed domain to `blocklists/allow.txt` and reload.
- Chrome Secure DNS and Firefox DNS-over-HTTPS can bypass system DNS. Disable
  them when testing browser integration later. Direct `dig` commands above
  query the blocker explicitly.
- If the address is busy, stop the other process or choose another local port.

See [system integration](docs/system-integration.md) for the inspected resolver
configuration, prepared user service, temporary routing commands, and rollback.
System DNS changes require explicit approval.

## Download a maintained list

The explicit updater defaults to [HaGeZi Light](https://github.com/hagezi/dns-blocklists#multi-light).
The maintainer describes it as relaxed with minimal breakage risk. The selected
`wildcard/light-onlydomains.txt` format contains plain domains and fits suffix
matching; asterisk syntax is not supported. The source URL comes from the
maintainer's current README. Light intentionally allows some error trackers.

```sh
./personal-blocker update-lists
./personal-blocker run --listen=127.0.0.1:5533 \
  --blocklists=blocklists/ads.txt,blocklists/trackers.txt,blocklists/hagezi-light.txt
```

The download is generated locally and ignored by Git. Starter-only runs still
work without it. Explicitly include the downloaded file in `--blocklists` for
both `run` and `test`; updating a file does not add it to a running server's paths.
Existing personal lists and allowlists are not edited by the default update.

Updates require HTTPS, limit redirects to five requests and decoded content to
16 MiB, and time out after 30 seconds. HTTP errors, malformed or empty lists,
oversized content, and failed writes leave the previous file intact. A validated
file is written beside the destination, synced, and atomically renamed. The
output reports domain count, byte count, and SHA-256 for diagnostics; the hash
is not independent source authentication. Header comments are preserved.

Custom domain/hosts sources and destinations are supported:

```sh
./personal-blocker update-lists --url=https://example.org/domains.txt \
  --output=blocklists/custom.txt --timeout=45s
```

The destination's parent directory must already exist. One file is updated per
invocation; updates do not run automatically and do not send reload signals.

## Reload without restarting

The `listening` log includes the process PID. After changing local lists or
running `update-lists`, send SIGHUP to that specific process:

```sh
# Replace 12345 with the PID shown by your running blocker.
kill -HUP 12345
```

`RELOAD complete; cache cleared` confirms activation. Missing or malformed files
log `RELOAD failed; keeping current rules`; fix them and signal again. Startup
still warns and skips malformed lines, but reload is deliberately strict to
avoid silently dropping active rules. Empty local files are allowed for
intentional removal of rules.

Each query uses one snapshot of rules and cache. Reload swaps both together.
Queries already in flight can finish using their old snapshot, but cannot put
old answers in the new cache. Browser/system DNS caches are separate and may
retain an earlier response until its TTL expires.

To repeat the live reload checks after building and downloading the list, run
`python3 scripts/check-reload.py`. It needs port 5533 free, `dig`, and upstream
network access. It uses temporary personal lists and stops its own server on
completion; system DNS is unaffected.

## Development

Run the checks locally:

```sh
test -z "$(gofmt -l cmd internal)"
go test -race ./...
go vet ./...
go build ./cmd/personal-blocker
```

GitHub Actions runs the same checks on pushes and pull requests.
