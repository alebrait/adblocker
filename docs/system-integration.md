# System integration

The blocker runs on localhost. Starting it does not change system or browser DNS.
Verify it directly with `dig` before configuring system integration.

## User service

The example in `packaging/personal-blocker.service` uses `%h/Proj/adblocker`.
Adjust WorkingDirectory and ExecStart for your checkout. Build the executable
and run `./personal-blocker update-lists` before using this example, which loads
the downloaded list explicitly. Stop any existing listener on port 5533 first.

```sh
systemd-analyze --user verify packaging/personal-blocker.service
mkdir -p ~/.config/systemd/user
cp packaging/personal-blocker.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user start personal-blocker
dig @127.0.0.1 -p 5533 example.com A
dig @127.0.0.1 -p 5533 doubleclick.net A
```

The service disables query logging because stderr goes to the journal.
Inspect operational messages with `journalctl --user -u personal-blocker`.
After editing lists, use `systemctl --user reload personal-blocker` and check
for `RELOAD complete`; signal delivery alone does not confirm validation.

## System DNS routing

Routing is a separate, manual step. Inspect your current resolver, active
interfaces, VPN settings, and DNS configuration before changing anything.
Save the baseline and prepare rollback commands specific to your machine.
Do not copy network settings from another system.

On systems using systemd-resolved, consult the installed `resolvectl` manual
for per-link DNS routing and whether IP:port upstreams are supported. Keep the
blocker's upstream resolvers external: routing it through the system stub can
create a forwarding loop. Verify both blocked and allowed queries through the
system resolver after making any change.

Restore and verify the original DNS configuration before stopping the blocker.
A normal user service stops on logout, so temporary routing must be restored
before logout. Persistent routing needs a separate plan for startup, reconnects,
VPNs, and service failures.

Chrome Secure DNS and Firefox DNS-over-HTTPS can bypass system DNS. Disable
these when testing the system resolver path. Browser caches and existing
connections can retain earlier results. DNS filtering cannot hide page elements.
