#!/usr/bin/env python3
"""Exercise the built blocker with dig and temporary lists; never change system DNS."""
from pathlib import Path
import signal
import subprocess
import tempfile
import time

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='personal-blocker-check-') as directory:
    temp = Path(directory)
    block, allow, log = (temp / name for name in ('block', 'allow', 'log'))
    block.write_text('doubleclick.net\n')
    allow.write_text('')
    with log.open('w') as output:
        proc = subprocess.Popen([
            str(root / 'personal-blocker'), 'run', '--listen=127.0.0.1:5533',
            '--blocklists=' + str(block) + ',' + str(root / 'blocklists/hagezi-light.txt'),
            '--allowlists=' + str(allow),
        ], cwd=root, stdout=output, stderr=output)
        def wait_log(text, after=0):
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                if text in log.read_text()[after:]:
                    return
                if proc.poll() is not None:
                    raise RuntimeError(log.read_text())
                time.sleep(0.03)
            raise AssertionError('missing log: ' + text + '\n' + log.read_text())
        def query(domain, blocked=False, extra=()):
            result = subprocess.run([
                'dig', '@127.0.0.1', '-p', '5533', domain, 'A', '+noedns',
                '+short', '+time=3', '+tries=1', *extra,
            ], text=True, capture_output=True, check=True).stdout.strip()
            assert result, (domain, 'empty answer')
            if blocked:
                assert result == '0.0.0.0', result
            else:
                # This check uses example.com, whose direct A answers are IPv4.
                import ipaddress
                assert all(not ipaddress.ip_address(v).is_unspecified for v in result.splitlines()), result
            print(domain, 'BLOCK' if blocked else 'ALLOW', result.replace('\n', ', '))
        def reload_rules(expect='RELOAD complete'):
            offset = len(log.read_text())
            proc.send_signal(signal.SIGHUP)
            wait_log(expect, offset)
        try:
            wait_log('msg=listening')
            downloaded_domain = next(line.strip() for line in (root / 'blocklists/hagezi-light.txt').read_text().splitlines() if line.strip() and not line.startswith('#'))
            query(downloaded_domain, True)
            query('doubleclick.net', True)
            query('ads.doubleclick.net', True, ('+tcp',))
            query('example.com')
            query('example.com')
            wait_log('msg=CACHE')
            block.write_text('doubleclick.net\nexample.com\n')
            reload_rules()
            query('example.com', True)
            block.write_text('bad rule\n')
            reload_rules('RELOAD failed')
            query('example.com', True)
            block.write_text('doubleclick.net\nexample.com\n')
            allow.write_text('example.com\n')
            reload_rules()
            query('example.com')
            print('PASS: list-backed DNS, cache, successful reload, failed reload, and allowlist override')
        finally:
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            print(log.read_text())
        assert proc.returncode == 0, proc.returncode
