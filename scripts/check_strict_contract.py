#!/usr/bin/env python3
"""Qualify strict compatibility while preserving mandatory incomplete-scan failure."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='prowl-strict-native-'))
    (root / 'home').mkdir()
    env = dict(os.environ, PROWL_HOME=str(root / 'home'))
    (root / 'clean.txt').write_text('ordinary text')
    (root / 'production.env').write_text('AWS=AKIANAFGYOEYPXU1DSYP')
    (root / 'malformed.json').write_text('{"password":"Winter42!Autumn\\q"}')
    (root / 'large.txt').write_text('x' * 256)
    checks = []

    def check(name, passed):
        checks.append({'case': name, 'passed': bool(passed)})
        if not passed: raise AssertionError(name)

    def run(args):
        return subprocess.run([str(binary), *args], cwd=root, env=env, input=b'', capture_output=True, timeout=20)

    for mode, flags in [('default', []), ('strict', ['--strict']), ('false', ['--strict=false']), ('ci', ['--ci']), ('ci-false', ['--ci', '--strict=false'])]:
        for fmt in ('json', 'sarif'):
            for name, path, extra, code, complete in [
                ('clean', 'clean.txt', [], 0, True),
                ('finding', 'production.env', ['--fail-on=high'], 1, True),
                ('malformed', 'malformed.json', [], 2, False),
                ('oversize', 'large.txt', ['--max-size=16'], 2, False),
            ]:
                result = run(['scan', path, '--format=' + fmt, '--silence', *extra, *flags])
                data = json.loads(result.stdout)
                meta = data if fmt == 'json' else data['runs'][0]['properties']
                check(f'{mode}/{fmt}/{name}', result.returncode == code and meta['complete'] == complete)
                if not complete:
                    baseline = root / f'{mode}-{fmt}-{name}.baseline'
                    baseline.write_bytes(b'owned sentinel baseline\n')
                    result = run(['scan', path, '--format=' + fmt, '--silence', '--min-severity=critical', '--write-baseline=' + str(baseline), *extra, *flags])
                    check(f'{mode}/{fmt}/{name}/baseline', result.returncode == 2 and baseline.read_bytes() == b'owned sentinel baseline\n')
        result = run(['scan', 'production.env', '--format=json', '--silence', '--fail-on=critical', *flags])
        check(mode + '/explicit-gate', result.returncode == 0)
    check('invalid-boolean', run(['scan', 'clean.txt', '--strict=invalid']).returncode == 2)
    check('startup-rejected', run(['mcp', '--strict']).returncode == 2)
    for protocol in ('2024-11-05', '2025-03-26', '2025-06-18', '2026-07-28'):
        proc = subprocess.Popen([str(binary), 'mcp'], cwd=root, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        replies = queue.Queue()
        def reader():
            for line in proc.stdout:
                try: replies.put(json.loads(line))
                except ValueError: replies.put({'invalid_json': True})
        threading.Thread(target=reader, daemon=True).start()
        def exchange(ident, method, params):
            if protocol == '2026-07-28':
                params['_meta'] = {'io.modelcontextprotocol/protocolVersion': protocol, 'io.modelcontextprotocol/clientCapabilities': {}}
            proc.stdin.write((json.dumps({'jsonrpc': '2.0', 'id': ident, 'method': method, 'params': params}) + '\n').encode())
            proc.stdin.flush()
            return replies.get(timeout=20)
        try:
            exchange(1, 'server/discover' if protocol == '2026-07-28' else 'initialize', {'protocolVersion': protocol})
            listing = exchange(2, 'tools/list', {})['result']['tools']
            check(protocol + '/schema', all('strict' in t['inputSchema']['properties'] for t in listing))
            for i, flag in enumerate((False, True)):
                result = exchange(i + 3, 'tools/call', {'name': 'prowl_scan', 'arguments': {'path': 'malformed.json', 'strict': flag}})['result']
                check(protocol + f'/incomplete/{flag}', result['isError'] and not result['structuredContent']['complete'])
        finally:
            proc.stdin.close()
            proc.wait(timeout=20)
    report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'passed': sum(c['passed'] for c in checks), 'total': len(checks), 'checks': checks,
              'root': str(root), 'scope': 'local CLI and four MCP transports; no provider calls'}
    (root / 'qualification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'checks'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
