#!/usr/bin/env python3
"""Qualify embedded policy selection without live provider calls or installed data changes."""
import argparse
import hashlib
import json
import os
import queue
import threading
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='prowl-bundled-native-'))
    checks = []

    def check(name, condition):
        checks.append({'case': name, 'passed': bool(condition)})
        if not condition:
            raise AssertionError(name)

    value = '83ea947bc2567d10a5f390c2eb468d91'
    typed = json.dumps({'assemblyai': {'api_key': value}})
    for mode in ('absent', 'broken-path', 'overlay'):
        work = root / mode
        home = work / 'home'
        home.mkdir(parents=True)
        env = dict(os.environ, PROWL_HOME=str(home))
        (work / 'production.json').write_text(typed)
        (work / 'clean.txt').write_text('ordinary text')
        if mode == 'broken-path':
            (home / 'rules').write_text('not a directory')
            (home / 'verifiers').write_text('not a directory')
        if mode == 'overlay':
            (home / 'rules').mkdir()
            (home / 'rules/owned.yaml').write_text('id: owned-unused\ninfo: {name: Owned, severity: high}\nmatchers:\n - type: word\n   words: [OWNED_UNUSED_PATTERN]\n')
            (home / 'verifiers').mkdir()
            (home / 'verifiers/owned.yaml').write_text('id: owned-unused\nmatch: [owned_unused_type]\nrequests:\n - url: http://127.0.0.1:9/check\n')
        def run(args, data=b''):
            return subprocess.run([str(binary), *args], cwd=work, env=env, input=data, capture_output=True, timeout=20)
        check(mode + '/identity-init', run(['identity', 'init']).returncode == 0)
        key_before = (home / 'identity.key').read_bytes()
        ids = []
        for bundled in (False, True):
            flags = ['--bundled'] if bundled else []
            for fmt in ('json', 'sarif'):
                result = run(['scan', 'production.json', '--format=' + fmt, '--silence', *flags])
                name = f'{mode}/{bundled}/{fmt}'
                if mode == 'broken-path' and not bundled:
                    check(name + '/fail-closed', result.returncode == 2)
                    continue
                data = json.loads(result.stdout)
                findings = data['findings'] if fmt == 'json' else data['runs'][0]['results']
                types = [f.get('type', f.get('ruleId')) for f in findings]
                expected = bundled or mode == 'absent'
                check(name + '/typed', ('assemblyai-api-key' in types) == expected)
                check(name + '/redaction', value.encode() not in result.stdout)
                if fmt == 'json' and expected:
                    ids.append(next(f['secret_id'] for f in findings if f['type'] == 'assemblyai-api-key'))
            # A clean fixture guarantees no provider can receive a candidate.
            result = run(['scan', 'clean.txt', '--verify', '--format=json', '--silence', *flags])
            if mode == 'broken-path' and not bundled:
                check(f'{mode}/{bundled}/verify-fail-closed', result.returncode == 2)
            else:
                data = json.loads(result.stdout)
                check(f'{mode}/{bundled}/verify-empty', result.returncode == 0 and data['complete'] and not data['findings'])
        check(mode + '/same-identity', len(set(ids)) == 1 and (home / 'identity.key').read_bytes() == key_before)
        result = run(['version', '--bundled'])
        check(mode + '/version-bundled', result.returncode == 0 and b'175 bundled' in result.stdout and b'84 bundled' in result.stdout)
        for args in (['rules', 'list'], ['rules', 'validate'], ['rules', 'stats'], ['verifiers', 'list'], ['verifiers', 'validate']):
            result = run(args)
            if mode == 'absent':
                count = b'84' if args[0] == 'verifiers' else b'175'
                check(mode + '/' + '/'.join(args), result.returncode == 0 and count in result.stdout + result.stderr)
            elif mode == 'broken-path':
                check(mode + '/' + '/'.join(args), result.returncode != 0)
        # MCP flags are per-call; a broken installed library must be ignored only on explicit selection.
        if mode == 'broken-path':
            for protocol in ('2024-11-05', '2025-03-26', '2025-06-18', '2026-07-28'):
                proc = subprocess.Popen([str(binary), 'mcp'], cwd=work, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                replies = queue.Queue()
                def read_output():
                    for line in proc.stdout:
                        try: replies.put(json.loads(line))
                        except ValueError: replies.put({'invalid_json': True})
                threading.Thread(target=read_output, daemon=True).start()
                def exchange(ident, method, params):
                    if protocol == '2026-07-28':
                        params['_meta'] = {'io.modelcontextprotocol/protocolVersion': protocol, 'io.modelcontextprotocol/clientCapabilities': {}}
                    proc.stdin.write((json.dumps({'jsonrpc': '2.0', 'id': ident, 'method': method, 'params': params}) + '\n').encode())
                    proc.stdin.flush()
                    return replies.get(timeout=20)
                try:
                    exchange(1, 'server/discover' if protocol == '2026-07-28' else 'initialize', {'protocolVersion': protocol})
                    listing = exchange(2, 'tools/list', {})['result']['tools']
                    check(protocol + '/schema', all('bundled' in t['inputSchema']['properties'] for t in listing))
                    for flag in (False, True):
                        response = exchange(3 + int(flag), 'tools/call', {'name': 'prowl_scan', 'arguments': {'path': 'production.json', 'bundled': flag}})['result']
                        check(protocol + f'/call/{flag}', (not response['isError']) == flag)
                        if flag:
                            fs = response['structuredContent']['findings']
                            check(protocol + '/typed-identity', any(f['type'] == 'assemblyai-api-key' and f['secret_id'] == ids[0] for f in fs))
                finally:
                    proc.stdin.close()
                    proc.wait(timeout=20)
            def frame(method, params=None, ident=None):
                msg = {'jsonrpc': '2.0', 'method': method}
                if params is not None: msg['params'] = params
                if ident is not None: msg['id'] = ident
                data = json.dumps(msg).encode()
                return f'Content-Length: {len(data)}\r\n\r\n'.encode() + data
            payload = frame('initialize', {'processId': None, 'rootUri': None, 'capabilities': {}}, 1)
            payload += frame('initialized', {})
            payload += frame('textDocument/didOpen', {'textDocument': {'uri': 'file:///production.json', 'version': 1, 'languageId': 'json', 'text': typed}})
            payload += frame('shutdown', ident=2) + frame('exit')
            result = run(['lsp', '--bundled'], payload)
            check('lsp/bundled-broken-overlay', result.returncode == 0 and b'assemblyai-api-key' in result.stdout and value.encode() not in result.stdout)
    report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'passed': sum(c['passed'] for c in checks), 'total': len(checks), 'checks': checks,
              'scope': 'local CLI, MCP and LSP; verification enabled only for empty fixtures; no live provider calls', 'root': str(root)}
    (root / 'qualification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'checks'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
