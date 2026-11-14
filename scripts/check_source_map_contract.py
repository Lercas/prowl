#!/usr/bin/env python3
"""Qualify source-map and literal module acquisition against owned loopback fixtures."""
import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
from urllib.parse import quote, urlparse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='prowl-maps-native-'))
    (root / 'home').mkdir()
    state = {'mode': 'basic', 'requests': [], 'external': 0}
    value = 'AKIANAFGYOEYPXU1DSYP'
    original = "// 🔐\nconst key='" + value + "';\n"
    map_data = {'version': 3, 'sources': ['src/config.ts'], 'sourcesContent': [original]}
    class External(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            state['external'] += 1
            self.send_response(200)
            self.end_headers()
    outside = ThreadingHTTPServer(('127.0.0.1', 0), External)
    outside_thread = threading.Thread(target=outside.serve_forever, daemon=True)
    outside_thread.start()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            path = urlparse(self.path).path
            state['requests'].append(self.path)
            mode = state['mode']
            name = path.rsplit('/', 1)[-1]
            status = 200
            body = ''
            if path == '/':
                ext = 'APP.JS' if mode == 'uppercase' else 'bundle.js'
                body = f'<script src="/{mode}/{ext}"></script>'
            elif mode == 'redirect' and path == '/redirect/bundle.js':
                self.send_response(302)
                self.send_header('Location', '/redirect/release/bundle.js?v=2')
                self.end_headers()
                return
            elif name in ('bundle.js', 'APP.JS'):
                if mode == 'inline':
                    ref = 'data:application/json;base64,' + base64.b64encode(json.dumps(map_data).encode()).decode()
                elif mode == 'percent':
                    ref = 'data:application/json;charset=utf-8,' + quote(json.dumps(map_data), safe='')
                elif mode == 'external':
                    ref = f'http://127.0.0.1:{outside.server_port}/outside.map'
                elif mode == 'bad-inline': ref = 'data:application/json;base64,not-base64'
                elif mode == 'opaque': ref = 'opaque-data'
                else: ref = 'renamed.map'
                body = "import './chunk.js';\n//# sourceMappingURL=" + ref
                if mode == 'depth': body = "import './chunk1.js';"
            elif name == 'chunk.js':
                body = 'const publicNumber = 42;'
            elif mode == 'depth' and name.startswith('chunk') and name.endswith('.js'):
                index = int(name[5:-3])
                body = "import './chunk" + str(index + 1) + ".js';" if index < 6 else "const key='" + value + "';"
            elif name in ('renamed.map', 'opaque-data'):
                if mode == 'missing': status = 404
                elif mode == 'invalid': body = '{"version":2,"sources":[],"sourcesContent":[]}'
                elif mode == 'duplicate': body = '{"version":3,"version":3,"sources":[],"sourcesContent":[]}'
                elif mode == 'null': body = '{"version":3,"sources":["src/config.ts"],"sourcesContent":[null]}'
                elif mode == 'empty': status = 204
                else: body = json.dumps(map_data)
            else: status = 404
            data = body.encode()
            self.send_response(status)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = f'http://127.0.0.1:{server.server_port}'
    env = dict(os.environ, PROWL_HOME=str(root / 'home'), PROWL_ALLOW_PRIVATE_IPS='1')
    checks = []
    def check(name, passed):
        checks.append({'case': name, 'passed': bool(passed)})
        if not passed: raise AssertionError(name)
    def run(args):
        return subprocess.run([str(binary), *args], cwd=root, env=env, input=b'', capture_output=True, timeout=30)
    try:
        check('identity', run(['identity', 'init']).returncode == 0)
        before = len(state['requests'])
        check('authorization-before-network', run(['domain', target, '--format=json']).returncode == 2 and len(state['requests']) == before)
        for mode in ('basic', 'inline', 'percent', 'opaque', 'redirect', 'uppercase'):
            state['mode'] = mode
            for ml in (False, True):
                for fmt in ('json', 'sarif'):
                    result = run(['domain', target, '--authorized', '--timeout=10s', '--max-assets=32', '--format=' + fmt, '--silence', *(['--ml'] if ml else [])])
                    data = json.loads(result.stdout)
                    meta = data if fmt == 'json' else data['runs'][0]['properties']
                    fs = data['findings'] if fmt == 'json' else [dict(f['properties'], type=f['ruleId']) for f in data['runs'][0]['results']]
                    mapped = [f for f in fs if f.get('provenance', {}).get('original_source') == 'src/config.ts']
                    name = f'{mode}/{ml}/{fmt}'
                    check(name + '/mapped', result.returncode == 0 and meta['complete'] and len(mapped) == 1 and mapped[0]['type'] == 'aws_access_key_id')
                    check(name + '/digest', mapped[0]['provenance']['digest'] == hashlib.sha256(original.encode()).hexdigest())
                    check(name + '/scope', any(s['kind'] == 'domain' for s in meta['scope']))
                    check(name + '/redacted', value.encode() not in result.stdout)
        for mode in ('missing', 'invalid', 'duplicate', 'null', 'empty', 'bad-inline', 'depth', 'budget'):
            state['mode'] = 'basic' if mode == 'budget' else mode
            for fmt in ('json', 'sarif'):
                baseline = root / (mode + '-' + fmt + '.baseline')
                baseline.write_bytes(b'owned sentinel baseline\n')
                result = run(['domain', target, '--authorized', '--timeout=10s', '--max-assets=' + ('2' if mode == 'budget' else '32'), '--format=' + fmt, '--silence', '--write-baseline=' + str(baseline)])
                data = json.loads(result.stdout)
                meta = data if fmt == 'json' else data['runs'][0]['properties']
                check(mode + '/' + fmt + '/incomplete', result.returncode == 2 and not meta['complete'])
                check(mode + '/' + fmt + '/baseline', baseline.read_bytes() == b'owned sentinel baseline\n')
        state['mode'] = 'external'
        result = run(['domain', target, '--authorized', '--format=json', '--silence'])
        check('outside-origin-not-fetched', result.returncode == 0 and state['external'] == 0)
        state['mode'] = 'basic'
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
                return replies.get(timeout=30)
            try:
                exchange(1, 'server/discover' if protocol == '2026-07-28' else 'initialize', {'protocolVersion': protocol})
                response = exchange(2, 'tools/call', {'name': 'prowl_domain', 'arguments': {'target': target, 'authorized': True}})['result']
                check(protocol + '/native-domain', not response['isError'] and response['structuredContent']['complete'] and any(f.get('provenance', {}).get('original_source') == 'src/config.ts' for f in response['structuredContent']['findings']))
            finally:
                proc.stdin.close()
                proc.wait(timeout=30)
    finally:
        server.shutdown()
        outside.shutdown()
        server.server_close()
        outside.server_close()
        thread.join(timeout=30)
        outside_thread.join(timeout=30)
        report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'passed': sum(c['passed'] for c in checks), 'total': len(checks), 'checks': checks,
                  'root': str(root), 'scope': 'owned loopback web surface, no recon, external hosts or live provider verification'}
        (root / 'qualification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps({k: v for k, v in report.items() if k != 'checks'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
