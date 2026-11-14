#!/usr/bin/env python3
"""Qualify semantic transport and source evidence using an owned loopback stub, not an actual model."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
    root = Path(tempfile.mkdtemp(prefix='prowl-semantic-native-'))
    (root / 'home').mkdir()
    state = {'mode': 'literal', 'calls': 0, 'auth': True}
    value = 'tulip-moon'
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_POST(self):
            state['calls'] += 1
            state['auth'] &= self.headers.get('Authorization') == 'Bearer owned-test-api-key'
            payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            text = payload['messages'][-1]['content']
            mode = state['mode']
            if mode == 'error':
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'owned private error body')
                return
            # Deliberately wrong offsets exercise exact unique-literal recovery.
            content = json.dumps({'candidates': [{'start': 1, 'end': 2, 'value': value}]})
            if mode == 'empty': content = '{"candidates":[]}'
            if mode == 'invented': content = '{"candidates":[{"start":0,"end":1,"value":"invented-secret"}]}'
            if mode == 'duplicate': content = '{"candidates":[],"candidates":[]}'
            if mode == 'missing': content = '{}'
            reason = 'length' if mode == 'length' else 'stop'
            data = json.dumps({'choices': [{'finish_reason': reason, 'message': {'content': content}}]}).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    env = dict(os.environ, PROWL_HOME=str(root / 'home'), PROWL_SEMANTIC_URL=f'http://127.0.0.1:{server.server_port}/model',
               PROWL_SEMANTIC_MODEL='owned-stub', PROWL_SEMANTIC_API_KEY='owned-test-api-key')
    checks = []
    def check(name, passed):
        checks.append({'case': name, 'passed': bool(passed)})
        if not passed: raise AssertionError(name)
    def run(args, data=b''):
        return subprocess.run([str(binary), *args], cwd=root, env=env, input=data, capture_output=True, timeout=20)
    try:
        check('identity-init', run(['identity', 'init']).returncode == 0)
        cases = [
            ('production.txt', 'Код доступа для архива завтра: tulip-moon', value),
            ('config.json', '{"note":"🔐 tulip\\u002dmoon"}', 'tulip\\u002dmoon'),
            ('config.toml', 'note="🔐 tulip\\u002dmoon"', 'tulip\\u002dmoon'),
            ('config.yaml', 'note: "🔐 tulip\\u002dmoon"', 'tulip\\u002dmoon'),
        ]
        for path, text, source in cases:
            (root / path).write_text(text)
            for stdin in (False, True):
                args = ['--stdin-name=' + path] if stdin else [path]
                for fmt in ('json', 'sarif'):
                    before = state['calls']
                    result = run(['scan', *args, '--semantic', '--format=' + fmt, '--silence'], text.encode() if stdin else b'')
                    data = json.loads(result.stdout)
                    meta = data if fmt == 'json' else data['runs'][0]['properties']
                    fs = data['findings'] if fmt == 'json' else [dict(f['properties'], type=f['ruleId']) for f in data['runs'][0]['results']]
                    name = f'{path}/{stdin}/{fmt}'
                    check(name + '/candidate', result.returncode == 0 and meta['complete'] and len(fs) == 1 and fs[0]['type'] == 'generic_semantic_secret' and fs[0].get('verified') is None)
                    check(name + '/one-request', state['calls'] == before + 1)
                    start = len(text[:text.index(source)].encode())
                    end = start + len(source.encode())
                    check(name + '/source-proof', any(e['transform'] == 'literal-semantic-span' and e['start'] == start and e['end'] == end for e in fs[0]['evidence']))
                    check(name + '/redaction', value.encode() not in result.stdout and b'owned-test-api-key' not in result.stdout)
        before = state['calls']
        check('opt-out', run(['scan', 'production.txt', '--semantic=false', '--format=json', '--silence']).returncode == 0 and state['calls'] == before)
        before = state['calls']
        check('compare-rejected', run(['compare', 'production.txt', '--semantic']).returncode == 2 and state['calls'] == before)
        output = root / 'owned-report.json'
        output.write_bytes(b'owned report sentinel\n')
        result = run(['scan', 'production.txt', '--semantic-url=https://owned.invalid/model', '--output=' + str(output)])
        check('remote-refused-before-output', result.returncode == 2 and output.read_bytes() == b'owned report sentinel\n' and state['calls'] == before and b'owned-test-api-key' not in result.stderr)
        for mode in ('invented', 'duplicate', 'missing', 'length', 'error'):
            state['mode'] = mode
            baseline = root / (mode + '.baseline')
            baseline.write_bytes(b'owned baseline sentinel\n')
            for fmt in ('json', 'sarif'):
                result = run(['scan', 'production.txt', '--semantic', '--format=' + fmt, '--silence', '--write-baseline=' + str(baseline)])
                data = json.loads(result.stdout)
                meta = data if fmt == 'json' else data['runs'][0]['properties']
                check(mode + '/' + fmt + '/incomplete', result.returncode == 2 and not meta['complete'] and baseline.read_bytes() == b'owned baseline sentinel\n')
                check(mode + '/' + fmt + '/safe-error', b'owned private error body' not in result.stdout and b'invented-secret' not in result.stdout)
        state['mode'] = 'literal'
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
                tools = exchange(2, 'tools/list', {})['result']['tools']
                check(protocol + '/schema', all('semantic' in t['inputSchema']['properties'] for t in tools))
                response = exchange(3, 'tools/call', {'name': 'prowl_scan', 'arguments': {'path': 'production.txt', 'semantic': True}})['result']
                check(protocol + '/candidate', not response['isError'] and response['structuredContent']['findings'][0]['type'] == 'generic_semantic_secret')
                state['mode'] = 'invented'
                response = exchange(4, 'tools/call', {'name': 'prowl_scan', 'arguments': {'path': 'production.txt', 'semantic': True}})['result']
                check(protocol + '/failed-model', response['isError'] and not response['structuredContent']['complete'])
                state['mode'] = 'literal'
            finally:
                proc.stdin.close()
                proc.wait(timeout=20)
        check('model-auth', state['auth'])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=20)
        report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'passed': sum(c['passed'] for c in checks), 'total': len(checks), 'checks': checks,
                  'root': str(root), 'scope': 'owned loopback stub only; no actual model quality or live-provider qualification'}
        (root / 'qualification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps({k: v for k, v in report.items() if k != 'checks'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
