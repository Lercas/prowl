#!/usr/bin/env python3
"""Qualify native web response/view provenance using owned HTTP and a port-scoped OS sandbox."""
import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
from urllib.parse import parse_qs, unquote, urlparse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='prowl-domain-provenance-native-'))
    model = Path(__file__).resolve().parents[1] / 'tool/internal/mlmodel/model_binary_go_literal_v1.json'
    key = 'AKIANAFGYOEYPXU1DSYP'
    logical = 'const key="' + key + '";'
    state_text = '{"api_key":"\\u0041' + key[1:] + '"}'
    map_bytes = json.dumps({'version': 3, 'sources': ['same #?秘密.js'] * 2,
                            'sourcesContent': [logical] * 2}).encode()
    state = {'mode': 'basic', 'requests': [], 'bodies': {}}
    checks = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_GET(self):
            state['requests'].append(self.path)
            path = urlparse(self.path).path
            mode = state['mode']
            status, body = 200, b''
            if path == '/':
                if mode == 'empty': status = 204
                else:
                    self.send_response(302)
                    self.send_header('Location', '/page?sig=PRIVATE_PAGE')
                    self.end_headers()
                    return
            elif path == '/page':
                if mode == 'selectors':
                    body = b'<script src="/bundle.js?sig=PRIVATE_ONE"></script><script src="/bundle.js?sig=PRIVATE_TWO"></script>'
                elif mode in ('prefix', 'missing'):
                    body = ('<script src="/' + mode + '.js?sig=PRIVATE_INPUT"></script>').encode()
                else:
                    body = ('<script id="__NEXT_DATA__" type="application/json">' + state_text
                            + '</script><script src="/bundle.js?sig=PRIVATE_BUNDLE"></script>').encode()
            elif path == '/bundle.js':
                if mode == 'selectors':
                    body = (logical + '\n// selection ' + parse_qs(urlparse(self.path).query)['sig'][0]).encode()
                elif mode == 'inline':
                    body = (logical + '\n//# sourceMappingURL=data:application/json;base64,'
                            + base64.b64encode(map_bytes).decode()).encode()
                else:
                    body = (logical + '\n//# sourceMappingURL=/source.map?sig=PRIVATE_MAP').encode()
            elif path == '/source.map': body = map_bytes
            elif path == '/prefix.js': body = logical.encode()
            else: status = 404
            state['bodies'].setdefault(path, set()).add(hashlib.sha256(body).hexdigest())
            self.send_response(status)
            self.send_header('Content-Length', str(len(body) + (5 if path == '/prefix.js' else 0)))
            self.end_headers()
            self.wfile.write(body)

    class Outside(BaseHTTPRequestHandler):
        calls = 0
        def log_message(self, *_): pass
        def do_GET(self):
            Outside.calls += 1
            self.send_response(200)
            self.end_headers()

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    outside = ThreadingHTTPServer(('127.0.0.1', 0), Outside)
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (server, outside)]
    for thread in threads: thread.start()
    target = f'http://127.0.0.1:{server.server_port}'
    profile = f'(version 1)(allow default)(deny network*)(allow network-outbound (remote ip "localhost:{server.server_port}"))'
    sandbox = ['/usr/bin/sandbox-exec', '-p', profile]
    env = {k: v for k, v in os.environ.items() if not k.startswith('PROWL_')}
    env.update(PROWL_HOME=str(root / 'home'), PROWL_ALLOW_PRIVATE_IPS='1', PROWL_LIVE_TEST='')

    def check(name, condition):
        assert condition, name
        checks.append({'case': name, 'passed': True})

    def run(args):
        p = subprocess.run([*sandbox, str(binary), *map(str, args)], cwd=root, env=env,
                           capture_output=True, timeout=35)
        assert key.encode() not in p.stdout + p.stderr, 'raw synthetic key leaked'
        assert b'PRIVATE_' not in p.stdout + p.stderr, 'private request selector leaked'
        return p

    def scan(fmt='json', ml=False, extra=()):
        flags = ['--ml', '--ml-model', model] if ml else []
        p = run(['domain', target, '--authorized', '--bundled', '--max-assets=30', '--format', fmt, *flags, *extra])
        d = json.loads(p.stdout)
        meta = d if fmt == 'json' else d['runs'][0]['properties']
        rows = d['findings'] if fmt == 'json' else [dict(f['properties'], type=f['ruleId']) for f in d['runs'][0]['results']]
        return p, d, meta, [f for f in rows if f['type'] == 'aws_access_key_id']

    try:
        allowed = subprocess.run([*sandbox, '/usr/bin/curl', '--silent', '--max-time', '2', target], capture_output=True)
        denied = subprocess.run([*sandbox, '/usr/bin/curl', '--silent', '--max-time', '2', f'http://127.0.0.1:{outside.server_port}'], capture_output=True)
        check('OS-sandbox-allows-only-owned-port', allowed.returncode == 0 and denied.returncode != 0 and Outside.calls == 0)
        check('report-identity-init', run(['identity', 'init']).returncode == 0)
        count = len(state['requests'])
        check('authorization-before-network', run(['domain', target]).returncode == 2 and len(state['requests']) == count)
        for mode in ('basic', 'inline', 'selectors', 'prefix', 'missing', 'empty'):
            state.update(mode=mode, bodies={})
            for ml in (False, True):
                for fmt in ('json', 'sarif'):
                    p, d, meta, findings = scan(fmt, ml)
                    complete = mode not in ('prefix', 'missing')
                    check(f'{mode}-{fmt}-ml{ml}-coverage', p.returncode == (0 if complete else 2) and meta['complete'] == complete
                          and any(s['kind'] == 'domain' for s in meta['scope']))
                    if mode in ('empty', 'missing'):
                        check(f'{mode}-{fmt}-ml{ml}-no-invented-key', not findings)
                        continue
                    check(f'{mode}-{fmt}-ml{ml}-findings', bool(findings) and all(f.get('occurrence_id') for f in findings))
                    for f in findings:
                        prov = f['provenance']
                        digest, container = prov['digest'], prov['container_digest']
                        check(f'{mode}-{fmt}-ml{ml}-digest-{len(checks)}', len(digest) == 64 and len(container) == 64
                              and container in state['bodies'][urlparse(prov['source_url']).path])
                        if prov['source_transform'].startswith('web-response'):
                            check('raw-or-prefix-digest-' + str(len(checks)), digest == container)
                    if fmt == 'sarif':
                        for f in d['runs'][0]['results']:
                            uri = f['locations'][0]['physicalLocation']['artifactLocation']['uri']
                            u = urlparse(uri)
                            check('safe-SARIF-URI-' + str(len(checks)), not u.query and not u.username)
                        if mode in ('basic', 'inline'):
                            views = [f for f in d['runs'][0]['results'] if f['properties'].get('provenance', {}).get('source_transform') == 'source-map-content']
                            uris = [f['locations'][0]['physicalLocation']['artifactLocation']['uri'] for f in views]
                            check('distinct-map-SARIF-views-' + str(len(checks)), len(uris) == 2 and len(set(uris)) == 2
                                  and all(urlparse(u).scheme == 'web+http' and 'same #?秘密.js' in unquote(urlparse(u).fragment) for u in uris))
            if mode in ('prefix', 'missing'):
                baseline = root / (mode + '-baseline.json')
                baseline.write_text('owned baseline sentinel')
                p, _, meta, _ = scan(extra=['--write-baseline', baseline])
                check(mode + '-baseline-protected', p.returncode == 2 and not meta['complete'] and baseline.read_text() == 'owned baseline sentinel')
        state.update(mode='selectors', bodies={})
        index = root / 'index'
        for n in range(2):
            p, _, meta, _ = scan(extra=['--index', index, '--scope=owned-web'])
            check('indexed-selector-scan-' + str(n), p.returncode == 0 and meta['complete'])
        p = run(['index', '--index', index, '--format=json'])
        view = json.loads(p.stdout)
        positions = [p for s in view['secrets'] for p in s['locations'] if p['type'] == 'aws_access_key_id']
        check('index-private-query-locations-stable', len(positions) == 2 and len({p['id'] for p in positions}) == 2
              and len({p['path'] for p in positions}) == 1 and all(p['path'] == target + '/bundle.js' for p in positions))
        state.update(mode='missing', bodies={})
        p, _, meta, _ = scan(extra=['--index', index, '--scope=owned-web'])
        check('index-failed-acquisition', p.returncode == 2 and not meta['complete'])
        p = run(['index', '--index', index, '--format=json'])
        view = json.loads(p.stdout)
        check('failed-snapshot-does-not-certify-absence', not view['scans'][-1]['complete'] and view['secrets'][0]['location_count'] == 2)
        check('SQLite-retains-no-private-inputs', all(key.encode() not in p.read_bytes() and b'PRIVATE_' not in p.read_bytes()
                                                   for p in index.iterdir() if p.is_file()))
        evidence = {'binary': str(binary), 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                    'model_sha256': hashlib.sha256(model.read_bytes()).hexdigest(), 'fixture_root': str(root),
                    'passed': len(checks), 'failed': 0, 'checks': checks,
                    'network_control': {'profile': profile, 'outside_owned_requests': Outside.calls, 'blocked_exit': denied.returncode},
                    'scope': 'Owned HTTP response, redirect, decoded state, duplicate/inline source-map views, partial response, JSON/SARIF, ML and index. No real provider/account qualification.'}
        (root / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
        print(json.dumps({'passed': len(checks), 'evidence': str(root / 'evidence.json')}))
    finally:
        for server in (server, outside): server.shutdown(); server.server_close()
        for thread in threads: thread.join()


if __name__ == '__main__':
    main()
