#!/usr/bin/env python3
"""Qualify ML transfer consent and loopback isolation using an owned local sidecar."""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading

VALUE = 'Xk9Zm2Qp7Lr4Ns8Tv1Wy6Bd3Fg5Hj0aQw'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    with socket.socket() as probe:
        try:
            probe.bind(('192.0.2.1', 0))
        except PermissionError:
            pass
        else:
            raise RuntimeError('OS deny except loopback is required')
    root = Path(tempfile.mkdtemp(prefix='prowl-ml-endpoint-native-'))
    (root / 'home').mkdir()
    (root / 'production.env').write_text('The secret is "' + VALUE + '"\n')
    env = {k: v for k, v in os.environ.items() if not k.startswith('PROWL_')}
    env.update(PROWL_HOME=str(root / 'home'), PROWL_LIVE_TEST='')
    state = {'mode': 'normal', 'score': 0, 'trap': 0, 'records': []}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            state['trap'] += 1
            self.send_response(200)
            self.end_headers()

        def do_POST(self):
            if self.path != '/selected/score':
                state['trap'] += 1
                self.send_response(500)
                self.end_headers()
                return
            state['score'] += 1
            data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            state['records'].extend(data['records'])
            if state['mode'] != 'normal':
                self.send_response(int(state['mode']))
                self.send_header('Location', '/trap')
                self.end_headers()
                return
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'results': [{'score': 1} for _ in data['records']]}).encode())

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    endpoint = 'http://127.0.0.1:' + str(server.server_port) + '/selected'
    checks = []

    def check(name, condition):
        if not condition:
            raise AssertionError(name)
        checks.append({'case': name, 'passed': True})

    def run(label, flags, fmt='json', stdin=False, env_extra=None):
        command = [str(binary), 'scan', '--format=' + fmt, '--silence', '--bundled', *flags]
        data = None
        if stdin:
            command += ['--stdin-name=unopened/owned.json']
            data = json.dumps({'note': 'The secret is "' + VALUE + '"'}).encode()
        else:
            command += ['production.env']
        result = subprocess.run(command, cwd=root, env=env | (env_extra or {}), input=data,
                                capture_output=True, timeout=20)
        (root / (label + '.stdout')).write_bytes(result.stdout)
        (root / (label + '.stderr')).write_bytes(result.stderr)
        check(label + '-privacy', VALUE.encode() not in result.stdout + result.stderr and b'PRIVATE_ENDPOINT' not in result.stdout + result.stderr)
        return result

    try:
        for fmt in ('json', 'sarif'):
            for stdin in (False, True):
                label = fmt + '-stdin' + str(stdin)
                before = state['score']
                result = run(label, ['--ml-url=' + endpoint], fmt, stdin,
                             {'HTTP_PROXY': endpoint + '/trap', 'HTTPS_PROXY': endpoint + '/trap', 'ALL_PROXY': endpoint + '/trap'})
                payload = json.loads(result.stdout)
                meta = payload if fmt == 'json' else payload['runs'][0]['properties']
                check(label + '-complete', result.returncode == 0 and meta['complete'])
                check(label + '-selected-service', state['score'] > before and state['trap'] == 0)
                check(label + '-raw-transfer-only-selected', any(r['value'] == VALUE for r in state['records']))
                check(label + '-unknown-model-policy', any(s['kind'] == 'unversioned_policy' and s['target'] == 'ml' for s in meta['scope']))
        for label, flags in [
            ('remote-default', ['--ml-url=https://owned.invalid/selected']),
            ('remote-plaintext', ['--ml-url=http://owned.invalid/selected', '--ml-allow-remote']),
            ('credential-url', ['--ml-url=http://user:PRIVATE_ENDPOINT@127.0.0.1:8799']),
            ('query-url', ['--ml-url=' + endpoint + '?token=PRIVATE_ENDPOINT']),
            ('fragment-url', ['--ml-url=' + endpoint + '#PRIVATE_ENDPOINT']),
            ('explicit-false', ['--ml-url=https://owned.invalid/selected', '--ml-allow-remote', '--ml-allow-remote=false']),
        ]:
            output = root / (label + '.report')
            baseline = root / (label + '.baseline')
            index = root / (label + '.index')
            output.write_text('owned report sentinel\n')
            baseline.write_text('owned baseline sentinel\n')
            before = state['score']
            result = run(label, [*flags, '--output=' + str(output), '--write-baseline=' + str(baseline), '--index=' + str(index)])
            check(label + '-preflight', result.returncode == 2 and b'ML endpoint policy' in result.stderr and not result.stdout)
            check(label + '-no-transfer', state['score'] == before and state['trap'] == 0)
            check(label + '-artifacts', output.read_text() == 'owned report sentinel\n' and baseline.read_text() == 'owned baseline sentinel\n' and not index.exists())
        for status in ('301', '302', '303', '307', '308'):
            state['mode'] = status
            label = 'redirect-' + status
            before = state['score']
            result = run(label, ['--ml-url=' + endpoint])
            data = json.loads(result.stdout)
            check(label + '-fail-open', result.returncode == 0 and data['complete'] and not data['filtered'] and any(s['kind'] == 'unversioned_policy' for s in data['scope']))
            check(label + '-no-forward', state['score'] > before and state['trap'] == 0)
            check(label + '-retains-finding', any(f['type'] == 'generic_high_entropy' for f in data['findings']))
        output = root / 'evidence.json'
        output.write_text(json.dumps({'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'passed': True,
                                      'checks': checks, 'network': 'OS denies all network except owned loopback',
                                      'boundary': 'Only owned local HTTP sidecar. No remote endpoint contacted; explicit remote HTTPS construction covered by a Go owned-transport test.'}, indent=2) + '\n')
        print(json.dumps({'passed': len(checks), 'evidence': str(output)}))
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


if __name__ == '__main__':
    main()
