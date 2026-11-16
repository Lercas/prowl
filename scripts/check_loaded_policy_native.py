#!/usr/bin/env python3
"""Qualify loaded-model/verifier scope snapshots and fail-closed remediation locally."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading

KEY = 'AKIANAFGYOEYPXU1DSYP'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    # Check sandbox denial without sending any packet; localhost must remain allowed.
    with socket.socket() as probe:
        try:
            probe.bind(('192.0.2.1', 0))
        except PermissionError:
            pass
        else:
            raise RuntimeError('OS network deny outside loopback is required')
    root = Path(tempfile.mkdtemp(prefix='prowl-loaded-policy-native-'))
    home = root / 'home'
    home.mkdir()
    config = root / 'trusted.yaml'
    config.write_text('{}\n')
    source = root / 'production.env'
    model_source = Path(__file__).resolve().parents[1] / 'tool/internal/mlmodel/model_binary_go_literal_v1.json'
    names = json.loads(model_source.read_text())['feature_names']
    env = {k: v for k, v in os.environ.items() if not k.startswith('PROWL_')}
    env.update(PROWL_HOME=str(home), PROWL_LIVE_TEST='', PROWL_ALLOW_PRIVATE_IPS='1', NO_PROXY='127.0.0.1,localhost')
    checks, outputs = [], {}

    def check(case, ok):
        assert ok, case
        checks.append({'case': case, 'passed': True})

    def run(label, args):
        result = subprocess.run([str(binary), *map(str, args)], cwd=root, env=env, capture_output=True, timeout=40)
        output = root / (label + '.stdout')
        assert not output.exists(), label
        output.write_bytes(result.stdout)
        (root / (label + '.stderr')).write_bytes(result.stderr)
        outputs[label] = output
        return result

    def scan(label, text, flags=(), fmt='json'):
        source.write_text(text)
        result = run(label, ['scan', source.name, '--config', config, '--format=' + fmt, '--silence', '--workers=1', '--max-per-file=0', *flags])
        data = json.loads(result.stdout)
        meta = data if fmt == 'json' else data['runs'][0]['properties']
        check(label + '-complete', result.returncode == 0 and meta['complete'] and not meta.get('filtered'))
        check(label + '-redaction', all(marker.encode() not in result.stdout + result.stderr for marker in (KEY, 'private-model-path-marker', 'private-header-marker')))
        return meta

    def scope(meta, kind):
        values = [s for s in meta['scope'] if s['kind'] == kind]
        check(kind + '-single-scope-' + str(len(checks)), len(values) == 1)
        return values[0]

    def remediate(label, before, after, comparable, presence):
        result = run(label, ['remediation-check', outputs[before], outputs[after]])
        data = json.loads(result.stdout)
        check(label, result.returncode == (0 if comparable else 2) and data['comparable'] == comparable and data['complete'] and
              len(data['items']) == 1 and data['items'][0]['presence'] == presence and not data['items'][0]['closed'] and
              data['items'][0]['revocation'] == 'not_checked')

    def model_bytes(bias):
        return json.dumps({'baseline': bias, 'feature_names': names, 'trees': [{'feature_idx': [-1], 'threshold': [0],
                           'left': [0], 'right': [0], 'value': [0], 'missing_left': [0], 'is_leaf': [1]}]}).encode()

    class Handler(BaseHTTPRequestHandler):
        verification_calls = 0
        score_calls = 0

        def do_GET(self):
            if self.path != '/health':
                Handler.verification_calls += 1
                assert self.headers.get('Authorization') == 'Bearer ' + KEY
                assert self.path == '/owned'
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{}')

        def do_POST(self):
            assert self.path == '/score'
            records = json.loads(self.rfile.read(int(self.headers['Content-Length'])))['records']
            Handler.score_calls += 1
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({'results': [{'score': .9} for _ in records]}).encode())

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        check('identity-init', run('identity-init', ['identity', 'init']).returncode == 0)
        for installed in (False, True):
            mode = 'installed' if installed else 'explicit'
            path = home / 'model_binary.json' if installed else root / 'private-model-path-marker.json'
            flags = ['--ml'] if installed else ['--ml', '--ml-model', path]
            for fmt in ('json', 'sarif'):
                prefix = mode + '-' + fmt
                path.write_bytes(model_bytes(100))
                before = scan(prefix + '-before', 'AWS=' + KEY + '\n', flags, fmt)
                before_id = scope(before, 'ml_model')
                same = scan(prefix + '-same', 'ordinary text\n', flags, fmt)
                check(prefix + '-same-snapshot', before['scope'] == same['scope'])
                path.write_bytes(model_bytes(99))
                changed = scan(prefix + '-changed', 'ordinary text\n', flags, fmt)
                check(prefix + '-changed-snapshot', before_id != scope(changed, 'ml_model') and before['scope'] != changed['scope'])
                threshold = scan(prefix + '-threshold', 'ordinary text\n', [*flags, '--ml-threshold=.8'], fmt)
                check(prefix + '-threshold-identified', scope(changed, 'ml_model') != scope(threshold, 'ml_model'))
                if fmt == 'json':
                    remediate(prefix + '-matching-remediation', prefix + '-before', prefix + '-same', True, 'absent_in_scope')
                    remediate(prefix + '-changed-remediation', prefix + '-before', prefix + '-changed', False, 'inconclusive')
            if not installed:
                duplicate = root / 'same-bytes-new-filename.json'
                duplicate.write_bytes(path.read_bytes())
                copied = scan('model-other-filename', 'ordinary text\n', ['--ml', '--ml-model', duplicate])
                original = scan('model-original-filename', 'ordinary text\n', flags)
                check('model-digest-independent-of-filename', scope(copied, 'ml_model') == scope(original, 'ml_model'))
        verifier = root / 'owned-verifier.yaml'
        policy = f"id: owned\nmatch: [aws_access_key_id]\nrequests:\n - method: GET\n   url: http://127.0.0.1:{server.server_port}/owned\n   headers: {{Authorization: 'Bearer {{{{secret}}}}', X-Owned: private-header-marker}}\n   matchers:\n    - type: status\n      status: [200]\n"
        flags = ['--verify', '--verifiers', verifier]
        for fmt in ('json', 'sarif'):
            prefix = 'verifier-' + fmt
            verifier.write_text(policy)
            before = scan(prefix + '-before', 'AWS=' + KEY + '\n', flags, fmt)
            before_id = scope(before, 'verifiers')
            same = scan(prefix + '-same', 'ordinary text\n', flags, fmt)
            check(prefix + '-same-snapshot', before['scope'] == same['scope'])
            for suffix, old, new in [('status', '[200]', '[201]'), ('header', 'private-header-marker', 'other-private-header-marker'),
                                     ('url', '/owned', '/changed'), ('method', 'method: GET', 'method: POST')]:
                verifier.write_text(policy.replace(old, new))
                changed = scan(prefix + '-' + suffix, 'ordinary text\n', flags, fmt)
                check(prefix + '-' + suffix + '-different-snapshot', before_id != scope(changed, 'verifiers'))
                if fmt == 'json':
                    remediate(prefix + '-' + suffix + '-remediation', prefix + '-before', prefix + '-' + suffix, False, 'inconclusive')
            if fmt == 'json':
                remediate(prefix + '-same-remediation', prefix + '-before', prefix + '-same', True, 'absent_in_scope')
        check('owned-provider-only', Handler.verification_calls == 2)
        flags = ['--ml-url', f'http://127.0.0.1:{server.server_port}']
        before = scan('sidecar-before', 'AWS=' + KEY + '\n', flags)
        after = scan('sidecar-after', 'ordinary text\n', flags)
        check('sidecar-unversioned', scope(before, 'unversioned_policy') == scope(after, 'unversioned_policy') and before['scope'] == after['scope'])
        remediate('sidecar-remediation', 'sidecar-before', 'sidecar-after', False, 'inconclusive')
        check('owned-sidecar-used', Handler.score_calls > 0)
        ordinary = scan('default', 'ordinary text\n')
        check('default-no-loaded-policies', not any(s['kind'] in ('ml_model', 'verifiers', 'unversioned_policy') for s in ordinary['scope']))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    evidence = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'model_feature_names_source_sha256': hashlib.sha256(model_source.read_bytes()).hexdigest(),
                'checks': checks, 'passed': True, 'network': 'OS deny outside loopback, checked by denied bind; owned loopback verifier and sidecar only',
                'verification_calls': Handler.verification_calls, 'score_calls': Handler.score_calls,
                'scope': 'Local synthetic model/verifier snapshots and report correlation. No real provider or hosted qualification.'}
    output = root / 'evidence.json'
    output.write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps({'passed': len(checks), 'evidence': str(output)}))


if __name__ == '__main__':
    main()
