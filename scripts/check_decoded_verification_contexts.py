#!/usr/bin/env python3
"""Check decoded companion isolation with synthetic values and an owned HTTP stub."""
import argparse
import base64
import gzip
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import zlib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='prowl-decoded-verification-'))
    model = Path(__file__).resolve().parents[1] / 'tool/internal/mlmodel/model_binary_go_literal_v1.json'
    key = 'AKIANAFGYOEYPXU1DSYP'
    checks = []

    def check(label, condition):
        checks.append({'case': label, 'passed': bool(condition)})
        if not condition:
            raise AssertionError(label)

    class Handler(BaseHTTPRequestHandler):
        accounts = []

        def do_GET(self):
            account = self.headers.get('X-Account')
            Handler.accounts.append(account)
            self.send_response(200 if account == 'tenant_a' else 401)
            self.end_headers()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    verifiers = root / 'verifiers'
    verifiers.mkdir()
    (verifiers / 'owned.yaml').write_text(
        'id: owned\nmatch: [aws_access_key_id, aws-access-key-id]\nextract:\n  account: "tenant_[ab]"\nrequests:\n'
        f' - url: http://127.0.0.1:{server.server_port}/owned\n'
        '   headers:\n     Authorization: "Bearer {{secret}}"\n     X-Account: "{{account}}"\n'
        '   matchers:\n    - type: status\n      status: [200]\n')
    env = {k: v for k, v in os.environ.items() if not k.startswith('PROWL_')}
    env.update(PROWL_HOME=str(root / 'home'), PROWL_ALLOW_PRIVATE_IPS='1', PROWL_LIVE_TEST='', NO_PROXY='127.0.0.1,localhost')

    def encode(payload, codec):
        raw = payload.encode()
        if codec == 'hex':
            return raw.hex()
        if codec == 'gzip-base64':
            raw = gzip.compress(raw, mtime=0)
        elif codec == 'zlib-base64':
            raw = zlib.compress(raw)
        elif codec == 'nested-base64':
            raw = ('account=tenant_b\ninner="' + base64.b64encode(raw).decode() + '"').encode()
        elif codec == 'base64-of-hex':
            raw = ('account=tenant_b\ninner="' + raw.hex() + '"').encode()
        return base64.b64encode(raw).decode()

    def run(path, fmt, ml, mode, dedupe=False):
        args = [str(binary), 'scan', str(path), '--verify', '--verifiers', str(verifiers), '--silence', '--workers=1', '--format=' + fmt]
        if not dedupe:
            args.append('--no-dedupe')
        if ml:
            args += ['--ml', '--ml-model', str(model)]
        if mode == 'all':
            args.append('--verify-all')
        elif mode == 'index':
            args += ['--index', str(root / ('index-' + str(len(checks)))), '--scope=owned-decoded']
        return subprocess.run(args, env=env, cwd=root, capture_output=True, timeout=40)

    def report(result, fmt):
        data = json.loads(result.stdout)
        if fmt == 'json':
            return data['findings'], data['complete']
        run = data['runs'][0]
        return [f['properties'] for f in run['results']], run['properties']['complete']

    try:
        for codec in ('base64', 'nested-base64', 'hex', 'gzip-base64', 'zlib-base64', 'base64-of-hex'):
            source = root / (codec + '.env')
            source.write_text('account=tenant_b\nfirst="' + encode('account=tenant_a\nAWS=' + key, codec) + '"\nsecond="' + encode('account=tenant_b\nAWS=' + key, codec) + '"\n')
            for fmt in ('json', 'sarif'):
                for ml in (False, True):
                    for mode in ('default', 'all', 'index'):
                        label = f'{codec}-{fmt}-ml{ml}-{mode}'
                        before = len(Handler.accounts)
                        result = run(source, fmt, ml, mode)
                        findings, complete = report(result, fmt)
                        statuses = sorted(f.get('verification', {}).get('status', '') for f in findings)
                        check(label + '/verdicts', result.returncode == 0 and complete and statuses == ['invalid', 'verified'])
                        check(label + '/contexts', sorted(Handler.accounts[before:]) == ['tenant_a', 'tenant_b'])
                        check(label + '/private', all(value.encode() not in result.stdout + result.stderr for value in (key, 'tenant_a', 'tenant_b')))
            result = run(source, 'json', False, 'default', dedupe=True)
            findings, complete = report(result, 'json')
            occurrences = findings[0].get('occurrences', []) if len(findings) == 1 else []
            check(codec + '/dedupe-occurrences', result.returncode == 0 and complete and sorted(o['verification']['status'] for o in occurrences) == ['invalid', 'verified'])
            missing = root / (codec + '-missing.env')
            missing.write_text('account=tenant_a\npayload="' + encode('AWS=' + key, codec) + '"\n')
            before = len(Handler.accounts)
            result = run(missing, 'json', False, 'default')
            findings, complete = report(result, 'json')
            check(codec + '/no-outer-borrowing', result.returncode == 2 and not complete and len(Handler.accounts) == before and any(f.get('verification', {}).get('status') == 'error' for f in findings))
        evidence = {'passed': len(checks), 'checks': checks, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                    'root': str(root), 'requests': len(Handler.accounts), 'scope': 'Owned loopback only; no real provider/account acceptance'}
        (root / 'qualification.json').write_text(json.dumps(evidence, indent=2) + '\n')
        print(json.dumps({'passed': len(checks), 'evidence': str(root / 'qualification.json')}))
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == '__main__':
    main()
