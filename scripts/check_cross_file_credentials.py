#!/usr/bin/env python3
"""Qualify opt-in local cross-file binding against an owned loopback provider."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import threading
import zipfile

KEY = 'AKIANAFGYOEYPXU1DSYP'
OTHER = 'AKIA4MNQ2RST7UVWX9YZ'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='prowl-cross-file-native-'))
    model = Path(__file__).resolve().parents[1] / 'tool/internal/mlmodel/model_binary_go_literal_v1.json'
    checks = []

    def check(name, ok):
        assert ok, name
        checks.append({'case': name, 'passed': True})

    class Handler(BaseHTTPRequestHandler):
        calls = []
        mutate = None

        def do_GET(self):
            auth, account = self.headers.get('Authorization'), self.headers.get('X-Account')
            valid = self.path == '/owned' and auth in ('Bearer ' + KEY, 'Bearer ' + OTHER) and account == 'tenant_a'
            Handler.calls.append(valid)
            if Handler.mutate:
                mutation, Handler.mutate = Handler.mutate, None
                mutation()
            self.send_response(200 if valid else 401)
            self.end_headers()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    verifiers = root / 'verifiers'
    verifiers.mkdir()
    (verifiers / 'owned.yaml').write_text(
        f"id: owned\nmatch: [aws_access_key_id, aws-access-key-id]\nextract:\n  account: 'tenant_[ab]'\nrequests:\n"
        f"  - url: http://127.0.0.1:{server.server_port}/owned\n"
        "    headers:\n      Authorization: 'Bearer {{secret}}'\n      X-Account: '{{account}}'\n"
        "    matchers:\n      - type: status\n        status: [200]\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith('PROWL_')}
    env.update(PROWL_HOME=str(root / 'home'), PROWL_LIVE_TEST='', PROWL_ALLOW_PRIVATE_IPS='1', NO_PROXY='127.0.0.1,localhost')

    def run(paths, extra=(), fmt='json', ml=False, cross=True):
        args = [str(binary), 'scan', *map(str, paths), '--verify', '--verifiers', str(verifiers),
                '--format=' + fmt, '--silence', '--workers=1', '--max-per-file=0']
        if cross:
            args.append('--cross-file')
        if ml:
            args += ['--ml', '--ml-model', str(model)]
        return subprocess.run([*args, *map(str, extra)], cwd=root, env=env, capture_output=True, timeout=40)

    def fixture(label, extension='json'):
        folder = root / label
        folder.mkdir()
        key, account = json.dumps({'accessKeyId': KEY}), json.dumps({'account': 'tenant_a', 'timeout': 30})
        if extension == 'toml':
            key, account = f'accessKeyId="{KEY}"\n', 'account="tenant_a"\ntimeout=30\n'
        if extension == 'yaml':
            key, account = f'accessKeyId: {KEY}\n', 'account: tenant_a\ntimeout: 30\n'
        if extension == 'env':
            key, account = f"export accessKeyId='{KEY}'\r\n", 'account="tenant_a" # comment\r\n'
        (folder / ('key.' + extension)).write_text(key)
        (folder / ('account.' + extension)).write_text(account)
        return folder

    def report(p, fmt):
        d = json.loads(p.stdout)
        if fmt == 'json':
            return [f for f in d['findings'] if f['type'].replace('-', '_') == 'aws_access_key_id'], d['complete']
        run = d['runs'][0]
        return [r['properties'] for r in run['results'] if r['ruleId'].replace('-', '_') == 'aws_access_key_id'], run['properties']['complete']

    try:
        for extension in ('json', 'toml', 'yaml', 'env'):
            source = fixture('positive-' + extension, extension)
            for fmt in ('json', 'sarif'):
                for ml in (False, True):
                    label = f'{extension}-{fmt}-ml{ml}'
                    before = len(Handler.calls)
                    p = run([source], fmt=fmt, ml=ml)
                    fs, complete = report(p, fmt)
                    check(label + '-status', p.returncode == 0 and complete and len(fs) == 1)
                    detail = fs[0]['verification']
                    check(label + '-verdict', (fmt != 'json' or fs[0].get('verified') is True) and detail['status'] == 'verified')
                    evidence = detail['components']
                    check(label + '-roles', len(evidence['primary']) == 1 and len(evidence['fields']['account']) == 1)
                    check(label + '-owned-request', len(Handler.calls) == before + 1 and Handler.calls[-1])
                    check(label + '-redaction', all(v.encode() not in p.stdout + p.stderr for v in (KEY, OTHER, 'tenant_a', 'accessKeyId')))

        source = fixture('duplicates')
        (source / 'key.json').write_text(json.dumps({'accessKeyId': KEY, 'secondKey': KEY}))
        for fmt in ('json', 'sarif'):
            p = run([source], fmt=fmt)
            fs, complete = report(p, fmt)
            check('duplicates-' + fmt, p.returncode == 0 and complete and len(fs) == 1 and len(fs[0]['occurrences']) == 2)
            primary = {o['verification']['components']['primary'][0] for o in fs[0]['occurrences']}
            check('duplicate-evidence-' + fmt, len(primary) == 2)

        for mode in ('conflict', 'unknown', 'empty', 'nested', 'duplicate', 'interpolation', 'foreign-root', 'nested-repo', 'archive', 'missing-source'):
            source = fixture('negative-' + mode)
            paths = [source]
            if mode in ('conflict', 'unknown', 'empty'):
                value = 'tenant_b' if mode == 'conflict' else (False if mode == 'unknown' else '')
                (source / 'other.json').write_text(json.dumps({'Account': value}))
            if mode == 'nested':
                (source / 'account.json').write_text('{"nested":{"account":"tenant_a"}}')
            if mode == 'duplicate':
                (source / 'account.json').write_text('{"account":"tenant_a","account":"tenant_b"}')
            if mode == 'interpolation':
                (source / 'account.json').write_text('{}')
                (source / 'account.env').write_text('account=${UNOBSERVED}\n')
            if mode in ('foreign-root', 'nested-repo', 'archive'):
                (source / 'account.json').write_text('{}')
                if mode == 'archive':
                    stream = io.BytesIO()
                    with zipfile.ZipFile(stream, 'w') as z:
                        z.writestr('account.json', '{"account":"tenant_a"}')
                    (source / 'owned.zip').write_bytes(stream.getvalue())
                else:
                    other = root / ('foreign-' + mode) if mode == 'foreign-root' else source / 'nested'
                    other.mkdir()
                    (other / 'account.json').write_text('{"account":"tenant_a"}')
                    if mode == 'foreign-root':
                        paths.append(other)
                    else:
                        (other / '.git').mkdir()
            if mode == 'missing-source':
                paths.append(root / 'does-not-exist')
            baseline = root / (mode + '-baseline.json')
            sentinel = b'owned baseline must remain unchanged'
            baseline.write_bytes(sentinel)
            for fmt in ('json', 'sarif'):
                before = len(Handler.calls)
                p = run(paths, extra=['--write-baseline', baseline, '--verified-only'], fmt=fmt)
                _, complete = report(p, fmt)
                check(mode + '-' + fmt + '-closed', p.returncode == 2 and not complete and len(Handler.calls) == before)
                check(mode + '-' + fmt + '-baseline', baseline.read_bytes() == sentinel)
                check(mode + '-' + fmt + '-redaction', KEY.encode() not in p.stdout + p.stderr and b'tenant_a' not in p.stdout + p.stderr)

        source = fixture('index')
        index = root / 'owned-index'
        p = run([source], extra=['--index', index, '--scope', 'owned-cross-file'])
        fs, complete = report(p, 'json')
        ids = fs[0]['verification']['components']
        check('index-complete', p.returncode == 0 and complete and all(i.startswith('hmac-location:v1:') for i in [*ids['primary'], *ids['fields']['account']]))
        indexed = subprocess.run([str(binary), 'index', '--index', str(index), '--format=json'], cwd=root, env=env, capture_output=True, timeout=20)
        places = {p['id'] for s in json.loads(indexed.stdout)['secrets'] for p in s['locations']}
        check('index-evidence-resolves-primary', indexed.returncode == 0 and set(ids['primary']) <= places)
        with sqlite3.connect(index / 'index.sqlite') as database:
            raw = '\n'.join(database.iterdump()).encode()
        check('index-no-plaintext', all(v.encode() not in raw for v in (KEY, OTHER, 'tenant_a', 'accessKeyId')))

        source = fixture('single-snapshot')
        (source / 'other-key.json').write_text(json.dumps({'secondKey': OTHER}))
        Handler.mutate = lambda: (source / 'account.json').write_text('{"account":"tenant_b"}')
        before = len(Handler.calls)
        p = run([source])
        _, complete = report(p, 'json')
        check('source-not-reread', p.returncode == 0 and complete and len(Handler.calls) == before + 2 and all(Handler.calls[before:]))

        for args in (['scan', '--cross-file'], ['scan', '-', '--cross-file', '--verify'], ['scan', '--cross-file', '--verify', '--history'], ['repo', '--cross-file', '--verify']):
            before = len(Handler.calls)
            p = subprocess.run([str(binary), *args], input=b'', capture_output=True, cwd=root, env=env, timeout=10)
            check('flag-guard-' + str(len(checks)), p.returncode == 2 and len(Handler.calls) == before)

        evidence = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'model_sha256': hashlib.sha256(model.read_bytes()).hexdigest(),
                    'passed': len(checks), 'failed': 0, 'checks': checks, 'fixture_root': str(root),
                    'provider': 'Owned loopback stub only; no real provider/account acceptance', 'owned_requests': len(Handler.calls),
                    'scope': 'Opt-in local configuration literals; JSON/SARIF, ML, occurrences, index, sealed snapshot and baseline guards. Other adapters are not qualified.'}
        (root / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
        print(json.dumps({'passed': len(checks), 'evidence': str(root / 'evidence.json')}))
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == '__main__':
    main()
