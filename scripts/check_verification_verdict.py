#!/usr/bin/env python3
"""Qualify provider verdicts with synthetic credentials and an owned loopback stub."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--without-ml', action='store_true', help='compare a legacy binary without loading a new model contract')
    parser.add_argument('--legacy-verdict-only', action='store_true', help='compare only provider verdicts; legacy coverage/exit policy is recorded, not certified')
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='prowl-verdict-native-'))
    model = Path(__file__).resolve().parents[1] / 'tool/internal/mlmodel/model_binary_go_literal_v1.json'
    key = 'AKIANAFGYOEYPXU1DSYP'
    generic = 'r4ndOm_vendorname_XJ28zP6qL5n!'
    checks = []
    observations = []

    def check(label, ok):
        checks.append({'case': label, 'passed': bool(ok)})
        if not ok:
            raise AssertionError(label)

    class Handler(BaseHTTPRequestHandler):
        status = 200
        positive = False
        calls = 0

        def do_GET(self):
            Handler.calls += 1
            self.send_response(Handler.status)
            self.end_headers()
            self.wfile.write(b'authenticated-private-response' if Handler.positive else b'unrelated response')

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    verifiers = root / 'verifiers'
    verifiers.mkdir()
    (verifiers / 'owned.yaml').write_text(
        'id: vendorname\nmatch: [aws_access_key_id, aws-access-key-id, vendorname]\nrequests:\n'
        f' - method: GET\n   url: http://127.0.0.1:{server.server_port}/owned\n'
        '   headers:\n     Authorization: "Bearer {{secret}}"\n'
        '   matchers:\n    - type: word\n      words: [authenticated-private-response]\n')
    source = root / 'production.json'
    source.write_text(json.dumps({'accessKeyId': key}))
    generic_source = root / 'generic.json'
    generic_source.write_text(json.dumps({'password': generic}))
    env = {k: v for k, v in os.environ.items() if not k.startswith('PROWL_')}
    env.update(PROWL_HOME=str(root / 'home'), PROWL_ALLOW_PRIVATE_IPS='1', PROWL_LIVE_TEST='', NO_PROXY='127.0.0.1,localhost')

    def run(path, fmt, ml, extra=()):
        args = [str(binary), 'scan', str(path), '--verify', '--verifiers', str(verifiers),
                '--format=' + fmt, '--silence', '--workers=1']
        if ml:
            args += ['--ml', '--ml-model', str(model)]
        return subprocess.run([*args, *map(str, extra)], cwd=root, env=env, capture_output=True, timeout=30)

    def report(result, fmt):
        data = json.loads(result.stdout)
        if fmt == 'json':
            return data['findings'], data['complete']
        run = data['runs'][0]
        return [f['properties'] for f in run['results']], run['properties']['complete']

    try:
        for status, positive, expected in ((200, True, 'verified'), (200, False, 'error'),
                                           (301, False, 'error'), (400, False, 'error'),
                                           (401, False, 'invalid'), (403, False, 'error'),
                                           (404, False, 'error'), (500, False, 'error')):
            Handler.status, Handler.positive = status, positive
            for fmt in ('json', 'sarif'):
                for ml in ((False,) if args.without_ml or args.legacy_verdict_only else (False, True)):
                    label = f'{status}-positive{positive}-{fmt}-ml{ml}'
                    before = Handler.calls
                    result = run(source, fmt, ml)
                    findings, complete = report(result, fmt)
                    selected = [f for f in findings if f.get('verification', {}).get('verifier') == 'vendorname']
                    check(label + '/request', Handler.calls == before + 1)
                    check(label + '/status', len(selected) == 1 and selected[0]['verification']['status'] == expected)
                    observations.append({'case': label, 'complete': complete, 'exit': result.returncode, 'status': selected[0]['verification']['status']})
                    if not args.legacy_verdict_only:
                        check(label + '/coverage', complete == (expected != 'error') and result.returncode == (2 if expected == 'error' else 0))
                    if fmt == 'json':
                        check(label + '/tristate', selected[0].get('verified') == {'verified': True, 'invalid': False, 'error': None}[expected])
                    check(label + '/redaction', key.encode() not in result.stdout + result.stderr)
                    if expected == 'error' and not args.legacy_verdict_only:
                        baseline = root / (label + '.baseline')
                        baseline.write_bytes(b'owned baseline sentinel')
                        result = run(source, fmt, ml, ['--verified-only', '--write-baseline', baseline])
                        _, complete = report(result, fmt)
                        check(label + '/baseline', result.returncode == 2 and not complete and baseline.read_bytes() == b'owned baseline sentinel')
        Handler.status, Handler.positive = 200, True
        result = run(source, 'json', False, ['--fail-on-verified'])
        check('live-gate', result.returncode == 1)
        if not args.legacy_verdict_only:
            for fmt in ('json', 'sarif'):
                for ml in ((False,) if args.without_ml else (False, True)):
                    for flag in ('--min-confidence=0.99', '--min-severity=critical', '--disable=aws_access_key_id'):
                        result = run(source, fmt, ml, ['--fail-on-verified', flag])
                        findings, complete = report(result, fmt)
                        check(f'live-display-guard-{fmt}-ml{ml}-{flag}', result.returncode == 1 and complete and any(f.get('verification', {}).get('status') == 'verified' for f in findings))
            for status, positive, expected in ((200, True, 'verified'), (200, False, 'error'), (401, False, 'invalid')):
                Handler.status, Handler.positive = status, positive
                for fmt in ('json', 'sarif'):
                    result = run(source, fmt, False, ['--verified-only'])
                    findings, complete = report(result, fmt)
                    credentials = [f for f in findings if f.get('verification')]
                    check(f'verified-only-{expected}-{fmt}', all(f['verification']['status'] == 'verified' for f in credentials) and len(credentials) == (1 if expected == 'verified' else 0) and complete == (expected != 'error') and result.returncode == (2 if expected == 'error' else 0))
            unsupported = root / 'unsupported.json'
            unsupported.write_text('{"token":"sk_live_Q5t7U9i2O4p6A8s0D3f5G7h9"}')
            before = Handler.calls
            result = run(unsupported, 'json', False, ['--verified-only'])
            findings, complete = report(result, 'json')
            check('verified-only-unsupported', result.returncode == 0 and complete and not findings and Handler.calls == before)
            password = 'Winter42!Autumn'
            for ext in ('json', 'yaml', 'toml'):
                for fmt in ('json', 'sarif'):
                    prose = root / ('prose.' + ext)
                    prose.write_text({'json': json.dumps({'message': 'Your password is ' + password}),
                                      'yaml': 'message: "Your password is ' + password + '"\n',
                                      'toml': 'message="Your password is ' + password + '"\n'}[ext])
                    before = Handler.calls
                    result = run(prose, fmt, False)
                    findings, complete = report(result, fmt)
                    check(f'structured-prose-{ext}-{fmt}', result.returncode == 0 and complete and len(findings) == 1 and findings[0]['stage'].endswith('L1-context-pw') and Handler.calls == before)
                    check(f'structured-prose-private-{ext}-{fmt}', password.encode() not in result.stdout + result.stderr)
                    for name_index, name in enumerate(('service_' * 40 + 'password', 'сервис_' * 40 + 'пароль', 'a' * 150 + '1' * 150 + '_password')):
                        binding = root / f'binding-{name_index}.{ext}'
                        binding.write_text({'json': json.dumps({name: password}), 'yaml': name + ': "' + password + '"\n', 'toml': '"' + name + '"="' + password + '"\n'}[ext])
                        for ml in ((False,) if args.without_ml else (False, True)):
                            result = run(binding, fmt, ml)
                            findings, complete = report(result, fmt)
                            check(f'long-binding-{name_index}-{ext}-{fmt}-ml{ml}', result.returncode == 0 and complete and len(findings) == 1 and Handler.calls == before)
                            check(f'long-binding-private-{name_index}-{ext}-{fmt}-ml{ml}', password.encode() not in result.stdout + result.stderr)
            for ext, text in (('json', '{"accessKeyId":"' + key + '\\q"}'),
                              ('yaml', 'accessKeyId: "' + key + '\\q"\n'),
                              ('toml', 'accessKeyId="' + key + '\\q"\n')):
                malformed = root / ('malformed.' + ext)
                malformed.write_text(text)
                for fmt in ('json', 'sarif'):
                    for before_ml in (False, True):
                        before = Handler.calls
                        result = run(malformed, fmt, False, ['--verify-all'] if before_ml else [])
                        findings, complete = report(result, fmt)
                        credentials = [f for f in findings if f.get('verification')]
                        label = f'unsafe-literal-{ext}-{fmt}-beforeml{before_ml}'
                        check(label, result.returncode == 2 and not complete and credentials and all(f['verification']['status'] == 'error' and f['verification']['reason'] == 'structured literal could not be established' for f in credentials) and Handler.calls == before)
                        check(label + '-private', key.encode() not in result.stdout + result.stderr)
            oversize_dir = root / 'oversize'
            oversize_dir.mkdir()
            oversize_file = oversize_dir / 'large.txt'
            oversize_file.write_text('owned oversized content')
            for path in (oversize_dir, oversize_file):
                for fmt in ('json', 'sarif'):
                    result = run(path, fmt, False, ['--max-size=4'])
                    data = json.loads(result.stdout)
                    envelope = data if fmt == 'json' else data['runs'][0]['properties']
                    check(f'max-size-{path.name}-{fmt}', result.returncode == 2 and not envelope['complete'] and any(d['code'] == 'max_size' and d['incomplete'] for d in envelope['diagnostics']))
        Handler.status, Handler.positive = 200, True
        before = Handler.calls
        result = run(generic_source, 'json', False)
        findings, complete = report(result, 'json')
        check('generic-candidate-retained', any(f['type'] == 'generic_password' for f in findings))
        check('generic-never-submitted', complete and result.returncode == 0 and Handler.calls == before and all(f.get('verification', {}).get('status') == 'unsupported' for f in findings))
        check('generic-redaction', generic.encode() not in result.stdout + result.stderr)
        evidence = {'passed': len(checks), 'checks': checks, 'root': str(root),
                    'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                    'observations': observations, 'legacy_verdict_only': args.legacy_verdict_only,
                    'provider': 'owned loopback stub only; no live account acceptance', 'requests': Handler.calls}
        (root / 'qualification.json').write_text(json.dumps(evidence, indent=2) + '\n')
        print(json.dumps({'passed': len(checks), 'evidence': str(root / 'qualification.json')}))
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == '__main__':
    main()
