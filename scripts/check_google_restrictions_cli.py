#!/usr/bin/env python3
"""Qualify Google restriction CLI guards and honest network-denied audit reports."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import zipfile

KEY = 'AIzaSy9Qw7Er5Ty3Ui1Op8As6Df4Gh2Jk0Lz5Xc'
TOKEN = 'owned-operator-token'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='prowl-google-cli-'))
    sandbox = ['/usr/bin/sandbox-exec', '-p', '(version 1)(allow default)(deny network*)']
    env = {k: v for k, v in os.environ.items() if not k.startswith('PROWL_') and not k.upper().endswith('_PROXY')}
    env.update(PROWL_HOME=str(root / 'home'), PROWL_LIVE_TEST='')
    class Handler(BaseHTTPRequestHandler):
        calls = 0
        def log_message(self, *_): pass
        def do_GET(self):
            Handler.calls += 1
            self.send_response(200); self.end_headers()
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    checks = []
    def check(name, ok):
        assert ok, name
        checks.append({'case': name, 'passed': True})
    def run(args, token=None, isolated=True):
        selected = env.copy()
        if token is not None:
            selected['PROWL_GOOGLE_AUDIT_TOKEN'] = token
        return subprocess.run([*(sandbox if isolated else []), str(binary), *map(str, args)], cwd=root, env=selected, input=b'', capture_output=True, timeout=30)
    try:
        url = f'http://127.0.0.1:{server.server_port}/owned'
        control = subprocess.run(['/usr/bin/curl', '--silent', '--max-time', '2', url], capture_output=True)
        blocked = subprocess.run([*sandbox, '/usr/bin/curl', '--silent', '--max-time', '2', url], capture_output=True)
        check('OS-network-deny', control.returncode == 0 and blocked.returncode != 0 and Handler.calls == 1)
        for command in ('scan', 'repo', 'org', 'serve', 'mcp', 'image', 'bucket', 'cicd'):
            p = run([command, '--audit-google-restrictions'])
            check('foreign-flag-' + command, p.returncode == 2)
        report = root / 'existing-report'
        baseline = root / 'existing-baseline'
        report.write_bytes(b'owned report'); baseline.write_bytes(b'owned baseline')
        for command in ('domain', 'mobile'):
            for token in (None, 'invalid operator credential'):
                p = run([command, url, '--audit-google-restrictions', '--audit-public', '--authorized', '--output', report, '--write-baseline', baseline], token=token, isolated=False)
                label = f'credential-{command}-{token is None}'
                check(label + '-preflight', p.returncode == 2 and Handler.calls == 1 and b'PROWL_GOOGLE_AUDIT_TOKEN' in p.stderr)
                check(label + '-artifacts', report.read_bytes() == b'owned report' and baseline.read_bytes() == b'owned baseline')
                check(label + '-private', b'invalid operator credential' not in p.stdout + p.stderr)
            for flags in ([], ['--audit-public'], ['--audit-public', '--authorized', '--verify']):
                p = run([command, url, '--audit-google-restrictions', *flags], token=TOKEN)
                check('authorization-' + command + '-' + str(len(flags)), p.returncode == 2 and Handler.calls == 1)
        apk = root / 'owned.apk'
        with zipfile.ZipFile(apk, 'w') as z:
            z.writestr('assets/config.json', json.dumps({'apiKey': KEY}))
        model = Path(__file__).resolve().parents[1] / 'tool/internal/mlmodel/model_binary_go_literal_v1.json'
        for fmt in ('json', 'sarif'):
            for ml in (False, True):
                args = ['mobile', apk, '--no-strings', '--audit-public', '--authorized', '--format=' + fmt, '--silence']
                if ml:
                    args += ['--ml', '--ml-model', model]
                p = run([*args, '--audit-google-restrictions', '--write-baseline', baseline], token=TOKEN)
                data = json.loads(p.stdout)
                if fmt == 'json':
                    meta = data
                    fs = [f for f in data['findings'] if f['type'].replace('-', '_') == 'gcp_api_key']
                else:
                    run_data = data['runs'][0]
                    meta = run_data['properties']
                    fs = [f['properties'] for f in run_data['results'] if f['ruleId'].replace('-', '_') == 'gcp_api_key']
                label = f'network-denied-{fmt}-ml{ml}'
                check(label + '-incomplete', p.returncode == 2 and not meta['complete'] and len(fs) == 1)
                audit = fs[0]['public_key_audit']
                check(label + '-honest-status', audit['status'] == 'inconclusive' and any(c['service'] == 'google_api_restrictions' for c in audit['checks']) and not fs[0].get('verified'))
                check(label + '-baseline', baseline.read_bytes() == b'owned baseline')
                check(label + '-private', all(v.encode() not in p.stdout + p.stderr for v in (KEY, TOKEN)))
                off = run(args, token=TOKEN)
                old = json.loads(off.stdout)
                findings = old['findings'] if fmt == 'json' else [r['properties'] for r in old['runs'][0]['results']]
                check(label + '-explicit-opt-in', off.returncode == 0 and all('public_key_audit' not in f for f in findings))
        evidence = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'passed': len(checks), 'failed': 0, 'checks': checks,
                    'scope': 'CLI authorization/token/artifact guards and network-denied JSON/SARIF/ML reporting; successful Google responses covered by owned HTTP Go pipeline tests, not by this native runner', 'fixture_root': str(root)}
        (root / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
        print(json.dumps({'passed': len(checks), 'evidence': str(root / 'evidence.json')}))
    finally:
        server.shutdown(); server.server_close(); thread.join()


if __name__ == '__main__':
    main()
