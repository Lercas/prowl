#!/usr/bin/env python3
"""Qualify native offline smoke profiles and read-only active-policy diagnostics."""
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
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='prowl-offline-native-'))
    calls = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            calls.append(self.path)
            self.send_response(200)
            self.end_headers()
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    checks = []
    def check(name, passed):
        checks.append({'case': name, 'passed': bool(passed)})
        if not passed: raise AssertionError(name)
    def run(args, home):
        env = dict(os.environ, PROWL_HOME=str(home))
        return subprocess.run([str(binary), *args], cwd=root, env=env, input=b'', capture_output=True, timeout=30)
    try:
        home = root / 'empty-home'
        home.mkdir()
        initial = sorted(str(p.relative_to(root)) for p in root.rglob('*'))
        negative = {'public-example', 'mobile-placeholder', 'public-identifier'}
        for profile, count in [('all', 7), ('web', 3), ('mobile', 2), ('enterprise', 2)]:
            for ml in (False, True):
                result = run(['selftest', '--profile=' + profile, *(['--ml'] if ml else [])], home)
                data = json.loads(result.stdout)
                name = f'{profile}/ml={ml}'
                check(name + '/passed', result.returncode == 0 and data['passed'] and not data['network'] and data['profile'] == profile and len(data['cases']) == count)
                check(name + '/complete', all(c['passed'] and c['complete'] for c in data['cases']))
                check(name + '/negative-controls', all(c['count'] == 0 for c in data['cases'] if c['name'] in negative))
        check('selftest-no-files-created', initial == sorted(str(p.relative_to(root)) for p in root.rglob('*')))
        for args in (['--verify'], ['--ocr'], ['--semantic'], ['--ml-model=owned'], ['--profile=unknown'], ['unexpected-path']):
            check('selftest-rejected/' + '/'.join(args), run(['selftest', *args], home).returncode == 2)
        check('selftest-help', run(['selftest', '--help'], home).returncode == 0)
        result = run(['doctor', '--bundled', '--no-color'], home)
        check('doctor-bundled-inventory', result.returncode == 0 and b'175 selected templates' in result.stdout and b'84 selected verifiers' in result.stdout)
        installed = root / 'installed-home'
        installed.mkdir()
        (installed / 'rules').mkdir()
        (installed / 'rules/owned.yaml').write_text('id: owned-unused\ninfo: {name: Owned, severity: high}\nmatchers:\n - type: word\n   words: [OWNED_UNUSED_PATTERN]\n')
        (installed / 'verifiers').mkdir()
        (installed / 'verifiers/owned.yaml').write_text(f'id: owned-unused\nmatch: [owned_unused_type]\nrequests:\n - url: http://127.0.0.1:{server.server_port}/owned\n')
        result = run(['doctor', '--no-color'], installed)
        check('doctor-selected-overlay', result.returncode == 0 and b'1 selected templates' in result.stdout and b'1 selected verifiers' in result.stdout and b'overrides bundled' in result.stdout)
        broken = root / 'broken-home'
        broken.mkdir()
        for kind in ('rules', 'verifiers'):
            (broken / kind).mkdir()
            (broken / kind / 'broken.yaml').write_text('not: [valid')
        check('doctor-corrupt-overlay-fails', run(['doctor', '--no-color'], broken).returncode == 1)
        check('doctor-bundled-ignores-unselected-overlay', run(['doctor', '--bundled', '--no-color'], broken).returncode == 0)
        result = run(['doctor', '--rules-dir=' + str(installed / 'rules'), '--verifiers=' + str(installed / 'verifiers'), '--no-color'], broken)
        check('doctor-explicit-selection', result.returncode == 0 and b'1 selected templates' in result.stdout and b'1 selected verifiers' in result.stdout)
        (root / 'clean.txt').write_text('ordinary text')
        output = root / 'owned-output.json'
        output.write_bytes(b'owned output sentinel\n')
        for flag in ('--rules-only', '--rules-dir=missing', '--verifiers=missing'):
            result = run(['scan', 'clean.txt', '--bundled', flag, '--output=' + str(output)], home)
            check('conflicting-selection/' + flag, result.returncode == 2 and output.read_bytes() == b'owned output sentinel\n')
        model_home = root / 'invalid-model-home'
        model_home.mkdir()
        (model_home / 'model_binary.json').write_text('not a model')
        check('selftest-selected-bad-model-fails', run(['selftest', '--profile=web', '--ml'], model_home).returncode == 2)
        check('selftest-disabled-ML-ignores-model', run(['selftest', '--profile=web', '--ml=false'], model_home).returncode == 0)
        check('doctor-no-provider-requests', len(calls) == 0)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=30)
        report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'passed': sum(c['passed'] for c in checks), 'total': len(checks), 'checks': checks,
                  'root': str(root), 'scope': 'synthetic offline CLI smoke and owned policy files; no provider or remote source qualification'}
        (root / 'qualification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps({k: v for k, v in report.items() if k != 'checks'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
