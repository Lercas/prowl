#!/usr/bin/env python3
"""Qualify one-pass comparison with an owned inference stub and synthetic local files."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='prowl-compare-native-')); (root / 'home').mkdir()
    value, aws = 'tulip-moon', 'AKIANAFGYOEYPXU1DSYP'
    state = {'mode': 'normal', 'calls': 0, 'auth_bad': 0, 'mutate': None}
    class API(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_POST(self):
            state['calls'] += 1
            if self.headers.get('Authorization') != 'Bearer owned-private-model-key': state['auth_bad'] += 1
            payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            text = payload['messages'][-1]['content']
            if state['mutate'] is not None:
                state['mutate'].write_text('AWS=' + aws + '\n')
            if state['mode'] == 'error':
                self.send_response(500); self.end_headers(); self.wfile.write(b'owned-private-model-body'); return
            if state['mode'] == 'slow': time.sleep(.2)
            candidate = 'hallucinated-owned-value' if state['mode'] == 'hallucinate' else value
            content = json.dumps({'candidates': [{'value': candidate}] if candidate in text or state['mode'] == 'hallucinate' else []})
            self.send_response(200); self.end_headers()
            try: self.wfile.write(json.dumps({'choices': [{'finish_reason': 'stop', 'message': {'content': content}}]}).encode())
            except (BrokenPipeError, ConnectionResetError): pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), API)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    env = dict(os.environ, PROWL_HOME=str(root / 'home'), PROWL_SEMANTIC_URL=f'http://127.0.0.1:{server.server_port}/model', PROWL_SEMANTIC_API_KEY='owned-private-model-key')
    checks = []; call = 0
    def check(name, passed):
        checks.append({'case': name, 'passed': bool(passed)})
        if not passed: raise AssertionError(name)
    def run(argv):
        nonlocal call
        call += 1
        r = subprocess.run([str(binary), 'compare', '--bundled', '--log-level=error', *argv], cwd=root, env=env, input=b'', capture_output=True, timeout=60)
        (root / f'case-{call:03}.stdout').write_bytes(r.stdout); (root / f'case-{call:03}.stderr').write_bytes(r.stderr)
        return r
    def summary(r):
        text = r.stdout.decode()
        before = re.search(r'fixed candidates\):\s+(\d+) findings', text)
        after = re.search(r"after Prowl's ML context filter:\s+(\d+) findings", text)
        dropped = re.search(r'suppressed by ML as not-a-secret:\s+(\d+)', text)
        if not all((before, after, dropped)): raise AssertionError('missing comparison summary')
        return int(before[1]), int(after[1]), int(dropped[1])
    def safe(r):
        return all(s.encode() not in r.stdout+r.stderr for s in (value, aws, 'owned-private-model-key', 'owned-private-model-body'))
    try:
        for name, text, flags in (
            ('production.txt', 'Archive access code for tomorrow: ' + value, []),
            ('production.json', '{"note":"tulip\\u002dmoon"}', []),
            ('production.yaml', "note: '" + value + "'", []),
            ('production.toml', 'note="tulip\\u002dmoon"', []),
            ('bundle.js', "const head='AKIA';const key=head+'NAFGYOEYPXU1DSYP';const note='" + value + "';", ['--reconstruct']),
        ):
            file = root / name
            file.write_text(text)
            before = state['calls']
            r = run([name, '--semantic', *flags])
            n, kept, dropped = summary(r)
            check(name + '/pool', r.returncode == 0 and n == (2 if flags else 1) and 0 <= kept <= n and dropped == n-kept)
            check(name + '/one-discovery', state['calls'] == before + 1)
            check(name + '/private', safe(r))
        file = root / 'mutating.txt'; file.write_text('Archive access code for tomorrow: ' + value)
        state['mutate'] = file; before = state['calls']
        r = run(['mutating.txt', '--semantic'])
        n, kept, dropped = summary(r)
        check('changed-during-inference/pool', r.returncode == 0 and n == 1 and kept <= 1 and dropped == n-kept)
        check('changed-during-inference/no-reread', state['calls'] == before+1 and file.read_text().startswith('AWS=') and safe(r))
        state['mutate'] = None
        (root / 'ordinary.env').write_text('AWS=' + aws)
        before = state['calls']; r = run(['ordinary.env'])
        check('ordinary/no-discovery', r.returncode == 0 and summary(r)[0] == 1 and state['calls'] == before and safe(r))
        r = run(['ordinary.env', '--format=json'])
        report = json.loads(r.stdout)
        check('json/schema', r.returncode == 0 and report['schema_version'] == '1.5.0-compare-v1' and report['complete'] and report['before'] == 1 and report['after'] <= 1 and report['suppressed'] == report['before']-report['after'] and safe(r))
        for name, flags in [('disable', ['--disable=AWS-ACCESS-KEY-ID']), ('severity', ['--min-severity=critical']), ('confidence', ['--min-confidence=1'])]:
            r = run(['ordinary.env', '--format=json', *flags])
            report = json.loads(r.stdout)
            check('filters/' + name, r.returncode == 0 and report['raw'] == [] and report['kept'] == [] and report['before'] == report['after'] == report['suppression_percent'] == 0)
        output = root / 'report.json'
        r = run(['ordinary.env', '--format=json', '-o', str(output)])
        check('output/json-private', r.returncode == 0 and not r.stdout and json.loads(output.read_text())['before'] == 1 and output.stat().st_mode & 0o777 == 0o600)
        r = run(['ordinary.env', '--silence', '-o', str(output)])
        check('output/pretty-explicit', r.returncode == 0 and not r.stdout and 'fixed candidates' in output.read_text())
        r = run(['ordinary.env', '--silence'])
        check('output/pretty-silence', r.returncode == 0 and not r.stdout)
        for name, flags in [('source', ['missing.env']), ('baseline', ['ordinary.env', '--baseline=missing']), ('ci', ['ordinary.env', '--ci=false']), ('fail-on', ['ordinary.env', '--fail-on=high']), ('cap', ['ordinary.env', '--max-per-file=0']), ('format', ['ordinary.env', '--format=sarif']), ('ml-false', ['ordinary.env', '--ml=false'])]:
            output.write_text('owned-existing-report')
            before = state['calls']
            r = run(['--format=json', '-o', str(output), *flags])
            check('output/preserve-' + name, r.returncode == 2 and not r.stdout and output.read_text() == 'owned-existing-report' and state['calls'] == before)
        r = run(['missing.env', '--format=json', '--min-confidence=1'])
        report = json.loads(r.stdout)
        check('json/incomplete-no-counts', r.returncode == 2 and report['complete'] is False and not any(key in report for key in ('before', 'after', 'suppressed', 'suppression_percent')) and safe(r))
        for mode, flags in (('error', []), ('hallucinate', []), ('slow', ['--timeout=50ms'])):
            state['mode'] = mode
            r = run(['production.txt', '--semantic', *flags])
            check(mode + '/no-percentage', r.returncode == 2 and b'fixed candidates vs' not in r.stdout)
            check(mode + '/private', safe(r))
            r = run(['production.txt', '--semantic', '--format=json', *flags])
            failed = json.loads(r.stdout)
            check(mode + '/json-incomplete', r.returncode == 2 and failed['complete'] is False and 'suppression_percent' not in failed and safe(r))
            output.write_text('owned-existing-report')
            r = run(['production.txt', '--semantic', '--format=json', '-o', str(output), *flags])
            check(mode + '/preserve-output', r.returncode == 2 and not r.stdout and output.read_text() == 'owned-existing-report')
        state['mode'] = 'normal'
        invalid = root / 'invalid-model.json'; invalid.write_text('{}')
        for name, argv in (
            ('bad-model', ['production.txt', '--semantic', '--ml-model=' + str(invalid)]),
            ('missing-source', ['missing.env']),
            ('verification', ['production.txt', '--verify']),
            ('sidecar', ['production.txt', '--ml-url=http://127.0.0.1:9/score']),
            ('remote-discovery', ['production.txt', '--semantic-url=https://owned.invalid/model']),
        ):
            before = state['calls']; r = run(argv)
            check(name + '/rejected', r.returncode == 2 and b'fixed candidates vs' not in r.stdout and state['calls'] == before)
        directory = root / 'budget'; directory.mkdir()
        for i in range(100): (directory / f'part-{i:03}.env').write_text(('AWS=' + aws + '\n') * 300)
        before = state['calls']; r = run(['budget'])
        check('global-pool-bound', r.returncode == 2 and b'fixed candidates vs' not in r.stdout and state['calls'] == before and safe(r))
        check('auth', state['auth_bad'] == 0)
    finally:
        server.shutdown(); server.server_close()
        report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'passed': sum(c['passed'] for c in checks), 'total': len(checks), 'checks': checks, 'root': str(root), 'scope': 'synthetic local files, owned loopback inference stub and embedded L2 only; no real model-quality, provider or production claim'}
        (root / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n'); print(json.dumps({k:v for k,v in report.items() if k!='checks'}))


if __name__ == '__main__': main()
