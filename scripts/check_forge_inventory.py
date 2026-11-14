#!/usr/bin/env python3
"""Qualify org inventory using owned API pages and a local-only Git clone wrapper."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
from urllib.parse import parse_qs, urlparse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    real_git = shutil.which('git')
    if not real_git:
        raise RuntimeError('Git required')
    root = Path(tempfile.mkdtemp(prefix='prowl-forge-inventory-native-'))
    (root / 'home').mkdir(); (root / 'bin').mkdir(); origin = root / 'origin'; origin.mkdir()
    value = 'AKIANAFGYOEYPXU1DSYP'
    def git(*argv):
        return subprocess.run([real_git, '-c', 'core.hooksPath=/dev/null', *argv], cwd=origin, check=True, capture_output=True)
    git('init', '-q', '-b', 'main'); git('config', 'user.name', 'Owned Fixture'); git('config', 'user.email', 'fixture@example.invalid')
    (origin / 'prod.env').write_text('AWS=' + value + '\n'); git('add', 'prod.env'); git('commit', '-qm', 'test: owned inventory fixture')
    wrapper = root / 'bin/git'
    wrapper.write_text('#!' + sys.executable + '\n' + "import os,sys\nfrom pathlib import Path\nargs=sys.argv[1:]\nif 'clone' in args:\n    assert args[-2].startswith('https://owned.invalid/')\n    args[-2]=Path(os.environ['PROWL_FIXTURE_ORIGIN']).as_uri()\nreal=os.environ['PROWL_REAL_GIT']\nos.execv(real,[real,'-c','core.hooksPath=/dev/null',*args])\n")
    wrapper.chmod(0o755)
    state = {'mode': 'normal', 'calls': [], 'bad_auth': 0}
    class API(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            state['calls'].append(self.path)
            if self.headers.get('Authorization') != 'Bearer owned-private-token' and self.headers.get('PRIVATE-TOKEN') != 'owned-private-token':
                state['bad_auth'] += 1
            parsed = urlparse(self.path); page = parse_qs(parsed.query).get('page', ['1'])[0]
            mode = state['mode']
            if (mode == 'fallback' and parsed.path.startswith('/orgs/')) or (mode == 'partial' and page == '2'):
                self.send_response(404 if mode == 'fallback' else 503); self.end_headers(); return
            self.send_response(200)
            if page == '1' and mode in ('normal', 'partial', 'changed-selection', 'cap', 'cycle', 'dual', 'conflict', 'malformed-url'):
                next_page = '1' if mode == 'cycle' else '2'
                selection = '&include_subgroups=true' if parsed.path.startswith('/groups/') else ''
                if mode == 'changed-selection':
                    selection += '&search=owned-private-filter'
                link = f'<?per_page=100&page={next_page}{selection}>; rel="next"'
                if mode == 'malformed-url':
                    link = '<https://owned.invalid/%xx?token=owned-private-link>; rel="next"'
                self.send_header('Link', link)
                if mode in ('dual', 'conflict'):
                    self.send_header('X-Next-Page', '2' if mode == 'dual' else '3')
            self.end_headers()
            field = 'git_pull_url' if parsed.path.endswith('/gists') else ('http_url_to_repo' if parsed.path.endswith('/projects') else 'clone_url')
            if mode == 'empty':
                body = '[]'
            elif mode == 'duplicate':
                body = '[{"'+field+'":"https://owned.invalid/a.git","'+field+'":"https://owned.invalid/owned-private-shadow.git"}]'
            elif mode == 'oversized':
                body = json.dumps([{field: f'https://owned.invalid/{i}.git'} for i in range(101)])
            elif mode == 'invalid-entry':
                body = json.dumps([{field: 'https://owned.invalid/a.git'}, {field: 'https://owned.invalid/' + 'x' * 4100}])
            else:
                name = 'a' if page == '1' else 'b'
                body = json.dumps([{field: f'https://owned.invalid/{name}.git'}])
            self.wfile.write(body.encode())
    server = ThreadingHTTPServer(('127.0.0.1', 0), API)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    endpoint = f'http://127.0.0.1:{server.server_port}'
    env = dict(os.environ, PROWL_HOME=str(root / 'home'), PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'],
               PROWL_REAL_GIT=real_git, PROWL_FIXTURE_ORIGIN=str(origin), PROWL_ALLOW_PRIVATE_IPS='1',
               GITHUB_API=endpoint, GITLAB_API=endpoint, GITHUB_TOKEN='owned-private-token', GITLAB_TOKEN='owned-private-token')
    checks = []; calls = 0
    def check(name, passed):
        checks.append({'case': name, 'passed': bool(passed)})
        if not passed:
            raise AssertionError(name)
    def run(platform, fmt, flags=()):
        nonlocal calls
        calls += 1
        result = subprocess.run([str(binary), 'org', platform + ':owned', '--bundled', '--format=' + fmt, '--silence', *flags], cwd=root, env=env, input=b'', capture_output=True, timeout=60)
        (root / f'case-{calls:03}.stdout').write_bytes(result.stdout); (root / f'case-{calls:03}.stderr').write_bytes(result.stderr)
        data = json.loads(result.stdout)
        if fmt == 'json':
            return result, data, data['findings']
        run_data = data['runs'][0]
        return result, run_data['properties'], [dict(f['properties'], type=f['ruleId']) for f in run_data['results']]
    def safe(result):
        return all(s.encode() not in result.stdout + result.stderr for s in (value, 'owned-private-token', 'owned-private-shadow', 'owned-private-filter', 'owned-private-link', 'prowl-repo-'))
    try:
        for platform in ('github', 'gitlab'):
            policies = []
            for ml in (False, True):
                for fmt in ('json', 'sarif'):
                    state['mode'] = 'normal'
                    result, meta, findings = run(platform, fmt, ['--ml'] if ml else [])
                    scopes = [s for s in meta['scope'] if s['kind'].startswith('forge-')]
                    check(f'{platform}/{ml}/{fmt}/normal', result.returncode == 0 and meta['complete'] and len(findings) == 2 and len(scopes) == 2)
                    check(f'{platform}/{ml}/{fmt}/safe', safe(result))
                    policies.append(scopes)
            check(platform + '/stable', all(p == policies[0] for p in policies))
            for mode in ('empty', 'partial', 'changed-selection', 'cap', 'cycle', 'duplicate', 'oversized', 'invalid-entry', 'dual', 'conflict', 'malformed-url'):
                state['mode'] = mode
                for fmt in ('json', 'sarif'):
                    baseline = root / f'{platform}-{mode}-{fmt}.baseline'; baseline.write_text('owned baseline sentinel')
                    flags = []
                    complete = mode in ('empty', 'dual')
                    if mode == 'cap':
                        config = root / 'page-cap.yaml'; config.write_text('limits:\n  org_max_pages: 1\n'); flags.append('--config=' + str(config))
                    if not complete:
                        flags.append('--write-baseline=' + str(baseline))
                    before = len(state['calls'])
                    result, meta, findings = run(platform, fmt, flags)
                    check(f'{platform}/{mode}/{fmt}/complete', result.returncode == (0 if complete else 2) and meta['complete'] == complete)
                    check(f'{platform}/{mode}/{fmt}/scope', any(s['kind'] == 'forge-inventory' for s in meta['scope']))
                    check(f'{platform}/{mode}/{fmt}/safe', safe(result))
                    if not complete:
                        check(f'{platform}/{mode}/{fmt}/baseline', baseline.read_text() == 'owned baseline sentinel')
                    if mode in ('partial', 'changed-selection', 'cap', 'cycle', 'invalid-entry', 'conflict', 'malformed-url'):
                        check(f'{platform}/{mode}/{fmt}/partial-findings', any(f['type'].replace('-', '_') == 'aws_access_key_id' for f in findings))
                    if mode in ('changed-selection', 'cap', 'cycle', 'conflict', 'malformed-url'):
                        check(f'{platform}/{mode}/{fmt}/no-follow', len(state['calls']) - before == 1)
            state['mode'] = 'fallback'
            if platform == 'github':
                result, meta, findings = run(platform, 'json')
                check('github/fallback', result.returncode == 0 and meta['complete'] and len([s for s in meta['scope'] if s['kind'] == 'forge-api']) == 2)
                result, meta, findings = run(platform, 'json', ['--gists'])
                check('github/gists', result.returncode == 0 and meta['complete'] and any('/gists' in s['target'] for s in meta['scope'] if s['kind'] == 'forge-api'))
        state['mode'] = 'malformed-url'
        result = subprocess.run([str(binary), 'org', 'github:owned', '--format=json'], cwd=root, env=env, input=b'', capture_output=True, timeout=60)
        check('visible-logs-private', result.returncode == 2 and safe(result) and b'pagination' in result.stderr)
        previous_endpoint = env['GITHUB_API']
        for kind, address in (
            ('credentials', endpoint.replace('://', '://user:owned-private-token@')),
            ('query', endpoint + '?token=owned-private-token'),
            ('fragment', endpoint + '#owned-private-token'),
        ):
            env['GITHUB_API'] = address
            before = len(state['calls'])
            result = subprocess.run([str(binary), 'org', 'github:owned', '--format=json'], cwd=root, env=env, input=b'', capture_output=True, timeout=60)
            check('invalid-api-before-request/' + kind, result.returncode == 2 and len(state['calls']) == before and safe(result))
        env['GITHUB_API'] = previous_endpoint
        check('auth', state['bad_auth'] == 0)
    finally:
        server.shutdown(); server.server_close()
        report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'passed': sum(c['passed'] for c in checks), 'total': len(checks), 'checks': checks, 'root': str(root), 'scope': 'owned loopback GitHub/GitLab API pages and local Git objects only; no external forge, provider or credentials used'}
        (root / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({k: v for k, v in report.items() if k != 'checks'}))


if __name__ == '__main__':
    main()
