#!/usr/bin/env python3
"""Qualify CLI operational limits using only an owned loopback forge and Git repositories."""
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
import urllib.parse


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
    root = Path(tempfile.mkdtemp(prefix='prowl-operational-native-'))
    served = root / 'served'
    served.mkdir()
    home = root / 'home'
    home.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith(('PROWL_', 'GIT_'))}
    env.update(PROWL_HOME=str(home), PROWL_ALLOW_PRIVATE_IPS='1', PROWL_LIVE_TEST='',
               GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_AUTHOR_NAME='Owned fixture', GIT_AUTHOR_EMAIL='owned@example.invalid',
               GIT_COMMITTER_NAME='Owned fixture', GIT_COMMITTER_EMAIL='owned@example.invalid',
               GITHUB_TOKEN='', GITLAB_TOKEN='', BITBUCKET_TOKEN='')
    for name, key in [('a', 'AKIANAFGYOEYPXU1DSYP'), ('b', 'AKIA4MNQ2RST7UVWX9YZ')]:
        work = root / ('work-' + name)
        work.mkdir()
        (work / 'production.env').write_text('AWS=' + key + '\n')
        for args in [('init', '-q'), ('add', 'production.env'), ('commit', '-qm', 'owned fixture')]:
            subprocess.run(['git', *args], cwd=work, env=env, check=True, capture_output=True)
        repo = served / (name + '.git')
        subprocess.run(['git', 'clone', '-q', '--bare', str(work), str(repo)], env=env, check=True, capture_output=True)
        subprocess.run(['git', 'update-server-info'], cwd=repo, env=env, check=True, capture_output=True)
    requests = []

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(served), **kwargs)

        def log_message(self, *args):
            pass

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path)
            if path.path == '/orgs/owned/repos':
                page = urllib.parse.parse_qs(path.query).get('page', ['1'])[0]
                requests.append(page)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                if page == '1':
                    self.send_header('Link', '<?per_page=100&page=2>; rel="next"')
                self.end_headers()
                name = 'a' if page == '1' else 'b'
                self.wfile.write(json.dumps([{'clone_url': base + '/' + name + '.git'}]).encode())
                return
            super().do_GET()

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    base = 'http://127.0.0.1:' + str(server.server_port)
    env['GITHUB_API'] = base
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    checks, results = [], {}

    def check(name, condition):
        if not condition:
            raise AssertionError(name)
        checks.append({'case': name, 'passed': True})

    def run(label, pages=2, clone='5s', extra=(), complete=True, repos=2):
        config = root / (label + '.yaml')
        config.write_text('limits:\n  org_max_pages: ' + str(pages) + '\n  clone_timeout: ' + clone + '\nperformance:\n  verify_concurrency: 2\n')
        before = len(requests)
        result = subprocess.run([str(binary), 'org', 'github:owned', '--history', '--bundled', '--config', str(config),
                                 '--format=json', '--silence', '--concurrency=1', *extra], cwd=root, env=env,
                                capture_output=True, timeout=30)
        (root / (label + '.stdout')).write_bytes(result.stdout)
        (root / (label + '.stderr')).write_bytes(result.stderr)
        data = json.loads(result.stdout)
        check(label + '-status', result.returncode == (0 if complete else 2) and data['complete'] == complete)
        check(label + '-pages', requests[before:] == (['1'] if pages == 1 else ['1', '2']))
        if complete:
            check(label + '-findings', len([f for f in data['findings'] if f['type'] in ('aws_access_key_id', 'aws-access-key-id')]) == repos)
        check(label + '-scope', any(s['kind'] == 'forge-inventory' for s in data['scope']) and any(s['kind'] == 'forge-api' for s in data['scope']))
        check(label + '-privacy', all(key.encode() not in result.stdout + result.stderr for key in ['AKIANAFGYOEYPXU1DSYP', 'AKIA4MNQ2RST7UVWX9YZ']))
        results[label] = data
        return data

    try:
        run('selected')
        run('partial', pages=1, complete=False, repos=1)
        run('defaults', pages=0)
        run('explicit-default', pages=200)
        run('hard-limit', pages=5000)
        run('explicit-hard-limit', pages=4096)
        run('timeout', clone='1ns', complete=False)
        run('explicit-timeout-wins', clone='1ns', extra=('--timeout=5s',))
        scope = lambda label: [s for s in results[label]['scope'] if s['kind'].startswith('forge-')]
        check('default-forge-scope', scope('defaults') == scope('explicit-default'))
        check('hard-forge-scope', scope('hard-limit') == scope('explicit-hard-limit'))
        check('different-page-scope', scope('selected') != scope('partial'))
        evidence = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'passed': True,
                    'checks': checks, 'network': 'OS denies all network except owned loopback',
                    'boundary': 'Real local CLI org/history and Git over owned dumb HTTP; no provider verification or remote production service.'}
        output = root / 'evidence.json'
        output.write_text(json.dumps(evidence, indent=2) + '\n')
        print(json.dumps({'passed': len(checks), 'evidence': str(output)}))
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


if __name__ == '__main__':
    main()
