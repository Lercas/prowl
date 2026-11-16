#!/usr/bin/env python3
"""Qualify immutable repository cross-file acquisitions against owned Git/HTTP fixtures."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import zipfile

KEY = 'AKIANAFGYOEYPXU1DSYP'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    real_git = shutil.which('git')
    assert real_git, 'Git required'
    root = Path(tempfile.mkdtemp(prefix='prowl-repository-components-'))
    (root / 'bin').mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith(('PROWL_', 'GIT_')) and not k.upper().endswith('_PROXY')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
               PROWL_HOME=str(root / 'home'), PROWL_LIVE_TEST='', PROWL_ALLOW_PRIVATE_IPS='1', NO_PROXY='127.0.0.1,localhost')
    def git(folder, *args, data=None):
        p = subprocess.run([real_git, '-c', 'core.hooksPath=/dev/null', *args], input=data, cwd=folder, env=env, capture_output=True, timeout=30)
        assert p.returncode == 0, 'owned Git setup failed'
        return p.stdout.strip().decode()
    origins = {}
    revisions = {}
    for name in ('app', 'other', 'key-only', 'companion-only', 'archive', 'symlink', 'empty'):
        folder = root / name
        folder.mkdir()
        origins[name] = str(folder)
        git(folder, 'init', '-q', '-b', 'main')
        git(folder, 'config', 'user.name', 'Owned Fixture')
        git(folder, 'config', 'user.email', 'fixture@example.invalid')
        if name == 'empty':
            continue
        if name != 'companion-only':
            (folder / 'key.json').write_text(json.dumps({'prod': {'rows': [{'accessKeyId': KEY}]}}))
        if name in ('app', 'other', 'companion-only'):
            (folder / 'account.toml').write_text('[[prod.rows]]\naccount="' + ('tenant_b' if name == 'other' else 'tenant_a') + '"\n')
        if name == 'archive':
            data = io.BytesIO()
            with zipfile.ZipFile(data, 'w') as z:
                z.writestr('account.json', '{"prod":{"rows":[{"account":"tenant_a"}]}}')
            (folder / 'owned.zip').write_bytes(data.getvalue())
        if name == 'symlink':
            (folder / 'account.json').symlink_to('{"prod":{"rows":[{"account":"tenant_a"}]}}')
        if name == 'app':
            # Cloned policy must not turn verification or the selected detector off.
            (folder / '.prowl.yaml').write_text('version: 1\ndetectors:\n  disable: [aws_access_key_id]\n')
            (folder / 'account.toml').write_text('[[prod.rows]]\naccount="tenant_b"\n')
            git(folder, 'add', '--all'); git(folder, 'commit', '-qm', 'owned old revision')
            revisions['old'] = git(folder, 'rev-parse', 'HEAD')
            git(folder, 'tag', 'old')
            (folder / 'account.toml').write_text('[[prod.rows]]\naccount="tenant_a"\n')
        git(folder, 'add', '--all'); git(folder, 'commit', '-qm', 'owned current revision')
        revisions[name] = git(folder, 'rev-parse', 'HEAD')
        # The copied checkout is modified by the clone wrapper below too.
        (folder / 'account.toml').write_text('[[prod.rows]]\naccount="tenant_b"\n')
    wrapper = root / 'bin/git'
    wrapper.write_text('#!' + sys.executable + '\n' + r'''
import json,os,subprocess,sys
from pathlib import Path
from urllib.parse import urlsplit
args=sys.argv[1:]
real=os.environ['PROWL_REAL_GIT']
if 'clone' in args:
    name=Path(urlsplit(args[-2]).path).name.removesuffix('.git')
    args[-2]=Path(json.loads(os.environ['PROWL_ORIGINS'])[name]).as_uri()
    result=subprocess.run([real,'-c','core.hooksPath=/dev/null',*args])
    if result.returncode==0 and name=='app':
        (Path(args[-1])/'account.toml').write_text('[[prod.rows]]\naccount="tenant_b"\n')
    sys.exit(result.returncode)
if 'HEAD^{commit}' in args and os.environ.get('PROWL_REPO_BAD_METADATA')=='1':
    print('OWNED_INVALID_PRIVATE_REVISION');sys.exit(0)
os.execv(real,[real,'-c','core.hooksPath=/dev/null',*args])
''')
    wrapper.chmod(0o755)
    state = {'repos': ['app'], 'calls': []}
    def locator(name):
        return 'https://user:private-url@owned.invalid/' + name + '.git?token=private-query'
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_GET(self):
            if self.path == '/owned':
                good = self.headers.get('Authorization') == 'Bearer ' + KEY and self.headers.get('X-Account') == 'tenant_a'
                state['calls'].append(good)
                self.send_response(200 if good else 401); self.end_headers()
            elif self.path.startswith('/orgs/owned/repos'):
                self.send_response(200); self.end_headers()
                self.wfile.write(json.dumps([{'clone_url': locator(name)} for name in state['repos']]).encode())
            else:
                self.send_response(404); self.end_headers()
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    env.update(PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'], PROWL_REAL_GIT=real_git,
               PROWL_ORIGINS=json.dumps(origins), GITHUB_TOKEN='', GITHUB_API=f'http://127.0.0.1:{server.server_port}')
    verifiers = root / 'verifiers'; verifiers.mkdir()
    (verifiers / 'owned.yaml').write_text(f"id: owned\nmatch: [aws_access_key_id]\nextract:\n  account: 'tenant_[ab]'\nrequests:\n  - url: http://127.0.0.1:{server.server_port}/owned\n    headers:\n      Authorization: 'Bearer {{{{secret}}}}'\n      X-Account: '{{{{account}}}}'\n    matchers:\n      - type: status\n        status: [200]\n")
    model = Path(__file__).resolve().parents[1] / 'tool/internal/mlmodel/model_binary_go_literal_v1.json'
    checks = []
    def check(name, ok):
        assert ok, name
        checks.append({'case': name, 'passed': True})
    def run(command='repo', name='app', fmt='json', ml=False, extra=()):
        target = locator(name) if command == 'repo' else 'github:owned'
        argv = [str(binary), command, target, '--cross-file', '--verify', '--verifiers', str(verifiers),
                '--format=' + fmt, '--silence', '--workers=1', '--max-per-file=0', *map(str, extra)]
        if ml:
            argv += ['--ml', '--ml-model', str(model)]
        return subprocess.run(argv, cwd=root, env=env, input=b'', capture_output=True, timeout=60)
    def report(p, fmt):
        data = json.loads(p.stdout)
        if fmt == 'sarif':
            data = data['runs'][0]
            return data['properties'], [f['properties'] for f in data['results'] if f['ruleId'].replace('-', '_') == 'aws_access_key_id']
        return data, [f for f in data['findings'] if f['type'].replace('-', '_') == 'aws_access_key_id']
    def private(p):
        return all(v.encode() not in p.stdout + p.stderr for v in (KEY, 'tenant_a', 'tenant_b', 'private-url', 'private-query', 'OWNED_INVALID_PRIVATE_REVISION', 'prowl-repo-'))
    try:
        for command in ('repo', 'org'):
            for history_flag in ('--history', '--git-timeline'):
                for fmt in ('json', 'sarif'):
                    for ml in (False, True):
                        before = len(state['calls'])
                        p = run(command, fmt=fmt, ml=ml, extra=[history_flag])
                        meta, fs = report(p, fmt)
                        label = f'{command}-{history_flag[2:]}-{fmt}-ml{ml}'
                        check(label + '-complete', p.returncode == 0 and meta['complete'] and bool(fs))
                        occurrences = [o for f in fs for o in f.get('occurrences', [f])]
                        verdicts = {o['provenance']['commit']: o['verification']['status'] for o in occurrences}
                        check(label + '-commit-verdicts', len(occurrences) == 2 and verdicts == {revisions['old']: 'invalid', revisions['app']: 'verified'})
                        ids = {i for o in occurrences for i in o['verification']['components']['primary']}
                        check(label + '-separate-component-ids', len(ids) == 2)
                        check(label + '-probe', len(state['calls']) == before + 2 and sorted(state['calls'][before:]) == [False, True])
                        check(label + '-scope', any(s['kind'] == 'components' and s['target'] == ('git-history-timeline' if history_flag == '--git-timeline' else 'git-history-commits') for s in meta['scope']) and any(s['kind'] == 'components-history-snapshot' for s in meta['scope']))
                        check(label + '-private', private(p))
                        check(label + '-lifecycle-opt-in', all(f.get('git', {}).get('complete') and f['git'].get('in_head') is True and f['git']['head'] == revisions['app'] and [c['hash'] for c in f['git']['appearances']] == [revisions['old']] and not f['git']['removals'] for f in fs) if history_flag == '--git-timeline' else all('git' not in f for f in fs))
                index = root / (command + '-' + history_flag[2:] + '-index')
                p = run(command, extra=[history_flag, '--index', index, '--scope', 'owned-history'])
                meta, fs = report(p, 'json')
                indexed = subprocess.run([str(binary), 'index', '--index', str(index), '--format=json'], cwd=root, env=env, capture_output=True, timeout=20)
                places = {place['id'] for secret in json.loads(indexed.stdout)['secrets'] for place in secret['locations']}
                ids = {i for f in fs for o in f.get('occurrences', [f]) for i in o['verification']['components']['primary']}
                check(command + '-' + history_flag[2:] + '-index', p.returncode == 0 and meta['complete'] and len(ids) == 2 and ids <= places)
                with sqlite3.connect(index / 'index.sqlite') as db:
                    raw = '\n'.join(db.iterdump()).encode()
                check(command + '-' + history_flag[2:] + '-index-private', all(value.encode() not in raw for value in (KEY, 'tenant_a', 'tenant_b')))
        for command in ('repo', 'org'):
            for fmt in ('json', 'sarif'):
                for ml in (False, True):
                    before = len(state['calls']); p = run(command, fmt=fmt, ml=ml)
                    label = f'{command}-{fmt}-ml{ml}'
                    assert p.returncode == 0, label + '-command'
                    meta, fs = report(p, fmt)
                    check(label + '-complete', meta['complete'] and len(fs) == 1)
                    check(label + '-verdict', fs[0]['verification']['status'] == 'verified')
                    check(label + '-components', len(fs[0]['verification']['components']['primary']) == 1 and len(fs[0]['verification']['components']['fields']['account']) == 1)
                    check(label + '-probe', len(state['calls']) == before + 1 and state['calls'][-1])
                    check(label + '-commit', fs[0]['provenance']['commit'] == revisions['app'] and len(fs[0]['provenance']['blob']) in (40, 64))
                    check(label + '-scope', any(s['kind'] == 'components' and s['target'] == 'repository-commit' for s in meta['scope']) and any(s['kind'] == 'components-repository-snapshot' for s in meta['scope']))
                    check(label + '-private', private(p))
            index = root / (command + '-index')
            p = run(command, extra=['--index', index, '--scope', 'owned-repository'])
            meta, fs = report(p, 'json')
            indexed = subprocess.run([str(binary), 'index', '--index', str(index), '--format=json'], cwd=root, env=env, capture_output=True, timeout=20)
            places = {p['id'] for s in json.loads(indexed.stdout)['secrets'] for p in s['locations']}
            check(command + '-index-primary', p.returncode == 0 and meta['complete'] and set(fs[0]['verification']['components']['primary']) <= places)
            with sqlite3.connect(index / 'index.sqlite') as db:
                raw = '\n'.join(db.iterdump()).encode()
            check(command + '-index-private', all(v.encode() not in raw for v in (KEY, 'tenant_a', 'private-url', 'private-query')))
        state['repos'] = ['app', 'other']
        for fmt in ('json', 'sarif'):
            for ml in (False, True):
                before = len(state['calls']); p = run('org', fmt=fmt, ml=ml)
                meta, fs = report(p, fmt)
                label = f'org-independent-{fmt}-ml{ml}'
                check(label + '-verdicts', p.returncode == 0 and meta['complete'] and len(fs) == 2 and
                      {f['verification']['status'] for f in fs} == {'verified', 'invalid'})
                check(label + '-probes', len(state['calls']) == before + 2 and sorted(state['calls'][before:]) == [False, True])
                check(label + '-revisions', {f['provenance']['commit'] for f in fs} == {revisions['app'], revisions['other']})
                check(label + '-private', private(p))
        state['repos'] = ['app']
        for fmt in ('json', 'sarif'):
            before = len(state['calls']); p = run(fmt=fmt, extra=['--branch', 'old'])
            meta, fs = report(p, fmt)
            check('selected-old-commit-' + fmt, p.returncode == 0 and meta['complete'] and len(fs) == 1 and fs[0]['provenance']['commit'] == revisions['old'] and fs[0]['verification']['status'] == 'invalid' and len(state['calls']) == before + 1 and not state['calls'][-1])
        for command in ('repo', 'org'):
            for mode in ('key-only', 'archive', 'symlink', 'split-repositories', 'metadata'):
                state['repos'] = ['key-only', 'companion-only'] if mode == 'split-repositories' else [mode if mode != 'metadata' else 'app']
                env['PROWL_REPO_BAD_METADATA'] = '1' if mode == 'metadata' else '0'
                name = 'key-only' if mode == 'split-repositories' else state['repos'][0]
                baseline = root / (command + '-' + mode + '.baseline'); baseline.write_bytes(b'owned baseline')
                for history in (None, '--history', '--git-timeline'):
                    for fmt in ('json', 'sarif'):
                        before = len(state['calls']); p = run(command, name, fmt=fmt, extra=['--verified-only', '--write-baseline', baseline, *([history] if history else [])])
                        meta, _ = report(p, fmt)
                        label = f'{command}-{mode}-{fmt}' + ('-' + history[2:] if history else '')
                        check(label + '-no-probe', p.returncode == 2 and not meta['complete'] and len(state['calls']) == before)
                        check(label + '-baseline', baseline.read_bytes() == b'owned baseline')
                        check(label + '-private', private(p))
            env['PROWL_REPO_BAD_METADATA'] = '0'; state['repos'] = ['empty']
            p = run(command, 'empty'); meta, fs = report(p, 'json')
            check(command + '-empty', p.returncode == 0 and meta['complete'] and not fs)
            for history_flag in ('--history', '--git-timeline'):
                p = run(command, 'empty', extra=[history_flag]); meta, fs = report(p, 'json')
                check(command + '-' + history_flag[2:] + '-empty', p.returncode == 0 and meta['complete'] and not fs)
            for flag in ('--stdin-name=owned.json',):
                before = len(state['calls']); p = run(command, extra=[flag])
                check(command + flag + '-guard', p.returncode == 2 and not p.stdout and len(state['calls']) == before)
        evidence = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'model_sha256': hashlib.sha256(model.read_bytes()).hexdigest(),
                    'passed': len(checks), 'failed': 0, 'checks': checks, 'fixture_root': str(root),
                    'scope': 'repo/org pinned-commit, per-revision history and timeline cross-file with owned Git origins, forge inventory and loopback verifier; no real provider acceptance'}
        (root / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
        print(json.dumps({'passed': len(checks), 'evidence': str(root / 'evidence.json')}))
    finally:
        server.shutdown(); server.server_close(); thread.join()


if __name__ == '__main__':
    main()
