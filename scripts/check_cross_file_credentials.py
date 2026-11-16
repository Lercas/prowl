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

    def run(paths, extra=(), fmt='json', ml=False, cross=True, cwd=None):
        args = [str(binary), 'scan', *map(str, paths), '--verify', '--verifiers', str(verifiers),
                '--format=' + fmt, '--silence', '--workers=1', '--max-per-file=0']
        if cross:
            args.append('--cross-file')
        if ml:
            args += ['--ml', '--ml-model', str(model)]
        return subprocess.run([*args, *map(str, extra)], cwd=cwd or root, env=git_env if cwd else env, capture_output=True, timeout=40)

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

    git_env = {k: v for k, v in env.items() if not k.startswith('GIT_')}
    git_env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)

    def git(folder, *args, data=None):
        p = subprocess.run(['git', *args], input=data, cwd=folder, env=git_env, capture_output=True, timeout=20)
        assert p.returncode == 0, 'owned Git fixture setup failed'
        return p.stdout

    def staged_fixture(label, extension='json'):
        folder = fixture('staged-' + label, extension)
        git(folder, 'init', '-q')
        git(folder, '-c', 'user.name=Owned Fixture', '-c', 'user.email=fixture@example.invalid',
            '-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'empty base', '--allow-empty')
        git(folder, 'add', '--all')
        return folder

    try:
        for extension in ('json', 'yaml', 'toml', 'env'):
            source = staged_fixture(extension, extension)
            # Conflicting worktree content must not replace staged components.
            (source / ('account.' + extension)).write_text('account=tenant_b\n')
            listing = git(source, 'ls-files', '--stage', '-z')
            snapshot = hashlib.sha256(listing).hexdigest()
            for fmt in ('json', 'sarif'):
                for ml in (False, True):
                    before = len(Handler.calls)
                    p = run([], extra=['--staged'], fmt=fmt, ml=ml, cwd=source)
                    label = f'staged-{extension}-{fmt}-ml{ml}'
                    assert p.returncode == 0, label + '-command-success'
                    fs, complete = report(p, fmt)
                    check(label + '-complete', p.returncode == 0 and complete and len(fs) == 1)
                    check(label + '-verdict', fs[0]['verification']['status'] == 'verified')
                    check(label + '-components', len(fs[0]['verification']['components']['fields']['account']) == 1)
                    check(label + '-owned-request', len(Handler.calls) == before + 1 and Handler.calls[-1])
                    check(label + '-private', all(v.encode() not in p.stdout + p.stderr for v in (KEY, 'tenant_a', 'tenant_b', 'accessKeyId')))
                    if fmt == 'json':
                        check(label + '-snapshot', fs[0]['provenance']['git_index_snapshot'] == snapshot and
                              any(scope['kind'] == 'components' and scope['target'] == 'git-index' for scope in json.loads(p.stdout)['scope']) and
                              any(scope['kind'] == 'components-index-snapshot' for scope in json.loads(p.stdout)['scope']))
            index = root / ('staged-index-' + extension)
            p = run([], extra=['--staged', '--index', index, '--scope', 'owned-staged'], cwd=source)
            fs, complete = report(p, 'json')
            ids = fs[0]['verification']['components']['primary']
            indexed = subprocess.run([str(binary), 'index', '--index', str(index), '--format=json'], cwd=root, env=env, capture_output=True, timeout=20)
            places = {p['id'] for s in json.loads(indexed.stdout)['secrets'] for p in s['locations']}
            check(f'staged-{extension}-index-primary', p.returncode == 0 and complete and indexed.returncode == 0 and set(ids) <= places)
            with sqlite3.connect(index / 'index.sqlite') as database:
                raw = '\n'.join(database.iterdump()).encode()
            check(f'staged-{extension}-index-private', all(v.encode() not in raw for v in (KEY, 'tenant_a', 'accessKeyId')))

        for mode in ('unstaged', 'committed-unselected', 'conflict', 'symlink', 'archive', 'unknown'):
            source = staged_fixture('negative-' + mode)
            account = source / 'account.json'
            if mode == 'unstaged':
                # Put the companion only in the working copy; stage an unrelated empty object.
                account.write_text('{}')
                git(source, 'add', '--', account.name)
                account.write_text('{"account":"tenant_a"}')
            elif mode == 'committed-unselected':
                git(source, '-c', 'user.name=Owned Fixture', '-c', 'user.email=fixture@example.invalid',
                    '-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'committed configuration')
                (source / 'key.json').write_text(json.dumps({'accessKeyId': OTHER}))
                git(source, 'add', '--', 'key.json')
            elif mode == 'conflict':
                blob = git(source, 'hash-object', '-w', '--stdin', data=account.read_bytes()).strip().decode()
                git(source, 'update-index', '--index-info', data=(f'0 {"0" * 40}\taccount.json\n' +
                    ''.join(f'100644 {blob} {stage}\taccount.json\n' for stage in (1, 2, 3))).encode())
            elif mode == 'symlink':
                git(source, 'update-index', '--force-remove', '--', account.name)
                account.rename(source / 'unselected-companion.json')
                (source / 'account.env').symlink_to('account=tenant_a')
                git(source, 'add', '--', 'account.env')
            elif mode == 'archive':
                account.write_text('{}')
                git(source, 'add', '--', account.name)
                stream = io.BytesIO()
                with zipfile.ZipFile(stream, 'w') as z:
                    z.writestr('account.json', '{"account":"tenant_a"}')
                (source / 'owned.zip').write_bytes(stream.getvalue())
                git(source, 'add', '--', 'owned.zip')
            else:
                (source / 'key.json').write_text(json.dumps({'accessKeyId': KEY, 'account': None}))
                git(source, 'add', '--', 'key.json')
            baseline = root / ('staged-' + mode + '.baseline')
            baseline.write_bytes(b'owned staged baseline')
            for fmt in ('json', 'sarif'):
                for ml in (False, True):
                    before = len(Handler.calls)
                    p = run([], extra=['--staged', '--verified-only', '--write-baseline', baseline], fmt=fmt, ml=ml, cwd=source)
                    _, complete = report(p, fmt)
                    label = f'staged-negative-{mode}-{fmt}-ml{ml}'
                    check(label + '-no-request', p.returncode == 2 and not complete and len(Handler.calls) == before)
                    check(label + '-baseline', baseline.read_bytes() == b'owned staged baseline')

        source = staged_fixture('empty')
        git(source, '-c', 'user.name=Owned Fixture', '-c', 'user.email=fixture@example.invalid',
            '-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'unchanged index')
        for fmt in ('json', 'sarif'):
            before = len(Handler.calls)
            p = run([], extra=['--staged'], fmt=fmt, cwd=source)
            fs, complete = report(p, fmt)
            check('staged-empty-' + fmt, p.returncode == 0 and complete and not fs and len(Handler.calls) == before)

        source = staged_fixture('subdirectory')
        child = source / 'nested'
        child.mkdir()
        for fmt in ('json', 'sarif'):
            before = len(Handler.calls)
            p = run([], extra=['--staged'], fmt=fmt, cwd=child)
            fs, complete = report(p, fmt)
            check('staged-subdirectory-' + fmt, p.returncode == 0 and complete and len(fs) == 1 and
                  fs[0]['verification']['status'] == 'verified' and len(Handler.calls) == before + 1 and Handler.calls[-1])

        source = staged_fixture('mutation')
        (source / 'other-key.json').write_text(json.dumps({'secondKey': OTHER}))
        git(source, 'add', '--', 'other-key.json')
        def mutate_index():
            (source / 'account.json').write_text('{"account":"tenant_b"}')
            git(source, 'add', '--', 'account.json')
        Handler.mutate = mutate_index
        before = len(Handler.calls)
        p = run([], extra=['--staged'], cwd=source)
        _, complete = report(p, 'json')
        check('staged-sealed-before-probes', p.returncode == 0 and complete and len(Handler.calls) == before + 2 and all(Handler.calls[before:]))
        p = run([], extra=['--staged'], cwd=source)
        fs, complete = report(p, 'json')
        check('staged-next-acquisition-observes-new-index', p.returncode == 0 and complete and len(fs) == 2 and all(f['verification']['status'] == 'invalid' for f in fs))

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

        nested_cases = (
            ('array-json', 'a.json', json.dumps({'rows': [None, 7, {'accessKeyId': KEY}]}), 'b.json', '{"rows":[false,"skip",{"account":"tenant_a"}]}'),
            ('array-root', 'a.json', json.dumps([[{'accessKeyId': KEY}]]), 'b.yaml', '- - account: tenant_a\n'),
            ('array-yaml', 'a.yaml', f'rows: [ignored, {{accessKeyId: {KEY}}}]\n', 'b.json', '{"rows":[null,{"account":"tenant_a"}]}'),
            ('array-yaml-alias', 'a.json', json.dumps({'rows': [{'accessKeyId': KEY}]}), 'b.yaml', 'defaults: &d {account: tenant_a}\nrows: [*d]\n'),
            ('array-yaml-sequence-alias', 'a.json', json.dumps({'rows': [{'accessKeyId': KEY}]}), 'b.yaml', 'defaults: &d [{account: tenant_a}]\nrows: *d\n'),
            ('array-yaml-merge', 'a.json', json.dumps({'rows': [{'accessKeyId': KEY}]}), 'b.yaml', 'defaults: &d {account: tenant_a}\nrows: [{<<: *d}]\n'),
            ('array-toml-tables', 'a.toml', f'[[rows]]\nignored=7\n[[rows]]\naccessKeyId="{KEY}"\n', 'b.json', '{"rows":[{}, {"account":"tenant_a"}]}'),
            ('array-toml-inline', 'a.toml', f'rows=[1,2,{{accessKeyId="{KEY}"}}]\n', 'b.yaml', 'rows: [null, false, {account: tenant_a}]\n'),
            ('array-toml-nested', 'a.toml', f'rows=[[{{accessKeyId="{KEY}"}}]]\n', 'b.json', '{"rows":[[{"account":"tenant_a"}]]}'),
            ('array-toml-nested-tables', 'a.toml', f'[[rows]]\n[[rows.db]]\n[[rows]]\n[[rows.db]]\naccessKeyId="{KEY}"\n', 'b.json', '{"rows":[{"db":[{}]},{"db":[{"account":"tenant_a"}]}]}'),
            ('array-toml-table', 'a.toml', f'[[rows]]\n[rows.service]\naccessKeyId="{KEY}"\n', 'b.json', '{"rows":[{"service":{"account":"tenant_a"}}]}'),
            ('json', 'a.json', json.dumps({'prod': {'service': {'accessKeyId': KEY}}}), 'b.json', '{"prod":{"service":{"account":"tenant_a"}}}'),
            ('yaml', 'a.yaml', f'prod:\n  service:\n    accessKeyId: {KEY}\n', 'b.yaml', 'prod:\n  service:\n    account: tenant_a\n'),
            ('toml', 'a.toml', f'[prod.service]\naccessKeyId="{KEY}"\n', 'b.toml', '[prod.service]\naccount="tenant_a"\n'),
            ('dotted', 'a.toml', f'prod.service.accessKeyId="{KEY}"\n', 'b.toml', 'prod.service.account="tenant_a"\n'),
            ('inline', 'a.toml', f'prod={{service={{accessKeyId="{KEY}"}}}}\n', 'b.toml', 'prod={service={account="tenant_a"}}\n'),
            ('mixed', 'a.json', json.dumps({'prod': {'service': {'accessKeyId': KEY}}}), 'b.yaml', 'prod:\n  service:\n    account: tenant_a\n'),
            ('quoted-dot', 'a.json', json.dumps({'prod.service': {'accessKeyId': KEY}}), 'b.toml', '["prod.service"]\naccount="tenant_a"\n'),
            ('yaml-map-alias', 'a.json', json.dumps({'prod': {'accessKeyId': KEY}}), 'b.yaml', 'defaults: &d {account: tenant_a}\nprod: *d\n'),
            ('yaml-scalar-alias', 'a.json', json.dumps({'prod': {'accessKeyId': KEY}}), 'b.yaml', 'value: &a tenant_a\nprod: {account: *a}\n'),
            ('yaml-nested-alias', 'a.json', json.dumps({'prod': {'service': {'accessKeyId': KEY}}}), 'b.yaml', 'defaults: &d {service: {account: tenant_a}}\nprod: *d\n'),
            ('yaml-merge', 'a.json', json.dumps({'prod': {'accessKeyId': KEY}}), 'b.yaml', 'defaults: &d {account: tenant_a}\nprod: {<<: *d}\n'),
            ('yaml-override', 'a.json', json.dumps({'prod': {'accessKeyId': KEY}}), 'b.yaml', 'defaults: &d {account: tenant_b}\nprod: {<<: *d, account: tenant_a}\n'),
            ('yaml-merge-sequence', 'a.json', json.dumps({'prod': {'accessKeyId': KEY}}), 'b.yaml', 'a: &a {account: tenant_a}\nb: &b {account: tenant_b}\nprod: {<<: [*a, *b]}\n'),
        )
        for name, key_name, key_text, account_name, account_text in nested_cases:
            source = root / ('namespace-' + name)
            source.mkdir()
            (source / key_name).write_text(key_text)
            (source / account_name).write_text(account_text)
            for fmt in ('json', 'sarif'):
                for ml in (False, True):
                    before = len(Handler.calls)
                    p = run([source], fmt=fmt, ml=ml)
                    fs, complete = report(p, fmt)
                    label = f'namespace-{name}-{fmt}-ml{ml}'
                    check(label + '-complete', p.returncode == 0 and complete and len(fs) == 1)
                    detail = fs[0]['verification']
                    check(label + '-verified', detail['status'] == 'verified' and len(detail['components']['fields']['account']) == 1)
                    check(label + '-request', len(Handler.calls) == before + 1 and Handler.calls[-1])
                    check(label + '-private', all(v.encode() not in p.stdout + p.stderr for v in (KEY, 'tenant_a', 'accessKeyId')))
            if name.startswith('array-') or name in ('mixed', 'yaml-map-alias', 'yaml-scalar-alias', 'yaml-nested-alias', 'yaml-merge-sequence'):
                nested_index = root / ('namespace-index-' + name)
                p = run([source], extra=['--index', nested_index, '--scope', 'owned-nested'])
                fs, complete = report(p, 'json')
                ids = fs[0]['verification']['components']['primary']
                indexed = subprocess.run([str(binary), 'index', '--index', str(nested_index), '--format=json'], cwd=root, env=env, capture_output=True, timeout=20)
                places = {p['id'] for s in json.loads(indexed.stdout)['secrets'] for p in s['locations']}
                check(f'namespace-{name}-index-primary', p.returncode == 0 and complete and indexed.returncode == 0 and set(ids) <= places)
                with sqlite3.connect(nested_index / 'index.sqlite') as database:
                    raw = '\n'.join(database.iterdump()).encode()
                check(f'namespace-{name}-index-private', all(v.encode() not in raw for v in (KEY, 'tenant_a', 'accessKeyId')))

        alias_bomb = 'base: &n0 {account: tenant_a}\n' + ''.join(
            f'node{i}: &n{i} {{left: *n{i-1}, right: *n{i-1}}}\n' for i in range(1, 21))
        for name, account_name, account_text in (
            ('sibling', 'b.json', '{"dev":{"account":"tenant_a"}}'),
            ('parent', 'b.json', '{"account":"tenant_a"}'),
            ('child', 'b.json', '{"prod":{"service":{"account":"tenant_a"}}}'),
            ('case', 'b.json', '{"Prod":{"account":"tenant_a"}}'),
            ('dots', 'b.json', '{"prod.account":"tenant_a"}'),
            ('null-shadow', 'b.json', '{"prod":{"Account":null,"account":"tenant_a"}}'),
            ('container-shadow', 'b.json', '{"prod":{"Account":{},"account":"tenant_a"}}'),
            ('array', 'b.json', '{"prod":[{"account":"tenant_a"}]}'),
            ('alias-sibling', 'b.yaml', 'defaults: &d {account: tenant_a}\ndev: *d\n'),
            ('alias-null-override', 'b.yaml', 'defaults: &d {account: tenant_a}\nprod: {<<: *d, account: null}\n'),
            ('alias-unknown-case', 'b.yaml', 'defaults: &d {account: tenant_a}\nprod: {<<: *d, Account: null}\n'),
            ('alias-cycle', 'b.yaml', 'defaults: &d {child: *d}\nprod: {account: tenant_a}\n'),
            ('alias-missing', 'b.yaml', 'prod: {account: *missing}\n'),
            ('alias-cross-document', 'b.yaml', 'value: &a tenant_a\n---\nprod: {account: *a}\n'),
            ('alias-duplicate-merge', 'b.yaml', 'defaults: &d {account: tenant_a}\nprod: {<<: *d, <<: *d}\n'),
            ('alias-expansion-budget', 'b.yaml', alias_bomb),
            ('alias-invalid-nested-merge', 'b.yaml', 'prod: {<<: [[{account: tenant_a}]]}\n'),
            ('alias-invalid-sequence-merge', 'b.yaml', 'a: &a {account: tenant_a}\nlist: &l [*a]\nprod: {<<: *l}\n'),
            ('documents', 'b.yaml', 'prod: {account: tenant_a}\n---\nprod: {account: tenant_b}\n'),
            ('array-tables', 'b.toml', '[[prod]]\naccount="tenant_a"\n'),
        ):
            source = root / ('namespace-negative-' + name)
            source.mkdir()
            (source / 'a.json').write_text(json.dumps({'prod': {'accessKeyId': KEY}}))
            (source / account_name).write_text(account_text)
            baseline = source / 'sentinel.baseline'
            baseline.write_bytes(b'owned namespace baseline')
            for fmt in ('json', 'sarif'):
                before = len(Handler.calls)
                p = run([source], extra=['--verified-only', '--write-baseline', baseline], fmt=fmt)
                _, complete = report(p, fmt)
                check(f'namespace-negative-{name}-{fmt}', p.returncode == 2 and not complete and len(Handler.calls) == before)
                check(f'namespace-baseline-{name}-{fmt}', baseline.read_bytes() == b'owned namespace baseline')

        for name, primary, account_name, account_text in (
            ('index', {'rows': [{}, {'accessKeyId': KEY}]}, 'b.json', '{"rows":[{"account":"tenant_a"},{}]}'),
            ('numeric-key', {'rows': [{'accessKeyId': KEY}]}, 'b.json', '{"rows":{"0":{"account":"tenant_a"}}}'),
            ('root-object', [{'accessKeyId': KEY}], 'b.json', '{"account":"tenant_a"}'),
            ('scalar-primary', {'rows': [KEY]}, 'b.json', '{"rows":[{"account":"tenant_a"}]}'),
            ('scalar-account', {'rows': [{'accessKeyId': KEY}]}, 'b.json', '{"rows":["tenant_a"]}'),
            ('null', {'rows': [{'accessKeyId': KEY, 'account': None}]}, 'b.yaml', 'rows: [{account: tenant_a}]\n'),
            ('container', {'rows': [{'accessKeyId': KEY, 'account': []}]}, 'b.toml', '[[rows]]\naccount="tenant_a"\n'),
            ('empty', {'rows': [{'accessKeyId': KEY, 'account': ''}]}, 'b.json', '{"rows":[{"account":"tenant_a"}]}'),
            ('depth', {'rows': [[{'accessKeyId': KEY}]]}, 'b.toml', 'rows=[{account="tenant_a"}]\n'),
            ('alias-index', {'rows': [{}, {'accessKeyId': KEY}]}, 'b.yaml', 'defaults: &d {account: tenant_a}\nrows: [*d, {}]\n'),
        ):
            source = root / ('indexed-negative-' + name)
            source.mkdir()
            (source / 'a.json').write_text(json.dumps(primary))
            (source / account_name).write_text(account_text)
            baseline = source / 'sentinel.baseline'
            baseline.write_bytes(b'owned indexed baseline')
            for fmt in ('json', 'sarif'):
                for ml in (False, True):
                    before = len(Handler.calls)
                    p = run([source], extra=['--verified-only', '--write-baseline', baseline], fmt=fmt, ml=ml)
                    _, complete = report(p, fmt)
                    label = f'indexed-negative-{name}-{fmt}-ml{ml}'
                    check(label + '-no-request', p.returncode == 2 and not complete and len(Handler.calls) == before)
                    check(label + '-baseline', baseline.read_bytes() == b'owned indexed baseline')

        for name, primary, account in (
            ('yaml-primary-alias', f'defaults: &d {{accessKeyId: {KEY}}}\nprod: *d\n', '{"defaults":{"account":"tenant_a"},"prod":{"account":"tenant_b"}}'),
            ('indexed-primary-alias', f'rows: [ &d {{accessKeyId: {KEY}}}, *d ]\n', '{"rows":[{"account":"tenant_a"},{"account":"tenant_b"}]}'),
        ):
            source = root / name
            source.mkdir()
            (source / 'a.yaml').write_text(primary)
            (source / 'b.json').write_text(account)
            for fmt in ('json', 'sarif'):
                for ml in (False, True):
                    before = len(Handler.calls)
                    p = run([source], fmt=fmt, ml=ml)
                    fs, complete = report(p, fmt)
                    label = f'{name}-{fmt}-ml{ml}'
                    check(label + '-complete', p.returncode == 0 and complete and len(fs) == 1)
                    occurrences = fs[0]['occurrences']
                    check(label + '-verdicts', len(occurrences) == 2 and
                          {o['verification']['status'] for o in occurrences} == {'verified', 'invalid'})
                    check(label + '-contexts', len(Handler.calls) == before + 2 and
                          sorted(Handler.calls[before:]) == [False, True])
                    check(label + '-private', all(v.encode() not in p.stdout + p.stderr for v in (KEY, 'tenant_a', 'tenant_b', 'accessKeyId')))

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
                    'scope': 'Opt-in local configuration literals; JSON/SARIF, ML, occurrences, index, sealed snapshot and baseline guards. Staged Git index is qualified separately from local roots; other adapters are not qualified.'}
        (root / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
        print(json.dumps({'passed': len(checks), 'evidence': str(root / 'evidence.json')}))
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == '__main__':
    main()
