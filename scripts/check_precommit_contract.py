#!/usr/bin/env python3
"""Qualify the native hook against disposable consumer indexes and real pre-commit."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pre-commit', type=Path, required=True)
    args = parser.parse_args()
    executable = args.pre_commit.resolve(strict=True)
    source = Path(__file__).resolve().parent.parent
    root = Path(tempfile.mkdtemp(prefix='prowl-precommit-native-'))
    go_root = subprocess.check_output(['go', 'env', 'GOROOT'], cwd=source / 'tool',
                                      env=dict(os.environ, GOTOOLCHAIN='go1.27.4'), text=True, timeout=60).strip()
    env = dict(os.environ, PATH=str(Path(go_root) / 'bin') + os.pathsep + os.environ['PATH'], PROWL_HOME=str(root / 'home'), PRE_COMMIT_HOME=str(root / 'cache'),
               GOTOOLCHAIN='local', CGO_ENABLED='0', GOMAXPROCS='2', GOFLAGS='-p=2',
               GOPROXY='off', GOSUMDB='off', NO_COLOR='1')
    rows = []
    value = 'AKIANAFGYOEYPXU1DSYP'
    def run(argv, cwd):
        return subprocess.run(list(map(str, argv)), cwd=cwd, env=env,
                              capture_output=True, text=True, timeout=180)
    def check(name, passed):
        rows.append({'case': name, 'passed': bool(passed)})
        if not passed:
            raise AssertionError(name)
    def git(cwd, *argv, input=None):
        result = subprocess.run(['git', *argv], cwd=cwd, env=env, input=input,
                                capture_output=True, text=True, check=True)
        return result.stdout.strip()
    def repo(name):
        path = root / name
        path.mkdir()
        git(path, 'init', '-q')
        git(path, 'config', 'core.hooksPath', '/dev/null')
        git(path, 'config', 'user.name', 'Owned Hook Fixture')
        git(path, 'config', 'user.email', 'fixture@example.invalid')
        return path
    def report(result, name, framework=False):
        (root / (name + '.stdout')).write_text(result.stdout)
        (root / (name + '.stderr')).write_text(result.stderr)
        check(name + '/redacted', value not in result.stdout + result.stderr)
        if not framework:
            return json.loads(result.stdout)
        decoder = json.JSONDecoder()
        for index, char in enumerate(result.stdout):
            if char == '{':
                try:
                    data, _ = decoder.raw_decode(result.stdout[index:])
                    if isinstance(data, dict) and 'schema_version' in data and 'findings' in data:
                        return data
                except json.JSONDecodeError:
                    pass
        raise AssertionError('framework did not expose hook JSON')
    try:
        revision = git(source, 'rev-parse', 'HEAD')
        hook = source / 'scripts/precommit-prowl'
        rules = root / 'home' / 'rules'
        rules.mkdir(parents=True)
        (rules / 'broken.yaml').write_text('id: [broken\n')
        consumer = repo('consumer')
        file = consumer / 'production.env'
        file.write_text('public_number=42\n')
        git(consumer, 'add', 'production.env')
        git(consumer, 'commit', '-qm', 'test: owned baseline')
        file.write_text('AWS_KEY=' + value + '\n')
        git(consumer, 'add', 'production.env')
        file.write_text('public_number=42\n')
        child = consumer / 'child'
        child.mkdir()
        result = run([hook, '--format=json'], child)
        data = report(result, 'direct-partial-staging')
        check('direct-consumer-index', result.returncode == 1 and data['complete'] and any(f['type'] == 'aws_access_key_id' and f['provenance']['git_index'] for f in data['findings']))
        js = consumer / 'bundle.js'
        js.write_text("const head='AKIA';const key=head+'NAFGYOEYPXU1DSYP';")
        git(consumer, 'add', 'bundle.js')
        js.write_text('public_number=42\n')
        result = run([hook, '--format=json', '--no-dedupe'], consumer)
        data = report(result, 'direct-reconstruction')
        check('direct-reconstruct', result.returncode == 1 and data['complete'] and any(f['stage'].startswith('reconstructed/') for f in data['findings']))
        config = consumer / '.pre-commit-config.yaml'
        config.write_text('repos:\n  - repo: ' + json.dumps(str(source)) + '\n    rev: ' + revision + '\n    hooks:\n      - id: prowl\n        args: [--format=json, --no-dedupe]\n')
        git(consumer, 'add', '.pre-commit-config.yaml')
        result = run([executable, 'run', 'prowl', '--verbose', '--color', 'never'], consumer)
        data = report(result, 'framework-partial-staging', True)
        check('framework-real-index', result.returncode == 1 and data['complete'] and any(f['stage'].startswith('reconstructed/') for f in data['findings']))
        check('framework-restored-working-copy', file.read_text() == 'public_number=42\n' and js.read_text() == 'public_number=42\n')
        git(consumer, 'add', 'production.env', 'bundle.js')
        result = run([executable, 'run', 'prowl', '--verbose', '--color', 'never'], consumer)
        data = report(result, 'framework-clean', True)
        check('framework-clean-index', result.returncode == 0 and data['complete'] and not data['findings'])
        conflict = repo('conflict')
        blob = git(conflict, 'hash-object', '-w', '--stdin', input='synthetic conflict\n')
        git(conflict, 'update-index', '--index-info', input=''.join('100644 ' + blob + ' ' + str(i) + '\tconflict.env\n' for i in (1, 2, 3)))
        result = run([hook, '--format=json'], conflict)
        data = report(result, 'direct-unmerged')
        check('direct-incomplete', result.returncode == 2 and not data['complete'] and any(d['code'] == 'git_index_unmerged' for d in data['diagnostics']))
        check('installed-overlay-untouched', (rules / 'broken.yaml').read_text() == 'id: [broken\n')
        empty = repo('empty')
        result = run([hook, '--format=json'], empty)
        data = report(result, 'direct-empty')
        check('empty-index-scope', result.returncode == 0 and data['complete'] and not data['findings'] and any(s['kind'] == 'git-index' for s in data['scope']))
    finally:
        result = {'passed': sum(r['passed'] for r in rows), 'total': len(rows), 'checks': rows,
                  'root': str(root), 'source_revision': git(source, 'rev-parse', 'HEAD'),
                  'pre_commit_version': run([executable, '--version'], source).stdout.strip(),
                  'scope': 'native script hook and real pre-commit on local disposable consumer repositories; Go module network disabled; Docker hook and publication not qualified'}
        (root / 'qualification.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({k: v for k, v in result.items() if k != 'checks'}))


if __name__ == '__main__':
    main()
