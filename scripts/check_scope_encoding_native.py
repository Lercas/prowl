#!/usr/bin/env python3
"""Check scope encoding with owned Git indexes containing distinct raw-byte paths."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile

KEY = b'AKIANAFGYOEYPXU1DSYP'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('before', type=Path)
    parser.add_argument('candidate', type=Path)
    args = parser.parse_args()
    binaries = {label: path.resolve(strict=True) for label, path in vars(args).items()}
    with socket.socket() as probe:
        try:
            probe.bind(('127.0.0.1', 0))
        except PermissionError:
            pass
        else:
            raise RuntimeError('OS network deny is required')
    root = Path(tempfile.mkdtemp(prefix='prowl-scope-encoding-native-'))
    repo, home = root / 'repo', root / 'home'
    repo.mkdir()
    home.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith(('PROWL_', 'GIT_'))}
    env.update(PROWL_HOME=str(home), PROWL_LIVE_TEST='', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null')
    checks, artifacts = [], {}

    def check(name, passed):
        if not passed:
            raise AssertionError(name)
        checks.append({'case': name, 'passed': True})

    def git(argv, data=None, use_env=env):
        return subprocess.run(['git', *argv], cwd=repo, env=use_env, input=data,
                              capture_output=True, check=True, timeout=20).stdout.strip()

    def run(label, name, argv, use_env=env):
        result = subprocess.run([str(binaries[label]), *argv], cwd=repo, env=use_env,
                                input=b'', capture_output=True, timeout=30)
        for suffix, data in [('stdout', result.stdout), ('stderr', result.stderr)]:
            path = root / (label + '-' + name + '.' + suffix)
            with path.open('xb') as stream:
                stream.write(data)
            artifacts[path.name] = hashlib.sha256(data).hexdigest()
        check(label + '/' + name + '/masked', KEY not in result.stdout and KEY not in result.stderr)
        return result

    git(['init', '-q'])
    check('identity-init', run('candidate', 'identity', ['identity', 'init']).returncode == 0)
    cases = [
        ('raw-bytes', b'owned-\xff.env', b'owned-\xfe.env', True, []),
        ('replacement-character', 'owned-\ufffd.env'.encode(), 'owned-\ufffd.env'.encode(), False, []),
        ('unicode', 'owned-日本語.env'.encode(), 'owned-日本語.env'.encode(), False, []),
        ('ascii', b'owned.env', b'owned.env', False, []),
    ]
    for case, before_path, after_path, invalid, flags in cases:
        indexes = {}
        for phase, raw_path, data in [('before', before_path, b'AWS=' + KEY + b'\n'), ('after', after_path, b'ordinary text\n')]:
            use_env = dict(env, GIT_INDEX_FILE=str(root / (case + '-' + phase + '.index')))
            oid = git(['hash-object', '-w', '--stdin'], data)
            git([b'update-index', b'--add', b'--cacheinfo', b'100644', oid, raw_path], use_env=use_env)
            indexes[phase] = use_env
        all_reports = {}
        for fmt in ('json', 'sarif'):
            for label in binaries:
                reports = {}
                for phase, use_env in indexes.items():
                    name = case + '-' + fmt + '-' + phase
                    result = run(label, name, ['scan', '--staged', '--bundled', '--format=' + fmt, '--silence', *flags], use_env)
                    document = json.loads(result.stdout)
                    report = document if fmt == 'json' else document['runs'][0]['properties']
                    reports[phase] = report
                    all_reports[fmt, label, phase] = report
                    incomplete = invalid and label == 'candidate'
                    check(label + '/' + name + '/coverage', result.returncode == (2 if incomplete else 0) and report['complete'] == (not incomplete))
                    findings = document['findings'] if fmt == 'json' else document['runs'][0]['results']
                    secrets = [f for f in findings if f.get('type', f.get('ruleId')) == 'aws_access_key_id']
                    check(label + '/' + name + '/findings-retained', len(secrets) == (1 if phase == 'before' else 0))
                    check(label + '/' + name + '/diagnostic',
                          any(d['code'] == 'scope_policy_failed' and d['incomplete'] and not d.get('path') for d in report['diagnostics']) == incomplete)
                    if incomplete:
                        check(label + '/' + name + '/no-repaired-index-scope', not any(s['kind'] == 'git-index' for s in report['scope']))
                if fmt == 'json':
                    paths = [str(root / (label + '-' + case + '-json-' + phase + '.stdout')) for phase in ('before', 'after')]
                    result = run(label, case + '-comparison', ['remediation-check', *paths])
                    comparison = json.loads(result.stdout)
                    incomplete = invalid and (label == 'candidate' or bool(flags))
                    check(label + '/' + case + '/absence', result.returncode == (2 if incomplete else 0)
                          and comparison['comparable'] == (not incomplete)
                          and comparison['items'][0]['presence'] == ('inconclusive' if incomplete else 'absent_in_scope'))
                    if label == 'before' and invalid and not flags:
                        check(case + '/legacy-collision-reproduced', reports['before']['scope'] == reports['after']['scope'])
        if not invalid:
            for fmt in ('json', 'sarif'):
                for phase in indexes:
                    for key in ('scope', 'complete', 'stats', 'diagnostics'):
                        check(case + '/' + fmt + '/' + phase + '/unchanged-' + key,
                              all_reports[fmt, 'before', phase][key] == all_reports[fmt, 'candidate', phase][key])
        if invalid:
            for existing in (False, True):
                baseline = root / (case + '-baseline-' + str(existing) + '.json')
                sentinel = b'["owned sentinel"]\n'
                if existing:
                    baseline.write_bytes(sentinel)
                result = run('candidate', case + '-baseline-' + str(existing),
                             ['scan', '--staged', '--bundled', '--format=json', '--silence', '--write-baseline=' + str(baseline), *flags], indexes['before'])
                check(case + '/baseline-' + str(existing), result.returncode == 2
                      and (baseline.read_bytes() == sentinel if existing else not baseline.exists()))
    evidence = {'passed': True, 'checks': checks, 'artifacts_sha256': artifacts,
                'binaries': {label: {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()} for label, path in binaries.items()},
                'network': 'OS denies all network', 'root': str(root),
                'scope': 'Two new Git indexes per case; one owned repository; synthetic fixture only. Invalid names reside in Git indexes, not in host filesystem names.'}
    output = root / 'evidence.json'
    with output.open('x') as stream:
        json.dump(evidence, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'passed': True, 'checks': len(checks), 'evidence': str(output)}))


if __name__ == '__main__':
    main()
