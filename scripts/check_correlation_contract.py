#!/usr/bin/env python3
"""Qualify report correlation and remediation using native scanner output and owned Git data."""
import argparse
import hashlib
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='prowl-correlation-native-'))
    home = root / 'home'
    home.mkdir()
    env = dict(os.environ, PROWL_HOME=str(home))
    value = 'AKIANAFGYOEYPXU1DSYP'
    checks = []
    def check(name, passed):
        checks.append({'case': name, 'passed': bool(passed)})
        if not passed: raise AssertionError(name)
    def run(args, cwd=root, use_env=env):
        return subprocess.run([str(binary), *args], cwd=cwd, env=use_env, input=b'', capture_output=True, timeout=20)
    def scan(name, path='production.env', flags=(), cwd=root, use_env=env):
        result = run(['scan', *([] if path is None else [path]), '--format=json', '--silence', *flags], cwd=cwd, use_env=use_env)
        check(name + '/scanner-envelope', result.returncode in (0, 2) and bool(result.stdout))
        data = json.loads(result.stdout)
        (root / (name + '.json')).write_bytes(result.stdout)
        return data
    def save(name, data):
        (root / (name + '.json')).write_text(json.dumps(data))
    def correlate(name, paths, code, predicate):
        result = run(['correlate', *[p + '.json' for p in paths]])
        check(name, result.returncode == code and ((not result.stdout) if predicate is None else bool(result.stdout) and predicate(json.loads(result.stdout))))
        check(name + '/masked', value.encode() not in result.stdout)
    def remediation(name, before, after, code, presence=None, comparable=True):
        result = run(['remediation-check', before + '.json', after + '.json'])
        data = json.loads(result.stdout) if result.stdout else {}
        check(name, result.returncode == code and data.get('comparable') == comparable and
              (presence is None or data['items'][0]['presence'] == presence) and all(not x['closed'] for x in data.get('items', [])))
        if data.get('items') and presence == 'absent_in_scope':
            check(name + '/no-revocation-inference', data['items'][0]['revocation'] == 'not_checked')
    check('identity-init', run(['identity', 'init']).returncode == 0)
    source = root / 'production.env'
    source.write_text('AWS=' + value + '\nAWS_AGAIN=' + value + '\n')
    before = scan('before')
    present = scan('present')
    check('two-occurrences', len(before['findings']) == 1 and len(before['findings'][0]['occurrences']) == 2)
    correlate('same-secret-observed', ['before', 'present'], 0, lambda d: d['complete'] and len(d['groups']) == 1 and d['groups'][0]['relationship'] == 'same_secret_observed' and len(d['groups'][0]['observations']) == 2)
    remediation('still-present', 'before', 'present', 1, 'present')
    # Declared verdict fixtures exercise report interpretation, not a live provider.
    for verdict, expected in [('invalid', 'provider_rejected'), ('verified', 'live'), ('error', 'not_checked')]:
        current = copy.deepcopy(present)
        for finding in current['findings']:
            for observation in [finding, *finding.get('occurrences', [])]:
                observation['verification'] = {'status': verdict, 'verifier': 'owned-fixture', 'checked_at': '2026-11-14T00:00:00Z'}
                if verdict == 'error': observation.pop('verified', None)
                elif observation is finding: observation['verified'] = verdict == 'verified'
        save('verdict-' + verdict, current)
        result = run(['remediation-check', 'before.json', 'verdict-' + verdict + '.json'])
        observed = json.loads(result.stdout)
        check('declared-verdict/' + verdict, result.returncode == 1 and observed['items'][0]['revocation'] == expected and not observed['items'][0]['closed'])
    current['findings'][0]['verified'] = True
    current['findings'][0]['verification']['status'] = 'invalid'
    save('conflicting-verdict', current)
    correlate('conflicting-verdict-refused', ['before', 'conflicting-verdict'], 2, None)

    scan('filtered', flags=['--min-severity=critical'])
    remediation('filtered-absence', 'before', 'filtered', 2, 'inconclusive', False)
    scan('partial', flags=['--max-size=4'])
    correlate('partial-join', ['before', 'partial'], 2, lambda d: not d['complete'])
    remediation('partial-absence', 'before', 'partial', 2, 'inconclusive', False)
    source.write_text('ordinary text\n')
    after = scan('after')
    remediation('absent-in-scope', 'before', 'after', 0, 'absent_in_scope')
    (root / 'other.env').write_text('ordinary text\n')
    scan('other-scope', path='other.env')
    remediation('different-target', 'before', 'other-scope', 2, 'inconclusive', False)
    scan('revealed-empty', flags=['--show-secrets'])
    correlate('revealed-empty-refused', ['before', 'revealed-empty'], 2, None)
    other_home = root / 'other-home'
    other_home.mkdir()
    other_env = dict(env, PROWL_HOME=str(other_home))
    check('second-identity', run(['identity', 'init'], use_env=other_env).returncode == 0)
    scan('other-key', use_env=other_env)
    correlate('different-key-refused', ['before', 'other-key'], 2, None)
    keyless = root / 'keyless-home'
    keyless.mkdir()
    scan('unkeyed', use_env=dict(env, PROWL_HOME=str(keyless)))
    correlate('keyless-refused', ['before', 'unkeyed'], 2, None)
    policy_kinds = {'command', 'pipeline', 'detection_policy', 'rules', 'semantic'}
    policy_before = dict(before, scope=[s for s in before['scope'] if s['kind'] in policy_kinds])
    policy_after = dict(after, scope=policy_before['scope'])
    save('policy-before', policy_before)
    save('policy-after', policy_after)
    remediation('policy-is-not-source', 'policy-before', 'policy-after', 2, 'inconclusive', False)
    bad = json.dumps(before, separators=(',', ':')).replace('"complete":true', '"complete":false,"complete":true', 1)
    (root / 'duplicate.json').write_text(bad)
    correlate('duplicate-json-refused', ['before', 'duplicate'], 2, None)
    huge = dict(before, findings=[0] * 100001, count=100001)
    save('row-overflow', huge)
    result = run(['correlate', 'before.json', 'row-overflow.json'])
    check('array-budget-before-decode', result.returncode == 2 and b'array row budget' in result.stderr)
    check('input-count-budget', run(['correlate', *(['before.json'] * 33)]).returncode == 2)
    check('unsupported-flags', run(['correlate', 'before.json', 'present.json', '--show-secrets']).returncode == 2)
    check('help', run(['remediation-check', '--help']).returncode == 0)
    if hasattr(os, 'mkfifo'):
        os.mkfifo(root / 'owned.pipe')
        check('fifo-is-not-report', run(['correlate', 'before.json', 'owned.pipe']).returncode == 2)
    # Real Git objects provide immutable shared-blob metadata, not an inferred propagation chain.
    repo = root / 'repo'
    repo.mkdir()
    def git(*args):
        return subprocess.run(['git', *args], cwd=repo, capture_output=True, check=True)
    git('init', '-q')
    git('config', 'user.name', 'Owned fixture')
    git('config', 'user.email', 'owned@example.invalid')
    for path in ('first.env', 'second.env'):
        (repo / path).write_text('AWS=' + value + '\n')
    git('add', 'first.env', 'second.env')
    git('commit', '-qm', 'owned fixture')
    history = scan('history', path=None, flags=['--history'], cwd=repo)
    repo = root / 'repo-two'
    repo.mkdir()
    git('init', '-q')
    git('config', 'user.name', 'Owned fixture')
    git('config', 'user.email', 'owned@example.invalid')
    (repo / 'third.env').write_text('AWS=' + value + '\n')
    git('add', 'third.env')
    git('commit', '-qm', 'second owned fixture')
    history_two = scan('history-two', path=None, flags=['--history'], cwd=repo)
    result = run(['correlate', 'before.json', 'history.json', 'history-two.json'])
    joined = json.loads(result.stdout)
    links = [link for g in joined['groups'] for link in g.get('links', [])]
    check('git-shared-blob-evidence', result.returncode == 0 and history['complete'] and history_two['complete'] and any(link['kind'] == 'shared_blob_metadata' for link in links))
    check('git-no-propagation-claim', all(g['relationship'] == 'same_secret_observed' for g in joined['groups']))
    # A report checksum establishes that these commands only read selected inputs.
    prior = (root / 'before.json').read_bytes()
    run(['correlate', 'before.json', 'present.json'])
    check('reports-preserved', (root / 'before.json').read_bytes() == prior)
    report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'passed': sum(c['passed'] for c in checks), 'total': len(checks), 'checks': checks,
              'root': str(root), 'scope': 'native local scanner JSON, owned Git objects and malformed report fixtures; no provider or remote access'}
    (root / 'qualification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'checks'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
