#!/usr/bin/env python3
"""Check that restored Go stdin API defaults preserve the explicit CLI byte budgets."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('before', type=Path)
    parser.add_argument('candidate', type=Path)
    args = parser.parse_args()
    binaries = {'before': args.before.resolve(strict=True), 'candidate': args.candidate.resolve(strict=True)}
    with socket.socket() as probe:
        try:
            probe.bind(('127.0.0.1', 0))
        except PermissionError:
            pass
        else:
            raise RuntimeError('OS network deny is required')
    root = Path(tempfile.mkdtemp(prefix='prowl-stdin-budget-native-'))
    (root / 'home').mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith('PROWL_')}
    env.update(PROWL_HOME=str(root / 'home'), PROWL_LIVE_TEST='')
    size = 5 << 20
    line = b'ordinary source line.\n'
    data = (line * (size // len(line) + 1))[:size]
    checks, reports = [], {}

    def check(name, condition):
        if not condition:
            raise AssertionError(name)
        checks.append({'case': name, 'passed': True})

    cases = [
        ('implicit', ['scan'], True),
        ('dash', ['scan', '-'], True),
        ('named', ['scan', '--stdin-name=unopened/owned.txt'], True),
        ('quick', [], True),
        ('explicit-4m', ['scan', '--max-size=4194304'], False),
        ('named-4m', ['scan', '--stdin-name=unopened/owned.txt', '--max-size=4194304'], False),
        ('exact-boundary', ['scan', '--max-size=5242880'], True),
    ]
    for name, argv, complete in cases:
        for label, binary in binaries.items():
            case = label + '-' + name
            result = subprocess.run([str(binary), *argv, '--bundled', '--format=json', '--silence'],
                                    cwd=root, env=env, input=data, capture_output=True, timeout=30)
            (root / (case + '.stdout')).write_bytes(result.stdout)
            (root / (case + '.stderr')).write_bytes(result.stderr)
            report = json.loads(result.stdout)
            reports[label, name] = report
            check(case + '-status', result.returncode == (0 if complete else 2) and report['complete'] == complete)
            check(case + '-stdin-scope', any(s['kind'] == 'stdin' for s in report['scope']))
            check(case + '-label-is-not-a-file', not (root / 'unopened').exists())
            if complete:
                check(case + '-full-input', report['stats']['processed'] == 1 and report['stats']['bytes'] == size and not report['findings'])
            else:
                check(case + '-max-size', any(d['code'] == 'max_size' and d['incomplete'] for d in report['diagnostics']))
        before, after = reports['before', name], reports['candidate', name]
        for key in ('complete', 'completion_reason', 'count', 'filtered', 'stats', 'diagnostics', 'scope', 'secrets_revealed'):
            check(name + '-same-' + key, before[key] == after[key])
    output = root / 'evidence.json'
    output.write_text(json.dumps({'binaries': {k: {'path': str(v), 'sha256': hashlib.sha256(v.read_bytes()).hexdigest()} for k, v in binaries.items()},
                                  'passed': True, 'checks': checks, 'network': 'OS denies all network',
                                  'boundary': 'Actual CLI pipes: default 10 MiB and explicit max-size. Direct API 4 MiB defaults and variadic limit are separately qualified by Go tests on both source revisions.'}, indent=2) + '\n')
    print(json.dumps({'passed': len(checks), 'evidence': str(output)}))


if __name__ == '__main__':
    main()
