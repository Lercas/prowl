#!/usr/bin/env python3
"""Qualify config disable spelling across native taxonomy and template producers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='prowl-config-disable-native-'))
    (root / 'home').mkdir()
    env = dict(os.environ, PROWL_HOME=str(root / 'home'))
    value = 'AKIANAFGYOEYPXU1DSYP'
    (root / 'production.env').write_text('AWS=' + value + '\n')
    checks = []

    def check(name, passed):
        checks.append({'case': name, 'passed': bool(passed)})
        if not passed:
            raise AssertionError(name)

    def run(fmt, flags):
        result = subprocess.run([str(binary), 'scan', 'production.env', '--bundled',
                                 '--format=' + fmt, '--silence', *flags], cwd=root,
                                env=env, input=b'', capture_output=True, timeout=30)
        data = json.loads(result.stdout)
        if fmt == 'json':
            meta, findings = data, data['findings']
        else:
            meta = data['runs'][0]['properties']
            findings = [{'type': f['ruleId']} for f in data['runs'][0]['results']]
        return result, meta, findings

    try:
        for ml in (False, True):
            for fmt in ('json', 'sarif'):
                flags = ['--ml'] if ml else []
                result, meta, findings = run(fmt, flags)
                check(f'{ml}/{fmt}/positive', result.returncode == 0 and meta['complete'] and any(f['type'].replace('-', '_') == 'aws_access_key_id' for f in findings))
                for i, spelling in enumerate(('aws_access_key_id', 'aws-access-key-id', ' AWS-Access_KEY-id ')):
                    config = root / f'disabled-{i}.yaml'
                    config.write_text('detectors:\n  disable: [' + json.dumps(spelling) + ']\n')
                    result, meta, findings = run(fmt, [*flags, '--config=' + str(config)])
                    check(f'{ml}/{fmt}/{i}/disabled', result.returncode == 0 and meta['complete'] and not findings)
                    check(f'{ml}/{fmt}/{i}/redacted', value.encode() not in result.stdout + result.stderr)
                control = root / 'unrelated.yaml'
                control.write_text('detectors:\n  disable: [stripe_secret_key]\n')
                result, meta, findings = run(fmt, [*flags, '--config=' + str(control)])
                check(f'{ml}/{fmt}/unrelated', meta['complete'] and any(f['type'].replace('-', '_') == 'aws_access_key_id' for f in findings))
        (root / 'production.env').write_text('OWNED_QWERTYUIOPAS\n')
        positive_custom = root / 'positive-custom.yaml'
        positive_custom.write_text('detectors:\n  custom:\n    - id: owned_custom\n      regex: OWNED_[A-Z]{12}\n      category: generic\n')
        for fmt in ('json', 'sarif'):
            result, meta, findings = run(fmt, ['--config=' + str(positive_custom)])
            check(fmt + '/custom-positive', result.returncode == 0 and meta['complete'] and any(f['type'] == 'owned_custom' for f in findings))
        custom = root / 'custom.yaml'
        custom.write_text('detectors:\n  disable: [OWNED-Custom]\n  custom:\n    - id: owned_custom\n      regex: OWNED_[A-Z]{12}\n      category: generic\n')
        (root / 'production.env').write_text('OWNED_QWERTYUIOPAS\n')
        for fmt in ('json', 'sarif'):
            result, meta, findings = run(fmt, ['--config=' + str(custom)])
            check(fmt + '/custom-disabled', result.returncode == 0 and meta['complete'] and not findings)
    finally:
        report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                  'passed': sum(c['passed'] for c in checks), 'total': len(checks),
                  'checks': checks, 'root': str(root),
                  'scope': 'synthetic local values, bundled rules, no provider or network requests'}
        (root / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({k: v for k, v in report.items() if k != 'checks'}))


if __name__ == '__main__':
    main()
