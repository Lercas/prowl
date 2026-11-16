#!/usr/bin/env python3
"""Qualify frozen configuration identity, declared suppression and report comparisons offline."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile

KEY = 'AKIANAFGYOEYPXU1DSYP'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    with socket.socket() as probe:
        try:
            probe.bind(('127.0.0.1', 0))
        except PermissionError:
            pass
        else:
            raise RuntimeError('OS network deny is required')
    root = Path(tempfile.mkdtemp(prefix='prowl-config-policy-native-'))
    home = root / 'home'
    home.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith('PROWL_')}
    env.update(PROWL_HOME=str(home), PROWL_LIVE_TEST='')
    model = Path(__file__).resolve().parents[1] / 'tool/internal/mlmodel/model_binary_go_literal_v1.json'
    cfg = root / 'selected-private-config-marker.yaml'
    checks, outputs = [], {}

    def check(case, ok):
        assert ok, case
        checks.append({'case': case, 'passed': True})

    def run(label, args, cwd=root):
        result = subprocess.run([str(binary), *map(str, args)], cwd=cwd, env=env, capture_output=True, timeout=60)
        path = root / (label + '.stdout')
        assert not path.exists(), label
        path.write_bytes(result.stdout)
        (root / (label + '.stderr')).write_bytes(result.stderr)
        outputs[label] = path
        return result

    def metadata(result, fmt):
        data = json.loads(result.stdout)
        return data if fmt == 'json' else data['runs'][0]['properties']

    def scan(label, content, text, fmt='json', ml=False, filtered=False, cwd=root, config_path=cfg, extra=(), code=0):
        config_path.write_text(text)
        (cwd / 'production.env').write_text(content)
        args = ['scan', 'production.env', '--config', config_path, '--format=' + fmt, '--silence', '--workers=1', '--max-per-file=0']
        if ml:
            args += ['--ml', '--ml-model', model]
        result = run(label, [*args, *extra], cwd)
        meta = metadata(result, fmt)
        check(label + '-status', result.returncode == code and meta['complete'] == (code == 0))
        if code == 0:
            check(label + '-filtered', meta['filtered'] == filtered)
            check(label + '-known-policy', len([s for s in meta['scope'] if s['kind'] == 'detector_config']) == 1 and not any(s['kind'] == 'unversioned_policy' for s in meta['scope']))
        check(label + '-privacy', all(marker.encode() not in result.stdout + result.stderr for marker in (KEY, 'selected-private-config-marker', 'unused-private-value')))
        return meta

    def config_scope(meta):
        return next(s for s in meta['scope'] if s['kind'] == 'detector_config')

    def remediate(label, before, after, comparable):
        result = run(label, ['remediation-check', outputs[before], outputs[after]])
        data = json.loads(result.stdout)
        check(label, result.returncode == (0 if comparable else 2) and data['comparable'] == comparable and len(data['items']) == 1 and
              data['items'][0]['presence'] == ('absent_in_scope' if comparable else 'inconclusive') and not data['items'][0]['closed'])

    check('identity-init', run('identity-init', ['identity', 'init']).returncode == 0)
    for fmt in ('json', 'sarif'):
        for ml in (False, True):
            prefix = fmt + '-ml' + str(ml)
            before = scan(prefix + '-before', 'AWS=' + KEY, '{}', fmt, ml)
            after = scan(prefix + '-same', 'ordinary text', '{}', fmt, ml)
            check(prefix + '-same-policy', before['scope'] == after['scope'])
            drift = scan(prefix + '-drift', 'ordinary text', 'performance: {verify_timeout: 2s}', fmt, ml)
            check(prefix + '-configuration-drift', config_scope(before) != config_scope(drift))
            duplicate = root / 'same-config-other-filename.yaml'
            copied = scan(prefix + '-other-filename', 'ordinary text', '{}', fmt, ml, config_path=duplicate)
            check(prefix + '-filename-independent', config_scope(before) == config_scope(copied))
            if fmt == 'json':
                remediate(prefix + '-matching-remediation', prefix + '-before', prefix + '-same', True)
                remediate(prefix + '-drift-remediation', prefix + '-before', prefix + '-drift', False)
            for name, declaration in [('values', 'allowlist: {values: [unused-private-value]}'), ('paths', 'allowlist: {paths: [unrelated/]}'),
                                      ('regexes', "allowlist: {regexes: ['UNRELATED_[0-9]{6}']}"), ('stopwords', 'allowlist: {stopwords: [unrelated-stopword]}'),
                                      ('disable', 'detectors: {disable: [unrelated_type]}')]:
                active = scan(prefix + '-' + name + '-before', 'AWS=' + KEY, declaration, fmt, ml, filtered=True)
                empty = scan(prefix + '-' + name + '-after', 'ordinary text', declaration, fmt, ml, filtered=True)
                check(prefix + '-' + name + '-same-policy', active['scope'] == empty['scope'])
                if fmt == 'json':
                    remediate(prefix + '-' + name + '-remediation', prefix + '-' + name + '-before', prefix + '-' + name + '-after', False)
    imported = root / 'imported'
    imported.mkdir()
    leaks = imported / '.gitleaks.toml'
    template = "[[rules]]\nid='owned-import'\nregex='IMPORT_[A-Z0-9]{8}'\n[allowlist]\nstopwords=['%s']\n"
    leaks.write_text(template % 'unused-import-a')
    first = scan('import-a', 'AWS=' + KEY, '{}', filtered=True, cwd=imported)
    leaks.write_text(template % 'unused-import-b')
    second = scan('import-b', 'ordinary text', '{}', filtered=True, cwd=imported)
    check('final-imported-allowlist-identity', config_scope(first) != config_scope(second))
    remediate('import-remediation', 'import-a', 'import-b', False)
    huge = 'allowlist:\n values:\n' + ' - unused-owned-value\n' * 100001
    for fmt in ('json', 'sarif'):
        baseline = root / (fmt + '-sentinel.baseline')
        sentinel = b'owned baseline remains unchanged'
        baseline.write_bytes(sentinel)
        report = scan('oversize-' + fmt, 'AWS=' + KEY, huge, fmt, extra=['--write-baseline', baseline], code=2)
        check(fmt + '-budget-diagnostic', any(d['code'] == 'configuration_policy_failed' for d in report['diagnostics']))
        check(fmt + '-baseline-preserved', baseline.read_bytes() == sentinel)
    evidence = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'model_sha256': hashlib.sha256(model.read_bytes()).hexdigest(),
                'checks': checks, 'passed': True, 'network': 'OS deny, checked by loopback bind',
                'scope': 'Synthetic config/allowlist/gitleaks, JSON/SARIF, canonical L2, default controls, absence and baseline guards. No provider or production qualification.'}
    output = root / 'evidence.json'
    output.write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps({'passed': len(checks), 'evidence': str(output)}))


if __name__ == '__main__':
    main()
