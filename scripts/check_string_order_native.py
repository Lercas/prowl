#!/usr/bin/env python3
"""Qualify opt-in static string ordering with the canonical model under OS network deny."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile

KEY = 'AKIANAFGYOEYPXU1DSYP'
PASSWORD = 'R3moteSecret9!'


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
            raise RuntimeError('An OS network deny is required')
    root = Path(tempfile.mkdtemp(prefix='prowl-string-order-native-'))
    model = Path(__file__).resolve().parents[1] / 'tool/internal/mlmodel/model_binary_go_literal_v1.json'
    env = {k: v for k, v in os.environ.items() if not k.startswith('PROWL_')}
    env.update(PROWL_HOME=str(root / 'home'), PROWL_LIVE_TEST='')
    checks = []

    def check(name, ok):
        assert ok, name
        checks.append({'case': name, 'passed': True})

    def fingerprint(typ, path, value):
        return hashlib.sha256((typ + '\0' + path + '\0' + value).encode()).hexdigest()

    def report(result, fmt):
        data = json.loads(result.stdout)
        if fmt == 'json':
            return data['findings'], data['complete']
        run = data['runs'][0]
        return [dict(r['properties'], type=r['ruleId'], fingerprint=r.get('partialFingerprints', {}).get('prowl/v1', ''), region=r['locations'][0]['physicalLocation']['region']) for r in run['results']], run['properties']['complete']

    def run(path, text, fmt='json', ml=False, stdin=False, extra=(), enabled=True):
        args = [str(binary), 'scan', '--format=' + fmt, '--silence', '--workers=1', '--max-per-file=0']
        if enabled:
            args.append('--reconstruct')
        if ml:
            args += ['--ml', '--ml-model', str(model)]
        args += ['--stdin-name=' + path.name] if stdin else [path.name]
        return subprocess.run([*args, *map(str, extra)], cwd=root, env=env,
                              input=text.encode() if stdin else b'', capture_output=True, timeout=40)

    def expression(value, reverse):
        if reverse:
            return json.dumps(value[::-1]) + '.split("").reverse().join("")'
        return json.dumps(' '.join(value)) + '.split(" ").join("")'

    fixtures = []
    for typ, name, value in [('aws_access_key_id', 'accessKeyId', KEY), ('generic_password', 'password', PASSWORD),
                              ('generic_password', 'unicode_password', '私密<p4ssw0rd>z9'),
                              ('generic_password', 'multiline_password', 'X7a\n私密<pwd>Z9')]:
        for reverse in (False, True):
            expr = expression(value, reverse)
            fixtures.append((name + ('-reverse' if reverse else '-spacing'), typ, name, value, expr, True))
    fixtures += [
        ('unrelated-name', 'generic_password', 'note', PASSWORD, expression(PASSWORD, True), False),
        ('unknown-separator', 'aws_access_key_id', 'key', KEY, json.dumps(KEY[::-1]) + '.split(separator).reverse().join("")', False),
        ('unknown-call', 'aws_access_key_id', 'key', KEY, json.dumps(KEY[::-1]) + '.split("").sort().join("")', False),
    ]
    for label, typ, name, value, expr, expected in fixtures:
        text = '/*🚀*/ const ' + name + '=' + expr + ';'
        path = root / (label + '.js')
        for fmt in ('json', 'sarif'):
            for ml in (False, True):
                for stdin in (False, True):
                    case = f'{label}-{fmt}-ml{ml}-stdin{stdin}'
                    sentinel = b'logical stdin must not read or overwrite this path'
                    path.write_bytes(sentinel if stdin else text.encode())
                    result = run(path, text, fmt, ml, stdin)
                    (root / (case + '.stdout')).write_bytes(result.stdout)
                    (root / (case + '.stderr')).write_bytes(result.stderr)
                    rows, complete = report(result, fmt)
                    found = [f for f in rows if f['type'] == typ and f.get('fingerprint') == fingerprint(typ, path.name, value) and f['stage'].startswith('reconstructed/')]
                    check(case + '-result', result.returncode == 0 and complete and len(found) == int(expected))
                    check(case + '-redaction', value.encode() not in result.stdout + result.stderr)
                    if expected:
                        f = found[0]
                        check(case + '-evidence', len(f.get('evidence', [])) >= 3 and all(e['start'] >= 0 and e['end'] <= len(text.encode()) for e in f['evidence']))
                        check(case + '-separate', not f.get('verified') and not f.get('verification'))
                        if fmt == 'json':
                            start = len(('/*🚀*/ const ' + name + '=').encode())
                            check(case + '-position', f['line'] == 1 and f['col'] == start + 1)
                        else:
                            col = len(('/*🚀*/ const ' + name + '=').encode('utf-16-le')) // 2 + 1
                            check(case + '-position', f['region']['startLine'] == 1 and f['region']['startColumn'] == col)
                    if stdin:
                        check(case + '-stdin-sentinel', path.read_bytes() == sentinel)
        path.write_text(text)
        result = run(path, text, enabled=False)
        rows, complete = report(result, 'json')
        check(label + '-opt-in', result.returncode == 0 and complete and not any(f.get('fingerprint') == fingerprint(typ, path.name, value) and f['stage'].startswith('reconstructed/') for f in rows))
        if expected:
            path.write_text(text + ' // prowl:allow')
            result = run(path, text)
            rows, complete = report(result, 'json')
            check(label + '-pragma', complete and not any(f['stage'].startswith('reconstructed/') for f in rows))
    for label, text in {
        'invalid-utf16': 'const key="prefix😀suffix".split("").reverse().join("");',
        'parts-limit': 'const key="' + 'x' * 4097 + '".split("").join("");',
        'prototype': 'Array.prototype.reverse=unknown;const key=' + expression(KEY, True) + ';',
    }.items():
        path = root / (label + '.js')
        path.write_text(text)
        for fmt in ('json', 'sarif'):
            for ml in (False, True):
                case = f'{label}-{fmt}-ml{ml}'
                baseline = root / (case + '.baseline')
                sentinel = b'owned existing baseline remains unchanged'
                baseline.write_bytes(sentinel)
                result = run(path, text, fmt, ml, extra=['--write-baseline', baseline])
                rows, complete = report(result, fmt)
                check(case + '-incomplete', result.returncode == 2 and not complete)
                check(case + '-baseline', baseline.read_bytes() == sentinel)
                check(case + '-no-invented-order', not any('constant-string-split' in f.get('stage', '') for f in rows))
    evidence = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'model_sha256': hashlib.sha256(model.read_bytes()).hexdigest(),
                'checks': checks, 'passed': True, 'network': 'OS deny checked by loopback bind',
                'scope': 'Local synthetic JS, file/stdin, JSON/SARIF, canonical ML. No real-provider or production qualification.'}
    output = root / 'evidence.json'
    output.write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps({'passed': len(checks), 'evidence': str(output)}))


if __name__ == '__main__':
    main()
