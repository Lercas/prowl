#!/usr/bin/env python3
"""Qualify the released noise corpus through the actual CLI and embedded ML cascade."""
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
    repo = Path(__file__).resolve().parents[1]
    root = Path(tempfile.mkdtemp(prefix='prowl-noise-ml-'))
    env = {k: v for k, v in os.environ.items() if not k.startswith('PROWL_')}
    env.update(PROWL_HOME=str(root / 'home'), PROWL_LIVE_TEST='')
    model = repo / 'tool/internal/mlmodel/model_binary_go_literal_v1.json'
    corpus = repo / 'tool/internal/scan/testdata'
    fixtures = []
    cases = []
    for name, expected in (
        ('noise-1.4.0.json', 'd030d08dd14ba1fbcc36f3ce087d4cecc08fa84fb1379425120c9099e1ff1be0'),
        ('noise-deep-1.4.0.json', '79ed1475c880a238d2ed7684332a51011b287ab206ba23c2170acaa1f73dac84'),
    ):
        data = (corpus / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == expected, name
        fixtures.append({'name': name, 'sha256': expected})
        cases.extend(json.loads(data))
    assert len(cases) == 644
    assert len({c['name'] for c in cases}) == len(cases)

    def run(case, fmt='json', threshold='.3'):
        args = [str(binary), 'scan', '--bundled', '--silence', '--format=' + fmt,
                '--stdin-name', case['path'], '--ml', '--ml-model', str(model),
                '--ml-threshold=' + threshold]
        result = subprocess.run(args, input=case['text'], text=True, cwd=root,
                                env=env, capture_output=True, timeout=30)
        assert result.returncode == 0, (case['name'], fmt, result.returncode)
        data = json.loads(result.stdout)
        if fmt == 'json':
            findings = data['findings']
        else:
            findings = [r['properties'] | {'type': r['ruleId'],
                        'fingerprint': r['partialFingerprints']['prowl/v1'],
                        'message': r['message']['text']}
                        for r in data['runs'][0].get('results', [])]
        hit = False
        for finding in findings:
            assert finding.get('verified') is not True, case['name']
            if not case.get('value'):
                continue
            digest = hashlib.sha256((finding['type'] + '\0' + case['path'] + '\0' + case['value']).encode()).hexdigest()
            if finding.get('fingerprint') == digest:
                hit |= finding['type'] in case['types'] or (
                    finding['type'] == 'generic_api_key' and 'generic_high_entropy' in case['types'])
                assert finding.get('redacted') != case['value'], case['name']
                if fmt == 'sarif':
                    assert case['value'] not in finding['message'], case['name']
        if case['truth'] == 'negative':
            assert not findings, case['name']
        elif case['truth'] == 'positive':
            assert hit, (case['name'], fmt, threshold)
        return {'id': case['name'], 'truth': case['truth'], 'format': fmt,
                'threshold': threshold, 'hit': hit, 'findings': len(findings)}

    rows = []
    selected = {'140014_positive_weakword.env', '140014_deepgram.env',
                '140014_twitch.js', '260210_hex_64_token',
                '260210_password_7_yaml', '140014_together.json'}
    assert selected <= {c['name'] for c in cases}
    for case in cases:
        if case['name'] in selected:
            rows.extend([run(case, 'json', '1'), run(case, 'sarif', '1')])
    rows.extend(run(case) for case in cases)
    report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'model_sha256': hashlib.sha256(model.read_bytes()).hexdigest(),
              'fixtures': fixtures, 'checks': len(rows), 'rows': rows,
              'scope': 'Local CLI cascade retention, not equality of model scores or live provider acceptance; caller records the network boundary.'}
    output = root / 'qualification.json'
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': len(rows), 'evidence': str(output)}))


if __name__ == '__main__':
    main()
