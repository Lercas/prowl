"""Приёмка канонических JSON-строк: identity, исходные spans, шум и strict без сети."""
import argparse
import base64
import hashlib
import json
import os
import random
import string
import subprocess
from pathlib import Path


def corpus():
    rng = random.Random(2602101404)
    cases = []

    def escape(value):
        # Encode UTF-16 units independently so astral characters exercise surrogate pairs.
        raw = value.encode('utf-16-be')
        return ''.join('\\u' + raw[i:i+2].hex() for i in range(0, len(raw), 2))

    def add(name, text, expected, suffix='.json'):
        cases.append({'name': name, 'path': name + suffix, 'text': text, 'expected': expected})

    def want(value, typ, source=None, transform='json-string'):
        return {'value': value, 'type': typ, 'source': source or value, 'transform': transform}

    for i in range(12):
        word = ''.join(rng.choices(string.ascii_letters, k=8))
        key = 'AKIA' + ''.join(rng.choices(string.ascii_uppercase + string.digits, k=16))
        stripe = 'sk_live_' + ''.join(rng.choices(string.ascii_letters + string.digits, k=24))
        for j, value in enumerate([
            'Winter42!' + word, 'Winter<42>' + word, 'Winter${42}' + word,
            'Winter{{42}}' + word, '  Winter42 ' + word, 'ЖукЖук🚀' + word,
            '\"Winter42\"\nAutumn\\53' + word,
        ]):
            raw = escape(value)
            text = '{"' + escape('пароль' if j == 5 else 'password') + '":"' + raw + '"}\n'
            add(f'{i}_password_{j}', text, [want(value, 'generic_password', raw)])
        for j, (value, typ) in enumerate([(key, 'aws_access_key_id'), (stripe, 'stripe_secret_key')]):
            raw = escape(value)
            add(f'{i}_typed_{j}', '{"api_key":"' + raw + '"}', [want(value, typ, raw)])
            add(f'{i}_array_{j}', '["' + raw + '"]', [want(value, typ, raw)])
            add(f'{i}_duplicates_{j}', '{"key":"' + raw + '","key":"' + raw + '"}',
                [want(value, typ, raw), want(value, typ, raw)])
        blob = base64.b64encode(key.encode()).decode()
        raw = escape(blob)
        add(f'{i}_composed', '{"payload":"' + raw + '"}', [want(key, 'aws_access_key_id', raw)])
        raw = escape(key)
        add(f'{i}_key_credential', '{"' + raw + '":"unrelated"}', [want(key, 'aws_access_key_id', raw)])
        add(f'{i}_synthetic_pragma', '{"note":"' + escape('prowl:allow') + '","key":"' + raw + '"}', [want(key, 'aws_access_key_id', raw)])
        raw = escape('first=' + key + ' second=' + key)
        add(f'{i}_inner_occurrences', '{"message":"' + raw + '"}',
            [want(key, 'aws_access_key_id', raw), want(key, 'aws_access_key_id', raw)])
        for j, value in enumerate(['${PASSWORD}', '{{PASSWORD}}', '<PASSWORD>', 'example', 'dummy', 'abc']):
            add(f'{i}_placeholder_{j}', '{"password":"' + escape(value) + '"}', [])
        add(f'{i}_nonbinding', '{"bypass":"' + escape('Winter42!' + word) + '"}', [])
        add(f'{i}_nonstring', '{"password":null,"note":"' + escape('unrelated') + '"}', [])
        add(f'{i}_numbers', '{"number":1e10000,"note":"' + escape('unrelated') + '"}', [])
        value = 'Winter<42>' + word
        add(f'{i}_env_angles', 'password="' + value + '"', [want(value, 'generic_password', transform=None)], '.env')
    return cases


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--binary', type=Path, required=True)
    ap.add_argument('--baseline-binary', type=Path)
    ap.add_argument('--output-dir', type=Path, required=True)
    args = ap.parse_args()
    root = args.output_dir.resolve()
    root.mkdir(parents=True, exist_ok=False)
    inputs = root / 'inputs'
    inputs.mkdir()
    cases = corpus()
    truth = json.dumps(cases, ensure_ascii=False, indent=2) + '\n'
    (root / 'truth.json').write_text(truth, encoding='utf-8')
    by_path = {}
    for case in cases:
        path = inputs / case['path']
        path.write_text(case['text'], encoding='utf-8', newline='\n')
        by_path[str(path)] = case
    env = {**os.environ, 'PROWL_HOME': str(root / 'home'), 'NO_COLOR': '1'}
    binary = args.binary.resolve()
    init = subprocess.run([str(binary), 'identity', 'init'], cwd=root, env=env, capture_output=True, encoding='utf-8', timeout=30)
    assert init.returncode == 0
    runs = []
    binaries = [('after', binary)]
    if args.baseline_binary:
        binaries.insert(0, ('before', args.baseline_binary.resolve()))
    for label, executable in binaries:
        for ml in (False, True):
            command = [str(executable), 'scan', str(inputs), '--strict', '--format', 'json', '--show-secrets', '--no-dedupe']
            if ml:
                command.append('--ml')
            result = subprocess.run(command, cwd=root, env=env, capture_output=True, encoding='utf-8', timeout=180)
            tag = label + ('-ml' if ml else '-default')
            (root / (tag + '.json')).write_text(result.stdout, encoding='utf-8')
            (root / (tag + '.stderr')).write_text(result.stderr, encoding='utf-8')
            report = json.loads(result.stdout)
            if label == 'after':
                # Duplicate objects keep physical occurrences but cannot establish companion context.
                assert result.returncode == 2 and not report['complete'] and not report['truncated'], tag
                assert {d['code'] for d in report['diagnostics']} == {'json_literal_duplicate'}, tag
                assert all('_duplicates_' in Path(d['path']).name for d in report['diagnostics']), tag
            else:
                assert result.returncode in (0, 1) and report['complete'] and not report['truncated'], tag
            found, missing, negatives, spans = 0, [], [], []
            for path, case in by_path.items():
                fs = [f for f in report['findings'] if f['path'] == path]
                if not case['expected'] and fs:
                    negatives.append(case['name'])
                unused = fs.copy()
                for expected in case['expected']:
                    hit = next((f for f in unused if f['redacted'] == expected['value'] and f['type'] == expected['type']), None)
                    if hit is None:
                        missing.append(case['name'] + ':' + expected['type'])
                        continue
                    found += 1
                    unused.remove(hit)
                    if label == 'after' and expected['transform']:
                        evidence = hit.get('evidence', [])
                        source = case['text'].encode('utf-8')
                        if not any(source[e['start']:e['end']] == expected['source'].encode('utf-8') and
                                   e['transform'] == expected['transform'] for e in evidence):
                            spans.append(case['name'])
                    if label == 'after':
                        assert hit.get('secret_id') and hit.get('occurrence_id')
                if label == 'after':
                    assert len(fs) == len(case['expected']), (case['name'], len(fs))
            runs.append({'label': label, 'ml': ml, 'found': found, 'missing': missing,
                         'negative_cases_with_findings': negatives, 'wrong_spans': spans,
                         'binary_sha256': hashlib.sha256(executable.read_bytes()).hexdigest()})
            if label == 'after':
                assert not missing and not negatives and not spans, tag
    # The same decoded key in four encodings has one identity and distinct source occurrences.
    report = json.loads((root / 'after-default.json').read_text(encoding='utf-8'))
    identity_groups = {}
    for f in report['findings']:
        identity_groups.setdefault(f['redacted'], []).append(f)
    for fs in identity_groups.values():
        assert len({f['secret_id'] for f in fs}) == 1
        assert len({f['occurrence_id'] for f in fs}) == len(fs)
    limit = root / 'invalid-unicode.json'
    limit.write_text(r'{"password":"Winter42\uD800Autumn"}', encoding='utf-8')
    result = subprocess.run([str(binary), 'scan', str(limit), '--strict', '--format', 'json'],
                            cwd=root, env=env, capture_output=True, encoding='utf-8', timeout=30)
    (root / 'limited.json').write_text(result.stdout, encoding='utf-8')
    report = json.loads(result.stdout)
    assert result.returncode == 2 and not report['complete']
    assert any(d['code'] == 'json_literal_unicode' for d in report['diagnostics'])
    evidence = {'version': '1.4.0', 'seed': 2602101404, 'cases': len(cases),
                'expected_credentials': sum(len(c['expected']) for c in cases),
                'negative_cases': sum(not c['expected'] for c in cases),
                'truth_sha256': hashlib.sha256(truth.encode()).hexdigest(), 'runs': runs,
                'identity_and_occurrences': True, 'strict_invalid_unicode_exit': 2,
                'duplicate_objects_incomplete': True,
                'boundary': 'Own synthetic regression corpus. Bounded canonical JSON strings and literal password punctuation. '
                            'No provider calls. This is not independent market precision/recall evidence.',
                'inputs_retained': str(root)}
    (root / 'json-literals.json').write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({**evidence, 'runs': [{**r, 'missing': len(r['missing'])} for r in runs]}, indent=2))


if __name__ == '__main__':
    main()
