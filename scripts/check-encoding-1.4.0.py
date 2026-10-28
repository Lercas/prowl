"""Приёмка декодирования и исходных spans на собственных синтетических данных без сети."""
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
    rng = random.Random(2602101403)
    cases = []

    def add(name, suffix, text, expected):
        cases.append({'name': name, 'path': name + suffix, 'text': text, 'expected': expected})

    def expectation(value, typ, source=None, transform=None):
        return {'value': value, 'type': typ, 'source': source or value, 'transform': transform}

    for i in range(12):
        key = 'AKIA' + ''.join(rng.choices(string.ascii_uppercase + string.digits, k=16))
        other = 'AKIA' + ''.join(rng.choices(string.ascii_uppercase + string.digits, k=16))
        stripe = 'sk_live_' + ''.join(rng.choices(string.ascii_letters + string.digits, k=24))
        for alphabet, encoder in [('std', base64.b64encode), ('url', base64.urlsafe_b64encode)]:
            for padding in (True, False):
                for kind, decoded, values in [
                    ('short', key, [(key, 'aws_access_key_id')]),
                    ('multi', 'first=' + key + '\nsecond=' + other + '\ntoken=' + stripe,
                     [(key, 'aws_access_key_id'), (other, 'aws_access_key_id'), (stripe, 'stripe_secret_key')]),
                    ('unicode', 'note=' + 'info ' * 12 + '🚀\nkey=' + key, [(key, 'aws_access_key_id')]),
                ]:
                    blob = encoder(decoded.encode()).decode()
                    if not padding:
                        blob = blob.rstrip('=')
                    add(f'{i}_{alphabet}_{padding}_{kind}', '.env', f'payload="{blob}"\n',
                        [expectation(v, t, blob, 'base64-decode') for v, t in values])
        word = ''.join(rng.choices(string.ascii_letters, k=8))
        value = f'Winter{i}42!{word}'
        escaped = value.replace('42', r'\u0034\u0032')
        for kind, text, raw, canonical in [
            ('flow', '{password: ' + value + ', other: harmless}', value, value),
            ('escape', '{пароль: "' + escaped + '"}', escaped, value),
            ('phrase', 'password: "a short first word ' + word + '"', 'a short first word ' + word, 'a short first word ' + word),
            ('plain_phrase', 'password: a short first word ' + word, 'a short first word ' + word, 'a short first word ' + word),
            ('comma', 'password: ' + value + ',Autumn', value + ',Autumn', value + ',Autumn'),
            ('single_quote', "password: '" + value + "''Autumn'", value + "''Autumn", value + "'Autumn"),
            ('leading_space', 'password: "  ' + value + '"', '  ' + value, '  ' + value),
            ('leading_punctuation', 'password: ",;' + value + '"', ',;' + value, ',;' + value),
        ]:
            add(f'{i}_yaml_{kind}', '.yaml', text + '\n', [expectation(canonical, 'generic_password', raw, 'yaml-scalar')])
        phrase = 'a short first word ' + word
        add(f'{i}_env_phrase', '.env', 'password="' + phrase + '"\n', [expectation(phrase, 'generic_password')])
        for alphabet, encoder in [('std', base64.b64encode), ('url', base64.urlsafe_b64encode)]:
            for padding in (True, False):
                def encode(value):
                    encoded = encoder(value.encode()).decode()
                    return encoded if padding else encoded.rstrip('=')
                branch = "first='" + encode('key=' + key) + "'\nsecond='" + encode('key=' + key) + "'"
                for depth in (2, 3, 4):
                    for kind, decoded, layers, count in [
                        ('short', key, depth, 1),
                        ('repeated', 'first=' + key + '\nsecond=' + key, depth, 2),
                        ('branches', branch, depth - 1, 2),
                    ]:
                        blob = decoded
                        for _ in range(layers):
                            blob = encode(blob)
                        add(f'{i}_nested_{alphabet}_{padding}_{depth}_{kind}', '.env', 'payload="' + blob + '"\n',
                            [expectation(key, 'aws_access_key_id', blob, 'base64-decode') for _ in range(count)])
        for j, raw in enumerate([
            'normal release documentation and configuration examples',
            'password=' + value,
            'AKIAIOSFODNN7EXAMPLE',
            '\x00\xff\x00binary',
        ]):
            blob = base64.b64encode(raw.encode()).decode()
            add(f'{i}_negative_encoded_{j}', '.env', f'payload="{blob}"\n', [])
        add(f'{i}_negative_short', '.yaml', 'password: "abc"\n', [])
        add(f'{i}_negative_reference', '.yaml', 'password: "${PASSWORD}"\n', [])
        add(f'{i}_negative_collection', '.yaml', 'password: {source: configuration}\n', [])
        add(f'{i}_negative_sequence', '.yaml', 'password: [Winter42, Autumn53]\n', [])
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
            assert result.returncode in (0, 1) and report['complete'] and not report['truncated'], tag
            found, missing, negatives, spans = 0, [], [], []
            for path, case in by_path.items():
                fs = [f for f in report['findings'] if f['path'] == path]
                if not case['expected'] and fs:
                    negatives.append(case['name'])
                for expected in case['expected']:
                    hit = next((f for f in fs if f['redacted'] == expected['value'] and f['type'] == expected['type']), None)
                    if hit is None:
                        missing.append(case['name'] + ':' + expected['type'])
                        continue
                    found += 1
                    if label == 'after' and expected['transform']:
                        start = len(case['text'][:case['text'].index(expected['source'])].encode())
                        evidence = hit.get('evidence', [])
                        if not any(e['start'] == start and e['end'] == start + len(expected['source'].encode()) and
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
    limit = root / 'oversized.env'
    limit.write_text('A' * 8193, encoding='utf-8')
    result = subprocess.run([str(binary), 'scan', str(limit), '--strict', '--format', 'json'],
                            cwd=root, env=env, capture_output=True, encoding='utf-8', timeout=30)
    (root / 'limited.json').write_text(result.stdout, encoding='utf-8')
    report = json.loads(result.stdout)
    assert result.returncode == 2 and not report['complete']
    assert any(d['code'] == 'base64_limit' for d in report['diagnostics'])
    repeated = inputs / '0_nested_std_True_2_repeated.env'
    result = subprocess.run([str(binary), 'scan', str(repeated), '--strict', '--format', 'json'],
                            cwd=root, env=env, capture_output=True, encoding='utf-8', timeout=30)
    (root / 'aggregated-repeated.json').write_text(result.stdout, encoding='utf-8')
    aggregate = json.loads(result.stdout)
    assert result.returncode == 0 and aggregate['complete'] and len(aggregate['findings']) == 1
    occurrences = aggregate['findings'][0]['occurrences']
    assert len(occurrences) == 2 and len({o['id'] for o in occurrences}) == 2
    original = next(c for c in cases if c['path'] == repeated.name)
    assert original['expected'][0]['value'] not in result.stdout and original['expected'][0]['source'] not in result.stdout
    depth = root / 'depth-limited.env'
    secret = original['expected'][0]['value']
    blob = secret
    for _ in range(5):
        blob = base64.b64encode(blob.encode()).decode()
    depth.write_text('key=' + secret + '\npayload="' + blob + '"\n', encoding='utf-8')
    result = subprocess.run([str(binary), 'scan', str(depth), '--strict', '--format', 'json'],
                            cwd=root, env=env, capture_output=True, encoding='utf-8', timeout=30)
    (root / 'depth-limited.json').write_text(result.stdout, encoding='utf-8')
    report = json.loads(result.stdout)
    assert result.returncode == 2 and not report['complete'] and len(report['findings']) == 1
    assert any(d['code'] == 'base64_limit' for d in report['diagnostics'])
    evidence = {'version': '1.4.0', 'seed': 2602101403, 'cases': len(cases),
                'expected_credentials': sum(len(c['expected']) for c in cases),
                'negative_cases': sum(not c['expected'] for c in cases),
                'truth_sha256': hashlib.sha256(truth.encode()).hexdigest(), 'runs': runs,
                'identity_and_occurrences': True, 'aggregate_repeated_occurrences': 2,
                'strict_limit_exit': 2, 'strict_depth_limit_exit': 2,
                'boundary': 'Own synthetic regression corpus. Up to four bounded Base64 layers, repeated inner occurrences and YAML password scalars. '
                            'No provider calls. This is not independent market precision/recall evidence.',
                'inputs_retained': str(root)}
    (root / 'encoding.json').write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({**evidence, 'runs': [{**r, 'missing': len(r['missing'])} for r in runs]}, indent=2))


if __name__ == '__main__':
    main()
