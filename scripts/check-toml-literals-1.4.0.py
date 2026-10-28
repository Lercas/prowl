"""Приёмка канонических TOML-строк и исходных spans на собственных данных без сети."""
import argparse
import hashlib
import json
import os
import random
import string
import subprocess
from pathlib import Path


def corpus():
    rng = random.Random(2602101405)
    cases = []

    def escape(value):
        return ''.join(('\\u%04x' if ord(c) <= 0xffff else '\\U%08x') % ord(c) for c in value)

    def add(name, text, expected):
        cases.append({'name': name, 'path': name + '.toml', 'text': text, 'expected': expected})

    def want(value, typ, source=None, transform='toml-string'):
        return {'value': value, 'type': typ, 'source': source or value, 'transform': transform}

    for i in range(12):
        word = ''.join(rng.choices(string.ascii_letters, k=8))
        value = 'Winter42!' + word
        key = 'AKIA' + ''.join(rng.choices(string.ascii_uppercase + string.digits, k=16))
        stripe = 'sk_live_' + ''.join(rng.choices(string.ascii_letters + string.digits, k=24))
        raw = escape(value)
        for label, text, canonical, source in [

            ('bom', '\ufeffpassword="' + value + '"', value, value),
            ('basic', 'password="' + raw + '"', value, raw),
            ('literal', "password='" + value + "\\'", value + '\\', value + '\\'),
            ('literal_unicode_text', "password='" + raw + "'", raw, raw),
            ('basic_multiline', 'password="""\n' + value + '\nSpring53"""', value + '\nSpring53', '\n' + value + '\nSpring53'),
            ('literal_multiline', "password='''\n" + value + "\nSpring53'''", value + '\nSpring53', '\n' + value + '\nSpring53'),
            ('crlf', 'password="""\r\n' + value + '\r\nSpring53"""', value + '\r\nSpring53', '\r\n' + value + '\r\nSpring53'),
            ('continuation', 'password="""Winter\\\n  42!' + word + '"""', value, 'Winter\\\n  42!' + word),
            ('escaped_name', '"' + escape('password') + '"="' + raw + '"', value, raw),
            ('inline', 'auth={password="' + raw + '"}', value, raw),
            ('dotted', 'auth.password="' + raw + '"', value, raw),
            ('astral', 'password="' + escape(value + '🚀') + '"', value + '🚀', escape(value + '🚀')),
        ]:
            add(f'{i}_{label}', text, [want(canonical, 'generic_password', source)])
        for j, (secret, typ) in enumerate([(key, 'aws_access_key_id'), (stripe, 'stripe_secret_key')]):
            raw = escape(secret)
            for label, text in [
                ('typed', 'api_key="' + raw + '"'),
                ('array', 'tokens=["' + raw + '"]'),
                ('key', '"' + raw + '"="unrelated"'),
                ('table', '[auth]\napi_key="' + raw + '"'),
            ]:
                add(f'{i}_{label}_{j}', text, [want(secret, typ, raw)])
        add(f'{i}_comments', '# first=' + key + '\nnote="normal"\n# second=' + key + '\n',
            [want(key, 'aws_access_key_id', transform=None), want(key, 'aws_access_key_id', transform=None)])
        placeholder = '$' + '{PASSWORD}'
        for j, text in enumerate([
            'password="' + escape(placeholder) + '"', "password='{{PASSWORD}}'",
            "password='<PASSWORD>'", "password='example'", "password='dummy'", "password='abc'",
            'password=true', 'password=123456', 'password=["' + value + '"]',
            'password={source="configuration"}', 'bypass="' + value + '"',
        ]):
            add(f'{i}_negative_{j}', text, [])
    return cases


def main(*, make_corpus=corpus, suite='toml', seed=2602101405,
         invalid_text=r'password="Winter42\uD800Autumn"', invalid_code='toml_literal_parse',
         boundary='Own synthetic regression corpus. Canonical TOML basic/literal/multiline strings, keys, comments and table-local contexts. '
                  'No provider calls. This is not independent market precision/recall evidence.'):
    ap = argparse.ArgumentParser()
    ap.add_argument('--binary', type=Path, required=True)
    ap.add_argument('--baseline-binary', type=Path)
    ap.add_argument('--output-dir', type=Path, required=True)
    args = ap.parse_args()
    root = args.output_dir.resolve()
    root.mkdir(parents=True, exist_ok=False)
    inputs = root / 'inputs'
    inputs.mkdir()
    cases = make_corpus()
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
                unused = fs.copy()
                for expected in case['expected']:
                    matches = [f for f in unused if f['redacted'] == expected['value'] and f['type'] == expected['type']]
                    source = case['text'].encode('utf-8')
                    def source_matches(f):
                        return any(source[e['start']:e['end']] == expected['source'].encode('utf-8') and
                                   e['transform'] == expected['transform'] for e in f.get('evidence', []))
                    hit = next((f for f in matches if source_matches(f)), None) if label == 'after' and expected['transform'] else None
                    if hit is None:
                        hit = next(iter(matches), None)
                    if hit is None:
                        missing.append(case['name'] + ':' + expected['type'])
                        continue
                    found += 1
                    unused.remove(hit)
                    if label == 'after' and expected['transform']:
                        evidence = hit.get('evidence', [])
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
    limit = root / ('invalid-unicode.' + suite)
    limit.write_text(invalid_text, encoding='utf-8')
    result = subprocess.run([str(binary), 'scan', str(limit), '--strict', '--format', 'json'],
                            cwd=root, env=env, capture_output=True, encoding='utf-8', timeout=30)
    (root / 'limited.json').write_text(result.stdout, encoding='utf-8')
    report = json.loads(result.stdout)
    assert result.returncode == 2 and not report['complete']
    assert any(d['code'] == invalid_code for d in report['diagnostics'])
    evidence = {'version': '1.4.0', 'seed': seed, 'cases': len(cases),
                'expected_credentials': sum(len(c['expected']) for c in cases),
                'negative_cases': sum(not c['expected'] for c in cases),
                'truth_sha256': hashlib.sha256(truth.encode()).hexdigest(), 'runs': runs,
                'identity_and_occurrences': True, 'strict_invalid_unicode_exit': 2,
                'boundary': boundary,
                'inputs_retained': str(root)}
    (root / (suite + '-literals.json')).write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({**evidence, 'runs': [{**r, 'missing': len(r['missing'])} for r in runs]}, indent=2))


if __name__ == '__main__':
    main()
