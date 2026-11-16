#!/usr/bin/env python3
"""Run hash-pinned 1.4 native contracts with explicit 1.5 compatibility adapters."""
import argparse
import ast
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

BASE = Path(__file__).resolve().parent
SUITES = {
    'acceptance': 'check-1.4.0.py',
    'quick': 'check-quick-scan-1.4.0.py',
    'interfaces': 'check-interfaces-1.4.0.py',
    'pipeline': 'check-pipeline-evidence-1.4.0.py',
    'json': 'check-json-literals-1.4.0.py',
    'encoding': 'check-encoding-1.4.0.py',
    'toml': 'check-toml-literals-1.4.0.py',
    'yaml': 'check-yaml-literals-1.4.0.py',
    'roles': 'check-password-roles-1.4.0.py',
    'noise': 'check-noise-1.4.0.py',
    'noise-deep': 'check-noise-1.4.0.py',
}
LOOPBACK = {'interfaces', 'pipeline'}
ENTROPY_TYPE_ALIASES = {
    prefix + suffix for prefix in ('140014_', '741913_') for suffix in (
        'positive_longkey.env', 'positive_tokenvalue.env', 'positive_after_public.env',
        'positive_after_integrity.html', 'positive_after_data.json')
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def adapt(name, text):
    changes = []
    corpus_before = [ast.dump(node) for node in ast.parse(text).body
                     if isinstance(node, ast.FunctionDef) and node.name == 'corpus']

    def replace(before, after, count=1):
        nonlocal text
        assert text.count(before) == count, (name, 'adapter source mismatch', before)
        text = text.replace(before, after)
        changes.append({'before': before, 'after': after, 'count': count})

    if name == 'check-quick-scan-1.4.0.py':
        for before, after, count in (
            ('Нет объектов для проверки', 'no objects to scan', 1),
            ('БЫСТРЫЙ СТАРТ', 'Quick start:', 1),
            ('Базовый скан без настройки', 'prowl scan [path...]', 2),
            ('Находок после фильтров и подавлений нет', 'no findings after filters and suppressions', 3),
            ('supported only by the local scan command', 'does not apply to command "repo"', 1),
            ("contains='source_error'", "contains='could not be read'", 1),
            ('applies only to stdin', 'applies to stdin only', 2),
        ):
            replace(before, after, count)
        replace("        run('reject_false_' + flag[2:], [flag + '=false', 'production.json'], code=2,\n"
                "            contains='does not accept a value')",
                "        report = run('explicit_false_' + flag[2:], [flag + '=false', 'production.json', '--format', 'json'], json_output=True)\n"
                "        assert report['complete'] and report['count'] == 1\n"
                "        assert report['findings'][0].get('verified') is None and report['findings'][0]['redacted'] != value\n"
                "        partial = run('explicit_false_incomplete_' + flag[2:], [flag + '=false', 'production.json', '--max-size', '1', '--format', 'json'], code=2, json_output=True)\n"
                "        assert not partial['complete'] and partial['stats']['skipped'] > 0")
    elif name == 'check-json-literals-1.4.0.py':
        replace("assert result.returncode == 2 and not report['complete'] and not report['truncated'], tag",
                "assert result.returncode == 2 and not report['complete'] and report['truncated'], tag")
        replace("                assert all('_duplicates_' in Path(d['path']).name for d in report['diagnostics']), tag\n",
                "                assert all('_duplicates_' in Path(d['path']).name for d in report['diagnostics']), tag\n"
                "                markers = [f for f in report['findings'] if f['type'] == 'response_truncated']\n"
                "                duplicate_paths = {p for p, c in by_path.items() if '_duplicates_' in c['name']}\n"
                "                assert len(markers) == len(duplicate_paths) and {f['path'] for f in markers} == duplicate_paths\n"
                "                assert all(f['detector'] == 'scan' and f['stage'] == 'intake' and not f.get('secret_id') for f in markers)\n"
                "                report['findings'] = [f for f in report['findings'] if f['type'] != 'response_truncated']\n")
        replace("    identity_groups = {}\n    for f in report['findings']:\n",
                "    identity_groups = {}\n    for f in report['findings']:\n"
                "        if f['type'] == 'response_truncated':\n            continue\n")
    elif name == 'check-encoding-1.4.0.py':
        replace("assert result.returncode == 2 and not report['complete'] and len(report['findings']) == 1",
                "assert result.returncode == 2 and not report['complete'] and len(report['findings']) == 2\n"
                "    assert sum(f['type'] == 'aws_access_key_id' for f in report['findings']) == 1\n"
                "    markers = [f for f in report['findings'] if f['type'] == 'results_truncated']\n"
                "    assert len(markers) == 1 and markers[0]['detector'] == 'scan' and markers[0]['stage'] == 'intake'\n"
                "    assert not markers[0].get('secret_id')")
    elif name == 'check-noise-1.4.0.py':
        replace("if not any(f['type'] in row['types'] for f in same):",
                "if not any(f['type'] in row['types'] or (row['name'] in "
                + repr(sorted(ENTROPY_TYPE_ALIASES)) + " and 'generic_high_entropy' in row['types'] "
                "and f['type'] == 'generic_api_key') for f in same):")
    compile(text, name, 'exec')
    corpus_after = [ast.dump(node) for node in ast.parse(text).body
                    if isinstance(node, ast.FunctionDef) and node.name == 'corpus']
    assert corpus_before == corpus_after, (name, 'adapter changed the corpus generator')
    return text, changes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--reference-binary', type=Path)
    parser.add_argument('--suite', choices=SUITES, action='append')
    parser.add_argument('--jobs', type=int, choices=range(1, 5), default=3)
    args = parser.parse_args()
    binaries = [('candidate', args.binary.resolve(strict=True))]
    if args.reference_binary:
        binaries.append(('reference', args.reference_binary.resolve(strict=True)))
    manifest = json.loads((BASE / 'compat14/manifest.json').read_text())
    assert manifest['reference'] == 'f72ea02d0295e764bec5a32359240e77192073fc'
    root = Path(tempfile.mkdtemp(prefix='prowl-compat14-native-'))
    adapters = {}
    for label, _ in binaries:
        folder = root / label / 'scripts'
        folder.mkdir(parents=True)
        for entry in manifest['files']:
            name = entry['name']
            assert name == Path(name).name
            data = (BASE / 'compat14/fixtures' / name).read_bytes()
            assert sha(data) == entry['sha256'], name
            if label == 'candidate' and name.endswith('.py'):
                text, changes = adapt(name, data.decode())
                data = text.encode()
                adapters[name] = changes
            (folder / name).write_bytes(data)
        fixtures = root / label / 'tool/internal/scan/testdata'
        fixtures.mkdir(parents=True)
        for name, expected in (
            ('noise-1.4.0.json', 'd030d08dd14ba1fbcc36f3ce087d4cecc08fa84fb1379425120c9099e1ff1be0'),
            ('noise-deep-1.4.0.json', '79ed1475c880a238d2ed7684332a51011b287ab206ba23c2170acaa1f73dac84'),
        ):
            data = (BASE.parent / 'tool/internal/scan/testdata' / name).read_bytes()
            assert sha(data) == expected, name
            (fixtures / name).write_bytes(data)

    env = {k: v for k, v in os.environ.items() if not k.startswith(('PROWL_', 'GIT_'))
           and k not in ('PYTHONPATH', 'PYTHONHOME') and not k.upper().endswith('_PROXY')}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
               GIT_CONFIG_NOSYSTEM='1', PYTHONNOUSERSITE='1', NO_PROXY='127.0.0.1,localhost,::1')

    def run(task):
        label, binary, suite = task
        script = root / label / 'scripts' / SUITES[suite]
        output = root / label / ('output-' + suite)
        command = [sys.executable, '-I', str(script), '--binary', str(binary), '--output-dir', str(output)]
        if suite == 'noise-deep':
            command += ['--fixture', str(root / label / 'tool/internal/scan/testdata/noise-deep-1.4.0.json')]
        boundary = 'reviewed owned loopback; proxy environment cleared'
        if suite not in LOOPBACK and Path('/usr/bin/sandbox-exec').is_file():
            command = ['/usr/bin/sandbox-exec', '-p', '(version 1)(allow default)(deny network*)', *command]
            boundary = 'OS network deny'
        elif suite not in LOOPBACK:
            boundary = 'reviewed local inputs; caller must supply OS network isolation'
        log = root / label / (suite + '.log')
        try:
            with log.open('wb') as stream:
                result = subprocess.run(command, cwd=root / label, env=env,
                                        stdout=stream, stderr=subprocess.STDOUT, timeout=300)
            status = result.returncode
        except subprocess.TimeoutExpired:
            status = 'timeout'
        files = []
        if output.exists():
            for path in sorted(output.glob('*.json')):
                files.append({'path': str(path), 'sha256': sha(path.read_bytes())})
        return {'label': label, 'suite': suite, 'exit': status, 'log': str(log),
                'log_sha256': sha(log.read_bytes()), 'output': str(output),
                'json_outputs': files, 'network_boundary': boundary}

    tasks = [(label, binary, suite) for label, binary in binaries for suite in (args.suite or SUITES)]
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(run, tasks))
    report = {'reference': manifest['reference'], 'manifest_sha256': sha((BASE / 'compat14/manifest.json').read_bytes()),
              'binaries': [{'label': label, 'path': str(path), 'sha256': sha(path.read_bytes())} for label, path in binaries],
              'adapters': adapters, 'runs': results, 'passed': all(r['exit'] == 0 for r in results),
              'scope': 'Historical native contracts with declared UI/type/completeness adapters; no legacy model-score parity or live-provider acceptance claim.',
              'excluded': {'benchmark-1.4.0.py': 'informational benchmark; pinned quality/performance gates qualify current candidates separately',
                           'check-docker-action.sh': 'Docker factory qualification must bind the final image source/digests separately'}}
    path = root / 'qualification.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'runs': len(results), 'evidence': str(path)}))
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
