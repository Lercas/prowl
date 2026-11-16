"""Измерение шума реальных CLI-сборок на собственных синтетических данных без сети."""
import argparse
import hashlib
import json
import os
import subprocess
from collections import Counter
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--binary', type=Path, required=True)
    ap.add_argument('--baseline-binary', type=Path)
    ap.add_argument('--output-dir', type=Path, required=True)
    ap.add_argument('--measure-only', action='store_true')
    ap.add_argument('--fixture', type=Path)
    args = ap.parse_args()
    root = args.output_dir.resolve()
    root.mkdir(exist_ok=False)
    fixture = args.fixture or Path(__file__).resolve().parent.parent / 'tool/internal/scan/testdata/noise-1.4.0.json'
    cases = json.loads(fixture.read_text())
    inputs = root / 'inputs'
    inputs.mkdir()
    by_path = {}
    for row in cases:
        directory = inputs / row['name']
        directory.mkdir()
        path = directory / row['path']
        path.write_text(row['text'])
        by_path[str(path)] = row
    env = {**os.environ, 'PROWL_HOME': str(root / 'isolated-home'), 'NO_COLOR': '1'}
    binaries = [('after', args.binary)]
    if args.baseline_binary:
        binaries.insert(0, ('before', args.baseline_binary))
    evidence = {'version': '1.4.0', 'fixture_sha256': hashlib.sha256(fixture.read_bytes()).hexdigest(),
                'truth_counts': dict(Counter(row['truth'] for row in cases)), 'runs': [],
                'boundary': 'Own authored synthetic corpus, two seeds. No live provider calls. '
                            'These are regression controls, not an independent market precision/recall benchmark. '
                            'Ambiguous ACLs excluded from negative counts. All inputs and outputs retained.',
                'inputs_retained': str(root)}
    failures = []
    for label, binary in binaries:
        for ml in (False, True):
            argv = [str(binary.resolve()), 'scan', str(inputs), '--strict', '--format', 'json', '--show-secrets']
            if ml:
                argv.append('--ml')
            p = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=120)
            tag = f'{label}-' + ('ml' if ml else 'default')
            (root / f'{tag}.stdout.json').write_text(p.stdout)
            (root / f'{tag}.stderr.txt').write_text(p.stderr)
            report = json.loads(p.stdout)
            assert p.returncode in (0, 1) and report['complete'] and not report['truncated'], tag
            found = {name: [] for name in by_path}
            for f in report['findings']:
                assert f['path'] in by_path, f['path']
                found[f['path']].append(f)
            fp, missing, wrong_type, hits, ambiguous = [], [], [], [], []
            types = Counter()
            for path, row in by_path.items():
                fs = found[path]
                if row['truth'] == 'negative' and fs:
                    fp.append(row['name'])
                    types.update(f['type'] for f in fs)
                if row['truth'] != 'negative':
                    same = [f for f in fs if f['redacted'] == row['value']]
                    if row['truth'] == 'ambiguous':
                        ambiguous.append({'case': row['name'], 'reported': bool(same)})
                    elif not same:
                        missing.append(row['name'])
                    else:
                        hits.append(row['name'])
                        if not any(f['type'] in row['types'] for f in same):
                            wrong_type.append(row['name'])
            run = {'label': label, 'ml': ml, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                   'exit': p.returncode, 'complete': report['complete'], 'false_positive_cases': len(fp),
                   'false_positive_findings_by_type': dict(types), 'false_positive_names': fp,
                   'positive_hits': len(hits), 'positive_missed': missing,
                   'positive_wrong_type': wrong_type, 'ambiguous': ambiguous}
            evidence['runs'].append(run)
            if label == 'after' and not args.measure_only:
                failures.extend(fp)
                failures.extend(name for name in missing if not ml or
                                next(row for row in cases if row['name'] == name)['ml_expected'])
                failures.extend(wrong_type)
    evidence['checks_passed'] = not failures
    evidence['failures'] = failures
    (root / 'noise.json').write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: v for k, v in evidence.items() if k not in ('runs', 'boundary')}, indent=2))
    for run in evidence['runs']:
        print(json.dumps({k: v for k, v in run.items() if k not in ('false_positive_names', 'ambiguous')}, indent=2))
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
