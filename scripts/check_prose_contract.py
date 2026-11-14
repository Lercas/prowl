#!/usr/bin/env python3
"""Check prose spans, keyed identity and redaction on synthetic files/stdin, with optional local L2."""
import argparse
import hashlib
import hmac
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
    cases = json.loads((repo / 'tool/internal/lsp/testdata/noise-prose-1.5.0.json').read_text())
    root = Path(tempfile.mkdtemp(prefix='prowl-prose-native-'))
    env = {k:v for k,v in os.environ.items() if not k.startswith('PROWL_')}
    env['PROWL_HOME'] = str(root / 'home')
    key = bytes(range(32))
    keyfile = root / 'identity.key'
    keyfile.write_text(key.hex()+'\n'); keyfile.chmod(0o600)
    checks, kept_counts = [], {}
    completed = False
    def check(name, condition):
        checks.append(dict(case=name, passed=bool(condition)))
        if not condition:
            raise AssertionError(name)
    try:
        for case in cases:
            name, text, value = case['name'], case['text'], case['value']
            expected = hmac.new(key, value.encode(), hashlib.sha256).hexdigest() if value else None
            for ml in (False, True):
                for stdin in (False, True):
                    for fmt in ('json', 'sarif'):
                        path = root / 'production.md'
                        sentinel = b'logical input must not be opened'
                        path.write_bytes(sentinel if stdin else text.encode())
                        command = [str(binary), 'scan', '--bundled', '--silence', '--no-dedupe',
                                   '--identity-key-file='+str(keyfile), '--format='+fmt]
                        command += ['--ml'] if ml else []
                        command += ['--stdin-name=production.md'] if stdin else ['production.md']
                        result = subprocess.run(command, cwd=root, env=env, input=text.encode() if stdin else b'',
                                                capture_output=True, timeout=30)
                        report = json.loads(result.stdout)
                        meta = report if fmt == 'json' else report['runs'][0]['properties']
                        fs = report['findings'] if fmt == 'json' else [dict(r['properties'], type=r['ruleId']) for r in report['runs'][0].get('results', [])]
                        good = (result.returncode == 0 and meta['complete'] and not meta['truncated']
                                and meta['stats']['processed'] == 1 and not meta['secrets_revealed']
                                and (not stdin or path.read_bytes() == sentinel))
                        if case['truth'] == 'negative':
                            good = good and not fs
                        else:
                            # L2 may suppress an L1 candidate. Every retained result must still have
                            # the exact known source value, identity and UTF-16 position; this is not
                            # an assertion that all synthetic passwords pass the trained classifier.
                            good = good and (ml or len(fs) == 1)
                            offset = text.index(value)
                            prefix = text[:offset]
                            line = prefix.count('\n')+1
                            col = len(prefix.rsplit('\n',1)[-1].encode('utf-16-le'))//2+1
                            good = good and all(f['secret_id'] == expected and f['type'] in case['types']
                                                and not f.get('context') for f in fs)
                            if fmt == 'json':
                                good = good and all(f['line'] == line and f['col'] == len(prefix.rsplit('\n',1)[-1].encode())+1 for f in fs)
                            else:
                                regions = [r['locations'][0]['physicalLocation']['region'] for r in report['runs'][0].get('results', [])]
                                good = good and all(r['startLine'] == line and r['startColumn'] == col for r in regions)
                            good = good and value.encode() not in result.stdout+result.stderr
                            kept_counts.setdefault(name, {})['ml' if ml else 'l1'] = len(fs)
                        check(f'{name}/ml={ml}/stdin={stdin}/{fmt}', good)
        check('local-l2-retains-proven-prose-label', kept_counts['prose-v2-api-label']['ml'] == 1)
        completed = True
    finally:
        report = dict(complete=completed, expected_checks=len(cases)*8+1, binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                      passed=sum(c['passed'] for c in checks), total=len(checks), checks=checks,
                      candidate_counts=kept_counts, root=str(root),
                      scope='synthetic local prose only; no providers, remote model or production acceptance')
        (root / 'qualification.json').write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps({k:v for k,v in report.items() if k not in ('checks','candidate_counts')}))


if __name__ == '__main__':
    main()
