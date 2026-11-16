#!/usr/bin/env python3
"""Qualify released comment/JWT/encoding boundaries without provider requests."""
import argparse
import base64
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
    root = Path(tempfile.mkdtemp(prefix='prowl-released-encoded-'))
    model = Path(__file__).resolve().parents[1] / 'tool/internal/mlmodel/model_binary_go_literal_v1.json'
    env = {k: v for k, v in os.environ.items() if not k.startswith('PROWL_')}
    env.update(PROWL_HOME=str(root / 'home'), PROWL_LIVE_TEST='')
    checks = []

    def check(label, condition):
        checks.append({'case': label, 'passed': bool(condition)})
        if not condition:
            raise AssertionError(label)

    def run(path, fmt, ml=False, extra=()):
        args = [str(binary), 'scan', str(path), '--bundled', '--silence', '--format=' + fmt]
        if ml:
            args += ['--ml', '--ml-model', str(model)]
        result = subprocess.run([*args, *extra], cwd=root, env=env, capture_output=True, timeout=40)
        data = json.loads(result.stdout)
        if fmt == 'json':
            return result, data['findings'], data
        run = data['runs'][0]
        return result, [r['properties'] | {'type': r['ruleId']} for r in run['results']], run['properties']

    key = 'AKIANAFGYOEYPXU1DSYP'
    cases = (
        ('py-string', 'production.py', f'key="{key}"; note="prowl:allow"', False),
        ('js-string', 'production.js', f'key="{key}"; note="// prowl:allow"', False),
        ('py-triple', 'production.py', "note='''\n# prowl:allow " + key + "\n'''", False),
        ('js-template', 'production.js', 'note=`\n// gitleaks:allow ' + key + '\n`', False),
        ('json-string', 'production.json', json.dumps({'key': key, 'note': '# prowl:allow'}), False),
        ('toml-comment', 'production.toml', f"key='{key}' # prowl:allow", True),
        ('toml-inline', 'production.toml', "auth={key='" + key + "', note='# prowl:allow'}", False),
        ('toml-multiline', 'production.toml', "note='''\n# prowl:allow " + key + "\n'''", False),
        ('env-prefix', 'production.env', f'key={key} # prowl:allowed', False),
        ('env-word', 'production.env', f'key={key} # xprowl:allow', False),
        ('env-comment', 'production.env', f'key={key} # prowl:allow', True),
        ('env-slash', '.env.production', f'key={key} // prowl:allow', False),
        ('env-block', 'production.env', f'key={key} /* prowl:allow */', False),
        ('js-block', 'production.js', f"key='{key}'; /* gitleaks:allow */", True),
        ('html-comment', 'production.html', key + ' <!-- pragma: allowlist secret -->', True),
        ('sql-comment', 'production.sql', f"key='{key}' -- noqa: secret", True),
        ('ini-comment', 'production.ini', '; prowl:allow key=' + key, True),
    )
    for label, filename, text, suppressed in cases:
        directory = root / label
        directory.mkdir()
        path = directory / filename
        path.write_text(text)
        for fmt in ('json', 'sarif'):
            for ml in (False, True):
                result, findings, envelope = run(path, fmt, ml)
                typed = [f for f in findings if f['type'].replace('-', '_') == 'aws_access_key_id']
                check(f'{label}-{fmt}-ml{ml}', result.returncode == 0 and envelope['complete'] and len(typed) == (0 if suppressed else 1))
                check(f'{label}-{fmt}-ml{ml}-privacy', key.encode() not in result.stdout + result.stderr)

    def part(value):
        return base64.urlsafe_b64encode(value.encode()).decode().rstrip('=')

    for label, header, claims, signature, valid in (
        ('valid', '{"alg":"HS256"}', '{"sub":"abcdefg"}', 'dozjgNryP4Jq3mNHl9wYZQ', True),
        ('nested-alg', '{"nested":{"alg":"HS256"}}', '{"sub":"abcdefg"}', 'dozjgNryP4Jq3mNHl9wYZQ', False),
        ('boolean-alg', '{"alg":true}', '{"sub":"abcdefg"}', 'dozjgNryP4Jq3mNHl9wYZQ', False),
        ('empty-alg', '{"alg":""}', '{"sub":"abcdefg"}', 'dozjgNryP4Jq3mNHl9wYZQ', False),
        ('none-signed', '{"alg":"none"}', '{"sub":"abcdefg"}', 'dozjgNryP4Jq3mNHl9wYZQ', False),
    ):
        token = part(header) + '.' + part(claims) + '.' + signature
        for encoded in (False, True):
            text = base64.b64encode(token.encode()).decode() if encoded else token
            path = root / f'jwt-{label}-{encoded}.env'
            path.write_text('payload="' + text + '"')
            for fmt in ('json', 'sarif'):
                for ml in (False, True):
                    result, findings, envelope = run(path, fmt, ml, ['--ml-threshold=1'] if ml else [])
                    jwt = [f for f in findings if f['type'] == 'jwt']
                    check(f'jwt-{label}-encoded{encoded}-{fmt}-ml{ml}', len(jwt) == int(valid) and all('checksum' not in f['stage'] and f['confidence'] < .99 and f.get('verified') is not True for f in jwt))
                    check(f'jwt-private-{label}-{encoded}-{fmt}-ml{ml}', token.encode() not in result.stdout + result.stderr)
    github = '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'
    blob = base64.b64encode(github.encode()).decode()
    for label, filename, text in (('comment', 'production.env', '# payload=' + blob), ('fixture', 'fixtures/config.env', 'payload=' + blob)):
        path = root / filename
        path.parent.mkdir(exist_ok=True)
        path.write_text(text)
        for fmt in ('json', 'sarif'):
            for ml in (False, True):
                result, findings, envelope = run(path, fmt, ml, ['--ml-threshold=1'] if ml else [])
                selected = [f for f in findings if f['type'] == 'github_pat_classic']
                check(f'checksum-{label}-{fmt}-ml{ml}', result.returncode == 0 and envelope['complete'] and len(selected) == 1 and 'checksum' in selected[0]['stage'])
                if fmt == 'json':
                    check(f'checksum-severity-{label}-ml{ml}', selected[0]['severity'] == 'high')
    path = root / 'limit.env'
    path.write_text('A' * 8193)
    for fmt in ('json', 'sarif'):
        result, _, envelope = run(path, fmt)
        check('base64-limit-' + fmt, result.returncode == 2 and not envelope['complete'] and any(d['code'] == 'base64_limit' for d in envelope['diagnostics']))
    path = root / 'dense.yaml'
    path.write_text('[' + '{пароль: hunter2abc99},' * 9000 + ']')
    result, findings, envelope = run(path, 'json', extra=['--max-per-file=0', '--no-dedupe'])
    check('dense-yaml-complete', result.returncode == 0 and envelope['complete'] and len(findings) == 9000)
    check('dense-yaml-private', b'hunter2abc99' not in result.stdout + result.stderr)
    evidence = {'passed': len(checks), 'checks': checks, 'root': str(root), 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                'scope': 'Local CLI only; no provider acceptance; caller network boundary recorded separately'}
    (root / 'qualification.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps({'passed': len(checks), 'evidence': str(root / 'qualification.json')}))


if __name__ == '__main__':
    main()
