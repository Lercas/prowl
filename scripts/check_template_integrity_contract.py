#!/usr/bin/env python3
"""Exercise template integrity through an isolated CLI; never install or contact providers."""
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
    root = Path(tempfile.mkdtemp(prefix='prowl-template-integrity-'))
    checks = []

    def check(name, passed):
        checks.append({'case': name, 'passed': bool(passed)})
        if not passed:
            raise AssertionError(name)

    rule = 'id: owned-integrity\ninfo: {name: Owned integrity, severity: high}\nmatchers:\n - type: word\n   words: [OWNED_INTEGRITY_MARKER]\n'
    verifier = 'id: owned-integrity\nmatch: [owned_integrity_unused]\nrequests:\n - method: GET\n   url: https://example.invalid/never-called\n   matchers:\n    - type: status\n      status: [200]\n'
    cases = ('unsigned', 'valid', 'spaces', 'tampered', 'unlisted', 'missing',
             'malformed', 'duplicate', 'traversal', 'absolute', 'manifest-directory',
             'manifest-link', 'template-link')
    for kind, body in (('rules', rule), ('verifiers', verifier)):
        for case in cases:
            work = root / kind / case
            home = work / 'home'
            library = home / kind
            library.mkdir(parents=True)
            name = ' leading  spaces.yaml' if case == 'spaces' else 'owned.yaml'
            template = library / name
            if case == 'template-link':
                outside = work / 'outside.yaml'
                outside.write_text(body)
                template.symlink_to(outside)
            else:
                template.write_text(body)
            checksum = hashlib.sha256(body.encode()).hexdigest()
            manifest = library / 'MANIFEST.sha256'
            line = checksum + '  ' + name + '\n'
            if case == 'tampered':
                line = '0' * 64 + '  ' + name + '\n'
            elif case == 'unlisted':
                (library / 'extra.yaml').write_text(body.replace('owned-integrity', 'owned-extra'))
            elif case == 'missing':
                line += checksum + '  missing.yaml\n'
            elif case == 'malformed':
                line = 'not a checksum manifest\n'
            elif case == 'duplicate':
                line += line
            elif case == 'traversal':
                line = checksum + '  ../outside.yaml\n'
            elif case == 'absolute':
                line = checksum + '  ' + str(template) + '\n'
            if case == 'manifest-directory':
                manifest.mkdir()
            elif case == 'manifest-link':
                outside = work / 'outside-manifest'
                outside.write_text(line)
                manifest.symlink_to(outside)
            elif case != 'unsigned':
                manifest.write_text(line)
            fixture = work / 'clean.txt'
            fixture.write_text('ordinary text\n')
            baseline = work / 'protected-baseline.json'
            baseline.write_bytes(b'owned baseline sentinel\n')
            env = dict(os.environ, PROWL_HOME=str(home))

            def run(args):
                return subprocess.run([str(binary), *args], cwd=work, env=env,
                                      input=b'', capture_output=True, timeout=30)

            accepted = case in ('unsigned', 'valid', 'spaces')
            label = kind + '/' + case
            for command in ('list', 'validate'):
                result = run([kind, command])
                check(label + '/' + command, (result.returncode == 0) == accepted)
            for explicit in (False, True):
                selected = []
                if explicit:
                    selected = ['--rules-dir' if kind == 'rules' else '--verifiers', str(library)]
                args = ['scan', str(fixture), '--format=json', '--silence', *selected]
                if not accepted:
                    args.append('--write-baseline=' + str(baseline))
                if kind == 'verifiers':
                    args.append('--verify')
                result = run(args)
                mode = label + ('/explicit' if explicit else '/installed')
                check(mode + '/exit', result.returncode == (0 if accepted else 2))
                if accepted:
                    data = json.loads(result.stdout)
                    check(mode + '/complete', data['complete'] and not data['findings'])
                else:
                    check(mode + '/baseline-protected', baseline.read_bytes() == b'owned baseline sentinel\n')
            # Explicit bundled selection must disregard damaged installed libraries.
            result = run(['scan', str(fixture), '--bundled', '--verify', '--format=json', '--silence'])
            check(label + '/bundled', result.returncode == 0 and json.loads(result.stdout)['complete'])
    report = {'passed': sum(c['passed'] for c in checks), 'total': len(checks),
              'checks': checks, 'root': str(root), 'binary': str(binary),
              'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'scope': 'local CLI template selection and integrity; no provider acceptance'}
    (root / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
