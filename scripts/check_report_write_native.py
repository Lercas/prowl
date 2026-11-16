#!/usr/bin/env python3
"""Check unchanged successful report bytes and native CLI output-failure behavior offline."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('before', type=Path)
    parser.add_argument('candidate', type=Path)
    args = parser.parse_args()
    binaries = {'before': args.before.resolve(strict=True), 'candidate': args.candidate.resolve(strict=True)}
    with socket.socket() as probe:
        try:
            probe.bind(('127.0.0.1', 0))
        except PermissionError:
            pass
        else:
            raise RuntimeError('OS network deny is required')
    root = Path(tempfile.mkdtemp(prefix='prowl-report-write-native-'))
    (root / 'home').mkdir()
    fixtures = {'clean.txt': 'ordinary source text\n',
                'production.env': 'AWS=AKIANAFGYOEYPXU1DSYP\n',
                'malformed.json': '{"password":"broken\\q"}'}
    for name, content in fixtures.items():
        (root / name).write_text(content)
    env = {k: v for k, v in os.environ.items() if not k.startswith('PROWL_')}
    env.update(PROWL_HOME=str(root / 'home'), PROWL_LIVE_TEST='', NO_COLOR='1')
    subprocess.run([str(binaries['candidate']), 'identity', 'init'], cwd=root, env=env,
                   capture_output=True, check=True, timeout=10)
    checks, outputs = [], {}

    def check(name, condition):
        if not condition:
            raise AssertionError(name)
        checks.append({'case': name, 'passed': True})

    for fmt in ('pretty', 'json', 'sarif', 'defectdojo', 'dojo'):
        for source in fixtures:
            for label, binary in binaries.items():
                name = label + '-' + fmt + '-' + source
                output = root / (name + '.report')
                result = subprocess.run([str(binary), 'scan', source, '--bundled', '--format=' + fmt,
                                         '--silence', '--output=' + str(output)], cwd=root, env=env,
                                        capture_output=True, timeout=20)
                (root / (name + '.stderr')).write_bytes(result.stderr)
                raw = output.read_bytes()
                outputs[label, fmt, source] = hashlib.sha256(raw).hexdigest()
                check(name + '-status', result.returncode == (2 if source == 'malformed.json' else 0) and raw and not result.stdout)
                check(name + '-private', stat.S_IMODE(output.stat().st_mode) == 0o600)
                check(name + '-privacy', b'AKIANAFGYOEYPXU1DSYP' not in raw + result.stdout + result.stderr)
            check(fmt + '-' + source + '-byte-equivalence', outputs['before', fmt, source] == outputs['candidate', fmt, source])
        for label, binary in binaries.items():
            name = label + '-' + fmt
            read_fd, write_fd = os.pipe()
            os.close(read_fd)
            try:
                result = subprocess.run([str(binary), 'scan', 'production.env', '--bundled', '--format=' + fmt,
                                         '--quiet', '--no-color'], cwd=root, env=env, stdin=subprocess.DEVNULL,
                                        stdout=write_fd, stderr=subprocess.PIPE, timeout=20)
            finally:
                os.close(write_fd)
            check(name + '-broken-pipe', result.returncode != 0)
            check(name + '-pipe-privacy', b'AKIANAFGYOEYPXU1DSYP' not in result.stderr)
            blocked = root / (name + '-directory-output')
            blocked.mkdir()
            result = subprocess.run([str(binary), 'scan', 'production.env', '--bundled', '--format=' + fmt,
                                     '--silence', '--output=' + str(blocked)], cwd=root, env=env,
                                    capture_output=True, timeout=20)
            check(name + '-output-refusal', result.returncode == 2 and not list(blocked.iterdir()))
    record = {'binaries': {k: {'path': str(v), 'sha256': hashlib.sha256(v.read_bytes()).hexdigest()} for k, v in binaries.items()},
              'passed': True, 'checks': checks, 'network': 'OS denies all network',
              'boundary': 'Native CLI checks actual broken stdout and nonregular destinations. The short-count-with-nil-error regression is exercised by Go io.Writer tests, not by an OS file claim.'}
    output = root / 'evidence.json'
    output.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'passed': len(checks), 'evidence': str(output)}))


if __name__ == '__main__':
    main()
