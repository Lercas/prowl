#!/usr/bin/env python3
"""Check real CLI coverage messages on pipes, report files and an actual terminal."""
import argparse
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import struct
import subprocess
import tempfile
import termios
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='prowl-pretty-coverage-'))
    env = {k: v for k, v in os.environ.items() if not k.startswith('PROWL_')}
    env.update(PROWL_HOME=str(root / 'home'), PROWL_LIVE_TEST='', NO_COLOR='1')
    key = 'AKIANAFGYOEYPXU1DSYP'
    empty = root / 'empty'
    empty.mkdir()
    clean = root / 'clean.env'
    clean.write_text('ordinary public configuration\n')
    secret = root / 'production.env'
    secret.write_text('credential="' + key + '"\n')
    allowed = root / 'allowed.env'
    allowed.write_text('credential="' + key + '" # prowl:allow\n')
    large = root / 'large.env'
    large.write_text('x' * 64)
    malformed = root / 'broken.json'
    malformed.write_text('{"password":"owned-fixture"')
    baseline = root / 'baseline.json'
    prep = subprocess.run([str(binary), 'scan', str(secret), '--bundled', '--quiet',
                           '--format=json', '--write-baseline', str(baseline)],
                          cwd=root, env=env, capture_output=True, timeout=30)
    assert prep.returncode == 0 and baseline.is_file()
    cases = [
        ('empty', [str(empty)], 0, 'no objects to scan', False),
        ('clean', [str(clean)], 0, '✓ no secrets found', True),
        ('pragma', [str(allowed)], 0, 'no findings after filters and suppressions', False),
        ('disabled', [str(secret), '--disable=aws_access_key_id'], 0, 'no findings after filters and suppressions', False),
        ('confidence', [str(secret), '--min-confidence=1'], 0, 'no findings after filters and suppressions', False),
        ('baseline', [str(secret), '--baseline', str(baseline)], 0, 'no findings after filters and suppressions', False),
        ('missing', [str(root / 'missing.env')], 2, 'scan incomplete', False),
        ('oversize', [str(large), '--max-size=4'], 2, 'max_size:', False),
        ('malformed', [str(malformed)], 2, 'scan incomplete', False),
        ('candidate', [str(secret)], 0, 'Candidates without a provider verdict are unconfirmed.', False),
    ]
    checks = []
    for mode in ('pipe', 'file', 'pty'):
        for name, args, expected_exit, expected_text, clean_banner in cases:
            command = [str(binary), 'scan', *args, '--bundled', '--quiet', '--no-color', '--format=pretty']
            path = root / (mode + '-' + name + '.log')
            if mode == 'file':
                command += ['--output', str(path)]
            if mode != 'pty':
                result = subprocess.run(command, cwd=root, env=env, capture_output=True, timeout=30)
                status = result.returncode
                body = path.read_bytes() if mode == 'file' else result.stdout
                assert key.encode() not in result.stderr
            else:
                master, slave = pty.openpty()
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 32, 100, 0, 0))
                process = subprocess.Popen(command, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                           stdout=slave, stderr=slave)
                os.close(slave)
                body = bytearray()
                deadline = time.monotonic() + 30
                try:
                    while True:
                        assert time.monotonic() < deadline, (mode, name, 'timeout')
                        if not select.select([master], [], [], .1)[0]:
                            continue
                        try:
                            chunk = os.read(master, 65536)
                        except OSError as error:
                            if error.errno == errno.EIO:
                                break
                            raise
                        if not chunk:
                            break
                        body.extend(chunk)
                    status = process.wait(timeout=5)
                finally:
                    os.close(master)
                    if process.poll() is None:
                        process.kill()
                        process.wait()
                body = bytes(body)
            text = body.decode().replace('\r\n', '\n')
            assert status == expected_exit, (mode, name, status)
            assert expected_text in text, (mode, name, 'missing state')
            assert ('✓ no secrets found' in text) == clean_banner, (mode, name, 'false clean state')
            assert key not in text and '\x1b' not in text, (mode, name, 'disclosure or terminal escape')
            if mode != 'file':
                path.write_bytes(body)
            checks.append({'mode': mode, 'case': name, 'exit': status,
                           'sha256': hashlib.sha256(body).hexdigest(), 'path': str(path)})
    report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'passed': len(checks), 'checks': checks,
              'scope': 'Local CLI, real PTY at 100 columns, quiet/no-color; caller records the network boundary.'}
    output = root / 'qualification.json'
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': len(checks), 'evidence': str(output)}))


if __name__ == '__main__':
    main()
