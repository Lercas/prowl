#!/usr/bin/env python3
"""Record a live interactive bash PTY as an asciicast, without editing its output."""
import argparse
import codecs
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import shutil
import struct
import subprocess
import tempfile
import termios
import time
import zlib
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    out = args.out.resolve()
    work = Path(tempfile.mkdtemp(prefix='prowl-terminal-'))
    (work / 'bin').mkdir()
    shutil.copy2(args.binary, work / 'bin/prowl')
    for name in ('config', 'logs', 'artifacts'):
        (work / 'checkout' / name).mkdir(parents=True)
    body = 'kP9aZ2bYwcX4dWqeV8fUmgThS6iRnjQ7'[:30]
    checksum, value = '', zlib.crc32(body.encode())
    alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    while value:
        checksum = alphabet[value % 62] + checksum
        value //= 62
    token = 'ghp_' + body + checksum.zfill(6)
    (work / 'checkout/config/app.env').write_text(
        'AWS_ACCESS_KEY_ID=AKIANAFGYOEYPXU1DSYP\n'
        'DATABASE_URL=postgres://admin:Pr0dPass99@db.internal:5432/prod\n')
    (work / 'checkout/logs/build.log').write_text(
        '[build] preparing checkout\n[debug] GITHUB_TOKEN=' + token + '\n[build] done\n')
    with zipfile.ZipFile(work / 'checkout/artifacts/release.zip', 'x') as z:
        z.writestr('deploy.env', 'DATABASE_URL=postgres://admin:Pr0dPass99@db.internal:5432/prod\n')
    (work / 'fix-demo.py').write_text(
        'from pathlib import Path\nimport zipfile\n'
        'Path("checkout/config/app.env").write_text("AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}\\nDATABASE_URL=${DATABASE_URL}\\n")\n'
        'Path("checkout/logs/build.log").write_text("[build] preparing checkout\\n[build] done\\n")\n'
        'with zipfile.ZipFile("checkout/artifacts/release.zip", "w") as z:\n'
        '    z.writestr("deploy.env", "DATABASE_URL=${DATABASE_URL}\\n")\n'
    )
    env = {**os.environ, 'PATH': str(work / 'bin') + ':' + os.environ['PATH'],
           'PROWL_HOME': str(work / 'home'), 'TERM': 'xterm-256color',
           'PS1': '\\[\\e[1;36m\\]demo ~/release $ \\[\\e[0m\\]',
           'HISTFILE': '/dev/null', 'LC_ALL': 'en_US.UTF-8', 'BASH_SILENCE_DEPRECATION_WARNING': '1'}
    env.pop('NO_COLOR', None)
    env.pop('PROMPT_COMMAND', None)
    start = time.monotonic()
    decoder = codecs.getincrementaldecoder('utf-8')('replace')
    recorded = []
    cast = (out / 'terminal.cast').open('x')
    cast.write(json.dumps({'version': 2, 'width': 110, 'height': 28,
                           'timestamp': int(time.time()), 'env': {'TERM': env['TERM'], 'SHELL': '/bin/bash'}}) + '\n')
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(work)
        os.execve('/bin/bash', ['bash', '--noprofile', '--norc', '-i'], env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', 28, 110, 0, 0))

    def drain(seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            ready, _, _ = select.select([fd], [], [], min(.03, max(0, end-time.monotonic())))
            if ready:
                try:
                    data = os.read(fd, 65536)
                except OSError:
                    return
                if not data:
                    return
                value = decoder.decode(data)
                if value:
                    recorded.append(value)
                    cast.write(json.dumps([round(time.monotonic()-start, 6), 'o', value], ensure_ascii=False)+'\n')
                    cast.flush()

    def command(text, pause):
        for char in text:
            os.write(fd, char.encode())
            drain(.035)
        drain(.25)
        os.write(fd, b'\r')
        drain(pause)

    drain(.8)
    steps = [
        ('find checkout -type f', 3),
        ('cat checkout/config/app.env checkout/logs/build.log', 5),
        ('clear', .2),
        ('prowl scan checkout', 9),
        ('clear', .2),
        ('prowl scan checkout --format json > findings.json', 1),
        ("python3 -c 'import json; print(json.dumps(json.load(open(\"findings.json\"))[\"findings\"][-1], indent=2))'", 7),
        ('clear', .2),
        ('prowl scan checkout --fail-on high', 4),
        ('echo $?', 4),
        ('clear', .2),
        ('python3 fix-demo.py', 2),
        ('cat checkout/config/app.env', 3),
        ('prowl scan checkout --fail-on high', 2),
        ('echo $?', 4),
    ]
    for text, pause in steps:
        command(text, pause)
    duration = time.monotonic() - start
    os.write(fd, b'exit\r')
    drain(.3)
    os.waitpid(pid, 0)
    os.close(fd)
    cast.close()
    full = ''.join(recorded)
    assert '4 findings' in full and 'no secrets found' in full, full
    assert 'echo $?\r\n1\r\n' in full and 'echo $?\r\n0\r\n' in full, full
    report = json.loads((work/'findings.json').read_text())
    assert report['count'] == 4 and not report['truncated']
    assert any('release.zip!' in f['path'] for f in report['findings'])
    (out/'findings.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n')
    (out/'recording.json').write_text(json.dumps({
        'duration': round(duration, 2), 'workspace': str(work),
        'binary_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        'method': 'Live bash PTY, unmodified timestamped output; agg terminal renderer, MP4 encoding.',
        'commands': [x[0] for x in steps],
    }, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps({'out': str(out), 'duration': duration, 'workspace': str(work)}))


if __name__ == '__main__':
    main()
