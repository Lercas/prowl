#!/usr/bin/env python3
"""Compare released local CLI contracts with a candidate under OS network denial."""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reference', type=Path)
    parser.add_argument('candidate', type=Path)
    args = parser.parse_args()
    if not Path('/usr/bin/sandbox-exec').is_file():
        parser.error('this local qualification requires macOS sandbox-exec')
    binaries = {'reference': args.reference.resolve(strict=True), 'candidate': args.candidate.resolve(strict=True)}
    root = Path(tempfile.mkdtemp(prefix='prowl-cli-upgrade-native-'))
    profile = '(version 1)(allow default)(deny network*)'
    sandbox = ['/usr/bin/sandbox-exec', '-p', profile]
    # Distinguish an enforced boundary from a test that never attempted a connection.
    class Handler(http.server.BaseHTTPRequestHandler):
        calls = 0
        def do_GET(self):
            Handler.calls += 1
            self.send_response(200)
            self.end_headers()
        def log_message(self, *_):
            pass
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f'http://127.0.0.1:{server.server_port}/owned'
    assert subprocess.run(['/usr/bin/curl', '--silent', '--max-time', '2', url], capture_output=True).returncode == 0
    blocked = subprocess.run([*sandbox, '/usr/bin/curl', '--silent', '--max-time', '2', url], capture_output=True)
    assert blocked.returncode != 0 and Handler.calls == 1
    server.shutdown()
    server.server_close()
    thread.join()
    checks = []
    literal_positions = {}
    value = "q7Vx9mK2'Cabin!R5"
    documents = {
        'prod.json': json.dumps({'note': '🚀', 'password': value}, ensure_ascii=False),
        'prod.yaml': "note: 🚀\npassword: '" + value.replace("'", "''") + "'\n",
        'prod.toml': "note='🚀'\npassword=\"" + value + "\"\n",
    }
    work = {}
    for label in binaries:
        directory = root / label
        directory.mkdir()
        work[label] = directory
        for name, text in documents.items():
            (directory / name).write_text(text)
        for name in ('clean.txt', '--help', 'scan'):
            (directory / name).write_text('ordinary source text')
        (directory / 'production.env').write_text('AWS_ACCESS_KEY_ID=AKIANAFGYOEYPXU1DSYP\n')
        (directory / 'malformed.json').write_text('{"password":"q7Vx9mK2\\q"}')
        (directory / 'large.txt').write_text('x' * 256)
        (directory / 'operator.yaml').write_text('version: 1\noutput: {format: json, fail_on: low}\nperformance: {max_size: 1, workers: 2}\n')

    def run(label, argv, data='', cwd=None, terminal=False):
        env = {k: v for k, v in os.environ.items() if not k.startswith('PROWL_')}
        env.update(PROWL_HOME=str(root / (label + '-home')), PROWL_LIVE_TEST='')
        command = [*sandbox, str(binaries[label]), *argv]
        if not terminal:
            result = subprocess.run(command, cwd=cwd or work[label], env=env,
                                    input=data, text=isinstance(data, str), capture_output=True, timeout=20)
            if isinstance(result.stdout, bytes):
                result.stdout = result.stdout.decode('utf-8')
                result.stderr = result.stderr.decode('utf-8')
            return result
        master, slave = os.openpty()
        try:
            return subprocess.run(command, cwd=cwd or work[label], env=env, stdin=slave,
                                  text=True, capture_output=True, timeout=20)
        finally:
            os.close(slave)
            os.close(master)

    def check(name, label, process, passed, contract='shared'):
        checks.append({'case': name, 'binary': label, 'passed': bool(passed), 'exit': process.returncode,
                       'contract': contract,
                       'stdout_sha256': hashlib.sha256(process.stdout.encode()).hexdigest(),
                       'stderr_sha256': hashlib.sha256(process.stderr.encode()).hexdigest()})

    def envelope(process):
        try:
            return json.loads(process.stdout)
        except ValueError:
            return {}

    for label in binaries:
        # Original physical/logical value behavior, with no ML/provider stage.
        for name, text in documents.items():
            for mode in ('file', 'stdin-inline', 'stdin-separate', 'stdin-dash'):
                source = [name] if mode == 'file' else (['--stdin-name', name, '-'] if mode == 'stdin-dash' else
                         ['--stdin-name=' + name] if mode == 'stdin-inline' else ['--stdin-name', name])
                for quick in (False, True):
                    p = run(label, ([] if quick else ['scan']) + source + ['--format=json'], text if mode != 'file' else '')
                    report = envelope(p)
                    found = [f for f in report.get('findings', []) if f.get('type') == 'generic_password']
                    ok = p.returncode == 0 and report.get('complete') is True and len(found) == 1
                    if ok:
                        ok = found[0]['path'] == name and found[0]['line'] >= 1 and found[0]['col'] >= 1 and value not in p.stdout
                        signature = {k: found[0].get(k) for k in ('type', 'path', 'line', 'col', 'utf16_col', 'redacted')}
                        key = f'{name}/{mode}/quick={quick}'
                        if label == 'reference':
                            literal_positions[key] = signature
                        else:
                            ok = ok and literal_positions.get(key) == signature
                    check(f'literal/{name}/{mode}/quick={quick}', label, p, ok)

        for encoding, bom in (('utf-16-le', b'\xff\xfe'), ('utf-16-be', b'\xfe\xff')):
            data = bom + documents['prod.json'].encode(encoding)
            name = encoding + '.json'
            (work[label] / name).write_bytes(data)
            for stdin in (False, True):
                source = ['--stdin-name', name] if stdin else [name]
                p = run(label, ['scan', *source, '--format=json'], data if stdin else '')
                d = envelope(p)
                found = [f for f in d.get('findings', []) if f.get('type') == 'generic_password']
                check(f'utf16/{encoding}/stdin={stdin}', label, p,
                      p.returncode == 0 and d.get('complete') is True and len(found) == 1 and found[0]['path'] == name and value not in p.stdout)

        label_path = 'unopened/nested/prod.json'
        p = run(label, ['scan', '--stdin-name', label_path, '--format=json'], documents['prod.json'])
        d = envelope(p)
        found = [f for f in d.get('findings', []) if f.get('type') == 'generic_password']
        check('logical-label-never-opened-or-created', label, p,
              p.returncode == 0 and d.get('complete') is True and len(found) == 1 and found[0]['path'] == label_path and not (work[label] / 'unopened').exists())

        for argv in (['scan', 'clean.txt'], ['clean.txt'], ['--', '--help'], ['scan', '--', '--help']):
            p = run(label, [*argv, '--format=json'] if '--' not in argv else ['--format=json', *argv] if argv[0] != 'scan' else ['scan', '--format=json', *argv[1:]])
            d = envelope(p)
            check('routing/' + '/'.join(argv), label, p, p.returncode == 0 and d.get('complete') is True and not d.get('findings'))
        # With piped data, no arguments select stdin rather than the current tree.
        for argv in ([], ['scan'], ['-'], ['scan', '-']):
            p = run(label, [*argv, '--format=json'], 'AWS_ACCESS_KEY_ID=AKIANAFGYOEYPXU1DSYP\n')
            check('piped/' + '/'.join(argv), label, p, p.returncode == 0 and envelope(p).get('count') == 1)
        for argv in (['--help'], ['--version'], ['scan', '--help']):
            p = run(label, argv)
            check('control/' + '/'.join(argv), label, p, p.returncode == 0 and bool(p.stdout))

        aws = run(label, ['scan', 'production.env', '--format=json'])
        aws_findings = envelope(aws).get('findings', [])
        assert aws.returncode == 0 and len(aws_findings) == 1
        redacted = aws_findings[0]['redacted']
        for argv in ([], ['scan']):
            p = run(label, argv, 'AWS_ACCESS_KEY_ID=AKIANAFGYOEYPXU1DSYP\n')
            check('actual-no-argument-pipe/' + '/'.join(argv), label, p,
                  p.returncode == 0 and redacted in p.stdout and 'AKIANAFGYOEYPXU1DSYP' not in p.stdout)
        tty_root = work[label] / 'terminal-cwd'
        tty_root.mkdir()
        (tty_root / 'only.env').write_text('AWS_ACCESS_KEY_ID=AKIANAFGYOEYPXU1DSYP\n')
        for argv in ([], ['scan'], ['--format=json'], ['scan', '--format=json']):
            p = run(label, argv, cwd=tty_root, terminal=True)
            ok = p.returncode == 0 and redacted in p.stdout and 'AKIANAFGYOEYPXU1DSYP' not in p.stdout
            if '--format=json' in argv:
                ok = ok and envelope(p).get('count') == 1 and envelope(p).get('complete') is True
            check('terminal-cwd/' + '/'.join(argv), label, p, ok)

        ci_modes = [([], 0), (['--ci'], 1), (['--ci', '--fail-on=critical'], 0),
                    (['--fail-on=critical', '--ci'], 0), (['--ci=false'], 0),
                    (['--ci', '--ci=false'], 0), (['--ci=false', '--ci'], 1)]
        for flags, expected in ci_modes:
            for quick in (False, True):
                p = run(label, ([] if quick else ['scan']) + ['production.env', '--format=json', *flags])
                extension = any(f == '--ci=false' for f in flags)
                ok = p.returncode == expected and envelope(p).get('complete') is True and value not in p.stdout
                if extension and label == 'reference':
                    ok = p.returncode == 2 and '--ci' in p.stderr and not p.stdout
                check('ci/' + '/'.join(flags) + f'/quick={quick}', label, p,
                      ok, 'explicit-false-extension' if extension else 'shared')

        for flags in ([], ['--ci'], ['--ci=false'], ['--strict=false']):
            for name in ('malformed.json', 'large.txt'):
                baseline = work[label] / ('baseline-' + str(len(checks)) + '.json')
                baseline.write_text('["owned sentinel"]\n')
                extra = ['--max-size=16'] if name == 'large.txt' else []
                p = run(label, ['scan', name, '--format=json', '--write-baseline=' + str(baseline), *extra, *flags])
                extension = any(f.endswith('=false') for f in flags)
                ok = p.returncode == 2 and envelope(p).get('complete') is False and baseline.read_text() == '["owned sentinel"]\n'
                if extension and label == 'reference':
                    ok = p.returncode == 2 and flags[0].split('=')[0] in p.stderr and not p.stdout and baseline.read_text() == '["owned sentinel"]\n'
                check('incomplete/' + name + '/' + '/'.join(flags), label, p,
                      ok, 'explicit-false-extension' if extension else 'shared')

        for conflict in (['clean.txt'], ['--history'], ['--since=HEAD'], ['--staged'], ['-', 'clean.txt']):
            output = work[label] / ('owned-report-' + str(len(checks)) + '.json')
            output.write_text('owned report sentinel\n')
            p = run(label, ['scan', '--stdin-name=unopened/owned.json', *conflict,
                            '--config=missing-config.yaml', '--output=' + str(output)])
            check('stdin-conflict/' + '/'.join(conflict), label, p, p.returncode == 2 and
                  '--stdin-name' in p.stderr and output.read_text() == 'owned report sentinel\n' and not (work[label] / 'unopened').exists())

        for command in ('repo', 'org', 'domain', 'mobile', 'bucket', 'image', 'cicd', 'compare', 'serve', 'mcp'):
            p = run(label, [command, '--stdin-name=owned.json'])
            check('stdin-scope/' + command, label, p, p.returncode == 2 and '--stdin-name' in p.stderr)

        for argv in (['--stdin-name'], ['--stdin-name=']):
            p = run(label, ['scan', *argv])
            check('stdin-invalid/' + '/'.join(argv), label, p, p.returncode == 2 and '--stdin-name' in p.stderr)
        for flag in ('--ml', '--verify', '--verified-only', '--verify-all', '--semantic', '--reconstruct', '--show-secrets'):
            p = run(label, ['serve', flag])
            diagnostic = flag in p.stderr
            if label == 'reference':
                diagnostic = ('serve does not support live verification' in p.stderr if flag in ('--verify', '--verified-only', '--verify-all')
                              else 'serve supports L1 and rule templates with redacted output' in p.stderr)
            check('worker-scope/' + flag, label, p, p.returncode == 2 and diagnostic)

        # Explicit default-valued flags retain precedence over configuration.
        for flags, expected in [(['--max-size=10MB', '--fail-on=critical'], 0),
                                (['--max-size=10MB', '--ci'], 0),
                                (['--max-size=10MB', '--ci', '--fail-on=medium'], 1)]:
            p = run(label, ['scan', 'prod.json', '--config=operator.yaml', *flags])
            check('config/' + '/'.join(flags), label, p, p.returncode == expected and envelope(p).get('complete') is True)

    report = {'reference': {'path': str(binaries['reference']), 'sha256': hashlib.sha256(binaries['reference'].read_bytes()).hexdigest()},
              'candidate': {'path': str(binaries['candidate']), 'sha256': hashlib.sha256(binaries['candidate'].read_bytes()).hexdigest()},
              'passed': sum(c['passed'] for c in checks), 'total': len(checks), 'checks': checks, 'root': str(root),
              'literal_positions_and_redaction_identical': all(c['passed'] for c in checks if c['case'].startswith('literal/')),
              'network_control': {'profile': profile, 'owned_requests': 1, 'sandbox_requests': 0, 'blocked_exit': blocked.returncode},
              'scope': 'Released local routing including real terminal stdin versus pipe, named JSON/YAML/TOML file/stdin, CI precedence, incomplete baseline guards and stdin scope/preflight. Explicit false is a declared candidate extension: 1.4 rejects it, 1.5 accepts it without weakening incomplete failure. No ML, provider, remote-source or full-product compatibility claim.'}
    (root / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k not in ('checks',)}, ensure_ascii=False))
    for failure in (c for c in checks if not c['passed']):
        print(json.dumps(failure))
    return int(report['passed'] != report['total'])


if __name__ == '__main__':
    raise SystemExit(main())
