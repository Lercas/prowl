#!/usr/bin/env python3
"""Qualify local Docker action images; retain named containers and synthetic fixtures."""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--action', action='append', required=True, help='Root/tool action image, repeatable')
    parser.add_argument('--cli', required=True, help='Normal nonroot CLI image')
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix='prowl-action-native-'))
    # The action must be able to traverse the host-owned synthetic workspace.
    root.chmod(0o755)
    checks, containers, images = [], [], {}
    value = 'AKIANAFGYOEYPXU1DSYP'
    def check(name, passed):
        checks.append({'case': name, 'passed': bool(passed)})
        if not passed:
            raise AssertionError(name)
    def call(argv, **kwargs):
        return subprocess.run(argv, capture_output=True, text=True, timeout=90, **kwargs)
    # Evaluate the shipped argument list with the documented action inputs.
    # Refuse unsupported syntax rather than silently testing a different invocation.
    action_args = []
    repo = Path(__file__).resolve().parent.parent
    for descriptor in (repo / 'action.yml', repo / 'tool/action.yml'):
        content = descriptor.read_text()
        lines = content.split('  args:', 1)[1].splitlines()
        argv = []
        for line in lines:
            if not line.strip():
                continue
            if not line.startswith('    - '):
                raise AssertionError('unsupported action argument syntax')
            token = line[6:].strip().strip("'\"")
            for key, input_value in {'path': '.', 'format': 'sarif', 'fail-on': 'high', 'output': 'report.sarif'}.items():
                token = token.replace('${{ inputs.' + key + ' }}', input_value)
            if '${{' in token:
                raise AssertionError('unresolved action expression')
            argv.append(token)
        check(str(descriptor.relative_to(repo)) + '/fixed-safety-flags', all(flag in argv for flag in ('--strict', '--bundled', '--reconstruct')))
        check(str(descriptor.relative_to(repo)) + '/literal-path', argv[-2:] == ['--', '.'])
        action_args.append(argv)
    counter = 0
    def run(image, workspace, argv, *, user=None, entrypoint=None):
        nonlocal counter
        counter += 1
        name = root.name + '-' + str(counter)
        containers.append(name)
        cmd = ['docker', 'run', '--name', name, '--network', 'none']
        if user is not None:
            cmd += ['--user', user]
        if entrypoint:
            cmd += ['--entrypoint', entrypoint]
        mount = '/github/workspace' if image in args.action else '/src'
        cmd += ['-v', str(workspace) + ':' + mount, '-w', mount, image, *argv]
        result = call(cmd)
        (root / (name + '.stdout')).write_text(result.stdout)
        (root / (name + '.stderr')).write_text(result.stderr)
        return result
    def workspace(name):
        w = root / name
        w.mkdir(mode=0o755)
        return w
    try:
        for image in [*args.action, args.cli]:
            inspected = call(['docker', 'image', 'inspect', image])
            check(image + '/inspect', inspected.returncode == 0)
            meta = json.loads(inspected.stdout)[0]
            images[image] = {'id': meta['Id'], 'architecture': meta['Architecture'], 'user': meta['Config'].get('User', ''), 'entrypoint': meta['Config']['Entrypoint']}
            w = workspace('selftest-' + str(counter))
            result = run(image, w, ['selftest', '--ml'])
            data = json.loads(result.stdout)
            check(image + '/static-ml', result.returncode == 0 and data['passed'] and not data['network'] and len(data['cases']) == 7 and all(c['complete'] for c in data['cases']))
        check('cli-nonroot-default', images[args.cli]['user'] == '65532:65532')
        for index, image in enumerate(args.action):
            for user in (None, str(os.getuid()) + ':' + str(os.getgid())):
                prefix = str(index) + '-' + ('default' if user is None else 'explicit')
                w = workspace(prefix)
                (w / 'production.env').write_text('aws_access_key_id="' + value + '"\n')
                result = run(image, w, action_args[index % len(action_args)], user=user)
                check(prefix + '/gate', result.returncode == 1)
                report = w / 'report.sarif'
                info = report.stat()
                check(prefix + '/owner-private', info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600)
                text = report.read_text()
                data = json.loads(text)
                check(prefix + '/sarif-redacted', data['version'] == '2.1.0' and data['runs'][0]['properties']['complete'] and bool(data['runs'][0]['results']) and value not in text)
            w = workspace(str(index) + '-literal-path')
            (w / '--show-secrets').write_text('aws_access_key_id="' + value + '"\n')
            literal_args = list(action_args[index % len(action_args)])
            literal_args[-1] = '--show-secrets'
            result = run(image, w, literal_args)
            report = w / 'report.sarif'
            check(str(index) + '/literal-path-gate', result.returncode == 1 and report.is_file())
            text = report.read_text()
            data = json.loads(text)
            check(str(index) + '/literal-path-redacted', value not in text and data['runs'][0]['properties']['complete'] and len(data['runs'][0]['results']) == 1)
            check(str(index) + '/literal-path-private', report.stat().st_uid == os.getuid() and stat.S_IMODE(report.stat().st_mode) == 0o600)
            w = workspace(str(index) + '-reconstruct')
            (w / 'app.js').write_text("const head='AKIA';\nconst key=head+'NAFGYOEYPXU1DSYP';")
            result = run(image, w, ['scan', '.', '--strict', '--bundled', '--reconstruct', '--format=json', '--fail-on=high'])
            data = json.loads(result.stdout)
            check(str(index) + '/reconstruction', result.returncode == 1 and data['complete'] and any(f['stage'].startswith('reconstructed/') for f in data['findings']) and value not in result.stdout)
            w = workspace(str(index) + '-incomplete')
            (w / 'broken.json').write_text('{"a":')
            (w / 'baseline.json').write_text('owned baseline sentinel')
            result = run(image, w, ['scan', 'broken.json', '--strict', '--bundled', '--format=json', '--write-baseline=baseline.json'])
            data = json.loads(result.stdout)
            check(str(index) + '/incomplete-baseline', result.returncode == 2 and not data['complete'] and (w / 'baseline.json').read_text() == 'owned baseline sentinel')
        for index, image in enumerate([*args.action, args.cli]):
            w = workspace('git-' + str(index))
            check(str(index) + '/host-init', call(['git', 'init', '-q', str(w)]).returncode == 0)
            (w / 'staged.env').write_text('aws_access_key_id="' + value + '"\n')
            check(str(index) + '/host-stage', call(['git', '-C', str(w), 'add', 'staged.env']).returncode == 0)
            # Only the Git index has the secret; the working file is now clean.
            (w / 'staged.env').write_text('public_number=42\n')
            user = None if image in args.action else str(os.getuid()) + ':' + str(os.getgid())
            result = run(image, w, ['scan', '--staged', '--strict', '--bundled', '--format=json', '--fail-on=high'], user=user)
            data = json.loads(result.stdout)
            check(str(index) + '/git-index', result.returncode == 1 and data['complete'] and any(f['type'] == 'aws_access_key_id' for f in data['findings']) and value not in result.stdout)
            committed = call(['git', '-C', str(w), '-c', 'core.hooksPath=/dev/null', '-c', 'user.name=Prowl QA', '-c', 'user.email=qa@invalid', 'commit', '-qm', 'owned synthetic history fixture'])
            check(str(index) + '/host-commit', committed.returncode == 0)
            result = run(image, w, ['scan', '--history', '--strict', '--bundled', '--ml', '--format=json', '--fail-on=high'], user=user)
            data = json.loads(result.stdout)
            check(str(index) + '/git-history-ml', result.returncode == 1 and data['complete'] and any(f['type'] == 'aws_access_key_id' for f in data['findings']) and value not in result.stdout)
    finally:
        result = {'passed': sum(c['passed'] for c in checks), 'total': len(checks), 'checks': checks, 'images': images, 'root': str(root), 'containers_retained': containers, 'scope': 'local Docker linux runtime, synthetic files and host-created Git index, no network/provider requests'}
        (root / 'qualification.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({k: v for k, v in result.items() if k not in ('checks', 'containers_retained')}))


if __name__ == '__main__':
    main()
