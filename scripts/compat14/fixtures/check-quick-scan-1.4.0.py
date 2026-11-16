"""Проверка первого запуска на собственных локальных входах; без сетевых сканов."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    root = args.output_dir.resolve()
    root.mkdir(parents=True, exist_ok=False)
    fixtures = root / 'fixtures'
    fixtures.mkdir()
    value = '83ea947bc2567d10a5f390c2eb468d91'
    content = json.dumps({'assemblyai': {'api_key': value}})
    plain = 'assemblyai_api_key=' + value
    (fixtures / 'production.json').write_text(content)
    env = {**os.environ, 'PROWL_HOME': str(root / 'empty-home'), 'NO_COLOR': '1'}
    checks = []

    def run(case, argv, *, code=0, input_text=None, json_output=False, contains=None, cwd=fixtures):
        options = {'input': input_text} if input_text is not None else {'stdin': subprocess.DEVNULL}
        proc = subprocess.run([str(binary), *argv], cwd=cwd, env=env, capture_output=True,
                              text=True, timeout=20, **options)
        (root / f'{case}.stdout').write_text(proc.stdout)
        (root / f'{case}.stderr').write_text(proc.stderr)
        assert proc.returncode == code, (case, proc.returncode, code)
        assert value not in proc.stdout and value not in proc.stderr, (case, 'unredacted value')
        if contains:
            assert contains in proc.stdout + proc.stderr, (case, contains)
        report = json.loads(proc.stdout) if json_output else None
        checks.append({'case': case, 'passed': True, 'exit_code': proc.returncode})
        return report

    run('bare_current_directory', [], contains='assemblyai-api-key')
    run('bare_stdin', [], input_text=plain, contains='assemblyai-api-key')
    baseline = run('explicit_scan', ['scan', 'production.json', '--format', 'json'], json_output=True)
    for case, argv, input_text in [
        ('bare_relative_file', ['production.json', '--format', 'json'], None),
        ('bare_absolute_file', [str(fixtures / 'production.json'), '--format', 'json'], None),
        ('bare_directory', ['./', '--format', 'json'], None),
        ('leading_flags', ['--format=json', 'production.json'], None),
        ('explicit_stdin', ['-', '--format', 'json'], plain),
        ('implicit_stdin', ['--format', 'json'], plain),
        ('named_json_stdin', ['--stdin-name', 'config.json', '--format', 'json'], content),
        ('local_ml', ['production.json', '--ml', '--format', 'json'], None),
    ]:
        report = run(case, argv, input_text=input_text, json_output=True)
        assert report['complete'] and report['count'] == baseline['count'] == 1, case
        assert report['findings'][0]['type'] == 'assemblyai-api-key', case
        assert report['findings'][0].get('verified') is None, case
    run('ci_threshold', ['--ci', 'production.json'], code=1)
    run('ci_explicit_override_before', ['--fail-on', 'critical', '--ci', 'production.json'])
    run('ci_explicit_override_after', ['--ci', 'production.json', '--fail-on', 'critical'])
    partial = run('ci_incomplete', ['--ci', 'production.json', '--max-size', '1', '--format', 'json'],
                  code=2, json_output=True)
    assert not partial['complete'] and partial['stats']['skipped'] > 0
    run('partial_pretty', ['production.json', '--max-size', '1'], code=2, contains='max_size:')
    run('empty_stdin', ['-'], input_text='', contains='Нет объектов для проверки')
    run('quiet_json', ['production.json', '--quiet', '--format', 'json'], json_output=True)
    run('short_help', ['--help'], contains='БЫСТРЫЙ СТАРТ')
    run('full_help', ['help', 'all'], contains='domain flags:')
    run('scan_help', ['./', '--help'], contains='Базовый скан без настройки')
    run('compare_help', ['compare', '--help'], contains='prowl compare')
    run('named_stdin_rejected_for_remote_source', ['repo', '--stdin-name', 'config.json'], code=2,
        contains='supported only by the local scan command')
    run('unknown_command', ['scna'], code=2, contains="did you mean 'prowl scan'")
    run('unknown_flag', ['--formt', 'json'], code=2, contains="did you mean '--format'")
    run('missing_local_path', ['./missing'], code=2, contains='source_error')
    run('no_implicit_remote', ['https://example.invalid'], code=2, contains='unknown command')
    for flag in ['--verify', '--show-secrets', '--ocr', '--ml', '--ci', '--strict', '--bundled']:
        run('reject_false_' + flag[2:], [flag + '=false', 'production.json'], code=2,
            contains='does not accept a value')
    for flag in ['--output', '--config', '--rules', '--taxonomy', '--exclude']:
        run('missing_value_' + flag[2:], [flag], code=2, contains='expects a value')
    for name in ['--help', '--verify']:
        (fixtures / name).write_text(content)
        report = run('literal_path_' + name[2:], ['--format', 'json', '--', name], json_output=True)
        assert report['count'] == 1 and report['findings'][0].get('verified') is None
    (fixtures / 'scan').mkdir()
    (fixtures / 'scan' / 'input.json').write_text(content)
    run('command_named_directory', ['./scan'], contains='assemblyai-api-key')
    run('command_takes_priority', ['scan', '--help'], contains='Базовый скан без настройки')
    run('named_stdin_rejects_paths', ['--stdin-name', 'config.json', 'production.json'], code=2,
        contains='applies only to stdin')
    run('named_stdin_rejects_git', ['--stdin-name', 'config.json', '--staged'], code=2,
        contains='applies only to stdin')
    malformed = run('named_stdin_malformed_json', ['--stdin-name', 'config.json', '--ci', '--format', 'json'],
                    input_text=content[:-1], code=2, json_output=True)
    assert not malformed['complete']
    for suffix, text in [
        ('json', '{"assemblyai":{"api_key":"' + ''.join(f'\\u{ord(c):04x}' for c in value) + '"}}'),
        ('yaml', 'assemblyai:\n  api_key: ' + value + '\n'),
        ('toml', '[assemblyai]\napi_key="' + value + '"\n'),
    ]:
        report = run('structured_stdin_' + suffix, ['--stdin-name', 'config.' + suffix, '--format', 'json'],
                     input_text=text, json_output=True)
        assert report['complete'] and report['count'] == 1
        assert report['findings'][0]['type'] == 'assemblyai-api-key'
        assert report['findings'][0]['path'] == 'config.' + suffix
        assert 'stdin' in {scope['kind'] for scope in report['scope']}
    assert not (fixtures / 'config.json').exists(), 'stdin label created a file'
    config = root / 'config.yaml'
    config.write_text('version: 1\noutput: {format: json}\nperformance: {max_size: 1, workers: 2}\n')
    run('explicit_defaults_override_config', ['production.json', '--config', str(config),
        '--format', 'pretty', '--max-size', '10MB', '--workers', '0'], contains='assemblyai-api-key')
    config.write_text('version: 1\nallowlist:\n  values: [' + json.dumps(value) + ']\n')
    run('filtered_empty_report', ['production.json', '--config', str(config)],
        contains='Находок после фильтров и подавлений нет')
    baseline_file = root / 'baseline.json'
    run('create_baseline', ['production.json', '--write-baseline', str(baseline_file)])
    run('baseline_empty_report', ['production.json', '--baseline', str(baseline_file)],
        contains='Находок после фильтров и подавлений нет')
    assert 'findings=0' in (root / 'baseline_empty_report.stderr').read_text(), 'summary counted suppressed findings'
    run('severity_filtered_report', ['production.json', '--min-severity', 'critical'],
        contains='Находок после фильтров и подавлений нет')
    (root / 'evidence.json').write_text(json.dumps({
        'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
        'checks': checks, 'passed': len(checks), 'network_targets': [],
    }, ensure_ascii=False, indent=2) + '\n')
    print(f'PASS: {len(checks)} quick-scan checks')


if __name__ == '__main__':
    main()
