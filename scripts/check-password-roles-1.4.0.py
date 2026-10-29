"""Отдельный воспроизводимый корпус password/UI/provider roles; только собственные данные."""
import argparse
import json
import random
import string
import subprocess
import sys
from pathlib import Path


def corpus():
    rng = random.Random(2602101409)
    rows = []

    def add(name, suffix, text, value=None, typ='generic_password'):
        rows.append({'name': name, 'path': 'production.' + suffix, 'text': text,
                     'truth': 'positive' if value else 'negative', 'value': value or '',
                     'types': [typ] if value else []})

    def encode(suffix, namespace, key, value):
        if suffix in ('json', 'yaml'):
            data = {namespace: {key: value}} if namespace else {key: value}
            return json.dumps(data, ensure_ascii=False)
        header = f'[{namespace}]\n' if namespace else ''
        return header + json.dumps(key, ensure_ascii=False) + '=' + json.dumps(value, ensure_ascii=False)

    for index in range(16):
        word = ''.join(rng.choices(string.ascii_letters, k=4))
        name = 'service_' * 45 + ('пароль' if index % 2 else 'password')
        for suffix in ('json', 'yaml', 'toml'):
            for n, value in enumerate(('Ab1234567' + word, 'p0000000!' + word, 'Winter42!' + word)):
                add(f'{index}_{suffix}_long_{n}', suffix, encode(suffix, '', name, value), value)
                add(f'{index}_{suffix}_weak_{n}', suffix, encode(suffix, '', 'password', value), value)
                add(f'{index}_{suffix}_ui_real_{n}', suffix, encode(suffix, 'labels', 'password', value), value)
            for n, value in enumerate(('Password', 'Пароль', 'Password is required', 'Confirm password')):
                add(f'{index}_{suffix}_label_{n}', suffix, encode(suffix, 'labels', 'password', value))
            add(f'{index}_{suffix}_config_label_word', suffix, encode(suffix, 'auth', 'password', 'Password'), 'Password')
            add(f'{index}_{suffix}_config_required', suffix, encode(suffix, 'auth', 'password', 'required'), 'required')
            for provider, length, typ in (('assemblyai', 32, 'assemblyai-api-key'), ('together', 64, 'together-api-key')):
                value = ''.join(rng.choices('0123456789abcdef', k=length))
                add(f'{index}_{suffix}_{provider}', suffix, encode(suffix, provider, 'api_key', value), value, typ)
                add(f'{index}_{suffix}_{provider}_metadata', suffix, encode(suffix, provider, 'checksum', value))
            for n, value in enumerate(('${PASSWORD}', '{{PASSWORD}}', '<PASSWORD>', 'example')):
                add(f'{index}_{suffix}_placeholder_{n}', suffix, encode(suffix, '', 'password', value))
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--baseline-binary', type=Path)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    root = args.output_dir.resolve()
    root.mkdir(parents=True, exist_ok=False)
    fixture = root / 'truth.json'
    fixture.write_text(json.dumps(corpus(), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    command = [sys.executable, str(Path(__file__).with_name('check-noise-1.4.0.py')),
               '--binary', str(args.binary.resolve()), '--fixture', str(fixture),
               '--output-dir', str(root / 'runs')]
    if args.baseline_binary:
        command += ['--baseline-binary', str(args.baseline_binary.resolve())]
    subprocess.run(command, check=True)


if __name__ == '__main__':
    main()
