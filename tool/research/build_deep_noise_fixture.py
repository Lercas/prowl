"""Контроль пропусков литералов и заимствования контекста, только синтетические значения."""
import argparse
import random
import string
from pathlib import Path

from safe_fixture_json import fixture_json


def corpus():
    rows = []

    def add(name, path, text, truth, value=None, types=None):
        rows.append(dict(name=name, path=path, text=text, truth=truth,
                         value=value, types=types or [], ml_expected=True))

    for seed in (260210, 912741):
        rng = random.Random(seed)
        value = 'K' + ''.join(rng.choice(string.ascii_letters + string.digits) for _ in range(39))
        for index, password in enumerate(['string', 'number', 'boolean', 'my_password',
                                          'Winter/2026', 'undefined', 'prototype2026',
                                          'Winter===2026', 'ExampleRoad42', 'DummyCarrot42',
                                          'XxxxTulip2026', 'required', '314159', 'Winter42,Autumn',
                                          'K' + value * 3]):
            for ext, text in [('env', f'PASSWORD={password}'), ('yaml', f'password: {password}'),
                              ('py', f'password = "{password}"')]:
                add(f'{seed}_password_{index}_{ext}', f'config.{ext}', text + '\n',
                    'positive', password, ['generic_password'])
        for width in (32, 40, 56, 64, 96, 128):
            hextoken = ''.join(rng.choice('0123456789abcdef') for _ in range(width))
            for name in ('token', 'credential', 'private_key', 'api_key'):
                add(f'{seed}_hex_{width}_{name}', 'config.env', f'{name}={hextoken}\n',
                    'positive', hextoken, ['generic_high_entropy', 'generic_api_key'])
            for name in ('checksum', 'token_id', 'public_key', 'password_hash'):
                add(f'{seed}_digest_{width}_{name}', 'config.yaml', f'{name}: {hextoken}\n', 'negative')
        for index, text in enumerate([
            'const url="https://internal.invalid"; const api_key=' + value + ';',
            'const note="#summary"; const api_key=' + value + ';',
            'const note="/* instructions */"; const api_key=' + value + ';',
            'const doc=`// comment text`; const api_key=' + value + ';',
            'const password: string;',
        ]):
            add(f'{seed}_code_reference_{index}', 'app.ts', text, 'negative')
        for index, (path, text) in enumerate([
            ('app.js', '/*\n api_key=' + value + '\n*/'),
            ('app.rs', '/* outer /* inner */\n api_key=' + value + '\n*/'),
            ('app.py', '# api_key=' + value),
            ('app.js', 'const doc="password: ' + value + '";'),
            ('app.py', 'doc = """\napi_key=' + value + '\n"""'),
        ]):
            add(f'{seed}_literal_region_{index}', path, text, 'positive', value,
                ['generic_api_key', 'generic_password'])
        for index, text in enumerate([
            'Driver={ODBC Driver 18 for SQL Server};Server=db.internal;UID=user;Password=Winter42!',
            'DSN=warehouse;Pwd=Winter42!',
            'Server=db.internal;Database=prod;Password=Winter42!',
            'Password=Winter42!;DSN=warehouse',
        ]):
            add(f'{seed}_odbc_{index}', 'connections.env', text, 'positive', 'Winter42!',
                ['odbc-dsn-password', 'mssql-ado-connection-string'] if index in (0, 2) else ['odbc-dsn-password'])
        for index, text in enumerate([
            'Driver=other\nPASSWORD=Winter42!',
            'const driver="Driver=warehouse"; const password="Winter42!";',
            'const server="Server=db.internal;"; const password="Winter42!";',
        ]):
            add(f'{seed}_separate_odbc_{index}', 'connections.js' if index else 'config.env',
                text, 'positive', 'Winter42!', ['generic_password'])
        for index, password in enumerate(['changeme', 'placeholder', 'redacted', 'xxxxxxxx',
                                          '${DB_PASSWORD}', '$DB_PASSWORD', '{{ secret }}', '<password>']):
            add(f'{seed}_placeholder_{index}', 'config.env', f'password="{password}"', 'negative')
        for index, (path, text) in enumerate([
            ('app.py', 'password = get_password_v2()'),
            ('app.ts', 'password: string'),
            ('config.yaml', 'password: $argon2id$v=19$m=65536,t=3,p=4$abcdefghijk$abcdefghijklmnopqr'),
        ]):
            add(f'{seed}_nonliteral_{index}', path, text, 'negative')
    return rows


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with args.output.open('x') as stream:
        stream.write(fixture_json(corpus()))
