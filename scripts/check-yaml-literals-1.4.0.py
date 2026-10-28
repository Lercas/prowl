"""Приёмка YAML scalars, aliases, merge и binary на собственных данных без сети."""
import base64
import importlib.util
import random
import string
from pathlib import Path


def corpus():
    rng = random.Random(2602101407)
    cases = []

    def add(name, text, expected):
        cases.append({'name': name, 'path': name + '.yaml', 'text': text, 'expected': expected})

    def want(value, typ='generic_password', source=None, transform='yaml-scalar'):
        return {'value': value, 'type': typ, 'source': value if source is None else source, 'transform': transform}

    def escape(value):
        return ''.join(('\\u%04x' if ord(c) <= 0xffff else '\\U%08x') % ord(c) for c in value)

    for i in range(12):
        word = ''.join(rng.choices(string.ascii_letters, k=8))
        value = 'Winter42!' + word
        key = 'AKIA' + ''.join(rng.choices(string.ascii_uppercase + string.digits, k=16))
        stripe = 'sk_live_' + ''.join(rng.choices(string.ascii_letters + string.digits, k=24))
        raw = escape(value)
        for label, text, canonical, source in [
            ('bom', '\ufeffpassword: ' + value, value, value),
            ('double', 'password: "' + raw + '"', value, raw),
            ('single', "password: '" + value + "\\'", value + '\\', value + '\\'),
            ('literal_unicode_text', "password: '" + raw + "'", raw, raw),
            ('literal', 'password: |-\n  ' + value + '\n  Spring53\n', value + '\nSpring53', '|-\n  ' + value + '\n  Spring53\n'),
            ('folded', 'password: >-\n  ' + value + '\n  Spring53\n', value + ' Spring53', '>-\n  ' + value + '\n  Spring53\n'),
            ('keep', 'password: |+\n  ' + value + '\n\n', value + '\n\n', '|+\n  ' + value + '\n\n'),
            ('explicit_indent', 'password: |2-\n    ' + value + '\n', '  ' + value, '|2-\n    ' + value + '\n'),
            ('plain_fold', 'password: ' + value + '\n  Spring53\n', value + ' Spring53', value + '\n  Spring53'),
            ('continuation', 'password: "Winter\\\n  42!' + word + '"', value, 'Winter\\\n  42!' + word),
            ('escaped_name', '"' + escape('password') + '": "' + raw + '"', value, raw),
            ('typed_tag', 'password: !!str &a "' + raw + '"', value, raw),
            ('astral', 'пароль: "' + escape(value + '🚀') + '"', value + '🚀', escape(value + '🚀')),
        ]:
            add(f'{i}_{label}', text, [want(canonical, source=source)])
        for sep_label, sep in [('cr', '\r'), ('crlf', '\r\n'), ('nel', '\u0085'), ('ls', '\u2028'), ('ps', '\u2029')]:
            add(f'{i}_line_{sep_label}', 'note: ordinary' + sep + 'password: ' + value + sep, [want(value)])
            add(f'{i}_pragma_{sep_label}', 'key: ' + key + sep + '# prowl:allow' + sep,
                [want(key, 'aws_access_key_id')])
        add(f'{i}_scalar_alias', 'definition: &a ' + value + '\npassword: *a\n', [want(value, source='*a', transform='yaml-alias')])
        for label, text in [
            ('mapping_alias', 'definition: &a {password: ' + value + '}\ncopy: *a\n'),
            ('merge', 'definition: &a {password: ' + value + '}\ncopy: {<<: *a}\n'),
        ]:
            add(f'{i}_{label}', text, [want(value), want(value, source='*a', transform='yaml-alias')])
        add(f'{i}_inline_merge', 'copy: {<<: [{password: ' + value + '}]}\n',
            [want(value), want(value, source='<<', transform='yaml-merge')])
        add(f'{i}_override', 'definition: &a {password: ' + value + '}\ncopy: {<<: *a, password: Spring53!Summer}\n',
            [want(value), want('Spring53!Summer')])
        add(f'{i}_shared_reference_paths', 'value: &t ' + stripe + '\ndefinition: &a\n'
            '  first: {account: account-A, token: *t}\n  second: {account: account-B, token: *t}\ncopy: *a\n',
            [want(stripe, 'stripe_secret_key')] + [want(stripe, 'stripe_secret_key', '*t', 'yaml-alias') for _ in range(2)] +
            [want(stripe, 'stripe_secret_key', '*a', 'yaml-alias') for _ in range(2)])
        for j, (secret, typ) in enumerate([(key, 'aws_access_key_id'), (stripe, 'stripe_secret_key')]):
            raw = escape(secret)
            blob = base64.b64encode(secret.encode()).decode()
            for label, text, source, transform in [
                ('typed', 'token: "' + raw + '"', raw, 'yaml-scalar'),
                ('array', 'tokens: ["' + raw + '"]', raw, 'yaml-scalar'),
                ('key', '"' + raw + '": unrelated', raw, 'yaml-scalar'),
                ('binary', 'token: !!binary "' + blob + '"', blob, 'yaml-binary'),
                ('binary_split', 'token: !!binary |\n  ' + blob[:12] + '\n  ' + blob[12:] + '\n', '|\n  ' + blob[:12] + '\n  ' + blob[12:] + '\n', 'yaml-binary'),
            ]:
                add(f'{i}_{label}_{j}', text, [want(secret, typ, source, transform)])
        add(f'{i}_comments', 'empty: |\n# first=' + key + '\nnote: normal\n# second=' + key + '\n',
            [want(key, 'aws_access_key_id', transform=None), want(key, 'aws_access_key_id', transform=None)])
        placeholder = '$' + '{PASSWORD}'
        for j, text in enumerate([
            'password: "' + escape(placeholder) + '"', "password: '{{PASSWORD}}'", "password: '<PASSWORD>'",
            'password: example', 'password: dummy', 'password: abc', 'password: false', 'password: null',
            'password: 2026-10-02', 'password: 3.14159', 'password: ["' + value + '"]',
            'password: {source: configuration}', 'bypass: "' + value + '"',
            'key: ' + key + ' # prowl:allow\n',
        ]):
            add(f'{i}_negative_{j}', text, [])
    return cases


if __name__ == '__main__':
    spec = importlib.util.spec_from_file_location('literal_contract', Path(__file__).with_name('check-toml-literals-1.4.0.py'))
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    runner.main(make_corpus=corpus, suite='yaml', seed=2602101407,
                invalid_text='password: "Winter42\\uD800Autumn"', invalid_code='yaml_scalar_parse',
                boundary='Own synthetic YAML scalar/alias/merge/binary corpus; canonical identity and original evidence. '
                         'No provider calls. This is not independent market precision/recall evidence.')
