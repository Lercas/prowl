"""Синтетические положительные и отрицательные контроли шума 1.4.0, без сети."""
import argparse
import json
import random
import string
from pathlib import Path

from safe_fixture_json import fixture_json


def corpus():
    rows = []

    def add(name, path, text, truth, value=None, types=None, ml=True):
        rows.append(dict(name=name, path=path, text=text, truth=truth,
                         value=value, types=types or [], ml_expected=ml))

    for seed in (140014, 741913):
        rng = random.Random(seed)

        def token(n, chars=string.ascii_letters + string.digits):
            return ''.join(rng.choice(chars) for _ in range(n))

        long = token(40)
        short = token(32)
        digest = token(64, '0123456789abcdef')
        negatives = {
            'bypass.js': 'const bypass = routesV2;',
            'passenger.js': 'const passenger = passenger2024;',
            'identifier.js': 'const passwordInput2 = document.getElementById("password");',
            'html.html': '<input type="password" id="passwordInput2" autocomplete="current-password">',
            'code_ref.js': 'const password = config.credentialsV2;',
            'code_call.py': 'password = get_password_v2()',
            'annotation.py': 'def login(password: str, mode: str = "oauth2flow") -> None: pass',
            'comparison.js': 'if (password === submittedPasswordV2) { return true; }',
            'schema.json': '{"properties":{"password":{"type":"string","format":"password","minLength":12}}}',
            'type.ts': 'let password: string;',
            'property.ts': 'password: String,',
            'bcrypt.env': 'PASSWORD="$2b$12$' + token(53, string.ascii_letters + string.digits + './') + '"',
            'argon.env': 'PASSWORD="$argon2id$v=19$m=65536,t=3,p=4$' + token(22) + '$' + token(43) + '"',
            'pbkdf.env': 'password="pbkdf2_sha256$600000$' + token(20) + '$' + token(44) + '"',
            'hash_context.js': 'const token = undefined; const checksum = "' + long + '";',
            'long_identifier.js': 'const secret = null; const f = A' + long + ';',
            'css.html': '<input type="password" class="' + long + '">',
            'public_key.json': '{"public_key":"' + long + '"}',
            'public_ssh.env': 'PUBLIC_KEY="ssh-ed25519 ' + token(68) + '"',
            'api_ref.js': 'api_key = A' + short + ';',
            'hmac_ref.js': 'secret = thisIsAConfigurationPropertyName;',
            'gcp_id.json': '{"type":"service_account","private_key_id":"' + digest[:40] + '"}',
            'help.md': 'Pass the sha256sum option releaseV2026 to the command.',
            'before_cue.md': 'Build releaseV2026 succeeded. Reset your password on the site.',
            'after_cue.md': 'Reset your password on the site. Build releaseV2026 succeeded.',
            'auth_css.json': '{"auth":true,"class":"' + long + '"}',
            'data_password.json': '{"password":"data:image/png;base64,' + token(60) + '"}',
            'stripe_public.js': 'const key = "pk_live_' + short + '";',
            'sentry_public.js': 'const url="https://' + digest[:32] + '@o123.ingest.sentry.io/456";',
            'sentry_other_url.json': '{"sentry":true,"url":"https://' + digest[:32] + '@storage.internal/456"}',
            'metadata.json': '{"auth_token_id":"' + long + '","password_hash":"' + digest + '"}',
        }
        for path, text in negatives.items():
            add(f'{seed}_{path}', path, text + '\n', 'negative')

        # Shapes without a provider prefix need a credential binding, not just provider branding.
        providers = [
            ('assemblyai', 'api_key', 32, 'hex', 'assemblyai-api-key'),
            ('cohere', 'api_key', 40, 'base62', 'cohere-api-key'),
            ('deepgram', 'api_key', 40, 'lower', 'deepgram-api-key'),
            ('deepinfra', 'api_key', 32, 'base62', 'deepinfra-api-key'),
            ('mistral', 'api_key', 32, 'base62', 'mistral-api-key'),
            ('together', 'api_key', 64, 'hex', 'together-api-key'),
            ('linode', 'token', 64, 'hex', 'linode-api-token'),
            ('vultr', 'api_key', 36, 'base32', 'vultr-api-key'),
            ('loops', 'api_key', 32, 'hex', 'loops-api-key'),
            ('twitch', 'client_secret', 30, 'lower', 'twitch-client-secret'),
            ('algolia', 'admin_api_key', 32, 'hex', 'algolia-api-key'),
            ('auth0', 'client_secret', 40, 'base62', 'auth0-client-secret'),
            ('netlify', 'token', 40, 'base62', 'netlify-access-token'),
            ('vercel', 'token', 24, 'base62', 'vercel-access-token'),
            ('segment', 'write_key', 32, 'base62', 'segment-write-key'),
            ('spotify', 'client_secret', 32, 'base62', 'spotify-client-credentials'),
        ]
        alphabets = {'hex': '0123456789abcdef', 'base62': string.ascii_letters + string.digits,
                     'lower': string.ascii_lowercase + string.digits, 'base32': string.ascii_uppercase + '234567'}
        for vendor, field, length, shape, rule in providers:
            value = token(length, alphabets[shape])
            for suffix in ('project_id', 'client_id', 'request_id', 'index', 'checksum', 'model'):
                path = vendor + '_' + suffix + '.json'
                add(f'{seed}_{path}', path, json.dumps({vendor + '_' + suffix: value}), 'negative')
            for ext, text in [('.env', f'{vendor.upper()}_{field.upper()}={value}\n'),
                              ('.json', json.dumps({vendor + '_' + field: value})),
                              ('.js', f'const {vendor}_{field} = "{value}";')]:
                add(f'{seed}_{vendor}{ext}', vendor + ext, text, 'positive', value, [rule])

        positives = [
            ('weak.env', 'password="hunter2"', 'hunter2', ['generic_password'], True),
            ('weakword.env', 'password="required"', 'required', ['generic_password'], True),
            ('bracket.env', 'PASSWORD="Winter(2024"', 'Winter(2024', ['generic_password'], True),
            ('hex.env', f'PASSWORD="{digest}"', digest, ['generic_password'], True),
            ('german.md', 'Ihr Passwort lautet F4QPE91sc6iN bitte sicher aufbewahren.', 'F4QPE91sc6iN', ['generic_password'], True),
            ('french.md', 'Votre mot de passe temporaire est C1CmREwv5Kac pour la connexion.', 'C1CmREwv5Kac', ['generic_password'], True),
            ('russian.md', 'Ваш ПАРОЛЬ для доступа: R4nd0mT3mp!', 'R4nd0mT3mp!', ['generic_password'], True),
            ('portuguese.md', 'Sua senha é R4nd0mT3mp!', 'R4nd0mT3mp!', ['generic_password'], True),
            ('aws.env', 'AWS_KEY=\x41KIANAFGYOEYPXU1DSYP', '\x41KIANAFGYOEYPXU1DSYP', ['aws_access_key_id'], True),
            ('apikey.env', f'api_key={short}', short, ['generic_api_key'], True),
            ('longkey.env', f'secret_key="{long}"', long, ['generic_high_entropy'], True),
            ('tokenvalue.env', f'token_value="{long}"', long, ['generic_high_entropy'], True),
            ('public_api.env', f'PUBLIC_API_KEY="{long}"', long, ['generic_api_key', 'generic_high_entropy'], True),
            ('after_public.env', 'ssh-ed25519 ' + token(68) + f'; secret_key="{long}"', long, ['generic_high_entropy'], True),
            ('after_integrity.html', '<script integrity="sha384-' + token(64) + f'" data-secret-key="{long}"></script>', long, ['generic_high_entropy'], True),
            ('after_data.json', '{"image":"data:image/png;base64,' + token(70) + f'","secret_key":"{long}"' + '}', long, ['generic_high_entropy'], True),
            ('after_comment.py', f'# api_key = {short}', short, ['generic_api_key'], True),
            ('azure.env', f'AZURE_CLIENT_SECRET="{long}"', long, ['azure-ad-client-secret'], True),
            ('unknown_oauth.env', f'client_secret="{long}"', long, ['generic_api_key'], True),
            ('auth0_mixed.json', '{"azure":true,"auth0_client_secret":"' + long + '"}', long, ['auth0-client-secret'], True),
            ('minified.js', 'const auth=false;' + ('const x=0;' * 700) + f'const api_key="{short}";', short, ['generic_api_key'], True),
            ('netlify_prefix.env', 'value=nfp_' + short + 'Ab9Z', 'nfp_' + short + 'Ab9Z', ['netlify-access-token'], True),
            ('hash_prefix_password.env', 'password="$2b$12$short"', '$2b$12$short', ['generic_password'], True),
            ('argon_prefix_password.env', 'password="$argon2id$MyP4ss"', '$argon2id$MyP4ss', ['generic_password'], True),
            ('sentry_legacy.env', f'SENTRY_DSN=https://{digest[:32]}:{digest[32:]}@o123.ingest.sentry.io/456',
             f'https://{digest[:32]}:{digest[32:]}@o123.ingest.sentry.io/456', ['basic_auth_header', 'sentry-dsn'], True),
        ]
        for path, text, value, types, ml in positives:
            add(f'{seed}_positive_{path}', path, text + '\n', 'positive', value, types, ml)

        # A variable name does not prove the ACL of an actual Algolia API key; keep this ambiguous.
        search = token(32, alphabets['hex'])
        add(f'{seed}_search_acl_unknown', 'algolia_search.env', f'ALGOLIA_SEARCH_KEY={search}',
            'ambiguous', search, ['algolia-api-key'])
    return rows


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    with args.output.open('x') as stream:
        stream.write(fixture_json(corpus()))
