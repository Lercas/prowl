#!/usr/bin/env python3
"""Qualify APK/IPA source identity through the native CLI on owned fixtures."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import warnings
from urllib.parse import unquote, urlparse
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='prowl-mobile-provenance-native-'))
    sandbox = ['/usr/bin/sandbox-exec', '-p', '(version 1)(allow default)(deny network*)']
    if not Path(sandbox[0]).is_file():
        parser.error('this local qualification requires macOS sandbox-exec')
    env = {k: v for k, v in os.environ.items() if not k.startswith('PROWL_')}
    env.update(PROWL_HOME=str(root / 'home'), PROWL_LIVE_TEST='')
    key = 'AKIANAFGYOEYPXU1DSYP'
    body = ('AWS=' + key + '\n').encode()
    member = 'assets/prod #?秘密.env'
    model = Path(__file__).resolve().parents[1] / 'tool/internal/mlmodel/model_binary_go_literal_v1.json'
    checks = []

    def check(name, condition):
        assert condition, name
        checks.append({'case': name, 'passed': True})

    def zipped(entries):
        stream = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(stream, 'w') as archive:
                for name, data in entries:
                    archive.writestr(name, data)
        return stream.getvalue()

    payload = zipped([(member, body)])
    class Handler(BaseHTTPRequestHandler):
        calls = 0
        def log_message(self, *_): pass
        def do_GET(self):
            Handler.calls += 1
            status, data = (404, b'owned missing') if '/missing' in self.path else (200, payload)
            self.send_response(status)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f'http://127.0.0.1:{server.server_port}/app.apk'
    control = subprocess.run(['/usr/bin/curl', '--silent', '--max-time', '2', url], capture_output=True)
    blocked = subprocess.run([*sandbox, '/usr/bin/curl', '--silent', '--max-time', '2', url], capture_output=True)
    check('OS-network-denial-enforced', control.returncode == 0 and blocked.returncode != 0 and Handler.calls == 1)

    def run(args, remote=False, keyless=False):
        localenv = dict(env)
        if keyless:
            localenv['PROWL_HOME'] = str(root / 'keyless-home')
        if remote:
            localenv['PROWL_ALLOW_PRIVATE_IPS'] = '1'
        p = subprocess.run([* ([] if remote else sandbox), str(binary), *map(str, args)], cwd=root,
                           env=localenv, capture_output=True, timeout=30)
        assert key.encode() not in p.stdout + p.stderr, 'raw synthetic credential leaked'
        assert b'PRIVATE_' not in p.stdout + p.stderr, 'private acquisition URL leaked'
        return p

    try:
        check('identity-init', run(['identity', 'init']).returncode == 0)
        report_key = root / 'home/identity.key'
        variants = []
        for parent, suffix, entries in [
            ('one', '.apk', [(member, body)]), ('two', '.apk', [(member, body)]),
            ('ios', '.ipa', [('Payload/Owned.app/prod.env', body)]),
            ('utf16', '.apk', [(member, b'\xff\xfe' + body.decode().encode('utf-16le'))]),
            ('binary', '.apk', [('classes.dex', b'\x00\x01' + body + b'\x00')]),
            ('duplicate', '.apk', [(member, body), (member, body)]),
        ]:
            (root / parent).mkdir()
            target = root / parent / ('app' + suffix)
            target.write_bytes(zipped(entries))
            variants.append(target)
            for fmt in ('json', 'sarif'):
                for ml in (False, True):
                    flags = ['--ml', '--ml-model', model] if ml else []
                    p = run(['mobile', target, '--bundled', '--format', fmt, *flags])
                    d = json.loads(p.stdout)
                    meta = d if fmt == 'json' else d['runs'][0]['properties']
                    fs = d['findings'] if fmt == 'json' else [f['properties'] for f in d['runs'][0]['results']]
                    expected = hashlib.sha256(entries[0][1]).hexdigest()
                    check(f'{parent}-{fmt}-ml{ml}', p.returncode == 0 and meta['complete'] and bool(fs)
                          and all(f.get('provenance', {}).get('digest') == expected for f in fs))
                    uris = [f['provenance']['source_url'] for f in fs] if fmt == 'json' else [
                        f['locations'][0]['physicalLocation']['artifactLocation']['uri'] for f in d['runs'][0]['results']]
                    check(f'{parent}-{fmt}-URI-ml{ml}', all(
                        urlparse(u).scheme == 'mobile+file' and unquote(urlparse(u).path) == str(target)
                        and unquote(urlparse(u).fragment) == '/' + entries[0][0] for u in uris))
                    if fmt == 'json':
                        f = fs[0]
                        check(f'{parent}-identity-ml{ml}', f['path'].startswith(target.name + '!/')
                              and f['provenance']['source_url'].startswith('mobile+file:') and bool(f.get('occurrence_id')))
                        if parent == 'duplicate':
                            occurrences = f.get('occurrences', [])
                            check(f'duplicate-observations-ml{ml}', len(occurrences) == 2
                                  and occurrences[0]['id'] != occurrences[1]['id'])
        first = json.loads(run(['mobile', variants[0], '--format=json']).stdout)['findings'][0]
        second = json.loads(run(['mobile', variants[1], '--format=json']).stdout)['findings'][0]
        check('same-basename-separate-report-identity', first['path'] == second['path']
              and first['secret_id'] == second['secret_id'] and first['fingerprint'] != second['fingerprint']
              and first['occurrence_id'] != second['occurrence_id'])
        keyless = [json.loads(run(['mobile', p, '--format=json'], keyless=True).stdout)['findings'][0]
                   for p in variants[:2]]
        check('keyless-public-archive-namespace', keyless[0]['fingerprint'] != keyless[1]['fingerprint']
              and all(not f.get('secret_id') and not f.get('occurrence_id') for f in keyless))
        remote_fs, policies = [], []
        for selector in ('ONE', 'ONE', 'TWO'):
            target = url.replace('http://', 'http://alice:PRIVATE_AUTH@') + '?signature=PRIVATE_' + selector
            p = run(['mobile', target, '--format=json'], remote=True)
            d = json.loads(p.stdout)
            check('owned-HTTP-acquisition-' + str(len(remote_fs)), p.returncode == 0 and d['complete'])
            remote_fs.append(d['findings'][0])
            policies.append(next(s['policy'] for s in d['scope'] if s['kind'] == 'mobile'))
        check('download-spool-independent-identity', remote_fs[0]['fingerprint'] == remote_fs[1]['fingerprint']
              and remote_fs[0]['occurrence_id'] == remote_fs[1]['occurrence_id'] and policies[0] == policies[1])
        check('private-selector-separates-identity', remote_fs[0]['provenance']['source_url'] == remote_fs[2]['provenance']['source_url']
              and remote_fs[0]['fingerprint'] != remote_fs[2]['fingerprint'] and policies[0] != policies[2])
        invalid = root / 'invalid.apk'
        invalid.write_bytes(b'not ZIP')
        for name, target, remote in [('missing', root / 'missing.apk', False), ('invalid', invalid, False),
                                      ('http404', url.replace('/app.apk', '/missing.apk') + '?sig=PRIVATE_ONE', True),
                                      ('blocked', url + '?sig=PRIVATE_ONE', False)]:
            for fmt in ('json', 'sarif'):
                p = run(['mobile', target, '--format', fmt], remote=remote)
                d = json.loads(p.stdout)
                meta = d if fmt == 'json' else d['runs'][0]['properties']
                check(f'{name}-{fmt}-incomplete', p.returncode == 2 and not meta['complete']
                      and any(x['code'] == 'mobile_acquisition_failed' for x in meta['diagnostics']))
                sentinel = root / (name + '-' + fmt + '-baseline.json')
                sentinel.write_text('owned baseline sentinel')
                p = run(['mobile', target, '--format', fmt, '--write-baseline', sentinel], remote=remote)
                check(f'{name}-{fmt}-baseline', p.returncode == 2 and sentinel.read_text() == 'owned baseline sentinel')
        index = root / 'index'
        for number, target in enumerate((variants[0], variants[1], variants[0])):
            p = run(['mobile', target, '--index', index, '--scope=owned-mobile', '--format=json'])
            check('index-acquisition-' + str(number), p.returncode == 0)
        p = run(['index', '--index', index, '--format=json'])
        d = json.loads(p.stdout)
        (root / 'index-view.json').write_bytes(p.stdout)
        check('index-links-one-value-two-archives', p.returncode == 0 and len(d['secrets']) == 1
              and d['secrets'][0]['location_count'] == 2)
        for number, selector in enumerate(('ONE', 'ONE', 'TWO')):
            target = url.replace('http://', 'http://alice:PRIVATE_AUTH@') + '?signature=PRIVATE_' + selector
            p = run(['mobile', target, '--index', index, '--scope=owned-mobile', '--format=json'], remote=True)
            check('index-HTTP-selection-' + str(number), p.returncode == 0)
        p = run(['mobile', variants[-1], '--index', index, '--scope=owned-mobile', '--format=json'])
        check('index-duplicate-entries', p.returncode == 0)
        p = run(['mobile', invalid, '--index', index, '--scope=owned-mobile', '--format=json'])
        check('index-failed-acquisition-incomplete', p.returncode == 2)
        p = run(['index', '--index', index, '--format=json'])
        d = json.loads(p.stdout)
        check('index-private-selectors-duplicates-and-failed-snapshot', p.returncode == 0
              and len(d['secrets']) == 1 and d['secrets'][0]['location_count'] == 6
              and d['scans'][-1]['complete'] is False)
        google = 'AIzaSy9Qw7Er5Ty3Ui1Op8As6Df4Gh2Jk0Lz5Xc'
        for name, entry, text in [
            ('derived-xml', 'res/values/strings.xml', '<resources><string name="google_api_key">KEY</string><string name="project_id">owned-project</string><string name="firebase_database_url">https://owned-project.firebaseio.com</string></resources>'),
            ('derived-plist', 'Payload/Owned.app/GoogleService-Info.plist', '<plist version="1.0"><dict><key>API_KEY</key><string>KEY</string><key>PROJECT_ID</key><string>owned-project</string><key>DATABASE_URL</key><string>https://owned-project.firebaseio.com</string></dict></plist>'),
        ]:
            literal = text.replace('>KEY</string>', '>' + google + '</string>').encode()
            control = root / (name + '-literal.apk')
            control.write_bytes(zipped([(entry, literal)]))
            p = run(['mobile', control, '--audit-public', '--authorized', '--format=json'])
            assert google.encode() not in p.stdout + p.stderr
            d = json.loads(p.stdout)
            audits = [f['public_key_audit'] for f in d['findings'] if f.get('public_key_audit')]
            check(name + '-literal-control-plans-blocked-read', p.returncode == 2 and not d['complete']
                  and len(audits) == 1 and bool(audits[0].get('checks')))
            target = root / (name + '.apk')
            target.write_bytes(zipped([(entry, b'\x00\x01' + literal + b'\x00')]))
            p = run(['mobile', target, '--audit-public', '--authorized', '--format=json'])
            assert google.encode() not in p.stdout + p.stderr
            d = json.loads(p.stdout)
            audits = [f['public_key_audit'] for f in d['findings'] if f.get('public_key_audit')]
            check(name + '-cannot-authorize-network-checks', p.returncode == 2 and not d['complete']
                  and len(audits) == 1 and audits[0]['status'] == 'inconclusive' and not audits[0].get('checks'))
        check('report-key-unmodified', len(report_key.read_text().strip()) == 64)
        evidence = {'binary': str(binary), 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                    'model_sha256': hashlib.sha256(model.read_bytes()).hexdigest(), 'passed': len(checks),
                    'failed': 0, 'checks': checks, 'fixture_root': str(root),
                    'network_control': 'Local cases: verified OS deny network*. HTTP acquisition: owned loopback server, no provider verification/audit flags.'}
        (root / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
        print(json.dumps({'passed': len(checks), 'evidence': str(root / 'evidence.json')}))
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == '__main__':
    main()
