#!/usr/bin/env python3
"""Qualify SaaS acquisition scopes and report provenance using owned loopback APIs."""
import argparse
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
from urllib.parse import parse_qs, urlparse, unquote


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='prowl-atlassian-native-')); (root / 'home').mkdir()
    values = ['AKIANAFGYOEYPXU1DSYP', 'AKIA4ZX9QJ7K2MNPL3RS']
    state = {'mode': 'normal', 'auth_bad': 0}
    class API(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_POST(self):
            self.send_response(404); self.end_headers()
        def do_GET(self):
            if self.headers.get('Authorization') != 'Bearer owned-private-token': state['auth_bad'] += 1
            u = urlparse(self.path); path = u.path; query = parse_qs(u.query); mode = state['mode']
            for prefix in ('/tenant-a', '/tenant-b'):
                if path.startswith(prefix + '/'):
                    path = path[len(prefix):]
                    break
            status, data = 200, None
            if mode == 'connect': status = 404
            elif path.endswith('/serverInfo'): data = {'deploymentType': 'Cloud'}
            elif path.endswith('/project/search'): data = {'isLast': True, 'startAt': 0, 'total': 0 if mode == 'empty' else 1, 'maxResults': 50, 'values': [] if mode == 'empty' else [{'key': 'P'}]}
            elif path.endswith('/search/jql'):
                fields = {'summary': 'AWS=' + values[0]}
                fields['comment'] = None if mode == 'partial' else {'comments': [], 'total': 0, 'startAt': 0, 'maxResults': 100}
                if mode in ('comments', 'unknown-comments'):
                    comments = [{'body': 'AWS=' + values[0]} for _ in range(2)]
                    if mode == 'comments':
                        for i, comment in enumerate(comments): comment['id'] = str(11 + i)
                    fields['comment'] = {'comments': comments, 'total': 2, 'startAt': 0, 'maxResults': 100}

                data = {'isLast': True, 'issues': [{'id': '1', 'key': 'P-1', 'fields': fields}]}
            elif path.endswith('/comment'):
                if mode == 'partial': status = 403
                else: data = {'comments': [], 'total': 0, 'startAt': 0, 'maxResults': 100}
            elif path.endswith('/changelog'): data = {'isLast': True, 'total': 1, 'maxResults': 100, 'startAt': 0, 'values': [{'id': '9', 'created': '2020-01-02T00:00:00.000+0000', 'items': [{'field': 'description', 'fieldId': 'description', 'fromString': 'AWS=' + values[1], 'toString': ''}]}]}
            elif path == '/wiki/api/v2/spaces': data = {'results': [] if mode == 'empty' else [{'id': '100', 'key': 'SP'}], '_links': {}}
            elif path == '/wiki/api/v2/spaces/100/pages':
                if query.get('status', ['current'])[0] != 'current': status = 404
                else: data = {'results': [{'id': '200', 'title': 'Runbook', 'version': {'number': 3}}], '_links': {}}
            elif path == '/wiki/api/v2/pages/200/versions':
                if mode == 'partial': status = 403
                else: data = {'results': [{'number': 1}, {'number': 3}], '_links': {}}
            elif path == '/wiki/api/v2/pages/200':
                version = int(query.get('version', ['3'])[0])
                data = {'id': '200', 'title': 'Runbook', 'body': {'storage': {'value': '<p>AWS=' + values[1 if version == 1 else 0] + '</p>'}}, 'version': {'number': version}, '_links': {'webui': '/spaces/SP/pages/200'}}
            else: status = 404
            if path.endswith('/changelog') and mode in ('events', 'unknown-history'):
                data['values'].append(dict(data['values'][0], id='10'))
                if mode == 'unknown-history':
                    for event in data['values']: event.pop('id', None)
                data['total'] = 2
            self.send_response(status); self.end_headers()
            self.wfile.write(json.dumps(data if status == 200 else {'message': 'owned-private-response'}).encode())
    server = ThreadingHTTPServer(('127.0.0.1', 0), API)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    second = ThreadingHTTPServer(('127.0.0.1', 0), API)
    threading.Thread(target=second.serve_forever, daemon=True).start()
    other_base = f'http://127.0.0.1:{second.server_port}'
    base = f'http://127.0.0.1:{server.server_port}'
    target = base.replace('://', '://u:owned-private-user@') + '?token=owned-private-query'
    env = dict(os.environ, PROWL_HOME=str(root / 'home'), PROWL_ALLOW_PRIVATE_IPS='1', ATLASSIAN_PAT='owned-private-token')
    checks = []; calls = 0
    def check(name, passed):
        checks.append({'case': name, 'passed': bool(passed)})
        if not passed: raise AssertionError(name)
    def run(product, fmt, flags=(), scan_target=None):
        nonlocal calls
        calls += 1
        result = subprocess.run([str(binary), product, scan_target or target, '--format=' + fmt, '--silence', '--bundled', *flags], cwd=root, env=env, input=b'', capture_output=True, timeout=60)
        (root / f'case-{calls:03}.stdout').write_bytes(result.stdout); (root / f'case-{calls:03}.stderr').write_bytes(result.stderr)
        data = json.loads(result.stdout)
        if fmt == 'json': return result, data, data['findings']
        r = data['runs'][0]
        return result, r['properties'], [dict(f['properties'], type=f['ruleId'], path=f['locations'][0]['physicalLocation']['artifactLocation']['uri'], fingerprint=f.get('partialFingerprints', {}).get('prowl/v1', '')) for f in r['results']]
    def safe(result):
        return all(s.encode() not in result.stdout + result.stderr for s in (*values, 'owned-private-token', 'owned-private-user', 'owned-private-query', 'owned-private-response'))
    try:
        for product in ('jira', 'confluence'):
            for current in (False, True):
                scopes = []
                for ml in (False, True):
                    for fmt in ('json', 'sarif'):
                        state['mode'] = 'normal'
                        flags = (['--current-only'] if current else []) + (['--ml'] if ml else [])
                        result, meta, findings = run(product, fmt, flags)
                        label = f'{product}/{current}/{ml}/{fmt}'
                        check(label + '/complete', result.returncode == 0 and meta['complete'] and len(findings) == (1 if current else 2))
                        check(label + '/provenance', all(f['provenance']['source_url'].startswith(base) and f['provenance']['source_version'] and not any(k in f['provenance'] for k in ('commit', 'blob', 'digest')) for f in findings))
                        if product == 'jira':
                            ids = {f['provenance']['source_version']: f['provenance'].get('issue_id' if f['provenance']['source_version'] == 'current' else 'history_id') for f in findings}
                            check(label + '/ids', ids == ({'current': '1'} if current else {'current': '1', 'history': '9'}))
                        else:
                            check(label + '/ids', all(f['provenance']['page_id'] == '200' for f in findings) and {f['provenance']['source_version'] for f in findings} == ({'3'} if current else {'1', '3'}))
                        check(label + '/safe', safe(result))
                        scopes.append([s for s in meta['scope'] if s['kind'] in (product, 'atlassian-deployment')])
                check(f'{product}/{current}/stable-scopes', len(scopes[0]) == 2 and all(s == scopes[0] for s in scopes))
            for mode in ('partial', 'empty', 'connect', 'budget'):
                state['mode'] = 'normal' if mode == 'budget' else mode
                for fmt in ('json', 'sarif'):
                    baseline = root / f'{product}-{mode}-{fmt}.baseline'; baseline.write_text('owned baseline sentinel')
                    flags = ['--write-baseline=' + str(baseline)] + (['--max-items=1'] if mode == 'budget' else [])
                    result, meta, findings = run(product, fmt, flags)
                    label = f'{product}/{mode}/{fmt}'
                    check(label + '/incomplete', result.returncode == 2 and not meta['complete'])
                    check(label + '/scope', any(s['kind'] == product for s in meta['scope']))
                    check(label + '/baseline', baseline.read_text() == 'owned baseline sentinel')
                    check(label + '/safe', safe(result))
                    if mode in ('partial', 'budget'): check(label + '/preserved', any(f['type'].replace('-', '_') == 'aws_access_key_id' for f in findings))
        for product in ('jira', 'confluence'):
            index = root / (product + '-index')
            flags = ['--index=' + str(index), '--scope=owned']
            state['mode'] = 'normal'
            for i in range(2):
                result, meta, findings = run(product, 'json', flags)
                check(f'{product}/index/complete/{i}', result.returncode == 0 and meta['complete'])
            for n, mode in enumerate(('empty', 'connect')):
                state['mode'] = mode
                result, meta, findings = run(product, 'json', flags)
                check(f'{product}/index/{mode}', result.returncode == 2 and not meta['complete'])
                result = subprocess.run([str(binary), 'index', '--format=json', *flags], cwd=root, env=env, input=b'', capture_output=True, timeout=30)
                scans = json.loads(result.stdout)['scans']
                check(f'{product}/index/{mode}/stored-incomplete', result.returncode == 0 and len(scans) == 3 + n and not scans[-1]['complete'])
                result = subprocess.run([str(binary), 'diff', '--format=json', *flags], cwd=root, env=env, input=b'', capture_output=True, timeout=30)
                check(f'{product}/index/{mode}/diff-blocked', result.returncode == 2 and safe(result))
        for product in ('jira', 'confluence'):
            state['mode'] = 'normal'
            a_target, b_target = base + '/tenant-a', base + '/tenant-b'
            result, meta, findings = run(product, 'json', ['--current-only'], a_target)
            first = findings[0]
            local = unquote(urlparse(first['path']).path.rsplit('/', 1)[1])
            legacy = root / (product + '-legacy.baseline')
            legacy.write_text(json.dumps([hashlib.sha256((first['type'] + '\x00' + local + '\x00' + values[0]).encode()).hexdigest()]))
            result, meta, findings = run(product, 'json', ['--current-only', '--baseline=' + str(legacy)], a_target)
            check(product + '/legacy-baseline-does-not-hide', result.returncode == 0 and meta['complete'] and len(findings) == 1)
            baseline = root / (product + '-qualified.baseline')
            result = subprocess.run([str(binary), product, a_target, '--current-only', '--bundled', '--silence', '--write-baseline=' + str(baseline)], cwd=root, env=env, input=b'', capture_output=True, timeout=60)
            check(product + '/qualified-baseline-written', result.returncode == 0 and json.loads(baseline.read_text()) == [first['fingerprint']])
            for label, target_url, expected in (('same', a_target, 0), ('other', b_target, 1)):
                result, meta, findings = run(product, 'json', ['--current-only', '--baseline=' + str(baseline)], target_url)
                check(product + '/baseline/' + label, result.returncode == 0 and meta['complete'] and len(findings) == expected)
        result = subprocess.run([str(binary), 'identity', 'init'], cwd=root, env=env, input=b'', capture_output=True, timeout=30)
        check('report-identity-init', result.returncode == 0)
        report_key = bytes.fromhex((root / 'home/identity.key').read_text().strip())
        for product in ('jira', 'confluence'):
            state['mode'] = 'normal'
            for ml in (False, True):
                for fmt in ('json', 'sarif'):
                    flags = ['--current-only'] + (['--ml'] if ml else [])
                    rows = []
                    for context in ('tenant-a', 'tenant-b', 'tenant-a'):
                        result, meta, findings = run(product, fmt, flags, base + '/' + context)
                        check(f'{product}/{ml}/{fmt}/{context}/identified', result.returncode == 0 and meta['complete'] and len(findings) == 1 and bool(findings[0].get('occurrence_id')))
                        rows.append(findings[0])
                    first, other, repeated = rows
                    check(f'{product}/{ml}/{fmt}/tenant-separation', first['path'] != other['path'] and first['fingerprint'] != other['fingerprint'] and first['occurrence_id'] != other['occurrence_id'] and first['secret_id'] == other['secret_id'])
                    check(f'{product}/{ml}/{fmt}/stable-identity', all(first[k] == repeated[k] for k in ('path', 'fingerprint', 'occurrence_id', 'secret_id')))
            result, meta, findings = run(product, 'json', ['--current-only'], base + '/tenant-a')
            item = findings[0]
            local = unquote(urlparse(item['path']).path.rsplit('/', 1)[1])
            legacy = root / (product + '-legacy-keyed.baseline')
            old_fp = hmac.new(report_key, ('fingerprint\x00' + item['type'] + '\x00' + local + '\x00' + values[0]).encode(), hashlib.sha256).hexdigest()
            legacy.write_text(json.dumps([old_fp]))
            result, meta, findings = run(product, 'json', ['--current-only', '--baseline=' + str(legacy)], base + '/tenant-a')
            check(product + '/keyed-legacy-baseline-does-not-hide', result.returncode == 0 and meta['complete'] and len(findings) == 1)
            origin_rows = []
            for origin in (base, other_base):
                result, meta, findings = run(product, 'json', ['--current-only'], origin + '/tenant-a')
                check(product + '/origin/complete', result.returncode == 0 and meta['complete'] and len(findings) == 1)
                origin_rows.append(findings[0])
            check(product + '/origin/identity', all(origin_rows[0][key] != origin_rows[1][key] for key in ('path', 'fingerprint', 'occurrence_id')) and origin_rows[0]['secret_id'] == origin_rows[1]['secret_id'])
            index = root / (product + '-tenant-index')
            flags = ['--current-only', '--index=' + str(index), '--scope=owned']
            for context in ('tenant-a', 'tenant-b', 'tenant-a'):
                result, meta, findings = run(product, 'json', flags, base + '/' + context)
                check(f'{product}/index/{context}/complete', result.returncode == 0 and meta['complete'])
            result = subprocess.run([str(binary), 'index', '--format=json', '--index=' + str(index), '--scope=owned'], cwd=root, env=env, input=b'', capture_output=True, timeout=30)
            secrets = json.loads(result.stdout)['secrets']
            check(product + '/index/one-value-two-locations', result.returncode == 0 and len(secrets) == 1 and secrets[0]['location_count'] == 2 and len({l['id'] for l in secrets[0]['locations']}) == 2)
        for mode, flags, count, complete in (('events', [], 3, True), ('comments', ['--current-only'], 3, True), ('unknown-history', [], 1, False), ('unknown-comments', ['--current-only'], 1, False)):
            state['mode'] = mode
            sentinel = root / (mode + '.baseline')
            if not complete:
                sentinel.write_text('owned baseline sentinel')
                flags = [*flags, '--write-baseline=' + str(sentinel)]
            result, meta, findings = run('jira', 'json', flags)
            check('jira/' + mode + '/identity', result.returncode == (0 if complete else 2) and meta['complete'] == complete and len(findings) >= count)
            if not complete:
                check('jira/' + mode + '/baseline-guard', sentinel.read_text() == 'owned baseline sentinel')
            if complete:
                check('jira/' + mode + '/distinct-observations', len({f['occurrence_id'] for f in findings}) == 3 and len({f['fingerprint'] for f in findings}) == 3)
        check('auth', state['auth_bad'] == 0)
    finally:
        server.shutdown(); server.server_close(); second.shutdown(); second.server_close()
        report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'passed': sum(c['passed'] for c in checks), 'total': len(checks), 'checks': checks, 'root': str(root), 'scope': 'owned loopback Jira/Confluence Cloud-shaped APIs and synthetic values only; no external tenant or live provider'}
        (root / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n'); print(json.dumps({k:v for k,v in report.items() if k != 'checks'}))


if __name__ == '__main__': main()
