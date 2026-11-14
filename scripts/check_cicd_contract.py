#!/usr/bin/env python3
"""Qualify CI provenance/completeness through actual CLI and MCP on owned loopback APIs."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
from urllib.parse import parse_qs, unquote, urlparse
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='prowl-cicd-native-'))
    (root / 'home').mkdir()
    value, token = 'AKIANAFGYOEYPXU1DSYP', 'owned-fixture-forge-bearer'
    original = ('AWS=' + value + '\n').encode()
    revision = 'a' * 40
    state = {'mode': 'normal', 'api_calls': 0, 'asset_calls': 0, 'auth_bad': 0}
    def archive(files):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as z:
            for name, data in files.items(): z.writestr(name, data)
        return stream.getvalue()
    zipped = archive({'config.env': original, 'image.bin': b'binary\x00data'})
    oversized = archive({'keep.env': original, 'large.txt': b'x' * 4000})
    class Assets(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            state['asset_calls'] += 1
            if self.headers.get('Authorization') or self.headers.get('PRIVATE-TOKEN'):
                state['auth_bad'] += 1
            mode = state['mode']
            body = original if '/trace' in self.path else zipped
            if mode == 'oversize': body = oversized
            if mode == 'prefix': body = original
            self.send_response(200)
            self.send_header('Content-Length', str(len(body) + (100 if mode == 'prefix' else 0)))
            self.end_headers()
            self.wfile.write(body)
    assets = ThreadingHTTPServer(('127.0.0.1', 0), Assets)
    asset_thread = threading.Thread(target=assets.serve_forever, daemon=True)
    asset_thread.start()
    class API(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            state['api_calls'] += 1
            github = self.path.startswith('/github/')
            expected = self.headers.get('Authorization') == 'Bearer ' + token if github else self.headers.get('PRIVATE-TOKEN') == token
            if not expected: state['auth_bad'] += 1
            path = unquote(urlparse(self.path).path)
            page = int(parse_qs(urlparse(self.path).query).get('page', ['1'])[0])
            mode = state['mode']
            is_runs = path.endswith('/actions/runs') or path.endswith('/pipelines')
            body = None
            if is_runs and mode in ('duplicate', 'trailing', 'null', 'shape', 'empty', 'row-limit', 'repeated-id'):
                if github:
                    body = {'duplicate': b'{"workflow_runs":[],"workflow_runs":[]}', 'trailing': b'{"workflow_runs":[{"id":7}]} {}', 'null': b'{"workflow_runs":null}', 'shape': b'{}', 'empty': b'{"workflow_runs":[]}', 'row-limit': json.dumps({'workflow_runs': [{'id': i + 1} for i in range(101)]}).encode(), 'repeated-id': b'{"workflow_runs":[{"id":7},{"id":7}]}'}[mode]
                else:
                    body = {'duplicate': b'[{"id":11,"id":12}]', 'trailing': b'[{"id":11}] {}', 'null': b'null', 'shape': b'{}', 'empty': b'[]', 'row-limit': json.dumps([{'id': i + 1} for i in range(101)]).encode(), 'repeated-id': b'[{"id":11},{"id":11}]'}[mode]
            elif path.endswith('/actions/runs'):
                runs = [{'id': 7, 'name': 'CI', 'head_sha': revision, 'html_url': 'https://u:private@forge.invalid/run/7?signature=locator-private'}]
                if mode == 'limit': runs = [{'id': page * 100 + i, 'name': 'CI'} for i in range(100)]
                body = json.dumps({'workflow_runs': runs}).encode()
            elif path.endswith('/pipelines'):
                body = json.dumps([{'id': 11, 'ref': 'main', 'sha': revision, 'web_url': 'https://forge.invalid/pipeline/11'}]).encode()
            elif '/pipelines/' in path and path.endswith('/jobs'):
                jobs = [{'id': 12, 'name': 'build', 'web_url': 'https://u:private@forge.invalid/job/12?signature=locator-private', 'artifacts_file': {'filename': 'bundle.zip', 'size': len(zipped)}}]
                if mode == 'limit': jobs = [{'id': page * 100 + i, 'name': 'build'} for i in range(100)]
                body = json.dumps(jobs).encode()
            elif path.endswith('/artifacts') and github:
                body = json.dumps({'artifacts': [{'id': 9, 'name': 'bundle', 'expired': mode == 'expired'}]}).encode()
            elif path.endswith('/logs') or path.endswith('/trace') or path.endswith('/zip') or path.endswith('/artifacts'):
                if mode == 'missing': self.send_error(404); return
                if mode == 'limit': body = b'public_number=42\n'
                else:
                    suffix = '/trace' if path.endswith('/trace') else '/archive'
                    self.send_response(302)
                    self.send_header('Location', f'http://127.0.0.1:{assets.server_port}' + suffix + '?sig=owned-signed-private')
                    self.end_headers()
                    return
            if body is None: self.send_error(404); return
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    api = ThreadingHTTPServer(('127.0.0.1', 0), API)
    api_thread = threading.Thread(target=api.serve_forever, daemon=True)
    api_thread.start()
    env = dict(os.environ, PROWL_HOME=str(root / 'home'), PROWL_ALLOW_PRIVATE_IPS='1',
               GITHUB_TOKEN=token, GITLAB_TOKEN=token,
               GITHUB_API=f'http://127.0.0.1:{api.server_port}/github', GITLAB_API=f'http://127.0.0.1:{api.server_port}/gitlab')
    checks = []
    def check(name, passed):
        checks.append({'case': name, 'passed': bool(passed)})
        if not passed: raise AssertionError(name)
    def run(argv):
        return subprocess.run([str(binary), *argv], cwd=root, env=env, input=b'', capture_output=True, timeout=120)
    def decoded(result, fmt):
        data = json.loads(result.stdout)
        if fmt == 'json': return data, data['findings']
        run = data['runs'][0]
        return run['properties'], [dict(f['properties'], type=f['ruleId']) for f in run['results']]
    def safe(result):
        return all(raw.encode() not in result.stdout + result.stderr for raw in (value, token, 'locator-private', 'owned-signed-private', 'u:private@'))
    try:
        check('identity-init', run(['identity', 'init']).returncode == 0)
        for provider in ('github', 'gitlab'):
            state['mode'] = 'normal'
            for ml in (False, True):
                for fmt in ('json', 'sarif'):
                    result = run(['cicd', provider + ':owned/app', '--max-runs=1', '--format=' + fmt, '--silence', *(['--ml'] if ml else [])])
                    meta, fs = decoded(result, fmt)
                    typed = [f for f in fs if f['type'] == 'aws_access_key_id']
                    name = f'{provider}/{ml}/{fmt}'
                    check(name + '/complete', result.returncode == 0 and meta['complete'] and bool(typed))
                    check(name + '/immutable', all(f['provenance']['commit'] == revision and f['provenance']['run_id'] == ('7' if provider == 'github' else '11') and f['provenance']['digest'] == hashlib.sha256(original).hexdigest() for f in typed))
                    check(name + '/artifact', provider != 'github' or any(f['provenance'].get('artifact_id') == '9' for f in typed))
                    check(name + '/scope', any(s['kind'] == 'cicd' for s in meta['scope']))
                    check(name + '/safe', safe(result) and all('?' not in f['provenance']['source_url'] and '@' not in f['provenance']['source_url'] for f in typed))
            for mode in ('duplicate', 'trailing', 'null', 'shape', 'empty', 'missing', 'prefix', 'oversize', 'row-limit', 'repeated-id', *(['expired'] if provider == 'github' else [])):
                state['mode'] = mode
                for fmt in ('json', 'sarif'):
                    baseline = root / f'{provider}-{mode}-{fmt}.baseline'
                    baseline.write_text('owned baseline sentinel')
                    result = run(['cicd', provider + ':owned/app', '--max-runs=2', '--format=' + fmt, '--silence', '--write-baseline=' + str(baseline), *(['--max-size=1kb'] if mode == 'oversize' else [])])
                    meta, fs = decoded(result, fmt)
                    name = f'{provider}/{mode}/{fmt}'
                    check(name + '/incomplete', result.returncode == 2 and not meta['complete'])
                    check(name + '/baseline', baseline.read_text() == 'owned baseline sentinel')
                    check(name + '/safe', safe(result))
                    if mode in ('prefix', 'oversize', 'expired'):
                        check(name + '/partial', any(f['type'] == 'aws_access_key_id' for f in fs))
        state['mode'] = 'normal'
        before = decoded(run(['cicd', 'github:owned/app', '--max-runs=1', '--logs-only', '--format=json', '--silence']), 'json')[0]
        changed = decoded(run(['cicd', 'github:owned/app', '--max-runs=1', '--logs-only', '--branch=other', '--format=json', '--silence']), 'json')[0]
        check('scope-policy-change', next(s['policy'] for s in before['scope'] if s['kind'] == 'cicd') != next(s['policy'] for s in changed['scope'] if s['kind'] == 'cicd'))
        state['mode'] = 'limit'
        before_calls = state['api_calls']
        result = run(['cicd', 'gitlab:owned/app', '--logs-only', '--max-runs=1', '--timeout=60s', '--format=json', '--silence'])
        meta, _ = decoded(result, 'json')
        check('bounded-provider-pagination', result.returncode == 2 and not meta['complete'] and any(d['code'] == 'ci_request_limit' for d in meta['diagnostics']) and state['api_calls'] - before_calls == 4096)
        state['mode'] = 'normal'
        for protocol in ('2024-11-05', '2025-03-26', '2025-06-18', '2026-07-28'):
            proc = subprocess.Popen([str(binary), 'mcp'], cwd=root, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            replies = queue.Queue()
            def read_output():
                for line in proc.stdout: replies.put(json.loads(line))
            threading.Thread(target=read_output, daemon=True).start()
            def exchange(ident, method, params):
                if protocol == '2026-07-28': params['_meta'] = {'io.modelcontextprotocol/protocolVersion': protocol, 'io.modelcontextprotocol/clientCapabilities': {}}
                proc.stdin.write((json.dumps({'jsonrpc': '2.0', 'id': ident, 'method': method, 'params': params}) + '\n').encode())
                proc.stdin.flush()
                return replies.get(timeout=60)
            try:
                exchange(1, 'server/discover' if protocol == '2026-07-28' else 'initialize', {'protocolVersion': protocol})
                for index, provider in enumerate(('github', 'gitlab')):
                    response = exchange(index + 2, 'tools/call', {'name': 'prowl_cicd', 'arguments': {'target': provider + ':owned/app'}})['result']
                    data = response['structuredContent']
                    check(protocol + '/' + provider, not response['isError'] and data['complete'] and any(f.get('provenance', {}).get('commit') == revision for f in data['findings']))
                state['mode'] = 'empty'
                response = exchange(4, 'tools/call', {'name': 'prowl_cicd', 'arguments': {'target': 'github:owned/app'}})['result']
                check(protocol + '/incomplete', response['isError'] and not response['structuredContent']['complete'])
                state['mode'] = 'normal'
            finally:
                proc.stdin.close(); proc.wait(timeout=60)
        check('forge-header-boundary', state['auth_bad'] == 0 and state['asset_calls'] > 0)
    finally:
        api.shutdown(); assets.shutdown(); api.server_close(); assets.server_close()
        api_thread.join(timeout=30); asset_thread.join(timeout=30)
        report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'passed': sum(c['passed'] for c in checks), 'total': len(checks), 'checks': checks, 'root': str(root), 'scope': 'owned GitHub/GitLab-shaped loopback APIs and asset server only; no live forge/provider use', 'requests': {k: state[k] for k in ('api_calls', 'asset_calls', 'auth_bad')}}
        (root / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({k: v for k, v in report.items() if k != 'checks'}))


if __name__ == '__main__':
    main()
