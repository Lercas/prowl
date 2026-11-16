"""Приёмка настоящих LSP/HTTP/doctor процессов на собственных loopback-входах."""
import argparse
import hashlib
import json
import os
import queue
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    root = args.output_dir.resolve()
    root.mkdir(parents=True, exist_ok=False)
    binary = str(args.binary.resolve())
    env = {**os.environ, 'PROWL_HOME': str(root / 'home'), 'NO_COLOR': '1'}
    checks = []
    value = '83ea947bc2567d10a5f390c2eb468d91'
    content = json.dumps({'assemblyai': {'api_key': value}})
    with (root / 'lsp.stderr').open('wb') as errors:
        proc = subprocess.Popen([binary, 'lsp'], cwd=root, env=env, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=errors)
        messages = queue.Queue()

        def read_messages(proc=proc):
            while True:
                line = proc.stdout.readline()
                if not line:
                    return
                if not line.lower().startswith(b'content-length:'):
                    continue
                length = int(line.split(b':', 1)[1])
                assert proc.stdout.readline() == b'\r\n'
                messages.put(json.loads(proc.stdout.read(length)))

        threading.Thread(target=read_messages, daemon=True).start()

        def send(message):
            body = json.dumps({'jsonrpc': '2.0', **message}).encode()
            proc.stdin.write(f'Content-Length: {len(body)}\r\n\r\n'.encode() + body)
            proc.stdin.flush()

        try:
            send({'id': 1, 'method': 'initialize', 'params': {
                'processId': None, 'rootUri': None, 'capabilities': {}}})
            initialized = messages.get(timeout=10)
            assert initialized['id'] == 1 and 'result' in initialized and 'error' not in initialized
            send({'method': 'initialized', 'params': {}})
            send({'method': 'textDocument/didOpen', 'params': {'textDocument': {
                'uri': 'file:///production.json', 'languageId': 'json', 'version': 1, 'text': content}}})
            diagnostic = messages.get(timeout=10)
            findings = diagnostic['params']['diagnostics']
            assert len(findings) == 1 and 'assemblyai-api-key' in findings[0]['message']
            assert value not in json.dumps(diagnostic)
            checks.append({'case': 'actual_lsp_bundled_typed_namespace_and_redaction', 'passed': True})
            send({'id': 2, 'method': 'shutdown'})
            shutdown = messages.get(timeout=10)
            assert shutdown['id'] == 2 and 'result' in shutdown and 'error' not in shutdown
            send({'method': 'exit'})
            proc.wait(timeout=5)
            assert proc.returncode == 0
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)

    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    address = f'http://127.0.0.1:{port}'
    with (root / 'serve.stderr').open('wb') as errors:
        proc = subprocess.Popen([binary, 'serve', '--addr', f'127.0.0.1:{port}'],
                                cwd=root, env=env, stdout=subprocess.DEVNULL, stderr=errors)

        def request(path, body=None):
            data = body.encode() if isinstance(body, str) else body
            req = urllib.request.Request(address + path, data=data,
                                         headers={'Content-Type': 'application/json'})
            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    body = response.read()
                    data = json.loads(body) if response.headers.get_content_type() == 'application/json' else body.decode()
                    return response.status, data
            except urllib.error.HTTPError as error:
                return error.code, json.loads(error.read())

        try:
            deadline = time.monotonic() + 10
            while True:
                try:
                    assert request('/healthz')[0] == 200
                    break
                except urllib.error.URLError:
                    assert proc.poll() is None and time.monotonic() < deadline
                    time.sleep(.05)
            status, caps = request('/capabilities')
            assert status == 200 and caps['redacted'] and caps['stages']['rules']
            assert not caps['stages']['verification'] and not caps['stages']['ml']
            checks.append({'case': 'worker_capabilities', 'passed': True})
            status, report = request('/scan', json.dumps({'path': 'production.json', 'content': content}))
            assert status == 200 and report['complete'] and report['findings'][0]['type'] == 'assemblyai-api-key'
            assert value not in json.dumps(report)
            assert {'rules', 'detection_policy', 'http-input'} <= {s['kind'] for s in report['scope']}
            checks.append({'case': 'worker_typed_redacted_scoped_result', 'passed': True})
            for index, body in enumerate(['null', '{}', '{"content":null}',
                                          '{"content":"clean","verify":true}',
                                          '{"content":"credential","content":"clean"}',
                                          '{"content":"clean"} {"content":"credential"}',
                                          r'{"content":"password=\ud800Winter42"}',
                                          r'{"content":"password=\udc00Winter42"}',
                                          r'{"content":"clean","path":"\ud800"}',
                                          b'{"content":"password=\xffWinter42"}']):
                assert request('/scan', body)[0] == 400
                checks.append({'case': f'worker_rejects_ambiguous_intake_{index}', 'passed': True})
            status, report = request('/scan', r'{"content":"password=Winter42\ud83d\ude80","path":"unicode.env"}')
            assert status == 200 and report['complete'] and any(f['type'] == 'generic_password' for f in report['findings'])
            checks.append({'case': 'worker_preserves_valid_transport_surrogate_pair', 'passed': True})
            status, report = request('/scan/batch', '[]')
            assert status == 200 and report['complete'] and len(report['scope']) >= 2
            checks.append({'case': 'empty_batch_has_policy', 'passed': True})
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)

    bad_home = root / 'bad-home'
    for name in ('rules', 'verifiers'):
        directory = bad_home / name
        directory.mkdir(parents=True)
        (directory / 'broken.yaml').write_text('not: [valid', encoding='utf-8')
    for command, expected in [('doctor', 1), ('lsp', 2), ('serve', 2)]:
        result = subprocess.run([binary, command], cwd=root, env={**env, 'PROWL_HOME': str(bad_home)},
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == expected, command
        checks.append({'case': command + '_rejects_corrupt_overlay', 'passed': True})
    selected_env = {**env, 'PROWL_HOME': str(bad_home)}
    initialized = subprocess.run([binary, 'identity', 'init'], cwd=root, env=selected_env,
                                 capture_output=True, text=True, timeout=10)
    assert initialized.returncode == 0
    old_bytes = {str(p.relative_to(bad_home)): p.read_bytes() for p in bad_home.rglob('*') if p.is_file()}
    item = root / 'production.json'
    item.write_text(content, encoding='utf-8')
    result = subprocess.run([binary, 'scan', item, '--bundled', '--strict', '--format', 'json'],
                            cwd=root, env=selected_env, capture_output=True, text=True, timeout=10)
    report = json.loads(result.stdout)
    assert result.returncode == 0 and report['findings'][0]['type'] == 'assemblyai-api-key'
    assert report['findings'][0]['secret_id']
    for command in ('doctor', 'version'):
        result = subprocess.run([binary, command, '--bundled'], cwd=root, env=selected_env,
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0 and '175' in result.stdout and '84' in result.stdout
    assert old_bytes == {str(p.relative_to(bad_home)): p.read_bytes() for p in bad_home.rglob('*') if p.is_file()}
    checks.append({'case': 'explicit_bundled_scan_doctor_version_preserve_installed_sets', 'passed': True})
    calls = [{'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}},
             {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': 'prowl_scan',
              'arguments': {'path': str(item), 'bundled': True, 'strict': True}}}]
    with (root / 'mcp.stderr').open('w') as errors:
        proc = subprocess.Popen([binary, 'mcp'], cwd=root, env=selected_env,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors, text=True)
        replies_queue = queue.Queue()

        def read_replies(proc=proc):
            for line in proc.stdout:
                replies_queue.put(json.loads(line))

        threading.Thread(target=read_replies, daemon=True).start()
        try:
            proc.stdin.write(''.join(json.dumps(c) + '\n' for c in calls))
            proc.stdin.flush()
            replies = [replies_queue.get(timeout=10), replies_queue.get(timeout=10)]
            proc.stdin.close()
            proc.wait(timeout=5)
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)
    tool = next(r['result'] for r in replies if r['id'] == 2)
    assert not tool.get('isError') and tool['structuredContent']['complete']
    assert tool['structuredContent']['findings'][0]['secret_id'] == report['findings'][0]['secret_id']
    checks.append({'case': 'actual_mcp_bundled_preserves_organization_identity', 'passed': True})
    for flag in ('--verify', '--ml', '--semantic', '--reconstruct'):
        result = subprocess.run([binary, 'serve', flag], cwd=root, env=env,
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 2, flag
        checks.append({'case': 'serve_rejects_' + flag, 'passed': True})
    evidence = {'binary_sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(), 'checks': checks,
                'passed': True, 'boundary': 'Owned inputs/processes, loopback only. No provider calls.',
                'inputs_retained': str(root)}
    (root / 'interfaces.json').write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'checks_passed': len(checks), 'passed': True}))


if __name__ == '__main__':
    main()
