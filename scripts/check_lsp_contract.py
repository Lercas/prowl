#!/usr/bin/env python3
"""Qualify real LSP stdio diagnostics, ranges and lifecycle on disposable local data."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading


def position(text, offset):
    prefix = text[:offset].replace('\r\n', '\n').replace('\r', '\n')
    return {'line': prefix.count('\n'), 'character': len(prefix.rsplit('\n', 1)[-1].encode('utf-16-le')) // 2}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    repo = Path(__file__).resolve().parents[1]
    root = Path(tempfile.mkdtemp(prefix='prowl-lsp-native-'))
    (root / 'home').mkdir()
    env = dict(os.environ, PROWL_HOME=str(root / 'home'))
    checks = []
    corpus_counts = {'positive': 0, 'negative': 0, 'ambiguous': 0}
    stderr = (root / 'stderr.log').open('wb')
    proc = subprocess.Popen([str(binary), 'lsp'], cwd=root, env=env, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=stderr)
    messages = queue.Queue()

    def reader():
        try:
            while True:
                headers = {}
                while line := proc.stdout.readline():
                    if line == b'\r\n':
                        break
                    key, value = line.decode().split(':', 1)
                    headers[key.lower()] = value.strip()
                if not line:
                    return
                size = int(headers['content-length'])
                data = proc.stdout.read(size)
                if len(data) != size:
                    raise RuntimeError('short LSP frame')
                messages.put(json.loads(data))
        except Exception as exc:
            messages.put(exc)
    threading.Thread(target=reader, daemon=True).start()

    def send(method, params=None, ident=None):
        msg = {'jsonrpc': '2.0', 'method': method}
        if params is not None:
            msg['params'] = params
        if ident is not None:
            msg['id'] = ident
        data = json.dumps(msg, ensure_ascii=False).encode()
        proc.stdin.write(f'Content-Length: {len(data)}\r\n\r\n'.encode() + data)
        proc.stdin.flush()

    def receive():
        result = messages.get(timeout=20)
        if isinstance(result, Exception):
            raise result
        return result

    def check(name, condition):
        checks.append({'name': name, 'passed': bool(condition)})
        if not condition:
            raise AssertionError(name)

    def open_doc(name, path, text):
        uri = f'file:///workspace/{name}/{path}'
        send('textDocument/didOpen', {'textDocument': {'uri': uri, 'languageId': 'plaintext', 'version': 1, 'text': text}})
        msg = receive()
        check(name + '/publication', msg.get('method') == 'textDocument/publishDiagnostics' and msg['params']['uri'] == uri)
        return uri, msg['params']['diagnostics']

    def close_doc(uri):
        send('textDocument/didClose', {'textDocument': {'uri': uri}})
        msg = receive()
        check(uri + '/close', msg.get('method') == 'textDocument/publishDiagnostics' and msg['params'] == {'uri': uri, 'diagnostics': []})

    try:
        send('initialize', {'processId': None, 'rootUri': None, 'capabilities': {}}, 1)
        msg = receive()
        check('initialize', msg.get('id') == 1 and msg['result']['capabilities']['textDocumentSync']['change'] == 1)
        send('initialized', {})
        corpus_counts = {'positive': 0, 'negative': 0, 'ambiguous': 0}
        for fixture in ('noise-1.4.0.json', 'noise-deep-1.4.0.json'):
            for i, case in enumerate(json.loads((repo / 'tool/internal/lsp/testdata' / fixture).read_text())):
                truth = case['truth']
                corpus_counts[truth] += 1
                if truth == 'ambiguous':
                    continue
                name = f'{fixture}/{i}'
                uri, diags = open_doc(name, case['path'], case['text'])
                if truth == 'negative':
                    check(name + '/negative', diags == [])
                else:
                    value = case['value']
                    offset = case['text'].index(value)
                    expected = {'start': position(case['text'], offset), 'end': position(case['text'], offset + len(value))}
                    check(name + '/redaction', all(value not in d['message'] for d in diags))
                    def matches(d):
                        msg = d['message']
                        types = any(f'possible secret: {typ} (' in msg for typ in case['types'])
                        types |= 'generic_high_entropy' in case['types'] and 'possible secret: generic_api_key (' in msg and 'L1-context-key' in msg
                        return d['range'] == expected and types
                    check(name + '/exact-range-type', any(matches(d) for d in diags))
                close_doc(uri)
        value = 'AKIANAFGYOEYPXU1DSYP'
        blob = base64.b64encode(value.encode()).decode()
        for i, (path, text, source) in enumerate([
            ('payload.env', '# 🔐\npayload="' + blob + '"', blob),
            ('config.json', '{"пароль":"Winter\\u0034\\u0032!Autumn"}', 'Winter\\u0034\\u0032!Autumn'),
            ('alias.yaml', 'definition: &a Winter42!Autumn\npassword: *a\n', '*a'),
            ('production.json', '\ufeff{\r"password":"Winter42!Autumn"}', 'Winter42!Autumn'),
        ]):
            uri, ds = open_doc(f'encoded/{i}', path, text)
            offset = text.index(source)
            expected = {'start': position(text, offset), 'end': position(text, offset + len(source))}
            check(f'encoded/{i}/range', len(ds) == 1 and ds[0]['range'] == expected)
            close_doc(uri)
        uri, ds = open_doc('lifecycle', 'production.env', 'PASSWORD="Winter42!Autumn"')
        check('lifecycle/open', len(ds) == 1)
        send('textDocument/didChange', {'textDocument': {'uri': uri, 'version': 2}, 'contentChanges': [{'text': 'nothing here'}]})
        msg = receive()
        check('lifecycle/change-clears', msg['params']['diagnostics'] == [])
        send('textDocument/didSave', {'textDocument': {'uri': uri}, 'text': 'PASSWORD="Winter42!Autumn" # prowl:allow'})
        msg = receive()
        check('lifecycle/save-pragma', msg['params']['diagnostics'] == [])
        close_doc(uri)
        uri, ds = open_doc('oversize', 'production.txt', 'x' * ((10 << 20) + 1))
        check('oversize/warning', len(ds) == 1 and ds[0].get('code') == 'document_too_large')
        close_doc(uri)
        send('shutdown', ident=2)
        check('shutdown', receive() == {'jsonrpc': '2.0', 'id': 2, 'result': None})
        send('exit')
        proc.stdin.close()
        check('exit', proc.wait(timeout=20) == 0)
        rules = root / 'home/rules'
        rules.mkdir()
        (rules / 'broken.yaml').write_text('not: [valid')
        broken = subprocess.run([str(binary), 'lsp'], cwd=root, env=env, input=b'', capture_output=True, timeout=20)
        check('corrupt-overlay/fail-closed', broken.returncode != 0 and not broken.stdout)
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=20)
        stderr.close()
        report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'checks': checks,
                  'passed': sum(c['passed'] for c in checks), 'total': len(checks), 'corpus': corpus_counts,
                  'scope': 'local real stdio; no ML, OCR or live-provider qualification', 'root': str(root)}
        (root / 'qualification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps({k: v for k, v in report.items() if k != 'checks'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
