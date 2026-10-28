"""Приёмка pragma/evidence/semantic через реальный CLI на собственных данных."""
import argparse
import base64
import hashlib
import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--binary', type=Path, required=True)
    ap.add_argument('--output-dir', type=Path, required=True)
    args = ap.parse_args()
    root = args.output_dir.resolve()
    root.mkdir(parents=True, exist_ok=False)
    binary = args.binary.resolve()
    env = {**os.environ, 'PROWL_HOME': str(root / 'home'), 'NO_COLOR': '1'}
    key = '\x41KIANAFGYOEYPXU1DSYP'
    github = '\x67hp_kP9aZ2bYwcX4dWqeV8fUmgThS6iRnj2XYtQi'
    jwt = '\x65yJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmNkZWZnIn0.dozjgNryP4Jq3mNHl9wYZQ'
    encoded = base64.b64encode(github.encode()).decode()
    cases = [
        ('quoted_marker', 'js', f'key="{key}"; note="// prowl:allow"', 'aws_access_key_id', False),
        ('triple_marker', 'py', f"note='''\n# prowl:allow {key}\n'''", 'aws_access_key_id', False),
        ('template_marker', 'js', f'note=`\n// gitleaks:allow {key}\n`', 'aws_access_key_id', False),
        ('json_marker', 'json', '{"key":"' + key + '","note":"# prowl:allow"}', 'aws_access_key_id', False),
        ('json_escape_marker', 'json', '{"key":"\\u0041' + key[1:] + '","note":"# prowl:allow"}', 'aws_access_key_id', False),
        ('toml_marker', 'toml', "auth={key='" + key + "',note='# prowl:allow'}", 'aws_access_key_id', False),
        ('toml_triple_marker', 'toml', "note='''\n# prowl:allow " + key + "\n'''", 'aws_access_key_id', False),
        ('env_foreign_comment', 'env', f'key={key} // prowl:allow', 'aws_access_key_id', False),
        ('env_foreign_block', 'env', f'key={key} /* prowl:allow */', 'aws_access_key_id', False),
        ('marker_suffix', 'env', f'key={key} # prowl:allowed', 'aws_access_key_id', False),
        ('marker_prefix', 'env', f'key={key} # xprowl:allow', 'aws_access_key_id', False),
        ('allow_env', 'env', f'key={key} # prowl:allow', None, True),
        ('allow_python', 'py', f'key="{key}" # prowl:allow', None, True),
        ('allow_js', 'js', f'key="{key}"; /* gitleaks:allow */', None, True),
        ('allow_toml', 'toml', "key='" + key + "' # prowl:allow", None, True),
        ('allow_toml_slash', 'toml', "password='Winter42\\' # prowl:allow", None, True),
        ('allow_sql', 'sql', f"key='{key}' -- noqa: secret", None, True),
        ('allow_html', 'html', key + ' <!-- pragma: allowlist secret -->', None, True),
        ('allow_ini', 'ini', '; prowl:allow key=' + key, None, True),
        ('checksum_comment', 'env', '# token=' + github, 'github_pat_classic', False),
        ('checksum_encoded_comment', 'env', '# payload=' + encoded, 'github_pat_classic', False),
        ('jwt_structure', 'env', 'payload=' + jwt, 'jwt', False),
        ('jwt_truncated_signature', 'env', 'payload=' + jwt[:-1], None, False),
    ]
    runs = []
    for index, (name, suffix, text, typ, filtered) in enumerate(cases):
        path = root / (name + '.' + suffix)
        path.write_text(text, encoding='utf-8', newline='\n')
        for ml in (False, True):
            command = [str(binary), 'scan', str(path), '--strict', '--format', 'json']
            if ml:
                command.append('--ml')
            p = subprocess.run(command, env=env, capture_output=True, encoding='utf-8', timeout=30)
            report = json.loads(p.stdout)
            (root / f'{index}-{ml}.json').write_text(p.stdout, encoding='utf-8')
            assert p.returncode == 0 and report['complete'] and report['filtered'] == filtered, name
            fs = report['findings']
            assert len(fs) == (1 if typ else 0) and (not typ or fs[0]['type'] == typ), name
            if typ == 'github_pat_classic':
                assert fs[0]['severity'] == 'high' and 'checksum' in fs[0]['stage'], name
            if typ == 'jwt':
                assert fs[0]['stage'] == 'L1-structure' and fs[0]['confidence'] < .99 and fs[0].get('verified') is None
            runs.append({'case': name, 'ml': ml, 'passed': True})

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            text = data['messages'][-1]['content']
            if 'FAILED_ONLY' in text:
                self.send_response(503)
                self.end_headers()
                return
            value = '"WRAPPER_ONLY": "' if 'WRAPPER_ONLY' in text else 'tulip-moon'
            start = text.index(value)
            candidates = [{'value': value, 'start': start, 'end': start + len(value)}]
            payload = {'choices': [{'finish_reason': 'stop', 'message': {'content': json.dumps({'candidates': candidates})}}]}
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for name, suffix, text, expected in [
            ('semantic_json', 'json', r'{"note":"tulip\u002dmoon"}', 1),
            ('semantic_toml', 'toml', r'note="tulip\u002dmoon"', 1),
            ('semantic_yaml', 'yaml', r'note: "tulip\u002dmoon"', 1),
            ('semantic_wrapper', 'toml', 'WRAPPER_ONLY="ordinary-value"', 0),
            ('semantic_failure', 'toml', 'FAILED_ONLY="ordinary-value"', -1),
        ]:
            path = root / (name + '.' + suffix)
            path.write_text(text, encoding='utf-8')
            command = [str(binary), 'scan', str(path), '--strict', '--semantic', '--semantic-url',
                       f'http://127.0.0.1:{server.server_port}/v1/chat/completions', '--format', 'json']
            p = subprocess.run(command, env=env, capture_output=True, encoding='utf-8', timeout=30)
            report = json.loads(p.stdout)
            (root / (name + '.report.json')).write_text(p.stdout, encoding='utf-8')
            if expected == -1:
                assert p.returncode == 2 and not report['complete']
                assert any(d['code'] == 'semantic_failed' for d in report['diagnostics'])
            else:
                assert p.returncode == 0 and report['complete'] and len(report['findings']) == expected, name
                if expected:
                    f = report['findings'][0]
                    assert f['type'] == 'generic_semantic_secret' and f.get('verified') is None
                    spans = [e for e in f['evidence'] if e['transform'] == 'literal-semantic-span']
                    assert len(spans) == 1 and len(f['evidence']) == 2
                    raw = text.encode()[spans[0]['start']:spans[0]['end']]
                    assert raw == b'tulip\\u002dmoon'
            runs.append({'case': name, 'passed': True})
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    evidence = {'version': '1.4.0', 'cases': len(cases) + 5, 'checks': len(runs), 'runs': runs,
                'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                'boundary': 'Own synthetic data and loopback semantic mock. No provider verification or external targets. Semantic checks use default L2 settings.',
                'inputs_retained': str(root)}
    (root / 'pipeline-evidence.json').write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in evidence.items() if k != 'runs'}, indent=2))


if __name__ == '__main__':
    main()
