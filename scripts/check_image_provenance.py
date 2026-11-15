#!/usr/bin/env python3
"""Qualify image provenance on owned Docker-save/OCI/stdin fixtures without a daemon or registry."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import threading
from urllib.parse import unquote, urlparse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='prowl-image-provenance-native-'))
    model = Path(__file__).resolve().parents[1] / 'tool/internal/mlmodel/model_binary_go_literal_v1.json'
    key, other = 'AKIANAFGYOEYPXU1DSYP', 'AKIA4MNQ2RST7UVWX9YZ'
    env = {k: v for k, v in os.environ.items() if not k.startswith('PROWL_')}
    env.update(PROWL_HOME=str(root / 'home'), PROWL_LIVE_TEST='')
    profile = '(version 1)(allow default)(deny network*)'
    sandbox = ['/usr/bin/sandbox-exec', '-p', profile]
    checks = []

    def sha(raw): return hashlib.sha256(raw).hexdigest()
    def check(name, condition):
        assert condition, name
        checks.append({'case': name, 'passed': True})

    def tar(entries):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, body in entries:
                header = tarfile.TarInfo(name)
                header.mode, header.size = 0o600, len(body)
                archive.addfile(header, io.BytesIO(body))
        return stream.getvalue()

    def fixture(label, kind, mode='normal'):
        directory = root / label
        directory.mkdir()
        payload = ('AWS=' + key + '\n').encode()
        if mode == 'utf16': payload = b'\xff\xfe' + payload.decode().encode('utf-16le')
        entries = [('prod.env', payload)]
        if mode == 'duplicate': entries.append(('prod.env', payload + b'# second physical entry\n'))
        layers = [tar(entries)]
        if mode == 'whiteout': layers.append(tar([('.wh.prod.env', b'')]))
        cfg = {'architecture': 'arm64', 'os': 'linux', 'config': {'Env': ['AWS=' + key]},
               'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + sha(x) for x in layers]},
               'history': [{'created_by': 'RUN export SECONDARY=' + other}]
                          + [{'created_by': 'RUN rm prod.env'}] * (len(layers) - 1)}
        if mode == 'bad-diff': cfg['rootfs']['diff_ids'][0] = 'sha256:' + 'a' * 64
        config = json.dumps(cfg, separators=(',', ':')).encode()
        if kind == 'tar':
            manifest = json.dumps([{'Config': 'config.json', 'RepoTags': ['owned:fixture'],
                                    'Layers': [f'layer{n}.tar' for n in range(len(layers))]}]).encode()
            data = tar([('manifest.json', manifest), ('config.json', config)]
                       + [(f'layer{n}.tar', x) for n, x in enumerate(layers)])
            path = directory / 'image.tar'
            path.write_bytes(data)
            return path, config, layers, None, payload
        blobs = directory / 'blobs/sha256'
        blobs.mkdir(parents=True)
        def blob(data):
            digest = sha(data)
            (blobs / digest).write_bytes(data)
            return {'digest': 'sha256:' + digest, 'size': len(data)}
        descriptor = blob(config)
        descriptor['mediaType'] = 'application/vnd.oci.image.config.v1+json'
        layer_descriptors = [dict(blob(x), mediaType='application/vnd.oci.image.layer.v1.tar') for x in layers]
        manifest = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                               'config': descriptor, 'layers': layer_descriptors}, separators=(',', ':')).encode()
        entry = dict(blob(manifest), mediaType='application/vnd.oci.image.manifest.v1+json')
        (directory / 'index.json').write_text(json.dumps({'schemaVersion': 2, 'manifests': [entry]}))
        (directory / 'oci-layout').write_text('{"imageLayoutVersion":"1.0.0"}')
        if mode == 'bad-config': (blobs / sha(config)).write_bytes(config + b' ')
        if mode == 'bad-manifest': (blobs / sha(manifest)).write_bytes(manifest + b' ')
        return directory, config, layers, manifest, payload

    def run(args, data=None, cwd=None, disclose=False):
        p = subprocess.run([*sandbox, str(binary), *map(str, args)], cwd=cwd or root,
                           env=env, input=data, capture_output=True, timeout=30)
        if not disclose:
            assert key.encode() not in p.stdout + p.stderr and other.encode() not in p.stdout + p.stderr, 'raw synthetic key leaked'
        assert b'PRIVATE_' not in p.stdout + p.stderr, 'private selected input reflected'
        return p

    class Handler(BaseHTTPRequestHandler):
        calls = 0
        def log_message(self, *_): pass
        def do_GET(self):
            Handler.calls += 1
            self.send_response(200)
            self.end_headers()
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f'http://127.0.0.1:{server.server_port}/owned'
        allowed = subprocess.run(['/usr/bin/curl', '--silent', '--max-time', '2', url], capture_output=True)
        denied = subprocess.run([*sandbox, '/usr/bin/curl', '--silent', '--max-time', '2', url], capture_output=True)
        check('OS-network-denial-enforced', allowed.returncode == 0 and denied.returncode != 0 and Handler.calls == 1)
        check('identity-init', run(['identity', 'init']).returncode == 0)
        normal_tar = None
        for kind in ('tar', 'oci-dir'):
            for mode in ('normal', 'utf16', 'duplicate', 'whiteout', 'bad-diff'):
                path, config, layers, manifest, payload = fixture(kind + '-' + mode, kind, mode)
                if kind == 'tar' and mode == 'normal': normal_tar = path
                for fmt in ('json', 'sarif'):
                    for ml in (False, True):
                        flags = ['--ml', '--ml-model', model] if ml else []
                        p = run(['image', path, '--image-input', kind, '--format', fmt, *flags])
                        d = json.loads(p.stdout)
                        meta = d if fmt == 'json' else d['runs'][0]['properties']
                        fs = d['findings'] if fmt == 'json' else [dict(f['properties'], type=f['ruleId']) for f in d['runs'][0]['results']]
                        fs = [f for f in fs if f['type'] == 'aws_access_key_id']
                        complete = mode != 'bad-diff'
                        check(f'{kind}-{mode}-{fmt}-ml{ml}', p.returncode == (0 if complete else 2) and meta['complete'] == complete and bool(fs))
                        for f in fs:
                            prov = f['provenance']
                            check('config-and-image-digest-' + str(len(checks)), prov['config_digest'] == sha(config)
                                  and len(prov['image_digest']) == 64 and (manifest is None or prov['image_digest'] == sha(manifest)))
                            if prov['source_transform'] in ('image-file', 'image-text-decoded'):
                                check('raw-file-and-layer-digest-' + str(len(checks)), prov['digest'] in {sha(payload), sha(payload + b'# second physical entry\n')}
                                      and prov['layer_diff_id'] == sha(layers[0]))
                                final = f.get('in_final_image')
                                check('flatten-status-' + str(len(checks)), final is None if not complete else final == (mode != 'whiteout'))
                            check('finalized-occurrence-' + str(len(checks)), bool(f.get('occurrence_id')) and not f.get('instruction'))
                        if fmt == 'sarif':
                            uris = [f['locations'][0]['physicalLocation']['artifactLocation']['uri'] for f in d['runs'][0]['results']]
                            check('source-declared-URI-' + str(len(checks)), all(urlparse(u).scheme == ('image+file' if kind == 'tar' else 'image+oci')
                                  and unquote(urlparse(u).path) == str(path) for u in uris))
                        elif mode == 'duplicate':
                            files = [f for f in fs if f['provenance']['source_transform'] == 'image-file']
                            occurrences = files[0].get('occurrences', [])
                            check('duplicate-physical-observations-' + str(len(checks)), len(files) == 1 and len(occurrences) == 2
                                  and occurrences[0]['id'] != occurrences[1]['id'] and len({o['provenance']['digest'] for o in occurrences}) == 2)
        for n in range(2):
            p = run(['image', '-', '--image-input=stdin', '--format=json'], data=normal_tar.read_bytes())
            d = json.loads(p.stdout)
            check('stdin-acquisition-' + str(n), p.returncode == 0 and d['complete'])
            fingerprints = sorted((f['fingerprint'], f.get('occurrence_id')) for f in d['findings'])
            if n == 0: first_stdin = fingerprints
            else: check('stdin-spool-independent-identity', fingerprints == first_stdin)
        p = run(['image', normal_tar, '--show-secrets', '--format=json'], disclose=True)
        d = json.loads(p.stdout)
        check('explicit-instruction-disclosure', p.returncode == 0 and d['secrets_revealed']
              and any(other in f.get('instruction', '') for f in d['findings']))
        for mode in ('bad-config', 'bad-manifest'):
            path, *_ = fixture(mode, 'oci-dir', mode)
            for fmt in ('json', 'sarif'):
                baseline = root / (mode + '-' + fmt + '-baseline.json')
                baseline.write_text('owned baseline sentinel')
                p = run(['image', path, '--image-input=oci-dir', '--format', fmt, '--write-baseline', baseline])
                d = json.loads(p.stdout)
                meta = d if fmt == 'json' else d['runs'][0]['properties']
                check(mode + '-' + fmt + '-incomplete-baseline', p.returncode == 2 and not meta['complete'] and baseline.read_text() == 'owned baseline sentinel')
        for target, kind in [(root / 'missing.tar', 'tar'), ('https://alice:PRIVATE_AUTH@owned.invalid/image?sig=PRIVATE_QUERY', 'ref')]:
            p = run(['image', target, '--image-input', kind, '--format=json'])
            d = json.loads(p.stdout)
            check('safe-acquisition-failure-' + str(len(checks)), p.returncode == 2 and not d['complete']
                  and any(x['code'] == 'image_acquisition_failed' for x in d['diagnostics']))
        index = root / 'index'
        for n in range(2):
            p = run(['image', root / 'tar-duplicate/image.tar', '--index', index, '--scope=owned-image', '--format=json'])
            check('index-duplicate-scan-' + str(n), p.returncode == 0)
        p = run(['index', '--index', index, '--format=json'])
        d = json.loads(p.stdout)
        # Index paths are synthetic URIs; the physical entry ordinal is private.
        positions = [p for s in d['secrets'] for p in s['locations'] if '/layer/' in urlparse(p['path']).fragment]
        check('index-separates-duplicate-entries', len(positions) == 2 and positions[0]['id'] != positions[1]['id'])
        evidence = {'binary': str(binary), 'binary_sha256': sha(binary.read_bytes()), 'model_sha256': sha(model.read_bytes()),
                    'fixture_root': str(root), 'passed': len(checks), 'failed': 0, 'checks': checks,
                    'network_control': {'profile': profile, 'owned_requests': Handler.calls, 'blocked_exit': denied.returncode},
                    'scope': 'Owned Docker-save/OCI-directory/stdin fixtures; raw/config/manifest/full-layer hashes, metadata mismatch, duplicate TAR, whiteout, UTF16, ML, JSON/SARIF, index and disclosure. No Docker daemon, registry or deployment.'}
        (root / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
        print(json.dumps({'passed': len(checks), 'evidence': str(root / 'evidence.json')}))
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == '__main__': main()
