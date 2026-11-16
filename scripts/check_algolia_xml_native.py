#!/usr/bin/env python3
"""Qualify literal Algolia XML/plist in APK/IPA under an OS network deny."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import zipfile

KEY = '13ad45b4d0a2f6ea65ecbddf6aa260f2'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    # A sandbox must block even a local bind, before fixtures or provider probes.
    with socket.socket() as probe:
        try:
            probe.bind(('127.0.0.1', 0))
        except PermissionError:
            pass
        else:
            raise RuntimeError('Run with an OS network deny; loopback bind succeeded')
    root = Path(tempfile.mkdtemp(prefix='prowl-algolia-xml-native-'))
    model = Path(__file__).resolve().parents[1] / 'tool/internal/mlmodel/model_binary_go_literal_v1.json'
    env = {k: v for k, v in os.environ.items() if not k.startswith('PROWL_')}
    env.update(PROWL_HOME=str(root / 'home'), PROWL_LIVE_TEST='')
    checks = []

    def check(case, ok):
        assert ok, case
        checks.append({'case': case, 'passed': True})

    for extension in ('apk', 'ipa'):
        resource = '<resources><string name="algolia_app_id">ABCDEF1234</string><string name="algolia_api_key">' + KEY + '</string></resources>'
        plist = '<plist version="1.0"><dict><key>algolia_app_id</key><string>ABCDEF1234</string><key>algolia_api_key</key><string>' + KEY + '</string></dict></plist>'
        text = resource if extension == 'apk' else plist
        member = 'res/values/strings.xml' if extension == 'apk' else 'Payload/App.app/Info.plist'
        closing = '</resources>' if extension == 'apk' else '</dict>'
        duplicate = '<string name="algolia_app_id">ZZZZZZ9999</string>' if extension == 'apk' else '<key>algolia_app_id</key><string>ZZZZZZ9999</string>'
        cases = {
            'literal': (text, True, True),
            'entity': (text.replace(KEY, KEY.replace('1', '&#49;', 1)), True, True),
            'cdata': (text.replace(KEY, '<![CDATA[' + KEY + ']]>'), True, True),
            'comment-split': (text.replace(KEY, KEY[:8] + '<!-- ignored -->' + KEY[8:]), True, True),
            'duplicate-app': (text.replace(closing, duplicate + closing), False, True),
            'missing-app': (text.replace('algolia_app_id', 'other_app_id'), False, True),
            'malformed': (text + 'broken', False, False),
        }
        if extension == 'apk':
            cases['reference'] = (text.replace(KEY, '@string/other'), False, False)
        for name, (source, bound, nominated) in cases.items():
            archive = root / (name + '.' + extension)
            with zipfile.ZipFile(archive, 'w') as z:
                z.writestr(member, source)
            for fmt in ('json', 'sarif'):
                for ml in (False, True):
                    label = f'{extension}-{name}-{fmt}-ml{ml}'
                    baseline = root / (label + '.baseline')
                    sentinel = b'owned baseline must remain unchanged'
                    baseline.write_bytes(sentinel)
                    args = [str(binary), 'mobile', str(archive), '--audit-public', '--authorized', '--format=' + fmt,
                            '--silence', '--workers=1', '--max-per-file=0', '--write-baseline', str(baseline)]
                    if ml:
                        args += ['--ml', '--ml-model', str(model)]
                    p = subprocess.run(args, env=env, cwd=root, capture_output=True, timeout=40)
                    (root / (label + '.stdout')).write_bytes(p.stdout)
                    (root / (label + '.stderr')).write_bytes(p.stderr)
                    check(label + '-exit2', p.returncode == 2)
                    check(label + '-baseline', baseline.read_bytes() == sentinel)
                    check(label + '-redacted', KEY.encode() not in p.stdout + p.stderr)
                    report = json.loads(p.stdout)
                    if fmt == 'json':
                        rows, complete = report['findings'], report['complete']
                    else:
                        run = report['runs'][0]
                        rows = [dict(r['properties'], type=r['ruleId']) for r in run['results']]
                        complete = run['properties']['complete']
                    found = [f for f in rows if f['type'] == 'algolia-api-key']
                    check(label + '-coverage', complete is False)
                    check(label + '-nomination', len(found) == int(nominated))
                    if nominated:
                        audit = found[0]['public_key_audit']
                        check(label + '-inconclusive', audit['status'] == 'inconclusive')
                        reason = 'audit transport failed' if bound else 'missing or ambiguous application binding'
                        check(label + '-binding', audit.get('reason') == reason)
                        check(label + '-separate', not found[0].get('verified') and not found[0].get('verification'))
            # An ordinary scan must not gain the opt-in nomination.
            p = subprocess.run([str(binary), 'mobile', str(archive), '--format=json', '--silence'], env=env, cwd=root, capture_output=True, timeout=40)
            report = json.loads(p.stdout)
            check(f'{extension}-{name}-default', all(f['type'] != 'algolia-api-key' for f in report['findings']))
        disabled = root / ('disabled-' + extension + '.yaml')
        disabled.write_text('detectors:\n  disable: [algolia-api-key]\n')
        p = subprocess.run([str(binary), 'mobile', str(root / ('literal.' + extension)), '--audit-public', '--authorized', '--config', str(disabled), '--format=json', '--silence'], env=env, cwd=root, capture_output=True, timeout=40)
        report = json.loads(p.stdout)
        check(extension + '-disabled-rule', p.returncode == 0 and report['complete'] and all(f['type'] != 'algolia-api-key' for f in report['findings']))
        # --disable is an existing report filter; it preserves incomplete audit coverage.
        p = subprocess.run([str(binary), 'mobile', str(root / ('literal.' + extension)), '--audit-public', '--authorized', '--disable=algolia-api-key', '--format=json', '--silence'], env=env, cwd=root, capture_output=True, timeout=40)
        report = json.loads(p.stdout)
        check(extension + '-report-filter-keeps-incomplete', p.returncode == 2 and not report['complete'] and all(f['type'] != 'algolia-api-key' for f in report['findings']))
    evidence = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                'model_sha256': hashlib.sha256(model.read_bytes()).hexdigest(), 'network': 'OS deny, checked by loopback bind',
                'checks': checks, 'passed': True, 'scope': 'Synthetic APK/IPA; no live provider response or production acceptance.'}
    output = root / 'evidence.json'
    output.write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps({'passed': len(checks), 'evidence': str(output)}))


if __name__ == '__main__':
    main()
