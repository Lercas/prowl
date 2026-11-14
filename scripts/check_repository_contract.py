#!/usr/bin/env python3
"""Qualify repository snapshot provenance using local Git objects and owned forge inventory."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import tempfile
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    real_git = shutil.which('git')
    if not real_git: raise RuntimeError('Git required')
    root = Path(tempfile.mkdtemp(prefix='prowl-repository-native-'))
    (root / 'home').mkdir(); (root / 'bin').mkdir()
    origin, empty = root / 'origin', root / 'empty'
    origin.mkdir(); empty.mkdir()
    values = ['AKIANAFGYOEYPXU1DSYP', 'AKIA4ZX9QJ7K2MNPL3RS']
    def git(cwd, *argv, input=None):
        return subprocess.check_output([real_git, '-c', 'core.hooksPath=/dev/null', *argv], cwd=cwd, text=True, stderr=subprocess.PIPE, input=input).strip()
    for repo in (origin, empty):
        git(repo, 'init', '-q', '-b', 'main'); git(repo, 'config', 'user.name', 'Owned Fixture'); git(repo, 'config', 'user.email', 'fixture@example.invalid')
    heads = []
    for index, value in enumerate(values):
        (origin / 'prod.env').write_text('AWS=' + value + '\n')
        git(origin, 'add', 'prod.env'); git(origin, 'commit', '-qm', 'test: owned snapshot ' + str(index))
        heads.append(git(origin, 'rev-parse', 'HEAD'))
    blobs = {git(origin, 'rev-parse', revision + ':prod.env') for revision in heads}
    wrapper = root / 'bin/git'
    wrapper.write_text('#!' + sys.executable + '\n' + "import os,sys\nfrom pathlib import Path\nargs=sys.argv[1:]\nif 'clone' in args:\n    origin=os.environ['PROWL_EMPTY_ORIGIN'] if 'empty.git' in args[-2] else os.environ['PROWL_FIXTURE_ORIGIN']\n    args[-2]=Path(origin).as_uri()\nelif 'HEAD^{commit}' in args:\n    if os.environ.get('PROWL_REPO_MODE')=='invalid':\n        print('OWNED_PRIVATE_INVALID_REVISION');print('OWNED_PRIVATE_DIAGNOSTIC',file=sys.stderr);sys.exit(0)\n    if os.environ.get('PROWL_REPO_MODE')=='warning':print('OWNED_PRIVATE_DIAGNOSTIC',file=sys.stderr)\nreal=os.environ['PROWL_REAL_GIT']\nos.execv(real,[real,'-c','core.hooksPath=/dev/null',*args])\n")
    wrapper.chmod(0o755)
    state = {'url': 'https://owned.invalid/app.git', 'mode': 'normal'}
    class API(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            self.send_response(200); self.end_headers()
            if state['mode'] == 'mixed': data = [{'clone_url': 'ext::invalid'}, {'clone_url': state['url']}]
            else: data = [{'clone_url': state['url']}]
            self.wfile.write(json.dumps(data).encode())
    server = ThreadingHTTPServer(('127.0.0.1', 0), API)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    env = dict(os.environ, PROWL_HOME=str(root / 'home'), PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'], PROWL_REAL_GIT=real_git,
               PROWL_FIXTURE_ORIGIN=str(origin), PROWL_EMPTY_ORIGIN=str(empty), PROWL_REPO_MODE='normal', GITHUB_TOKEN='',
               GITHUB_API=f'http://127.0.0.1:{server.server_port}', PROWL_ALLOW_PRIVATE_IPS='1')
    checks = []
    def check(name, passed):
        checks.append({'case': name, 'passed': bool(passed)})
        if not passed: raise AssertionError(name)
    calls = 0
    def run(argv):
        nonlocal calls
        calls += 1
        result = subprocess.run([str(binary), *argv], cwd=root, env=env, input=b'', capture_output=True, timeout=60)
        (root / f'case-{calls:03}.stdout').write_bytes(result.stdout)
        (root / f'case-{calls:03}.stderr').write_bytes(result.stderr)
        return result
    def decoded(result, fmt):
        data=json.loads(result.stdout)
        if fmt=='json': return data,data['findings']
        run=data['runs'][0]
        return run['properties'],[dict(f['properties'],type=f['ruleId'],artifact_uri=f['locations'][0]['physicalLocation']['artifactLocation']['uri']) for f in run['results']]
    def safe(result):
        return all(raw.encode() not in result.stdout + result.stderr for raw in (*values,'query-private','user-private','OWNED_PRIVATE_INVALID_REVISION','OWNED_PRIVATE_DIAGNOSTIC','prowl-repo-'))
    try:
        check('identity',run(['identity','init']).returncode==0)
        for command in ('repo','org'):
            url='https://u:user-private@owned.invalid/app.git?token=query-private'
            state['url']=url
            for history in (False,True):
                policies=[]
                for ml in (False,True):
                    for fmt in ('json','sarif'):
                        target=url if command=='repo' else 'github:owned'
                        result=run([command,target,'--format='+fmt,'--silence',*(['--history'] if history else []),*(['--ml'] if ml else [])])
                        meta,fs=decoded(result,fmt); typed=[f for f in fs if f['type']=='aws_access_key_id']
                        name=f'{command}/{history}/{ml}/{fmt}'
                        check(name+'/complete',result.returncode==0 and meta['complete'] and len(typed)==(2 if history else 1))
                        check(name+'/provenance',all(f['provenance'].get('source_url')=='https://owned.invalid/app.git' and (f['provenance'].get('blob') in blobs and 'commit' not in f['provenance'] if history else f['provenance'].get('commit')==heads[-1]) for f in typed))
                        check(name+'/no-local-scope',all(s['kind'] not in ('filesystem','git-history') and 'prowl-repo-' not in s['target'] for s in meta['scope']) and any(s['kind']=='repository' for s in meta['scope']))
                        check(name+'/safe',safe(result))
                        if fmt=='sarif': check(name+'/uri',all(f['artifact_uri'].startswith('https://owned.invalid/app.git!/') for f in typed))
                        if not ml and fmt=='json': policies.append([s for s in meta['scope'] if s['kind'].startswith('repository')])
                repeat=run([command,url if command=='repo' else 'github:owned','--format=json','--silence',*(['--history'] if history else [])])
                meta,_=decoded(repeat,'json')
                check(f'{command}/{history}/stable-scope',policies[0]==[s for s in meta['scope'] if s['kind'].startswith('repository')])
        for mode in ('warning','invalid'):
            env['PROWL_REPO_MODE']=mode
            for command in ('repo','org'):
                for fmt in ('json','sarif'):
                    baseline=root/f'{mode}-{command}-{fmt}.baseline';baseline.write_text('owned baseline sentinel')
                    result=run([command,'https://owned.invalid/app.git' if command=='repo' else 'github:owned','--format='+fmt,'--silence',*(['--write-baseline='+str(baseline)] if mode=='invalid' else [])])
                    meta,fs=decoded(result,fmt)
                    check(f'{mode}/{command}/{fmt}',result.returncode==(2 if mode=='invalid' else 0) and meta['complete']==(mode!='invalid') and any(f['type']=='aws_access_key_id' for f in fs) and safe(result))
                    if mode=='invalid':check(f'{mode}/{command}/{fmt}/baseline',baseline.read_text()=='owned baseline sentinel')
        env['PROWL_REPO_MODE']='normal'
        for history in (False,True):
            result=run(['repo','https://owned.invalid/empty.git','--format=json','--silence',*(['--history'] if history else [])])
            meta,fs=decoded(result,'json')
            check(f'empty/{history}',result.returncode==0 and meta['complete'] and not fs and any(s['kind']=='repository' for s in meta['scope']))
        # Pin the complete ref inventory: adding a branch changes the history snapshot, not HEAD.
        first=decoded(run(['repo','https://owned.invalid/app.git','--history','--format=json','--silence']),'json')[0]
        git(origin,'branch','other',heads[0])
        second=decoded(run(['repo','https://owned.invalid/app.git','--history','--format=json','--silence']),'json')[0]
        check('history-refset',next(s['policy'] for s in first['scope'] if s['kind']=='repository')!=next(s['policy'] for s in second['scope'] if s['kind']=='repository'))
        tag_blob=git(origin,'hash-object','-w','--stdin',input='TAG_ONLY=1\nAWS='+values[0]+'\n')
        tree=git(origin,'mktree',input='100644 blob '+tag_blob+'\ttag-only.env\n')
        tag_commit=git(origin,'commit-tree',tree,'-m','test: tag-only fixture')
        git(origin,'tag','owned-tag-only',tag_commit)
        result=run(['repo','https://owned.invalid/app.git','--history','--format=json','--silence'])
        meta,fs=decoded(result,'json')
        check('history-tag-only',result.returncode==0 and meta['complete'] and any(f.get('provenance',{}).get('blob')==tag_blob for f in fs))
        result=run(['repo','https://owned.invalid/app.git','--history','--branch=main','--format=json','--silence'])
        meta,fs=decoded(result,'json')
        check('history-selected-branch',result.returncode==0 and meta['complete'] and not any(f.get('provenance',{}).get('blob')==tag_blob for f in fs))
        result=run(['repo','https://owned.invalid/app.git','--history','--branch=owned-tag-only','--format=json','--silence'])
        meta,fs=decoded(result,'json')
        check('history-selected-tag',result.returncode==0 and meta['complete'] and any(f.get('provenance',{}).get('blob')==tag_blob for f in fs) and not any(f.get('provenance',{}).get('blob') in blobs for f in fs))
        for protocol in ('2024-11-05','2025-03-26','2025-06-18','2026-07-28'):
            proc=subprocess.Popen([str(binary),'mcp'],cwd=root,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
            replies=queue.Queue()
            def reader():
                for line in proc.stdout:replies.put(json.loads(line))
            threading.Thread(target=reader,daemon=True).start()
            def exchange(ident,method,params):
                if protocol=='2026-07-28':params['_meta']={'io.modelcontextprotocol/protocolVersion':protocol,'io.modelcontextprotocol/clientCapabilities':{}}
                proc.stdin.write((json.dumps({'jsonrpc':'2.0','id':ident,'method':method,'params':params})+'\n').encode());proc.stdin.flush()
                return replies.get(timeout=60)
            try:
                exchange(1,'server/discover' if protocol=='2026-07-28' else 'initialize',{'protocolVersion':protocol})
                result=exchange(2,'tools/call',{'name':'prowl_repo','arguments':{'url':'https://owned.invalid/app.git'}})['result']
                data=result['structuredContent']
                check(protocol+'/repo',not result['isError'] and data['complete'] and any(f.get('provenance',{}).get('commit')==heads[-1] for f in data['findings']))
            finally:
                proc.stdin.close();proc.wait(timeout=60)
    finally:
        server.shutdown();server.server_close();thread.join(timeout=30)
        report={'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'passed':sum(c['passed'] for c in checks),'total':len(checks),'checks':checks,'root':str(root),'scope':'local Git clone wrapper, owned Git objects and loopback org inventory only; no real remote repository or provider use'}
        (root/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({k:v for k,v in report.items() if k!='checks'}))


if __name__=='__main__':main()
