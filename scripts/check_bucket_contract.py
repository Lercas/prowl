#!/usr/bin/env python3
"""Qualify S3/GCS download provenance through owned local cloud-CLI fixtures."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.parse import unquote, urlparse
import zipfile


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary',type=Path)
    binary=parser.parse_args().binary.resolve(strict=True)
    root=Path(tempfile.mkdtemp(prefix='prowl-bucket-native-'))
    (root/'home').mkdir();(root/'bin').mkdir();fixture=root/'fixture';fixture.mkdir()
    value='AKIANAFGYOEYPXU1DSYP'
    payload=('AWS='+value+'\n').encode()
    files={'Ключ #?%20.env':payload,'utf16.env':b'\xff\xfe'+payload.decode().encode('utf-16le'),'bang!/prod.env':payload}
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w',zipfile.ZIP_DEFLATED) as z:z.writestr('deep/config.env',payload)
    files['bundle.zip']=stream.getvalue()
    for name,data in files.items():
        file=fixture/name;file.parent.mkdir(parents=True,exist_ok=True);file.write_bytes(data)
    (fixture/'binary.bin').write_bytes(b'binary\x00data')
    (fixture/'.prowl.yaml').write_text('detectors:\n  disable: [aws_access_key_id]\n')
    helper=r"""import os,sys,shutil
from pathlib import Path
args=sys.argv[1:]
dest=Path(args[4] if Path(sys.argv[0]).name=='gcloud' else args[3])
mode=os.environ.get('PROWL_BUCKET_MODE','normal')
with open(os.environ['PROWL_BUCKET_MARKER'],'a') as marker:marker.write('called\n')
if mode!='empty':
    for source in Path(os.environ['PROWL_BUCKET_FIXTURE']).rglob('*'):
        if source.is_file():
            target=dest/source.relative_to(os.environ['PROWL_BUCKET_FIXTURE']);target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
if mode=='partial':
    print('OWNED_CLOUD_STDOUT_PRIVATE');print('OWNED_CLOUD_STDERR_PRIVATE',file=sys.stderr);sys.exit(7)
if mode=='budget':
    with open(dest/'oversize.bin','wb') as large:large.truncate(6<<30)
"""
    for name in ('aws','gcloud'):
        path=root/'bin'/name;path.write_text('#!'+sys.executable+'\n'+helper);path.chmod(0o755)
    marker=root/'calls'
    env=dict(os.environ,PROWL_HOME=str(root/'home'),PATH=str(root/'bin')+os.pathsep+os.environ['PATH'],PROWL_BUCKET_FIXTURE=str(fixture),PROWL_BUCKET_MARKER=str(marker),PROWL_BUCKET_MODE='normal')
    checks=[];calls=0
    def check(name,passed):
        checks.append({'case':name,'passed':bool(passed)})
        if not passed:raise AssertionError(name)
    def run(argv):
        nonlocal calls
        calls+=1
        result=subprocess.run([str(binary),*argv],cwd=root,env=env,input=b'',capture_output=True,timeout=60)
        (root/f'case-{calls:03}.stdout').write_bytes(result.stdout);(root/f'case-{calls:03}.stderr').write_bytes(result.stderr)
        return result
    def decoded(result,fmt):
        data=json.loads(result.stdout)
        if fmt=='json':return data,data['findings']
        run=data['runs'][0]
        findings=[]
        for finding in run['results']:
            uri=finding['locations'][0]['physicalLocation']['artifactLocation']['uri']
            parsed=urlparse(uri)
            findings.append(dict(finding['properties'],type=finding['ruleId'],artifact_uri=uri,path=parsed.scheme+'://'+parsed.netloc+unquote(parsed.path)))
        return run['properties'],findings
    def safe(result):return all(raw.encode() not in result.stdout+result.stderr for raw in (value,'OWNED_CLOUD_STDOUT_PRIVATE','OWNED_CLOUD_STDERR_PRIVATE','prowl-bucket-'))
    try:
        check('identity',run(['identity','init']).returncode==0)
        for scheme in ('s3','gs'):
            target=scheme+'://owned/prefix#?%20'
            scopes=[]
            for ml in (False,True):
                for fmt in ('json','sarif'):
                    result=run(['bucket',target,'--format='+fmt,'--silence',*(['--ml'] if ml else [])])
                    meta,fs=decoded(result,fmt);typed=[f for f in fs if f['type']=='aws_access_key_id']
                    name=f'{scheme}/{ml}/{fmt}'
                    check(name+'/complete',result.returncode==0 and meta['complete'] and len(typed)==4)
                    check(name+'/safe',safe(result))
                    check(name+'/scope',any(s['kind']=='bucket' and s['target']==target for s in meta['scope']) and all(s['kind']!='filesystem' for s in meta['scope']))
                    for f in typed:
                        key=f['path'].removeprefix(target+'/')
                        object_key='bundle.zip' if key.startswith('bundle.zip!/') else key
                        source=urlparse(f['provenance']['source_url'])
                        check(name+'/'+object_key+'/object',source.scheme==scheme and source.netloc=='owned' and unquote(source.path)=='/prefix#?%20/'+object_key and not source.query and not source.fragment and f['provenance']['digest']==hashlib.sha256(files[object_key]).hexdigest())
                        if fmt=='sarif':
                            address=urlparse(f['artifact_uri'])
                            check(name+'/'+object_key+'/uri',address.scheme==scheme and address.netloc=='owned' and not address.query and not address.fragment)
                    if not ml and fmt=='json':scopes=[s for s in meta['scope'] if s['kind'].startswith('bucket')]
            repeat,_=decoded(run(['bucket',target,'--format=json','--silence']),'json')
            check(scheme+'/stable-scope',scopes==[s for s in repeat['scope'] if s['kind'].startswith('bucket')])
            for mode in ('partial','budget'):
                env['PROWL_BUCKET_MODE']=mode
                for fmt in ('json','sarif'):
                    baseline=root/f'{scheme}-{mode}-{fmt}.baseline';baseline.write_text('owned baseline sentinel')
                    result=run(['bucket',target,'--format='+fmt,'--silence','--write-baseline='+str(baseline)])
                    meta,fs=decoded(result,fmt)
                    check(f'{scheme}/{mode}/{fmt}/incomplete',result.returncode==2 and not meta['complete'] and any(f['type']=='aws_access_key_id' for f in fs))
                    check(f'{scheme}/{mode}/{fmt}/safe',safe(result))
                    check(f'{scheme}/{mode}/{fmt}/baseline',baseline.read_text()=='owned baseline sentinel')
            env['PROWL_BUCKET_MODE']='partial'
            for log_format in ('console','json'):
                result=run(['bucket',target,'--format=json','--log-format='+log_format])
                meta,fs=decoded(result,'json')
                check(f'{scheme}/{log_format}/visible-logs-safe',result.returncode==2 and not meta['complete'] and safe(result))
                check(f'{scheme}/{log_format}/exit-classification',b'exit status 7' in result.stderr)
            env['PROWL_BUCKET_MODE']='empty'
            result=run(['bucket',target,'--format=json','--silence']);meta,fs=decoded(result,'json')
            check(scheme+'/empty',result.returncode==0 and meta['complete'] and not fs and any(s['kind']=='bucket' for s in meta['scope']))
            env['PROWL_BUCKET_MODE']='normal'
        before=marker.read_text()
        for target in ('s3://u:private@owned/prefix','gs://owned?private=1','s3:///prefix','https://owned/prefix'):
            result=run(['bucket',target,'--format=json','--silence'])
            check('invalid/'+target.split(':',1)[0],result.returncode==2 and marker.read_text()==before and b'private' not in result.stderr)
    finally:
        report={'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'passed':sum(c['passed'] for c in checks),'total':len(checks),'checks':checks,'root':str(root),'scope':'owned fake aws/gcloud commands and synthetic local object bytes only; no cloud credentials, APIs or live providers exercised'}
        (root/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='checks'}))


if __name__=='__main__':main()
