#!/usr/bin/env python3
"""Exercise real PTYs with owned Git, image stdin and loopback verification fixtures."""
import argparse
import errno
import fcntl
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import pty
import select
import shutil
import struct
import subprocess
import tarfile
import tempfile
import termios
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='prowl-progress-native-'))
    repo = root / 'repo'; repo.mkdir()
    real_git = shutil.which('git')
    env = {k:v for k,v in os.environ.items() if not k.startswith('PROWL_')}
    env.update(PROWL_HOME=str(root/'home'), PROWL_ALLOW_PRIVATE_IPS='1', NO_COLOR='1', TERM='xterm',
               GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
               GIT_AUTHOR_NAME='Owned fixture', GIT_AUTHOR_EMAIL='owned@example.invalid',
               GIT_COMMITTER_NAME='Owned fixture', GIT_COMMITTER_EMAIL='owned@example.invalid')
    value = 'AKIANAFGYOEYPXU1DSYP'
    payload = ('AWS='+value+'\n').encode()
    for args in (['init','-q'], ['config','core.hooksPath',os.devnull]):
        subprocess.run([real_git,*args],cwd=repo,env=env,check=True,capture_output=True)
    (repo/'production.env').write_bytes(payload)
    subprocess.run([real_git,'add','production.env'],cwd=repo,env=env,check=True,capture_output=True)
    subprocess.run([real_git,'commit','-qm','owned fixture'],cwd=repo,env=env,check=True,capture_output=True)
    shim = root/'bin';shim.mkdir()
    (shim/'git').write_text('#!/usr/bin/env python3\nimport os,sys,time\na=sys.argv[1:]\nif "clone" in a:\n time.sleep(float(os.environ["OWNED_CLONE_DELAY"]))\n a=[os.environ["OWNED_REPO"] if "owned.invalid" in x else x.replace("protocol.file.allow=user","protocol.file.allow=always") for x in a]\nos.execv(os.environ["OWNED_REAL_GIT"],[os.environ["OWNED_REAL_GIT"],*a])\n')
    (shim/'git').chmod(0o700)
    env.update(PATH=str(shim)+os.pathsep+env['PATH'], OWNED_REAL_GIT=real_git, OWNED_REPO=repo.as_uri(), OWNED_CLONE_DELAY='1.4')
    state = dict(delay=1.4, requests=0)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_GET(self):
            state['requests'] += 1
            time.sleep(state['delay'])
            self.send_response(200);self.end_headers()
            try:self.wfile.write(b'owned response')
            except (BrokenPipeError,ConnectionResetError):pass
    server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    rule=root/'owned.yaml'
    rule.write_text('id: owned\nmatch: [aws_access_key_id]\nrequests:\n  - url: http://127.0.0.1:'+str(server.server_port)+'/check\n    matchers:\n      - type: status\n        status: [200]\n')
    (root/'production.env').write_bytes(payload)
    layer=io.BytesIO()
    with tarfile.open(fileobj=layer,mode='w') as archive:
        h=tarfile.TarInfo('prod.env');h.size=len(payload);archive.addfile(h,io.BytesIO(payload))
    layer_bytes=layer.getvalue()
    config=json.dumps(dict(architecture='amd64',os='linux',config={},rootfs=dict(type='layers',diff_ids=['sha256:'+hashlib.sha256(layer_bytes).hexdigest()]),history=[dict(created_by='owned fixture')])).encode()
    image=io.BytesIO()
    with tarfile.open(fileobj=image,mode='w') as archive:
        for name,data in [('config.json',config),('manifest.json',json.dumps([dict(Config='config.json',RepoTags=['owned:fixture'],Layers=['layer.tar'])]).encode()),('layer.tar',layer_bytes)]:
            h=tarfile.TarInfo(name);h.size=len(data);archive.addfile(h,io.BytesIO(data))
    def screen(data):
        text=data.decode();lines=[];line=[];column=0;i=0
        while i<len(text):
            if text.startswith('\x1b[K',i):
                line=line[:column];i+=3;continue
            c=text[i];i+=1
            if c=='\r':column=0
            elif c=='\n':lines.append(''.join(line));line=[];column=0
            else:
                while len(line)<=column:line.append(' ')
                line[column]=c;column+=1
        return '\n'.join([*lines,''.join(line)])
    checks=[];complete=False
    def check(name,ok):
        checks.append(dict(case=name,passed=bool(ok)))
        if not ok:raise AssertionError(name)
    def run(args,*,tty=True,stdout_tty=True,stderr_tty=True,width=80,feed_image=False,feed_delay=1.4,overrides=None):
        current=dict(env,**(overrides or {}))
        command=[str(binary),*args,'--no-color','--log-level=error']
        if not tty:stdout_tty=stderr_tty=False
        master,slave=(pty.openpty() if tty else (None,None))
        if tty:fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',24,width,0,0))
        process=subprocess.Popen(command,cwd=root,env=current,stdin=subprocess.PIPE if feed_image else subprocess.DEVNULL,
                                 stdout=slave if stdout_tty else subprocess.PIPE,stderr=slave if stderr_tty else subprocess.PIPE)
        if tty:os.close(slave)
        feeder=None
        if feed_image:
            def feed():
                time.sleep(feed_delay)
                try:process.stdin.write(image.getvalue());process.stdin.close()
                except (BrokenPipeError,OSError):pass
            feeder=threading.Thread(target=feed,daemon=True);feeder.start()
        output=bytearray()
        try:
            if tty:
                deadline=time.monotonic()+15
                while time.monotonic()<deadline:
                    if not select.select([master],[],[],.1)[0]:continue
                    try:data=os.read(master,65536)
                    except OSError as error:
                        if error.errno==errno.EIO:break
                        raise
                    if not data:break
                    output.extend(data)
                process.wait(timeout=3)
                stdout=bytes(output) if stdout_tty else process.stdout.read()
                stderr=(b'' if stdout_tty else bytes(output)) if stderr_tty else process.stderr.read()
            else:
                stdout,stderr=process.communicate(timeout=15)
        finally:
            if process.poll() is None:process.kill();process.wait(timeout=3)
            if tty:os.close(master)
            if feeder:feeder.join(timeout=3)
        label='case-'+str(len(checks))
        (root/(label+'.stdout')).write_bytes(stdout);(root/(label+'.stderr')).write_bytes(stderr)
        return process.returncode,stdout,stderr
    verify=['scan','production.env','--verify','--verifiers='+str(rule)]
    try:
        for label,args,phase,feed in [
            ('clone',['repo','https://user:owned-private-url@owned.invalid/private.git?token=owned-private-query','--bundled'],b'cloning repository',False),
            ('image',['image','-','--image-input=stdin','--bundled'],b'loading image',True),
            ('verify',verify,b'scanning and verifying',False),
        ]:
            code,out,err=run(args,feed_image=feed)
            check(label+'/phase',code==0 and phase+b'\xe2\x80\xa6' in out)
            check(label+'/private',all(x not in out+err for x in (value.encode(),b'owned-private-url',b'owned-private-query')))
            tail=out[out.rfind(phase):]
            check(label+'/cleared-before-report',b'\r\x1b[K' in tail and b'\x1b[K' in out and out.rstrip().endswith(b'\x1b[K') is False)
            check(label+'/final-screen',all(phase not in screen(out).encode() for phase in (b'cloning repository\xe2\x80\xa6',b'loading image\xe2\x80\xa6',b'verifying\xe2\x80\xa6')))
        code,out,_=run(verify,width=30)
        progress=[line.split(b'\x1b[K',1)[1] for line in out.split(b'\r') if b'\x1b[K' in line and b'\xe2\x80\xa6' in line]
        check('narrow/no-wrap',code==0 and progress and all(len(line.decode())<30 for line in progress))
        for label,extra,overrides in [('quiet',['--quiet'],{}),('silence',['--silence'],{}),('dumb',[],{'TERM':'dumb'})]:
            code,out,err=run([*verify,*extra],overrides=overrides)
            check(label+'/no-controls',code==0 and b'\x1b[' not in out+err)
        for label,extra in [('json',['--format=json']),('sarif',['--format=sarif']),('file',['--format=json','-o','report.json']),('pipe-pretty',[]),('log-json',['--format=json','--log-format=json'])]:
            code,out,err=run([*verify,*extra],stdout_tty=False)
            check(label+'/stderr-progress',code==0 and b'verifying\xe2\x80\xa6' in err)
            check(label+'/stdout-clean',b'\x1b[' not in out and value.encode() not in out+err)
            if label in ('json','log-json'):check(label+'/complete',json.loads(out)['complete'] is True)
            if label=='sarif':check('sarif/complete',json.loads(out)['runs'][0]['properties']['complete'] is True)
            if label=='file':check('file/complete',not out and json.loads((root/'report.json').read_text())['complete'] is True)
        code,out,err=run([*verify,'--format=json'],tty=False)
        check('both-pipes/json-clean',code==0 and json.loads(out)['complete'] and b'\x1b[' not in out+err)
        code,out,err=run(verify,stderr_tty=False)
        check('redirected-stderr/no-controls',code==0 and b'\x1b[' not in out+err)
        state['delay']=3
        code,out,_=run([*verify,'--timeout=1800ms'])
        check('cancel/verify-cleared',code==2 and b'verifying\xe2\x80\xa6' in out and b'\r\x1b[K' in out and b'verifying\xe2\x80\xa6' not in screen(out).encode())
        code,out,_=run(['repo','https://owned.invalid/private.git','--bundled','--timeout=1800ms'],overrides={'OWNED_CLONE_DELAY':'4'})
        check('cancel/clone-cleared',code==2 and b'cloning repository\xe2\x80\xa6' in out and b'cloning repository\xe2\x80\xa6' not in screen(out).encode())
        code,out,_=run(['image','-','--image-input=stdin','--bundled','--timeout=1800ms'],feed_image=True,feed_delay=2.3)
        check('cancel/image-cleared',code==2 and b'loading image\xe2\x80\xa6' in out and b'loading image\xe2\x80\xa6' not in screen(out).encode())
        state['delay']=0
        code,out,_=run(verify)
        check('fast/no-flicker',code==0 and b'\x1b[' not in out)
        complete=True
    finally:
        server.shutdown();server.server_close()
        report=dict(complete=complete,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),passed=sum(c['passed']for c in checks),total=len(checks),checks=checks,requests=state['requests'],root=str(root),scope='real local Unix PTYs with independent stdout/stderr, owned local Git clone shim, stdin image tar and loopback verifier only; preserves stderr progress for files and pipes; Windows terminal runtime not qualified')
        (root/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k!='checks'}))


if __name__=='__main__':main()
