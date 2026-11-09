#!/usr/bin/env python3
"""Build the accepted Tools proxy closure for the disposable native host."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

TOOLS='134237cd8f9b169c53dfc31beb4172bb481e49ec'
SOURCES=('caddy.go.mod','caddy.go.sum','caddy-build.sh')


def run(arguments,**options):
    result=subprocess.run(arguments,capture_output=True,timeout=options.pop('timeout',30),**options)
    if result.returncode:
        error=result.stderr if isinstance(result.stderr,str) else result.stderr.decode(errors='replace')
        raise ValueError('proxy build command failed: '+arguments[0]+'\n'+error[-8192:])
    return result.stdout


def identity(info):
    lines=info.splitlines()
    if not lines or lines[0].split()[-1]!='go1.27.3':raise ValueError('proxy compiler build identity differs')
    rows=[line.strip().split('\t') for line in lines[1:]]
    if [row for row in rows if row[0]=='path']!=[['path','github.com/caddyserver/caddy/v2/cmd/caddy']]:raise ValueError('proxy entrypoint differs')
    modules=[row for row in rows if row[:2]==['dep','github.com/caddyserver/caddy/v2']]
    if len(modules)!=1 or len(modules[0])!=4 or modules[0][2]!='v2.11.6' or not modules[0][3].startswith('h1:'):
        raise ValueError('proxy upstream module differs')
    if any(row[0]=='=>' for row in rows):raise ValueError('proxy module replacements are forbidden')
    flags=[row[1] for row in rows if len(row)==2 and row[0]=='build']
    for key,value in {'GOOS':'linux','GOARCH':'amd64','CGO_ENABLED':'0','-trimpath':'true'}.items():
        if [flag for flag in flags if flag.split('=',1)[0]==key]!=[key+'='+value]:raise ValueError('proxy target/compiler settings differ')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--tools',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();tools=args.tools.resolve(strict=True);destination=args.output.absolute()
    command=['git','--no-replace-objects','-c','core.hooksPath='+os.devnull,'-c','core.fsmonitor=false','-C',str(tools)]
    if run([*command,'rev-parse','HEAD'],text=True).strip()!=TOOLS or run([*command,'status','--porcelain','--untracked-files=all']):
        raise ValueError('proxy requires its exact clean accepted Tools source')
    if run([*command,'remote','get-url','origin'],text=True).strip().removesuffix('.git') not in {'https://github.com/nicodes/tools','git@github.com:nicodes/tools'}:
        raise ValueError('proxy source origin differs')
    files={}
    for name in SOURCES:
        path=tools/'helpers'/name
        if path.is_symlink() or not path.is_file() or path.stat().st_size>1<<20:raise ValueError('proxy source is not an ordinary bounded file')
        body=path.read_bytes()
        if body!=run([*command,'show',TOOLS+':helpers/'+name]):raise ValueError('proxy source differs from accepted Git bytes')
        files[name]=body
    compiler=Path(run(['go','env','GOROOT'],text=True).strip())/'bin'/'go'
    if run([str(compiler),'env','GOVERSION'],text=True).strip()!='go1.27.3':raise ValueError('proxy requires exact Go1.27.3')
    scanner=shutil.which('govulncheck')
    if not scanner:raise ValueError('proxy requires the explicitly installed pinned binary scanner')
    destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if destination.exists() or destination.with_name(destination.name+'.json').exists():raise ValueError('fresh proxy output required')
    with tempfile.TemporaryDirectory(prefix='.proxy-',dir=destination.parent) as temporary:
        root=Path(temporary);(root/'home').mkdir(mode=0o700)
        for name,target in [('caddy.go.mod','go.mod'),('caddy.go.sum','go.sum'),('caddy-build.sh','build.sh')]:
            (root/target).write_bytes(files[name])
        environment={'PATH':str(compiler.parent)+':'+str(Path(scanner).parent)+':/usr/bin:/bin','HOME':str(root/'home'),'LANG':'C.UTF-8',
            'GOENV':'off','GOWORK':'off','GOTOOLCHAIN':'local','CGO_ENABLED':'0','GOOS':'linux','GOARCH':'amd64','GOFLAGS':'-buildvcs=false'}
        run(['sh','build.sh'],cwd=root,env=environment,timeout=900)
        binary=root/'caddy';raw=binary.read_bytes()
        if not 0<len(raw)<=128<<20 or raw[:7]!=b'\x7fELF\x02\x01\x01' or int.from_bytes(raw[18:20],'little')!=62:
            raise ValueError('proxy build is not its bounded native Linux executable')
        offset=int.from_bytes(raw[32:40],'little');size=int.from_bytes(raw[54:56],'little');count=int.from_bytes(raw[56:58],'little')
        if size!=56 or not 0<count<=128 or offset<64 or offset+size*count>len(raw) or any(int.from_bytes(raw[offset+i*size:offset+i*size+4],'little')==3 for i in range(count)):
            raise ValueError('proxy requires static bounded ELF program metadata')
        identity(run([str(compiler),'version','-m',str(binary)],text=True,cwd=root,env=environment))
        if run([str(binary),'version'],text=True,cwd=root,env=environment).split()[0]!='v2.11.6':raise ValueError('proxy version differs')
        report=run([scanner,'-mode=binary','-json',str(binary)],cwd=root,env=environment,timeout=600)
        if len(report)>16<<20:raise ValueError('proxy binary audit exceeds metadata bound')
        spec=importlib.util.spec_from_file_location('accepted_proxy_scanner',tools/'helpers'/'scan-image.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        if module.judge_report(report.decode())['reached']:raise ValueError('proxy contains vulnerable linked symbols')
        for name,target in [('caddy.go.mod','go.mod'),('caddy.go.sum','go.sum'),('caddy-build.sh','build.sh')]:
            if (root/target).read_bytes()!=files[name]:raise ValueError('proxy build changed accepted input bytes')
        destination.write_bytes(raw);destination.chmod(0o755)
        receipt={'kind':'komizo.proxy-build','version':1,'tools_revision':TOOLS,'platform':'linux/amd64','go_version':'1.27.3','caddy_version':'2.11.6',
            'source_sha256':{name:'sha256:'+hashlib.sha256(body).hexdigest() for name,body in files.items()},'binary_sha256':'sha256:'+hashlib.sha256(raw).hexdigest()}
        path=destination.with_name(destination.name+'.json');path.write_bytes(json.dumps(receipt,sort_keys=True,separators=(',',':')).encode());path.chmod(0o644)
    print('Exact locked proxy source, compiler, native ELF and linked-symbol audit passed.')


if __name__=='__main__':main()
