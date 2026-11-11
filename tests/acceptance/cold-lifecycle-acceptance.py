#!/usr/bin/env python3
"""Accept exact authenticated standalone bytes on real disposable Alpine guests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))

from native_release import SOURCE,TAG,cli_binary,verify
from release_acceptance import REQUIRED_STEPS

ROOT=Path(__file__).resolve().parents[2]


def virtualization():
    if sys.platform!='linux' or not Path('/dev/kvm').exists():raise ValueError('release acceptance requires a real Linux KVM host')
    import shutil
    if any(shutil.which(name) is None for name in ('qemu-system-x86_64','qemu-img','cloud-localds','setfacl')):
        subprocess.run(['sudo','apt-get','update'],check=True,timeout=90)
        subprocess.run(['sudo','apt-get','install','--yes','--no-install-recommends','qemu-system-x86','qemu-utils','cloud-image-utils','acl'],check=True,timeout=150)
    if not os.access('/dev/kvm',os.R_OK|os.W_OK):subprocess.run(['sudo','setfacl','-m','u:'+str(os.getuid())+':rw','/dev/kvm'],check=True,timeout=10)


def native_run(binary,proxy,receipt,cli,profile,output,source,deadline):
    # Device ACLs can be refreshed between independent guest lifetimes.
    # Re-establish this trial's actual KVM precondition within the same deadline.
    virtualization()
    remaining=min(1000,deadline-time.monotonic())
    if remaining<=0:raise ValueError('native release acceptance exhausted its original aggregate deadline')
    environment={key:value for key,value in os.environ.items() if key not in {'GH_TOKEN','GITHUB_TOKEN','MISE_GITHUB_TOKEN','SSH_AUTH_SOCK'}}
    environment['NATIVE_HOST_SOURCE']=source
    subprocess.run([sys.executable,'-I','-B',str(ROOT/'tests/support/native_host_vm.py'),'--binary',str(binary),
        '--proxy-binary',str(proxy),'--proxy-receipt',str(receipt),'--cli',str(cli),'--profile',profile,'--output',str(output)],
        env=environment,check=True,timeout=remaining)
    report=json.loads((output/'report.json').read_bytes())
    if report.get('ok') is not True:raise ValueError('real native guest did not complete acceptance')
    closed={key:report[key] for key in ('ok','profile','source')}
    closed['checks']={key:value for key,value in report['checks'].items() if key in REQUIRED_STEPS|{'bounded_full_postgresql_offline_reboot','fixed_budget_performance'}}
    return closed


def cleanup(outputs,destination):
    results=[]
    for directory in outputs:
        path=directory/'cleanup.json'
        if path.is_file() and not path.is_symlink():results.append(json.loads(path.read_bytes()))
    required={'version':1,'owned_guest_removed':True,'private_storage_removed':True,'shared_images_removed':False}
    accepted=bool(results) and len(results)==len(outputs) and all(type(row.get('version')) is int and row==required for row in results)
    result=required if accepted else {**required,'owned_guest_removed':False,'private_storage_removed':False}
    (destination/'cleanup.json').write_text(json.dumps(result,sort_keys=True)+'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release',required=True);parser.add_argument('--source',required=True)
    parser.add_argument('--release-dir',required=True,type=Path);parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args();deadline=time.monotonic()+2040
    if not SOURCE.fullmatch(args.source) or not TAG.fullmatch(args.release) or not os.environ.get('GH_TOKEN'):raise ValueError('authenticated exact main release/source required')
    if args.output.exists() or args.output.is_symlink():raise ValueError('fresh private observations destination required')
    args.output.mkdir(mode=0o700,parents=True);outputs=[]
    try:
        publication=verify(args.release_dir,args.source,args.release,deadline=time.monotonic()+300)
        with tempfile.TemporaryDirectory(prefix='komizo-cold-owner-') as temporary:
            cli=Path(temporary)/'komizo';cli.write_bytes(cli_binary(args.release_dir/'komizo_Linux_x86_64.tar.gz'));cli.chmod(0o700)
            profiles={}
            for name in ('functional','bounded'):
                output=args.output/name;outputs.append(output)
                profiles[name]=native_run(args.release_dir/'komizo-box_Linux_x86_64',args.release_dir/'caddy_Linux_x86_64',
                    args.release_dir/'caddy_Linux_x86_64.json',cli,name,output,args.source,deadline)
            native={'version':1,'release':args.release,'source':args.source,'candidate_cli':None,'signed_release_acceptance':True,
                'cli_sha256':hashlib.sha256(cli.read_bytes()).hexdigest(),
                'host_sha256':publication['artifacts']['komizo-box_Linux_x86_64']['sha256'],
                'proxy_sha256':publication['artifacts']['caddy_Linux_x86_64']['sha256'],
                'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'authenticated_files':publication['artifacts'],'profiles':profiles,
                'steps':[{'step':name,'accepted':profiles['functional']['checks'].get(name)=='passed'} for name in sorted(REQUIRED_STEPS)]}
            (args.output/'accepted.json').write_text(json.dumps(native,sort_keys=True)+'\n')
            for name in ('performance.json','onboarding.json'):(args.output/name).write_bytes((args.output/'bounded'/name).read_bytes())
    finally:cleanup(outputs,args.output)


if __name__=='__main__':main()
