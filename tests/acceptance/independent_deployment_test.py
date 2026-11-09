"""Exercise source-candidate standalone bytes in a real disposable Debian host."""
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
from native_release import SOURCE,read,host_elf
from candidate_evidence import export
import importlib.util

ROOT=Path(__file__).resolve().parents[2]


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--binary',type=Path,required=True);parser.add_argument('--source',required=True)
    parser.add_argument('--host',type=Path,default=ROOT/'.artifacts/native-host/komizo-box_Linux_x86_64')
    parser.add_argument('--proxy-binary',type=Path,default=ROOT/'.artifacts/native-proxy/caddy_Linux_x86_64')
    parser.add_argument('--proxy-receipt',type=Path,default=ROOT/'.artifacts/native-proxy/caddy_Linux_x86_64.json')
    args=parser.parse_args()
    if sys.platform!='linux' or not SOURCE.fullmatch(args.source):raise ValueError('native Linux and exact source required')
    for path in (args.binary,args.host,args.proxy_binary,args.proxy_receipt):
        if path.is_symlink() or not path.resolve(strict=True).is_relative_to(ROOT):raise ValueError('source candidate inputs must be checkout-owned ordinary outputs')
    host_elf(read(args.binary),62);host_elf(read(args.host),62)
    output=ROOT/'.artifacts/independent-deployment'
    if output.exists() or output.is_symlink():raise ValueError('fresh source acceptance evidence required')
    spec=importlib.util.spec_from_file_location('native_lifecycle',Path(__file__).with_name('cold-lifecycle-acceptance.py'))
    lifecycle=importlib.util.module_from_spec(spec);spec.loader.exec_module(lifecycle)
    deadline=time.monotonic()+1740
    lifecycle.virtualization()
    with tempfile.TemporaryDirectory(prefix='komizo-source-observations-') as temporary:
        observations=Path(temporary);outputs=[];profiles={}
        try:
            for name in ['functional','bounded']:
                guest=observations/name;outputs.append(guest)
                profiles[name]=lifecycle.native_run(args.host.absolute(),args.proxy_binary.absolute(),args.proxy_receipt.absolute(),args.binary.absolute(),
                    name,guest,args.source,deadline)
            result={'source':args.source,'accepted':True,'signed_release_acceptance':False,'github_credentials_present':False,
                'candidate_cli':{'authenticated':False,'sha256':hashlib.sha256(read(args.binary)).hexdigest()},
                'host_sha256':hashlib.sha256(read(args.host)).hexdigest(),'proxy_sha256':hashlib.sha256(read(args.proxy_binary)).hexdigest(),'profiles':profiles}
            (observations/'candidate-deployment.json').write_text(json.dumps(result,sort_keys=True)+'\n')
            for name in ['performance','onboarding']:
                (observations/(name+'.json')).write_bytes((observations/'bounded'/(name+'.json')).read_bytes())
        finally:lifecycle.cleanup(outputs,observations)
        export(observations,output,args.source)



if __name__=='__main__':main()
