"""Persist reviewed finite service limits through the existing platform journal."""
import argparse
import base64
import json
import os
from pathlib import Path

READER=r'''
import base64,json,os,pathlib,stat
def read(path,private=False,maximum=1<<20):
 p=pathlib.Path(path)
 for parent in (p.parent,*p.parent.parents):
  i=parent.lstat()
  if i.st_uid!=0 or i.st_mode&0o022 or not stat.S_ISDIR(i.st_mode):raise ValueError('unprotected parent')
 if not p.exists():return None
 i=p.lstat()
 if i.st_uid!=0 or i.st_mode&0o022 or not stat.S_ISREG(i.st_mode) or i.st_size>maximum or private and i.st_mode&0o077:raise ValueError('unprotected input')
 return base64.b64encode(p.read_bytes()).decode()
print(json.dumps({'resources':read('/etc/komizo/resources.json',True),'configs':{name:read('/etc/conf.d/'+name,maximum=65536) for name in ('docker','komizo-rootd','komizo-api')}}))
'''

def prepare_controls(host,release,source,release_dir,stage,operation,expected=None):
    if not HOST.fullmatch(host):raise ValueError('literal host required')
    protected_directory(stage.parent)
    inputs=stage.parent/('controls-inputs-'+stage.name)
    review=inputs/'review.json'
    if operation=='plan':
        if expected or inputs.exists() or stage.exists():raise ValueError('fresh control planning paths required')
        ssh=['ssh','-T','-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oUpdateHostKeys=no','-oForwardAgent=no','root@'+host]
        run(ssh+['komizo-box workload host-resources --check --policy /etc/komizo/resources.json'])
        observed=json.loads(run(ssh+['python3 -I -'],READER.encode()))
        resources=base64.b64decode(observed['resources'],validate=True);policy=json.loads(resources)
        candidates={name:control_configuration(base64.b64decode(observed['configs'][name],validate=True) if observed['configs'][name] is not None else b'',policy,name) for name in CONTROL_SERVICES}
        inputs.mkdir(mode=0o700)
        rows=[]
        for name,body,path in [('resources.json',resources,'/etc/komizo/resources.json'),*[(name+'.conf',candidates[name],'/etc/conf.d/'+name) for name in CONTROL_SERVICES]]:
            file=inputs/name;file.write_bytes(body);file.chmod(0o600)
            rows.append({'path':path,'source':name,'mode':0o600})
        review.write_text(json.dumps({'version':1,'files':rows})+'\n');review.chmod(0o600)
    elif operation!='apply' or not expected or not review.exists():raise ValueError('apply requires the retained exact control plan')
    return prepare(host,release,source,release_dir,None,stage,operation=='apply',operation=='apply',expected,review)

def main():
    if os.geteuid()!=0:raise ValueError('control planning requires the Root operator')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=('plan','apply'))
    parser.add_argument('--host',required=True)
    parser.add_argument('--release',required=True)
    parser.add_argument('--source',required=True)
    parser.add_argument('--release-dir',type=Path,required=True)
    parser.add_argument('--stage',type=Path,required=True)
    parser.add_argument('--expected-manifest')
    args=parser.parse_args()
    print(json.dumps(prepare_controls(args.host,args.release,args.source,args.release_dir,args.stage,args.operation,args.expected_manifest)))

if __name__=='__main__':main()
