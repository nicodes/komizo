"""Public Root operator for finite, reviewed Alpine maintenance transactions."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=('plan','apply','inspect','finish'))
    parser.add_argument('--host',required=True)
    parser.add_argument('--port',type=int,default=22)
    parser.add_argument('--stage',required=True)
    parser.add_argument('--binary-sha256',required=True)
    parser.add_argument('--manifest-sha256')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if not re.fullmatch(r'root@[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}',args.host) or not 1<=args.port<=65535:raise ValueError('literal Root host required')
    if not re.fullmatch(r'/var/lib/komizo/maintenance/[a-zA-Z0-9_-]{1,64}',args.stage):raise ValueError('fixed maintenance stage required')
    if not re.fullmatch('[a-f0-9]{64}',args.binary_sha256):raise ValueError('authenticated installed binary hash required')
    if args.operation!='plan' and not re.fullmatch('[a-f0-9]{64}',args.manifest_sha256 or ''):raise ValueError('exact reviewed manifest required')
    if args.operation=='plan' and args.manifest_sha256:raise ValueError('plan has no previous manifest')
    # Refuse before effects if output cannot be retained. The SSH return alone
    # is never acceptance; durable host inspect resolves an interrupted client.
    with args.output.open('xb') as output:
        args.output.chmod(0o600)
        command='set -eu; test "$(sha256sum /usr/local/bin/komizo-box | cut -d " " -f 1)" = '+shlex.quote(args.binary_sha256)+'; '
        if args.operation=='plan':command+='mkdir -m 700 -p /var/lib/komizo/maintenance; mkdir -m 700 '+shlex.quote(args.stage)+'; '
        command+='exec /usr/local/bin/komizo-box platform maintenance '+shlex.join([args.operation,args.stage,*([args.manifest_sha256] if args.manifest_sha256 else [])])
        result=subprocess.run(['ssh','-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oForwardAgent=no','-oConnectTimeout=10','-p',str(args.port),args.host,command],stdin=subprocess.DEVNULL,stdout=output,timeout=1100)
    if result.returncode:raise ValueError('maintenance refused; inspect retained host operation')
    data=args.output.read_bytes()
    if len(data)>4<<20:raise ValueError('maintenance output exceeds its bound')
    print(json.dumps({'operation':args.operation,'evidence':str(args.output),'evidence_sha256':hashlib.sha256(data).hexdigest(),'result':json.loads(data)},sort_keys=True))

if __name__=='__main__':
    try:main()
    except Exception as error:
        print('maintenance refused: '+str(error),file=sys.stderr);raise SystemExit(1)
