#!/usr/bin/python3
import sys,os,json,shlex,hashlib
args=sys.argv[1:]
if '-G' in args:
 print('port 22');sys.exit(0)
command=args[-1];body=sys.stdin.buffer.read();env={}
for token in shlex.split(command):
 if '=' in token and token.split('=',1)[0].isidentifier():
  k,v=token.split('=',1);env[k]=v
record={'command':command,'env':env,'stdin_sha256':hashlib.sha256(body).hexdigest()}
if 'owner-secret' in command:record['stdin_hex']=body.hex()
with open(os.environ['FIXTURE_TRACE'],'a') as file:file.write(json.dumps(record)+'\n')
if command=='true':pass
elif command.startswith('cat /etc/ssh/'):
 print('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixture host')
elif 'deployment-submit' in command:
 if os.environ.get('FIXTURE_MODE')=='bad-ack':print('ambiguous')
 else:print('deploy: previous-version=\ndeploy: submitted='+'1'*32+'\n'+'1'*32)
elif "'report'" in command:
 print(json.dumps({'v':1,'server':{'state':'ready','komizo':{'installed':True}},'apps':[{'name':'demo','config_image':'ghcr.io/o/config'},{'name':'app','config_image':'ghcr.io/o/config'},{'name':'a','config_image':'ghcr.io/o/config'},{'name':'fixture','config_image':'ghcr.io/example/fixture-config'}]}))
elif "'capabilities'" in command:
 print('{"version":1,"policy_bootstrap":true}')
elif "'policy-bootstrap'" in command:
 tokens=shlex.split(command);app=tokens[tokens.index('--app')+1];print(json.dumps({'version':1,'app':app,'installed':True,'deployment_enabled':True}))
elif 'memory_kib' in command:
 print('os=alpine\nkernel=Linux\narch=x86_64\nuid=0\nmemory_kib=1048576\ndisk_kib=10485760\ninodes=100000\napk=yes\nopenrc=yes\ncgroup_v2=yes\ninstalled=yes')
elif 'sh -s' in command:print('fixture program accepted')
elif 'owner-secret' in command:print('secret accepted',file=sys.stderr)
else:
 print('unexpected fake SSH request: '+command,file=sys.stderr);sys.exit(90)
