"""Authenticate a release and prepare a protected typed one-box upgrade.

The operator's protected receipt records verified provenance; root remains the
trust boundary. Preparation changes no services. --apply invokes only the new,
authenticated host executor, which journals prior bytes and service states.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
import time

HOST = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z')


def run(args, body=None, timeout=90, maximum=4*1024*1024):
    result = subprocess.run(args, input=body, capture_output=True, timeout=timeout)
    if result.returncode:
        # The executor emits one bounded diagnostic without subprocess output.
        if result.stderr.startswith(b'platform refused: ') and len(result.stderr)<=1024:
            raise ValueError(result.stderr.decode().strip())
        raise subprocess.CalledProcessError(result.returncode,args)
    if len(result.stdout) > maximum:
        raise ValueError('platform preparation output exceeds its bound')
    return result.stdout


def digest(body):
    return hashlib.sha256(body).hexdigest()


def verify(directory, source, release, worktree=None):
    if not re.fullmatch('[a-f0-9]{40}', source) or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', release):
        raise ValueError('exact source and release are required')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    archive = directory/'komizo_Linux_x86_64.tar.gz'
    if not archive.exists():
        run(['gh','release','download',release,'--repo','nicodes/komizo','--pattern',archive.name,
             '--pattern','checksums.txt','--dir',str(directory)], timeout=180)
    authority = 'https://github.com/nicodes/komizo/.github/workflows/release.yml@refs/heads/main'
    proof = run(['gh','attestation','verify',str(archive),'--repo','nicodes/komizo',
                 '--cert-identity',authority,'--cert-oidc-issuer','https://token.actions.githubusercontent.com',
                 '--signer-digest',source,'--source-digest',source,'--source-ref','refs/heads/main',
                 '--deny-self-hosted-runners','--format','json'])
    rows = json.loads(proof)
    if not rows:
        raise ValueError('release provenance is absent')
    for row in rows:
        verified = row['verificationResult']
        certificate = verified['signature']['certificate']
        if (certificate['subjectAlternativeName'] != authority
                or certificate['issuer'] != 'https://token.actions.githubusercontent.com'
                or certificate['sourceRepositoryDigest'] != source
                or certificate['githubWorkflowRef'] != 'refs/heads/main'
                or not any(s['name'] == archive.name and s['digest']['sha256'] == digest(archive.read_bytes())
                           for s in verified['statement']['subject'])):
            raise ValueError('release identity differs from reviewed source')
    (directory/'attestation.json').write_bytes(proof)
    checks = {line.split()[1].lstrip('*'): line.split()[0]
              for line in (directory/'checksums.txt').read_text().splitlines()}
    if checks.get(archive.name) != digest(archive.read_bytes()):
        raise ValueError('release checksum differs')
    executable = directory/'komizo'
    with tarfile.open(archive) as bundle:
        entry = bundle.getmember('komizo')
        if not entry.isfile() or not 1_000_000 <= entry.size <= 100_000_000:
            raise ValueError('invalid released executable')
        body = bundle.extractfile(entry).read()
    if executable.exists():
        if executable.read_bytes() != body:
            raise ValueError('prepared release executable differs')
    else:
        with executable.open('xb') as stream:
            stream.write(body)
        executable.chmod(0o755)
    exported = directory/'komizo-box-linux-amd64'
    if exported.exists():
        metadata = json.loads((directory/'embedded-agents.json').read_text())
    else:
        metadata = json.loads(run([str(executable),'artifact','--arch','amd64','--output',str(exported)]))
        (directory/'embedded-agents.json').write_text(json.dumps(metadata,indent=2)+'\n')
    if (metadata['architecture'] != 'amd64' or metadata['version'].removeprefix('v') != release.removeprefix('v')
            or metadata['sha256'] != digest(exported.read_bytes())
            or not re.fullmatch('[a-f0-9]{12}',metadata['stamp'])):
        raise ValueError('embedded artifact receipt differs')
    # The authenticated executable owns the exact installer template. No
    # repository checkout or independently maintained preparation copy is needed.
    template = run([str(executable),'script','add']).decode()
    (directory/'alpine.sh').write_text(template)
    return template


def wrapper(template, previous):
    separator = "<<'KOMIZO_DEPLOY_EOF'\n"
    if template.count(separator) != 1:
        raise ValueError('unknown generated wrapper contract')
    body = template.split(separator,1)[1].split('\nKOMIZO_DEPLOY_EOF',1)[0]+'\n'
    fields = dict(re.findall(r'^([A-Z_]+)="([^"\n]*)"$', previous, re.M))
    mapping = {k:fields[k] for k in ('APP_NAME','APP_DIR','CONFIG_IMAGE','PROXY_CONTAINER','PROXY_DIR','SCOPED_ENV')}
    mapping.update(ROUTES_DIR=str(Path(fields['ROUTE_FILE']).parent),STATE_DIR='/var/lib/komizo/apps')
    if any(not re.fullmatch('[A-Za-z0-9/._:@-]*', value) for value in mapping.values()):
        raise ValueError('wrapper metadata is not a safe fixed value')
    for key,value in mapping.items():
        body = body.replace('__'+key+'__',value)
    if re.search('__+[A-Z_]+__',body):
        raise ValueError('unknown wrapper placeholders')
    return body.encode()



def task_wrapper(template, app):
    if not re.fullmatch('[a-z][a-z0-9_-]{0,62}', app): raise ValueError('invalid named task app')
    separator="<<'KOMIZO_TASK_EOF'\n"
    if template.count(separator) != 1: raise ValueError('unknown task wrapper contract')
    body=template.split(separator,1)[1].split('\nKOMIZO_TASK_EOF',1)[0]+'\n'
    body=body.replace('__APP_NAME__',app)
    if re.search('__+[A-Z_]+__',body): raise ValueError('unknown task wrapper placeholders')
    return body.encode()


def legacy_migration(ssh, stage):
    version = run(ssh+['komizo-box version']).decode().strip().removeprefix('v')
    if tuple(map(int, version.split('.'))) < (0, 0, 79):
        raise ValueError('upgrade requires the supported typed executor v0.0.79 or newer')


def protected_directory(path, *, root=Path('/'), owner=0):
    path = Path(path)
    if not path.is_absolute() or path != Path(os.path.abspath(path)) or not path.is_relative_to(root):
        raise ValueError('local preparation paths must be absolute and canonical')
    for ancestor in (path, *path.parents):
        info = ancestor.lstat()
        if not ancestor.is_dir() or ancestor.is_symlink() or info.st_uid != owner or info.st_mode & 0o022:
            raise ValueError('preparation directory ancestry must be protected')
        if ancestor == root: break


def authority_inputs(review, owner=0):
    review = Path(review)
    protected_directory(review.parent)
    info = review.lstat()
    if not review.is_file() or review.is_symlink() or info.st_uid != owner or info.st_mode & 0o077 or info.st_size > 1<<20:
        raise ValueError('authority review must be a bounded private root-owned file')
    document = json.loads(review.read_bytes())
    if set(document) != {'version', 'files'} or document['version'] != 1 or not isinstance(document['files'], list) or not 1 <= len(document['files']) <= 131:
        raise ValueError('invalid authority review')
    inputs = []
    for index, row in enumerate(document['files']):
        if set(row) != {'path', 'source', 'mode'} or not re.fullmatch('[A-Za-z0-9_.-]{1,128}', row['source']) or row['source'] in ('.', '..'):
            raise ValueError('authority candidates must be named files beside the review')
        permitted = row['path'] == '/etc/doas.conf' and row['mode'] == 0o600
        for pattern, mode in ((r'/etc/komizo/workloads/[a-z][a-z0-9_-]{0,62}\.json', 0o600),
                              (r'/var/lib/komizo/tasks/[a-z][a-z0-9_-]{0,62}\.sh', 0o700),
                              (r'/usr/local/bin/(?:deploy|task|set-secret|set-release-secrets|export-backup)-[a-z][a-z0-9_-]{0,62}', 0o755)):
            permitted |= bool(re.fullmatch(pattern, row['path']) and type(row['mode']) is int and row['mode'] == mode)
        if not permitted or any(path == row['path'] for path, *_ in inputs):
            raise ValueError('authority review path or permissions are outside the migration contract')
        candidate = review.parent/row['source']
        info = candidate.lstat()
        if not candidate.is_file() or candidate.is_symlink() or info.st_uid != owner or info.st_mode & 0o077 or not 0 < info.st_size <= 1<<20:
            raise ValueError('authority candidate must be a bounded private root-owned file')
        inputs.append((row['path'], 'authority-'+str(index), candidate.read_bytes(), row['mode']))
    return inputs


def remote_identity(ssh, path):
    # The fixed Python reader reports only identity and mode, never prior bytes.
    program = """import hashlib,json,os,stat,sys
from pathlib import Path
p=Path(sys.argv[1])
for q in p.parents:
 s=q.lstat()
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise ValueError('unprotected ancestry')
try:s=p.lstat()
except FileNotFoundError:print(json.dumps([None,None]));raise SystemExit
if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022 or s.st_size>64<<20:raise ValueError('unprotected file')
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
h=hashlib.sha256()
with os.fdopen(fd,'rb') as f:
 for b in iter(lambda:f.read(65536),b''):h.update(b)
print(json.dumps([h.hexdigest(),stat.S_IMODE(s.st_mode)]))
"""
    return json.loads(run(ssh+['python3 -I -c '+shlex.quote(program)+' '+shlex.quote(path)]))


def prepare(host, release, source, release_dir, worktree, stage, apply=False, resume=False, expected_manifest=None, authority_review=None):
    if apply and (not isinstance(expected_manifest,str) or not re.fullmatch('[a-f0-9]{64}',expected_manifest)):
        raise ValueError('apply requires the exact reviewed prepared manifest digest')
    if not isinstance(host, str) or not HOST.fullmatch(host) or (stage.exists() and not resume) or not re.fullmatch('[A-Za-z0-9_-]{1,100}', stage.name):
        raise ValueError('a valid host and fresh canonical staging directory are required')
    protected_directory(stage.parent)
    protected_directory(release_dir.parent)
    if release_dir.exists(): protected_directory(release_dir)
    if stage.exists(): protected_directory(stage)
    template = verify(release_dir,source,release,worktree)
    ssh = ['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no',
           '-o','ForwardAgent=no','root@'+host]
    if resume:
        if not apply or not stage.is_dir() or not re.fullmatch('[a-zA-Z0-9_-]{1,100}',stage.name):
            raise ValueError('resume requires an existing protected preflight stage and --apply')
        manifest = json.loads((stage/'manifest.json').read_text())
        if manifest['source'] != source or manifest['release'] != release or manifest['kind'] not in ('self-upgrade', 'workload-authority'):
            raise ValueError('resume identity differs')
        if manifest['kind'] == 'workload-authority' and run(ssh+['komizo-box version']).decode().strip().removeprefix('v') != release.removeprefix('v'):
            raise ValueError('install this authenticated executor before changing workload authority')
        receipt = json.loads((stage/'verified-release.json').read_text())
        if receipt.get('host') != host or digest((stage/'verified-release.json').read_bytes()) != manifest['receipt_sha256']:
            raise ValueError('resume host or receipt differs')
        if digest((stage/'manifest.json').read_bytes()) != expected_manifest:
            raise ValueError('resume differs from the reviewed prepared manifest')
        remote='/var/lib/komizo/upgrades/'+stage.name
        names = ('manifest.json','verified-release.json',*(r['staged'] for r in manifest['files']))
        if manifest['kind'] == 'workload-authority': names += ('box',)
        if len(set(names)) != len(names): raise ValueError('duplicate staged filename')
        payloads = {}
        for name in names:
            if not re.fullmatch('[a-zA-Z0-9_.-]+',name): raise ValueError('invalid staged filename')
            payloads[name] = (stage/name).read_bytes()
        for row in manifest['files']:
            if digest(payloads[row['staged']]) != row['after']: raise ValueError('prepared platform file differs')
        if digest(payloads['box']) != json.loads((release_dir/'embedded-agents.json').read_text())['sha256']:
            raise ValueError('resume executable is not the authenticated release')
        # Plan stays local. Applying that exact plan can stage it once. Existing
        # staging is reusable only before a durable remote operation begins.
        state = run(ssh+['if test -d '+remote+'; then printf existing; elif test -e '+remote+'; then exit 1; else printf absent; fi']).strip()
        if state == b'absent':
            run(ssh+['set -eu; test ! -e '+remote+'; install -d -m 700 '+remote])
            for name, body in payloads.items():
                mode = '755' if name == 'box' or name.startswith(('deploy-','task-')) else '600'
                run(ssh+['set -eu; umask 077; test ! -e '+remote+'/'+name+'; cat > '+remote+'/'+name+'; chmod '+mode+' '+remote+'/'+name], body, timeout=120)
        elif state != b'existing': raise ValueError('unknown remote staging state')
        run(ssh+['test ! -e '+remote+'/operation.json'])
        for name, body in payloads.items():
            actual=run(ssh+['sha256sum '+remote+'/'+name]).decode().split()[0]
            if actual != digest(body):raise ValueError('remote preflight stage differs')
        legacy_migration(ssh,stage)
        expected=digest((stage/'manifest.json').read_bytes())
        accepted=json.loads(run(ssh+[remote+'/box platform apply '+remote+' '+expected],timeout=300))
        if accepted['phase'] != 'complete':raise ValueError('typed upgrade is not accepted')
        result={'host':host,'release':release,'source':source,'manifest_sha256':expected,'prepared':True,
                'applied':True,'application_restart':accepted['application_restart']}
        (stage/'installed.json').write_text(json.dumps(accepted,indent=2)+'\n')
        (stage/'acceptance.json').write_text(json.dumps(result,indent=2)+'\n')
        return result
    stage.mkdir(mode=0o700)
    if run(ssh+['uname -m']).strip() != b'x86_64':
        raise ValueError('authenticated self-upgrade currently supports Linux/amd64 only')
    legacy_migration(ssh, stage)
    report = json.loads(run(ssh+['komizo-box report']))
    apps = sorted(app['name'] for app in report['apps'])
    if len(apps) > 64 or any(not re.fullmatch('[a-z][a-z0-9_-]{0,62}', app) for app in apps):
        raise ValueError('invalid installed roster')
    metadata = json.loads((release_dir/'embedded-agents.json').read_text())
    files = []
    kind = 'workload-authority' if authority_review is not None else 'self-upgrade'
    inputs = [('/usr/local/bin/komizo-box','box',(release_dir/'komizo-box-linux-amd64').read_bytes(),0o755),
              ('/var/lib/komizo/version','version',(release+'\n'+metadata['stamp']+'\n').encode(),0o644)]
    if authority_review is not None:
        if run(ssh+['komizo-box version']).decode().strip().removeprefix('v') != release.removeprefix('v'):
            raise ValueError('install this authenticated executor before changing workload authority')
        inputs = authority_inputs(authority_review)
        for path, _, _, _ in inputs:
            if path == '/etc/doas.conf': continue
            app = Path(path).stem if path.startswith(('/etc/komizo/workloads/', '/var/lib/komizo/tasks/')) else re.sub(r'^(deploy|task|set-secret|set-release-secrets|export-backup)-', '', Path(path).name)
            if app not in apps: raise ValueError('authority review names an unregistered app')
        (stage/'box').write_bytes((release_dir/'komizo-box-linux-amd64').read_bytes()); (stage/'box').chmod(0o755)
    for app in apps if authority_review is None else ():
        path='/usr/local/bin/deploy-'+app
        previous=run(ssh+['cat '+shlex.quote(path)],maximum=1024*1024).decode()
        inputs.append((path,'deploy-'+app,wrapper(template,previous),0o755))
        task='/usr/local/bin/task-'+app
        state=run(ssh+['if test -f '+task+' && test -f /var/lib/komizo/tasks/'+app+'.sh; then printf installed; elif test -e '+task+'; then exit 1; else printf absent; fi']).strip()
        if state == b'installed': inputs.append((task,'task-'+app,task_wrapper(template,app),0o755))
        elif state != b'absent': raise ValueError('unknown installed task state')
    for path,name,body,mode in inputs:
        if authority_review is not None:
            prior, previous_mode = remote_identity(ssh, path)
        else:
            prior = run(ssh+['sha256sum '+shlex.quote(path)]).decode().split()[0]
            previous_mode = None
            if not re.fullmatch('[a-f0-9]{64}',prior): raise ValueError('installed identity is invalid')
        if prior is None and authority_review is None: raise ValueError('installed identity is absent')
        (stage/name).write_bytes(body);os.chmod(stage/name,0o600 if authority_review is not None else mode)
        if name.startswith(('deploy-','task-')):run(['sh','-n',str(stage/name)])
        files.append({'path':path,'staged':name,'before':prior,'after':digest(body),'mode':mode})
        if authority_review is not None: files[-1]['before_mode'] = previous_mode
    receipt={'version':1,'kind':kind,'host':host,'source':source,'authenticated':True,'files':files,'image':None,
             'release':release,'artifact_sha256':digest((release_dir/'komizo_Linux_x86_64.tar.gz').read_bytes()),
             'independent_review_claimed':False}
    raw=(json.dumps(receipt,sort_keys=True)+'\n').encode();(stage/'verified-release.json').write_bytes(raw)
    manifest={'version':1,'kind':kind,'source':source,'release':release,'files':files,
              'receipt_sha256':digest(raw),'image':None,'probes':[]}
    raw=(json.dumps(manifest,sort_keys=True)+'\n').encode();(stage/'manifest.json').write_bytes(raw)
    for name in ('manifest.json','verified-release.json'):os.chmod(stage/name,0o600)
    expected=digest(raw)
    result={'host':host,'release':release,'source':source,'manifest_sha256':expected,'prepared':True,'applied':False}
    if apply:
        if expected != expected_manifest:
            raise ValueError('prepared upgrade identity differs from the reviewed manifest')
        legacy_migration(ssh,stage)
        remote='/var/lib/komizo/upgrades/'+stage.name
        if not re.fullmatch('[a-zA-Z0-9_-]{1,100}',stage.name):raise ValueError('unsafe staging identity')
        run(ssh+['set -eu; test ! -e '+remote+'; install -d -m 700 '+remote])
        for path in sorted(stage.iterdir()):
            mode='755' if path.name=='box' or path.name.startswith(('deploy-','task-')) else '600'
            command='set -eu; umask 077; test ! -e '+remote+'/'+path.name+'; cat > '+remote+'/'+path.name+'; chmod '+mode+' '+remote+'/'+path.name
            run(ssh+[command],path.read_bytes(),timeout=120)
        accepted=json.loads(run(ssh+[remote+'/box platform apply '+remote+' '+expected],timeout=300))
        if accepted['phase'] != 'complete':raise ValueError('typed upgrade is not accepted')
        result.update(applied=True,application_restart=accepted['application_restart'])
        (stage/'installed.json').write_text(json.dumps(accepted,indent=2)+'\n')
    (stage/'acceptance.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def main(arguments=None):
    parser=argparse.ArgumentParser(prog='komizo platform')
    parser.add_argument('operation', choices=('plan','apply'))
    parser.add_argument('--host',required=True)
    parser.add_argument('--release',required=True)
    parser.add_argument('--source',required=True)
    parser.add_argument('--release-dir',type=Path,required=True)
    parser.add_argument('--stage',type=Path,required=True)
    parser.add_argument('--expected-manifest',help='exact digest returned by the reviewed preparation')
    parser.add_argument('--resume',action='store_true',help='retry only an identical stage with no operation journal')
    parser.add_argument('--authority-review',type=Path,help='private operator review of registered workload policy, adapter, task and doas files; no container activation')
    args=parser.parse_args(arguments)
    if os.geteuid()!=0: raise ValueError('protected preparation requires the root operator')
    if args.operation == 'plan' and (args.resume or args.expected_manifest): raise ValueError('plan accepts no apply options')
    print(json.dumps(prepare(args.host,args.release,args.source,args.release_dir,None,args.stage,args.operation=='apply',args.resume or (args.operation=='apply' and args.stage.exists()),args.expected_manifest,args.authority_review)))


if __name__ == '__main__':
    main()
