"""Authenticate an immutable proxy and use the protected host platform executor."""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shlex
import sys
import urllib.parse
import stat

# The CLI supplies this shared owner directly from its embedded source. Standalone
# fixture imports resolve the sibling implementation explicitly, never sys.path.
if 'run' not in globals():
    import importlib.util
    spec = importlib.util.spec_from_file_location('komizo_platform_prepare', Path(__file__).with_name('platform_prepare.py'))
    shared = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shared)
    run, digest, protected_directory, HOST = shared.run, shared.digest, shared.protected_directory, shared.HOST

TIMEOUTS = '    servers {\n        timeouts {\n            read_header 5s\n            read_body 3m\n            idle 2m\n        }\n    }\n'


def private_bytes(path, maximum=1024*1024):
    protected_directory(path.parent)
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != path.parent.stat().st_uid or info.st_mode & 0o077 or info.st_size > maximum:
        raise ValueError('proxy input must be protected, regular and bounded')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        opened=os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev,opened.st_ino) != (info.st_dev,info.st_ino):
            raise ValueError('proxy input identity changed')
        body=stream.read(maximum+1)
        if len(body) > maximum: raise ValueError('proxy input exceeds its byte bound')
        return body


def existing_probe(probe):
    url=urllib.parse.urlsplit(probe['url'])
    connection=http.client.HTTPSConnection(url.hostname,port=url.port or 443,timeout=10)
    try:
        if url.scheme == 'wss':
            key=base64.b64encode(os.urandom(16)).decode()
            expected=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            connection.request('GET',url.path,headers={'Connection':'Upgrade','Upgrade':'websocket',
                'Sec-WebSocket-Version':'13','Sec-WebSocket-Key':key})
            response=connection.getresponse()
            return (response.status==101 and response.getheader('X-Komizo-Revision')==probe['revision']
                    and response.getheader('Upgrade','').lower()=='websocket'
                    and response.getheader('Sec-WebSocket-Accept')==expected)
        # Direct HTTPS does not follow redirects or use environment proxies.
        connection.request('GET',url.path)
        response=connection.getresponse()
        if 'status' in probe:
            return (response.status==probe['status'] and response.getheader('Location')==probe['location']
                    and response.getheader('X-Komizo-Revision')==probe['revision'])
        return (response.status==200 and response.getheader('X-Komizo-Revision')==probe['revision']
                and bool(response.read(512).strip()))
    finally:connection.close()


def bounded_listener(previous):
    """Preserve TLS/imports verbatim; refuse ambiguous pre-existing servers."""
    if re.search(r'^\s*servers(?:\s|\{)', previous, re.M):
        if previous.count(TIMEOUTS)==1 and len(re.findall(r'^\s*servers(?:\s|\{)',previous,re.M))==1:
            return previous.encode()
        raise ValueError('existing listener policy needs explicit review')
    lines = previous.splitlines(keepends=True)
    first = next((i for i, line in enumerate(lines) if line.strip() and not line.lstrip().startswith('#')), len(lines))
    if first < len(lines) and lines[first].strip() == '{':
        lines.insert(first + 1, TIMEOUTS)
    else:
        lines.insert(first, '{\n' + TIMEOUTS + '}\n\n')
    return ''.join(lines).encode()


def resource_budget(value):
    if (not isinstance(value,dict) or set(value)!={'version','memory_bytes','total_memory_swap_bytes','milli_cpus','pids','cgroup_parent','policy_sha256'}
            or value['version']!=1 or any(type(value[k]) is not int or value[k]<=0 for k in ('memory_bytes','total_memory_swap_bytes','milli_cpus','pids'))
            or value['total_memory_swap_bytes']<value['memory_bytes'] or value['cgroup_parent'] not in ('','/komizo-proxy')
            or bool(value['cgroup_parent']) != (isinstance(value['policy_sha256'],str) and re.fullmatch('[a-f0-9]{64}',value['policy_sha256']) is not None)
            or not value['cgroup_parent'] and value['policy_sha256'] is not None):
        raise ValueError('proxy resource grant must bind finite protected host budgets')
    return value


def installed_compose(ssh, previous):
    """Keep exact file bytes in the grant; normalize legacy YAML with its project."""
    try:
        json.loads(previous)
        return previous
    except json.JSONDecodeError:
        labels=json.loads(run(ssh+['docker inspect --format \'{{json .Config.Labels}}\' komizo-proxy']))
        if (labels.get('com.docker.compose.project')!='komizo-proxy'
                or labels.get('com.docker.compose.service')!='komizo-proxy'):
            raise ValueError('legacy YAML proxy lacks the expected installed Compose identity')
        normalized=run(ssh+['docker compose --project-name komizo-proxy --file /srv/_proxy/compose.yml config --format json --no-interpolate --no-env-resolution'])
        document=json.loads(normalized)
        if document.get('name')!='komizo-proxy' or set(document.get('services',{}))!={'komizo-proxy'}:
            raise ValueError('legacy proxy normalization changed the installed project')
        return normalized


def compose_candidate(previous, reference, budget=None):
    doc = json.loads(previous)
    if doc.get('name') != 'komizo-proxy' or set(doc.get('services', {})) != {'komizo-proxy'}:
        raise ValueError('unknown installed proxy project')
    doc['services']['komizo-proxy']['image'] = reference
    if budget is not None:
        budget=resource_budget(budget)
        service=doc['services']['komizo-proxy']
        service.update(mem_limit=budget['memory_bytes'],memswap_limit=budget['total_memory_swap_bytes'],
                       cpus=f"{budget['milli_cpus']/1000:.3f}",pids_limit=budget['pids'])
        if budget['cgroup_parent']:service['cgroup_parent']=budget['cgroup_parent']
        else:service.pop('cgroup_parent',None)
    return (json.dumps(doc, indent=2)+'\n').encode()


def verify(reference, source):
    if not re.fullmatch('ghcr.io/nicodes/platform-proxy@sha256:[a-f0-9]{64}', reference) or not re.fullmatch('[a-f0-9]{40}', source):
        raise ValueError('immutable proxy and exact publisher source required')
    authority = 'https://github.com/nicodes/tools/.github/workflows/platform-proxy.yml@refs/heads/main'
    proof = run(['gh','attestation','verify','oci://'+reference,'--repo','nicodes/tools',
                 '--cert-identity',authority,'--cert-oidc-issuer','https://token.actions.githubusercontent.com',
                 '--signer-digest',source,'--source-digest',source,'--source-ref','refs/heads/main',
                 '--deny-self-hosted-runners','--format','json'])
    rows = json.loads(proof)
    if not rows:
        raise ValueError('proxy provenance is absent')
    for row in rows:
        verified = row['verificationResult']
        cert = verified['signature']['certificate']
        if (cert['subjectAlternativeName'] != authority or cert['sourceRepositoryDigest'] != source
                or cert['issuer'] != 'https://token.actions.githubusercontent.com'
                or not any(s['digest'].get('sha256') == reference.split(':')[-1]
                           for s in verified['statement']['subject'])):
            raise ValueError('proxy provenance differs')
    return proof


def prepare(host, reference, source, stage, probes, apply=False, expected_manifest=None, bind_resources=False):
    if not HOST.fullmatch(host) or not stage.is_absolute() or stage.resolve(strict=False) != stage or not re.fullmatch('[A-Za-z0-9_-]{1,100}',stage.name):
        raise ValueError('approved host and fresh protected stage required')
    protected_directory(stage.parent)
    ssh = ['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no',
           '-o','ForwardAgent=no','root@'+host]
    if apply:
        if not stage.is_dir(): raise ValueError('apply requires the protected prepared plan')
        protected_directory(stage)
        manifest_raw=private_bytes(stage/'manifest.json')
        manifest=json.loads(manifest_raw)
        receipt_raw=private_bytes(stage/'verified-release.json')
        receipt=json.loads(receipt_raw)
        if (digest(manifest_raw) != expected_manifest or manifest.get('kind') != 'proxy-upgrade'
                or manifest.get('source') != source or manifest.get('image',{}).get('reference') != reference
                or receipt.get('host') != host or digest(receipt_raw) != manifest.get('receipt_sha256')
                or receipt.get('probes') != probes or manifest.get('probes') != probes
                or bool('resource_budget' in manifest)!=bind_resources
                or receipt.get('resource_budget')!=manifest.get('resource_budget')):
            raise ValueError('proxy apply differs from the reviewed host, source, probes or manifest')
        verify(reference,source)
        if bind_resources and resource_budget(json.loads(run(ssh+['komizo-box workload proxy-budget']))) != manifest['resource_budget']:
            raise ValueError('protected proxy resource budget changed after planning')
        names=('manifest.json','verified-release.json',*(row['staged'] for row in manifest['files']))
        if len(set(names)) != len(names) or any(not re.fullmatch('[a-zA-Z0-9_.-]+',name) for name in names):
            raise ValueError('invalid proxy staging filenames')
        payloads={name:private_bytes(stage/name) for name in names}
        for row in manifest['files']:
            if digest(payloads[row['staged']]) != row['after']: raise ValueError('prepared proxy bytes differ')
        for probe in probes:
            if not existing_probe(probe): raise ValueError('serving identity changed since proxy planning')
        remote='/var/lib/komizo/upgrades/'+stage.name
        state=run(ssh+['if test -d '+remote+'; then printf existing; elif test -e '+remote+'; then exit 1; else printf absent; fi']).strip()
        if state == b'absent':
            run(ssh+['set -eu; test ! -e '+remote+'; install -d -m 700 '+remote])
            for name,body in payloads.items():
                run(ssh+['set -eu; umask 077; test ! -e '+remote+'/'+name+'; cat > '+remote+'/'+name],body,timeout=120)
        elif state != b'existing': raise ValueError('unknown remote stage')
        run(ssh+['test ! -e '+remote+'/operation.json'])
        for name,body in payloads.items():
            if run(ssh+['sha256sum '+remote+'/'+name]).decode().split()[0] != digest(body):
                raise ValueError('remote preflight bytes differ')
        accepted=json.loads(run(ssh+['komizo-box platform apply '+remote+' '+expected_manifest],timeout=300))
        if accepted.get('phase') != 'complete': raise ValueError('proxy upgrade requires inspection or recovery')
        result={'host':host,'source':source,'image':manifest['image'],'manifest_sha256':expected_manifest,'prepared':True,'applied':True}
        (stage/'installed.json').write_text(json.dumps(accepted,indent=2)+'\n')
        (stage/'acceptance.json').write_text(json.dumps(result,indent=2)+'\n')
        return result
    if stage.exists() or expected_manifest is not None: raise ValueError('plan needs a fresh stage and no apply digest')
    proof = verify(reference, source)
    stage.mkdir(mode=0o700)
    (stage/'attestation.json').write_bytes(proof)
    report = json.loads(run(ssh+['komizo-box report']))
    budget=resource_budget(json.loads(run(ssh+['komizo-box workload proxy-budget']))) if bind_resources else None
    release = report['server']['komizo']['version']
    if tuple(map(int,release.removeprefix('v').split('.'))) < (0,0,79):
        raise ValueError('proxy upgrade requires the reviewed platform executor')
    if run(ssh+['uname -m']).strip() != b'x86_64':
        raise ValueError('this attested proxy supports linux/amd64 only')
    expected={}
    for app in report['apps']:
        if app.get('runtime_state') != 'running': continue
        if not re.fullmatch('[a-f0-9]{40}',app.get('version','')): raise ValueError('serving source identity unavailable')
        for host_row in app.get('hosts',[]):
            hostname=host_row['name']
            if not HOST.fullmatch(hostname) or hostname in expected: raise ValueError('ambiguous installed route')
            expected[hostname]=app['version']
    observed={}
    for probe in probes:
        if set(probe) not in ({'url','revision'}, {'url','revision','status','location'}): raise ValueError('invalid probe contract')
        url=urllib.parse.urlsplit(probe['url'])
        if url.scheme not in ('https','wss') or url.username or url.password or url.port not in (None,443) or url.query or url.fragment or not url.path.startswith('/'):
            raise ValueError('invalid serving probe URL')
        if url.hostname in observed or expected.get(url.hostname) != probe['revision']:
            raise ValueError('probe differs from installed serving identity')
        if 'status' in probe:
            target=urllib.parse.urlsplit(probe['location'])
            if (url.scheme != 'https' or type(probe['status']) is not int or probe['status'] not in (301,302,303,307,308)
                    or target.scheme != 'https' or target.hostname not in expected or target.username or target.password
                    or target.port not in (None,443) or target.query or target.fragment or not target.path.startswith('/')):
                raise ValueError('redirect probe requires an explicit status and installed HTTPS destination')
        observed[url.hostname]=probe['revision']
    if observed != expected: raise ValueError('every running installed hostname requires an explicit readiness probe')
    if not 1 <= len(probes) <= 64:
        raise ValueError('bounded serving route probes are required')
    # Pull happens before the durable operation. It changes no container or
    # service; activation itself forbids pulls and retains the running image.
    run(ssh+['docker pull '+shlex.quote(reference)], timeout=180)
    identity = run(ssh+['docker image inspect --format "{{.Id}}" '+shlex.quote(reference)]).decode().strip()
    old_identity = run(ssh+['docker inspect --format "{{.Image}}" komizo-proxy']).decode().strip()
    image = {'reference':reference,'id':identity,'previous_id':old_identity}
    if any(not re.fullmatch('sha256:[a-f0-9]{64}',image[k]) for k in ('id','previous_id')):
        raise ValueError('invalid host image identity')
    label = run(ssh+['docker image inspect --format \'{{index .Config.Labels "org.opencontainers.image.revision"}}\' '+shlex.quote(reference)]).decode().strip()
    if label != source:
        raise ValueError('local proxy source label differs')
    files = []
    for path, name, convert in [('/srv/_proxy/compose.yml','proxy-compose',lambda b:compose_candidate(installed_compose(ssh,b),reference,budget)),
                                ('/srv/_proxy/Caddyfile','proxy-caddy',lambda b:bounded_listener(b.decode()))]:
        previous = run(ssh+['cat '+shlex.quote(path)])
        body = convert(previous)
        (stage/name).write_bytes(body)
        files.append({'path':path,'staged':name,'before':digest(previous),'after':digest(body),'mode':0o644})
    # Establish the acceptance contract before any activation, including API
    # health paths whose ordinary root is intentionally not a public document.
    for probe in probes:
        if not existing_probe(probe):
            raise ValueError('existing proxy does not meet the reviewed route contract')
    receipt = {'version':1,'kind':'proxy-upgrade','source':source,'authenticated':True,'files':files,'image':image,
               'host':host,'probes':probes,'independent_review_claimed':False,'provenance_sha256':digest(proof)}
    if budget is not None:receipt['resource_budget']=budget
    raw = (json.dumps(receipt,sort_keys=True)+'\n').encode()
    (stage/'verified-release.json').write_bytes(raw)
    manifest = {'version':1,'kind':'proxy-upgrade','source':source,'release':release,'files':files,
                'receipt_sha256':digest(raw),'image':image,'probes':probes}
    if budget is not None:manifest['resource_budget']=budget
    raw = (json.dumps(manifest,sort_keys=True)+'\n').encode()
    (stage/'manifest.json').write_bytes(raw)
    for file in stage.iterdir():file.chmod(0o600)
    expected = digest(raw)
    result = {'host':host,'source':source,'image':image,'manifest_sha256':expected,'prepared':True,'applied':False}
    (stage/'acceptance.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def main(arguments=None):
    parser = argparse.ArgumentParser(prog='komizo platform proxy')
    parser.add_argument('operation',choices=('plan','apply'))
    parser.add_argument('--host',required=True)
    parser.add_argument('--reference',required=True)
    parser.add_argument('--source',required=True)
    parser.add_argument('--stage',type=Path,required=True)
    parser.add_argument('--probes',type=Path,required=True)
    parser.add_argument('--expected-manifest')
    parser.add_argument('--bind-resources',action='store_true',help='bind finite leaf limits and group to the current protected host resource policy')
    args=parser.parse_args(arguments)
    if os.geteuid()!=0: raise ValueError('protected proxy preparation requires root')
    probes=json.loads(private_bytes(args.probes,65536))
    if not isinstance(probes,list) or not 1 <= len(probes) <= 64: raise ValueError('bounded probe list is required')
    print(json.dumps(prepare(args.host,args.reference,args.source,args.stage,probes,args.operation=='apply',args.expected_manifest,args.bind_resources)))

if __name__ == '__main__': main()
