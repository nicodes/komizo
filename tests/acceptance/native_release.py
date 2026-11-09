"""Independently verify the finite standalone host and owner release payload."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tarfile
import time

REPOSITORY='nicodes/komizo'
WORKFLOW='https://github.com/'+REPOSITORY+'/.github/workflows/release.yml@refs/heads/main'
CLI_NAMES={f'komizo_{platform}_{arch}.tar.gz' for platform in ['Linux','Darwin'] for arch in ['x86_64','arm64']}
HOSTS={'komizo-box_Linux_x86_64':('Linux/x86_64',62),'komizo-box_Linux_arm64':('Linux/arm64',183)}
PROXIES={'caddy_Linux_x86_64':('linux/amd64',62),'caddy_Linux_arm64':('linux/arm64',183)}
PAYLOAD=CLI_NAMES|set(HOSTS)|set(PROXIES)|{name+'.json' for name in [*HOSTS,*PROXIES]}
SHA=re.compile(r'[a-f0-9]{64}\Z')
SOURCE=re.compile(r'[a-f0-9]{40}\Z')
TAG=re.compile(r'v[0-9]+\.[0-9]+\.[0-9]+\Z')


def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('release metadata contains duplicate fields')
        result[key]=value
    return result


def read(path,maximum=128<<20):
    path=Path(path)
    descriptor=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
    with os.fdopen(descriptor,'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or not 0<before.st_size<=maximum:
            raise ValueError('release payload requires a bounded ordinary file')
        raw=stream.read(maximum+1);after=os.fstat(stream.fileno())
        if (len(raw)!=before.st_size or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
                !=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)):
            raise ValueError('release payload changed while being verified')
    return raw


def digest(raw):return hashlib.sha256(raw).hexdigest()


def host_elf(raw,machine):
    if (len(raw)<64 or raw[:7]!=b'\x7fELF\x02\x01\x01' or struct.unpack_from('<H',raw,16)[0] not in {2,3}
            or struct.unpack_from('<H',raw,18)[0]!=machine or struct.unpack_from('<I',raw,20)[0]!=1
            or struct.unpack_from('<Q',raw,24)[0]==0):
        raise ValueError('standalone host must be its declared native Linux ELF')
    offset=struct.unpack_from('<Q',raw,32)[0];size,count=struct.unpack_from('<HH',raw,54)
    if size!=56 or not 0<count<=128 or offset<64 or offset+size*count>len(raw):
        raise ValueError('standalone host has invalid bounded ELF program headers')
    if any(struct.unpack_from('<I',raw,offset+index*size)[0]==3 for index in range(count)):
        raise ValueError('standalone host requires an unapproved dynamic interpreter')


def cli_binary(path):
    with tarfile.open(path,'r:gz') as archive:
        entries=archive.getmembers()
        if (len(entries)!=3 or {entry.name for entry in entries}!={'komizo','README.md','LICENSE'}
                or any(not entry.isfile() or entry.sparse or entry.pax_headers or not 0<entry.size<=128<<20 for entry in entries)):
            raise ValueError('owner archive has an unapproved member, link or payload')
        return archive.extractfile('komizo').read()


def cli_platform(raw,name):
    arm='_arm64.' in name
    if name.startswith('komizo_Linux_'):host_elf(raw,183 if arm else 62)
    elif (len(raw)<32 or raw[:4]!=b'\xcf\xfa\xed\xfe'
            or int.from_bytes(raw[4:8],'little')!=(0x0100000c if arm else 0x01000007)
            or int.from_bytes(raw[12:16],'little')!=2
            or int.from_bytes(raw[16:20],'little')>4096
            or 32+int.from_bytes(raw[20:24],'little')>len(raw)):
        raise ValueError('owner archive has another native executable platform')


def inventory(directory,source,release):
    directory=Path(directory)
    if directory.is_symlink() or not directory.is_dir() or not SOURCE.fullmatch(source) or not TAG.fullmatch(release):
        raise ValueError('release verification requires exact source, tag and ordinary payload directory')
    checks={}
    for line in read(directory/'checksums.txt',65536).decode().splitlines():
        values=line.split()
        if len(values)!=2 or values[1] in checks or values[1] not in PAYLOAD or not SHA.fullmatch(values[0]):
            raise ValueError('release checksum inventory is not closed and unique')
        checks[values[1]]=values[0]
    if set(checks)!=PAYLOAD:raise ValueError('release requires four owner archives and independently receipted host and proxy companions')
    result={}
    for name,expected in sorted(checks.items()):
        raw=read(directory/name,65536 if name.endswith('.json') else 128<<20)
        if digest(raw)!=expected:raise ValueError('release payload checksum differs')
        result[name]={'sha256':expected,'size_bytes':len(raw)}
        if name in CLI_NAMES:
            binary=cli_binary(directory/name);cli_platform(binary,name)
            result[name]['executable_sha256']=digest(binary)
        if name in HOSTS:
            platform,machine=HOSTS[name];host_elf(raw,machine)
            receipt=json.loads(read(directory/(name+'.json'),65536),object_pairs_hook=unique)
            if receipt!={'schema':1,'source':source,'version':release[1:],'kind':'host','platform':platform,'dependencies':{},'sha256':expected}:
                raise ValueError('standalone host receipt differs from source, version, role or dependencies')
        if name in PROXIES:
            platform,machine=PROXIES[name];host_elf(raw,machine)
            receipt=json.loads(read(directory/(name+'.json'),65536),object_pairs_hook=unique)
            baseline=json.loads(read(Path(__file__).resolve().parents[1]/'fixtures/native_host/baseline.json',65536),object_pairs_hook=unique)
            if receipt!={'kind':'komizo.proxy-build','version':1,'tools_revision':baseline['proxy_tools_revision'],
                    'platform':platform,'go_version':baseline['proxy_go_version'],'caddy_version':baseline['caddy_version'],
                    'source_sha256':baseline['proxy_source_sha256'],'binary_sha256':'sha256:'+expected}:
                raise ValueError('native proxy receipt differs from the independently reviewed source closure or compiler')
    return result


def attestation(rows,name,expected,source):
    if not isinstance(rows,list) or not rows:raise ValueError('release attestation is absent')
    for row in rows:
        verified=row['verificationResult'];certificate=verified['signature']['certificate']
        if (certificate['subjectAlternativeName']!=WORKFLOW or certificate['issuer']!='https://token.actions.githubusercontent.com'
                or certificate['sourceRepositoryDigest']!=source or certificate['githubWorkflowRef']!='refs/heads/main'
                or not any(subject.get('name')==name and subject.get('digest')=={'sha256':expected}
                    for subject in verified['statement']['subject'])):
            raise ValueError('release attestation differs from the exact trusted source workflow and artifact')


def verify(directory,source,release,*,deadline=None,execute=subprocess.run):
    deadline=deadline if deadline is not None else time.monotonic()+1200
    payload=inventory(directory,source,release)
    for name,metadata in payload.items():
        remaining=min(120,deadline-time.monotonic())
        if remaining<=0:raise ValueError('release provenance verification exceeded the acceptance deadline')
        response=execute(['gh','attestation','verify',str(Path(directory)/name),'--repo',REPOSITORY,
            '--cert-identity',WORKFLOW,'--cert-oidc-issuer','https://token.actions.githubusercontent.com',
            '--signer-digest',source,'--source-digest',source,'--source-ref','refs/heads/main',
            '--deny-self-hosted-runners','--limit','10','--format','json'],check=True,capture_output=True,timeout=remaining)
        if len(response.stdout)>4<<20:raise ValueError('release attestation exceeds its metadata bound')
        attestation(json.loads(response.stdout,object_pairs_hook=unique),name,metadata['sha256'],source)
    if payload!=inventory(directory,source,release):raise ValueError('release bytes changed after provenance verification')
    return {'version':1,'source':source,'release':release,'signer':WORKFLOW,'artifacts':payload}
