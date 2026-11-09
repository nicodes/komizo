#!/usr/bin/env python3
"""Fetch the exact native-test SDK through GitHub's authenticated asset API."""
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION='2026.10.17'
ASSET='mise-v2026.10.17-linux-x64.tar.zst'
ASSET_ID=660998924
SIZE=40900203
SHA256='149221df8c937bfb89aef773d11d2440df7c010f0145b62e6708560f86b32cc7'
API='https://api.github.com/repos/jdx/mise/releases/'
CDN={'release-assets.githubusercontent.com','objects.githubusercontent.com'}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*_):return None


def request(url,headers,deadline,opener):
    remaining=deadline-time.monotonic()
    if remaining<=0:raise ValueError('pinned SDK bootstrap exceeded its deadline')
    return opener.open(urllib.request.Request(url,headers=headers),timeout=min(20,remaining))


def metadata(value):
    if not isinstance(value,dict) or value.get('tag_name')!='v'+VERSION or value.get('draft') is not False:
        raise ValueError('pinned SDK release identity differs')
    matches=[row for row in value.get('assets',[]) if row.get('name')==ASSET]
    expected={'id':ASSET_ID,'name':ASSET,'size':SIZE,'digest':'sha256:'+SHA256,'url':API+'assets/'+str(ASSET_ID)}
    if len(matches)!=1 or any(matches[0].get(key)!=item for key,item in expected.items()):
        raise ValueError('pinned SDK asset identity differs')


def download(target,token,deadline,opener=None):
    if not token or len(token)>32768 or any(char in token for char in '\r\n\0'):
        raise ValueError('pinned SDK bootstrap requires one bounded read token')
    opener=opener or urllib.request.build_opener(NoRedirect())
    common={'User-Agent':'komizo-native-sdk','X-GitHub-Api-Version':'2022-11-28'}
    authorization={**common,'Authorization':'Bearer '+token}
    with request(API+'tags/v'+VERSION,{**authorization,'Accept':'application/vnd.github+json'},deadline,opener) as source:
        raw=source.read((1<<20)+1)
        if len(raw)>1<<20:raise ValueError('pinned SDK metadata exceeds its bound')
        metadata(json.loads(raw))
    try:
        source=request(API+'assets/'+str(ASSET_ID),{**authorization,'Accept':'application/octet-stream'},deadline,opener)
    except urllib.error.HTTPError as error:
        if error.code not in {301,302,303,307,308}:raise
        location=error.headers.get('Location','');error.close()
        parsed=urllib.parse.urlsplit(location)
        if parsed.scheme!='https' or parsed.hostname not in CDN or parsed.username or parsed.password or parsed.port not in {None,443} or parsed.fragment:
            raise ValueError('pinned SDK asset redirected outside the official CDN')
        # The bearer token is sent only to api.github.com; never forward it to
        # the signed CDN URL or accept another redirect there.
        source=request(location,common,deadline,opener)
    digest=hashlib.sha256();size=0
    with source,Path(target).open('xb') as output:
        while block:=source.read(1<<16):
            size+=len(block)
            if size>SIZE or time.monotonic()>=deadline:raise ValueError('pinned SDK asset exceeds its size or deadline')
            digest.update(block);output.write(block)
    if size!=SIZE or digest.hexdigest()!=SHA256:raise ValueError('pinned SDK asset bytes changed')


def install(directory,token,deadline):
    directory=Path(directory);binary=directory/'mise';archive=directory/ASSET
    download(archive,token,deadline)
    try:
        remaining=deadline-time.monotonic()
        if remaining<=0:raise ValueError('pinned SDK bootstrap exceeded its deadline')
        with binary.open('xb') as output:
            subprocess.run(['tar','--zstd','-xOf',str(archive),'mise/bin/mise'],stdout=output,stderr=subprocess.PIPE,
                check=True,timeout=min(20,remaining))
        with binary.open('rb') as source:header=source.read(20)
        if not 0<binary.stat().st_size<=256<<20 or len(header)!=20 or header[:7]!=b'\x7fELF\x02\x01\x01' or struct.unpack_from('<H',header,18)[0]!=62:
            raise ValueError('pinned SDK executable has another native platform')
        binary.chmod(0o700)
        remaining=deadline-time.monotonic()
        if remaining<=0:raise ValueError('pinned SDK bootstrap exceeded its deadline')
        result=subprocess.run([str(binary),'--version'],check=True,capture_output=True,text=True,
            timeout=min(10,remaining))
        if not result.stdout.startswith(VERSION+' '):raise ValueError('pinned SDK executable reports another version')
        if time.monotonic()>=deadline:raise ValueError('pinned SDK bootstrap exceeded its deadline')
    finally:archive.unlink(missing_ok=True)
    return binary


def main():
    if sys.platform!='linux' or platform.machine().lower() not in {'x86_64','amd64'}:
        raise ValueError('this native SDK bootstrap selects Linux x86_64 only')
    parent=Path(os.environ['RUNNER_TEMP']);workspace=os.environ['GITHUB_WORKSPACE']
    if not parent.is_absolute() or any(char in workspace for char in '\r\n\0'):
        raise ValueError('native SDK bootstrap requires fixed runner paths')
    directory=Path(tempfile.mkdtemp(prefix='komizo-native-sdk-',dir=parent));directory.chmod(0o700)
    binary=install(directory,os.environ.get('GH_TOKEN',''),time.monotonic()+90)
    with open(os.environ['GITHUB_PATH'],'a') as output:output.write(str(binary.parent)+'\n')
    with open(os.environ['GITHUB_ENV'],'a') as output:
        output.write('MISE_YES=1\nMISE_LOG_LEVEL=info\nMISE_TRUSTED_CONFIG_PATHS='+workspace+'\n')
    print('Authenticated pinned Mise '+VERSION+' via official asset API and SHA256')


if __name__=='__main__':
    try:main()
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        # HTTP errors can contain a signed CDN query; never print raw URLs,
        # credentials, response bodies or exception representations.
        raise SystemExit('Pinned native SDK bootstrap failed: '+type(error).__name__) from None
