#!/usr/bin/env python3
"""Exact-byte, loopback-only OCI registry for the disposable native host suite."""
import argparse
import gzip
import hashlib
import http.server
import io
import json
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import tarfile

MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
STATIC = 'application/vnd.komizo.static.v1.tar+gzip'


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def digest(value):return 'sha256:'+hashlib.sha256(value).hexdigest()


def blob(root, body):
    identity=digest(body);path=root/'blobs'/identity[7:];path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():assert path.read_bytes()==body
    else:path.write_bytes(body)
    return identity


def static(root, app, revision, *, unsafe=False):
    data=io.BytesIO()
    with tarfile.open(fileobj=data,mode='w:',format=tarfile.USTAR_FORMAT) as archive:
        entry=tarfile.TarInfo('index.html');body=('<html>'+app+' '+revision+'</html>').encode();entry.mode=0o644;entry.size=len(body)
        archive.addfile(entry,io.BytesIO(body))
        if unsafe:
            entry=tarfile.TarInfo('outside');entry.type=tarfile.SYMTYPE;entry.linkname='/etc/shadow';archive.addfile(entry)
    payload=gzip.compress(data.getvalue(),mtime=0);identity=blob(root,payload);empty=blob(root,b'{}')
    manifest=canonical({'schemaVersion':2,'mediaType':MANIFEST,'artifactType':'application/vnd.komizo.static.v1',
        'config':{'mediaType':'application/vnd.oci.empty.v1+json','digest':empty,'size':2},
        'layers':[{'mediaType':STATIC,'digest':identity,'size':len(payload)}]})
    reference='registry.fixture.test:5443/example/'+app+'-web@'+blob(root,manifest)
    return {'kind':'archive','reference':reference,'digest':identity,'size_bytes':len(payload),'media_type':STATIC}


def image_sources():
    for executable,required in [('/bin/busybox.static',{'sh','cat','awk','wget','nc','nslookup','sha256sum','timeout','sleep','touch'}),
            ('/bin/busybox-extras',{'httpd'})]:
        result=subprocess.run([executable,'--list'],capture_output=True,timeout=5,check=True,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
        if not required.issubset(set(result.stdout.decode().splitlines())):
            raise ValueError('signed fixture binary lacks required applets: '+executable)
    return {name:Path(source).read_bytes() for name,source in [
        ('bin/busybox','/bin/busybox.static'),('bin/busybox-extras','/bin/busybox-extras'),
        ('lib/ld-musl-x86_64.so.1','/lib/ld-musl-x86_64.so.1')]}


def image(root, app, revision, *, repository=None):
    sources=image_sources()  # Refuse an unusable producer before any image blobs are created.
    data=io.BytesIO()
    with tarfile.open(fileobj=data,mode='w:',format=tarfile.USTAR_FORMAT) as archive:
        for name in ['bin','lib','www','www/cgi-bin','data']:
            info=tarfile.TarInfo(name);info.type=tarfile.DIRTYPE;info.mode=0o755;info.uid=info.gid=10001;archive.addfile(info)
        cgi=b'#!/bin/busybox sh\nprintf "Content-Type: text/plain\\r\\n\\r\\n%s\\n" "$HTTP_X_FORWARDED_FOR"\n'
        dispatcher=b'#!/bin/busybox sh\nif [ "${1-}" = httpd ]; then shift; exec /bin/busybox-extras httpd "$@"; fi\nexec /bin/busybox "$@"\n'
        for name,body,mode in [*[(name,body,0o755) for name,body in sources.items()],
                ('bin/fixture-entrypoint',dispatcher,0o755),
                ('www/index.html',(app+' '+revision).encode(),0o644),('www/cgi-bin/who',cgi,0o755)]:
            info=tarfile.TarInfo(name);info.size=len(body);info.mode=mode;info.uid=info.gid=10001;archive.addfile(info,io.BytesIO(body))
        info=tarfile.TarInfo('lib/libc.musl-x86_64.so.1');info.type=tarfile.SYMTYPE;info.linkname='ld-musl-x86_64.so.1';info.uid=info.gid=10001;archive.addfile(info)
    raw=data.getvalue();layer=gzip.compress(raw,mtime=0)
    config=canonical({'architecture':'amd64','os':'linux','config':{'User':'10001:10001','Entrypoint':['/bin/fixture-entrypoint'],
        'Env':['PATH=/bin'],'Labels':{'org.opencontainers.image.source':'https://github.com/'+(repository or 'example/'+app),'org.opencontainers.image.revision':revision}},
        'rootfs':{'type':'layers','diff_ids':[digest(raw)]}})
    config_id=blob(root,config);layer_id=blob(root,layer)
    manifest=canonical({'schemaVersion':2,'mediaType':MANIFEST,'config':{'mediaType':'application/vnd.oci.image.config.v1+json','digest':config_id,'size':len(config)},
        'layers':[{'mediaType':'application/vnd.oci.image.layer.v1.tar+gzip','digest':layer_id,'size':len(layer)}]})
    identity=blob(root,manifest)
    return {'kind':'image','reference':'registry.fixture.test:5443/example/'+app+'-api@'+identity,'digest':identity,'config_digest':config_id,'platform':'linux/amd64'}


def serve(root, certificate, key, port):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            match=re.fullmatch(r'/v2/example/[a-z][a-z0-9-]*/(manifests|blobs)/(sha256:[a-f0-9]{64})',self.path)
            path=root/'blobs'/match[2][7:] if match else None
            if path is None or not path.is_file():self.send_error(404);return
            self.send_response(200);self.send_header('Content-Length',str(path.stat().st_size))
            self.send_header('Docker-Content-Digest',match[2]);self.send_header('Content-Type',MANIFEST if match[1]=='manifests' else 'application/octet-stream')
            self.end_headers()
            with path.open('rb') as stream:shutil.copyfileobj(stream,self.wfile,1<<16)
        def log_message(self,*_):pass
    server=http.server.ThreadingHTTPServer(('127.0.0.1',port),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(certificate,key)
    server.socket=context.wrap_socket(server.socket,server_side=True);server.serve_forever()


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);parser.add_argument('--cert',required=True);parser.add_argument('--key',required=True)
    args=parser.parse_args();serve(args.root,args.cert,args.key,5443)
