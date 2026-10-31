"""Check a native builder's source and digest before embedding its Rust API."""
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys

path = Path(sys.argv[1])
meta = json.loads(path.with_suffix('.json').read_text())
source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
if meta.get('schema') != 1 or meta.get('source') != source:
    raise SystemExit('native API source mismatch')
raw = path.read_bytes()
if not raw or hashlib.sha256(raw).hexdigest() != meta.get('sha256'):
    raise SystemExit('native API digest mismatch')
Path('internal/nativeapi/payload.gz').write_bytes(gzip.compress(raw, mtime=0))
