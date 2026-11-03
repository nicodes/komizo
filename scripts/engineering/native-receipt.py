"""Verify native CI build inputs belong to this exact source and release."""
import hashlib,json,os,subprocess,sys
from pathlib import Path
path=Path(sys.argv[1]);meta=json.loads(path.with_suffix('.json').read_bytes())
source=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
if meta.get('schema')!=1 or meta.get('source')!=source or meta.get('version')!=os.environ.get('VERSION','dev'):
    raise SystemExit('native artifact source/version mismatch')
if not path.is_file() or path.is_symlink() or path.stat().st_size>128<<20 or hashlib.sha256(path.read_bytes()).hexdigest()!=meta.get('sha256'):
    raise SystemExit('native artifact digest/type mismatch')
