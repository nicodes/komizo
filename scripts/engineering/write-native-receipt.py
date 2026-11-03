"""Record a native executable's exact source, release and digest."""
import hashlib,json,os,subprocess,sys
from pathlib import Path
path=Path(sys.argv[1]);source=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
path.with_suffix('.json').write_text(json.dumps({'schema':1,'source':source,'version':os.environ.get('VERSION','dev'),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()},sort_keys=True)+'\n')
