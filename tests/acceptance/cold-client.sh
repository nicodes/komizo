#!/usr/bin/env bash
set -euo pipefail
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
archive="$PWD/dist/komizo_Linux_x86_64.tar.gz"
test -s "$archive"
mkdir "$scratch/bin" "$scratch/project" "$scratch/home"
python3 -I -B - "$PWD/tests/acceptance" "$archive" "$scratch/bin/komizo" <<'EXTRACT'
from pathlib import Path
import sys
sys.path.insert(0,sys.argv[1])
from native_release import cli_binary,cli_platform
archive=Path(sys.argv[2]);binary=cli_binary(archive);cli_platform(binary,archive.name)
target=Path(sys.argv[3]);target.write_bytes(binary);target.chmod(0o755)
EXTRACT
# The installed client uses only ordinary system executables. Its isolated
# home has no hosted account, SDK installation, fleet policy or repository.
export PATH=/usr/bin:/bin
export HOME="$scratch/home"
unset GH_TOKEN GITHUB_TOKEN MISE_GITHUB_TOKEN
cd "$scratch/project"
"$scratch/bin/komizo" capabilities > capabilities.json
"$scratch/bin/komizo" version > version.txt
"$scratch/bin/komizo" --help > help.txt
if "$scratch/bin/komizo" artifact --arch amd64 --output host > refused.json 2> refused.txt; then
  exit 1
fi
test ! -e host
python3 - <<'CHECK'
import json,re
from pathlib import Path
capabilities=json.loads(Path('capabilities.json').read_bytes())
assert capabilities['kind']=='komizo.capabilities' and capabilities['version']==1
assert capabilities['host']=={'os':'debian','version':'13','engine':'podman','rootful':True}
assert capabilities['commands']=={'status':'read','inspect':'read','logs':'read','ui':'local','request':'typed',
 'start':'effect','stop':'effect','restart':'effect','backup':'effect'}
assert re.fullmatch(r'komizo [A-Za-z0-9.+_-]{1,128}\n',Path('version.txt').read_text())
assert 'komizo' in Path('help.txt').read_text() and Path('refused.json').read_bytes()==b''
assert not any(p.name.startswith('.komizo') or p.name in ('mise.toml','komizo.lock') for p in Path('.').iterdir())
CHECK
