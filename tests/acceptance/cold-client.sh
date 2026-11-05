#!/usr/bin/env bash
set -euo pipefail
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
archive="$PWD/dist/komizo_Linux_x86_64.tar.gz"
test -s "$archive"
mkdir "$scratch/bin" "$scratch/project" "$scratch/home"
tar -xzf "$archive" -C "$scratch/bin" komizo
# The installed client uses only ordinary system executables. Its isolated
# home has no hosted account, SDK installation, fleet policy or repository.
export PATH=/usr/bin:/bin
export HOME="$scratch/home"
unset GH_TOKEN GITHUB_TOKEN MISE_GITHUB_TOKEN
cd "$scratch/project"
"$scratch/bin/komizo" --json capabilities > capabilities.json
"$scratch/bin/komizo" --json version > version.json
"$scratch/bin/komizo" --json deploy --help > help.json
"$scratch/bin/komizo" artifact --arch amd64 --output host > artifact.json
test -s host
python3 - <<'CHECK'
import json
from pathlib import Path
for name in ('capabilities','version','help'):
 assert json.loads(Path(name+'.json').read_bytes())['ok']
names={c['name'] for c in json.loads(Path('capabilities.json').read_bytes())['data']['commands']}
assert {'setup','deploy','status','operation'} <= names
assert not names & {'init','lock','dev','check','run','exec','describe','validate','operator','dependencies','metadata','workspace','publication'}
assert not any(p.name.startswith('.komizo') or p.name in ('mise.toml','komizo.lock') for p in Path('.').iterdir())
CHECK
