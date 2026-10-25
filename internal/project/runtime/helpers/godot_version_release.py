"""Content-address the Godot shell's payload; keep only this image's release."""

import hashlib
import json
from pathlib import Path
import re
import shutil
import stat


def payload_path(root, name):
    if not isinstance(name, str) or not name or Path(name).is_absolute() or '..' in Path(name).parts or Path(name).as_posix() != name:
        raise ValueError('payload path must remain inside the serving root')
    path = root / name
    if any(parent.is_symlink() for parent in [path, *path.parents]):
        raise ValueError('payload path may not contain links')
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('payload must be a regular file')
    return path


def digest(path):
    with path.open('rb') as incoming:
        return hashlib.file_digest(incoming, 'sha256').hexdigest()


def compact_payloads(root, files, release_id, root_files=()):
    """Remove only verified duplicate inputs; public versioned URLs stay identical."""
    if Path(root).is_symlink():
        raise ValueError('serving root may not be a link')
    root = Path(root).resolve(strict=True)
    if not re.fullmatch(r'[a-f0-9]{64}', release_id):
        raise ValueError('exact content release required')
    retained = {'index.html', *root_files}
    if not retained <= set(files):
        raise ValueError('root metadata must name existing export files')
    removals = []
    for name, info in files.items():
        original = payload_path(root, name)
        if name in retained:
            continue
        versioned = payload_path(root, f'releases/{release_id}/{name}')
        if digest(original) != info['sha256'] or digest(versioned) != info['sha256']:
            raise ValueError('versioned payload differs from its audited source')
        removals.append(original)
        for suffix in ('.gz', '.br'):
            if (root / (name + suffix)).exists() or (root / (name + suffix)).is_symlink():
                source = payload_path(root, name + suffix)
                target = payload_path(root, f'releases/{release_id}/{name}{suffix}')
                if digest(source) != digest(target):
                    raise ValueError('versioned sidecar differs from its source')
                removals.append(source)
    # Validate the complete plan before changing any path.
    removed = sum(path.stat().st_size for path in removals)
    for path in removals:
        path.unlink()
    for name, info in files.items():
        info['path'] = name if name in retained else f'releases/{release_id}/{name}'
    return {'layout': 'versioned-payload-v1', 'duplicate_logical_bytes_removed': removed}


def restore_export_inputs(root):
    """Rehydrate audited raw inputs for a disposable cache-upgrade/repack fixture."""
    if Path(root).is_symlink():
        raise ValueError('serving root may not be a link')
    root = Path(root).resolve(strict=True)
    manifest_path = payload_path(root, 'release-manifest.json')
    if manifest_path.stat().st_size > 1_000_000:
        raise ValueError('release manifest exceeds its bound')
    manifest = json.loads(manifest_path.read_text())
    release_id = manifest['release_id']
    if not re.fullmatch(r'[a-f0-9]{64}', release_id):
        raise ValueError('exact content release required')
    copies = []
    for name, info in manifest['files'].items():
        expected = name if info.get('path', name) == name else f'releases/{release_id}/{name}'
        if info.get('path', name) != expected:
            raise ValueError('manifest payload path differs from its release')
        source = payload_path(root, expected)
        if digest(source) != info['sha256']:
            raise ValueError('fixture input differs from the audited release')
        destination = root / name
        if destination != source:
            if any(parent.is_symlink() for parent in destination.parents):
                raise ValueError('fixture input parent may not be a link')
            if destination.exists() or destination.is_symlink():
                raise ValueError('fixture input destination must be absent')
            copies.append((source, destination))
    for source, destination in copies:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

RECOVERY = '''<script id="godot-release-recovery">
window.godotLoadFailure = function () {
  if (document.getElementById('release-reload')) return;
  const panel = document.createElement('div');
  panel.style.cssText = 'position:fixed;inset:30% 10% auto;padding:2rem;background:#201d2b;color:white;z-index:99;text-align:center';
  const message = document.createElement('p');
  message.textContent = 'The game could not finish loading. A release may have changed or the connection was interrupted. Reload to try the current release.';
  const button = document.createElement('button');
  button.id = 'release-reload';
  button.textContent = 'Reload game';
  button.onclick = function () { window.location.reload(); };
  panel.append(message, button);
  document.body.appendChild(panel);
};
</script>'''


def stage_version(root, files, relative_urls=False):
    root = Path(root)
    payload = {name: info['sha256'] for name, info in files.items() if name != 'index.html'}
    release_id = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    prefix = f'{"" if relative_urls else "/"}releases/{release_id}/'
    html = (root / 'index.html').read_text()
    html = re.sub(r'/?releases/[0-9a-f]{64}/', '', html)
    match = re.search(r'const GODOT_CONFIG = (\{[^\n]+\});', html)
    if not match:
        raise ValueError('Expected the reviewed Godot shell configuration')
    config = json.loads(match[1])
    config['executable'] = prefix + 'index'
    config['fileSizes'] = {prefix + Path(name).name: size for name, size in config['fileSizes'].items()}
    html = html[:match.start(1)] + json.dumps(config, separators=(',', ':')) + html[match.end(1):]
    for name in payload:
        html = html.replace(f'src="{name}"', f'src="{prefix}{name}"')
        html = html.replace(f'href="{name}"', f'href="{prefix}{name}"')
    if 'id="godot-release-recovery"' not in html:
        html = html.replace('<script src=', RECOVERY + '\n<script src=', 1)
        html = html.replace(f'src="{prefix}index.js"', f'src="{prefix}index.js" onerror="godotLoadFailure()"')
        html = html.replace('const engine = new Engine(GODOT_CONFIG);',
                            "const engine = typeof Engine === 'function' ? new Engine(GODOT_CONFIG) : null;")
        html = html.replace('(function () {', '(function () {\n\tif (!engine) { godotLoadFailure(); return; }', 1)
        html = html.replace('function displayFailureNotice(err) {',
                            'function displayFailureNotice(err) {\n\t\tgodotLoadFailure();', 1)
    (root / 'index.html').write_text(html)
    releases = root / 'releases'
    if releases.is_symlink():
        raise ValueError('Release output cannot be a symlink')
    releases.mkdir(exist_ok=True)
    destination = releases / release_id
    if destination.is_symlink():
        raise ValueError('Version output cannot be a symlink')
    destination.mkdir(exist_ok=True)
    for name in payload:
        shutil.copy2(root / name, destination / name)
        for suffix in ('.gz', '.br'):
            sidecar = root / (name + suffix)
            if sidecar.exists():
                shutil.copy2(sidecar, destination / sidecar.name)
    # This is generated output, not a historical artifact store. Old shells
    # fail explicitly and offer reload instead of fetching a different pack.
    for entry in releases.iterdir():
        if entry.name != release_id and re.fullmatch(r'[0-9a-f]{64}', entry.name):
            if entry.is_symlink():
                raise ValueError('Historical release output cannot be a symlink')
            shutil.rmtree(entry)
    return release_id
