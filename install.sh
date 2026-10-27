#!/bin/sh
# Install a published komizo release into a user-owned directory.
set -eu

tool=komizo
repo_url=https://github.com/nicodes/komizo
release=latest
install_dir=${INSTALL_DIR:-"$HOME/.local/bin"}
work_dir=
stage_dir=
fail() { printf '%s: %s\n' "$tool" "$*" >&2; exit 1; }
cleanup() {
    [ -z "$work_dir" ] || rm -rf "$work_dir"
    [ -z "$stage_dir" ] || rm -rf "$stage_dir"
}
trap cleanup 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version|-v|--install-dir)
            [ "$#" -ge 2 ] || fail "$1 needs a value."
            case "$1" in
                --version|-v) release=$2 ;;
                --install-dir) install_dir=$2 ;;
            esac
            shift 2 ;;
        --help|-h)
            printf 'Install %s: [--version X.Y.Z|latest] [--install-dir /absolute/path]\nDefaults: latest release, ~/.local/bin.\n' "$tool"
            exit 0 ;;
        *) fail "Unknown option: $1" ;;
    esac
done
case "$install_dir" in /*) ;; *) fail 'The install directory must be an absolute path.' ;; esac
for command in curl tar mktemp awk grep cut cp chmod mv; do
    command -v "$command" >/dev/null 2>&1 || fail "Install $command first."
done
command -v gh >/dev/null 2>&1 || fail 'Install the GitHub CLI (gh) to verify release provenance.'
if command -v sha256sum >/dev/null 2>&1; then
    checksum_tool=sha256sum
elif command -v shasum >/dev/null 2>&1; then
    checksum_tool=shasum
else
    fail 'A SHA-256 utility (sha256sum or shasum) is required.'
fi
case "$(uname -s)" in
    Linux) platform=Linux ;;
    Darwin) platform=Darwin ;;
    *) fail 'Supported operating systems: Linux and macOS.' ;;
esac
case "$(uname -m)" in
    x86_64|amd64) arch=x86_64 ;;
    arm64|aarch64) arch=arm64 ;;
    *) fail 'Supported CPU architectures: x86_64 and arm64.' ;;
esac
if [ "$platform" = Darwin ] && [ "$arch" = x86_64 ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || true)" = 1 ]; then
    arch=arm64
fi
fetch() {
    curl --fail --silent --show-error --location --retry 3 \
        --connect-timeout 10 --max-time 300 --proto '=https' --proto-redir '=https' "$@"
}
if [ "$release" = latest ]; then
    latest_url=$(fetch --output /dev/null --write-out '%{url_effective}' "$repo_url/releases/latest") || fail 'Could not find the latest release.'
    case "$latest_url" in
        "$repo_url/releases/tag/"*) release=${latest_url##*/} ;;
        *) fail 'No published release was found.' ;;
    esac
fi
case "$release" in v*) ;; *) release=v$release ;; esac
printf '%s\n' "$release" | LC_ALL=C grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || fail 'Use a release version such as v1.2.3.'
asset=${tool}_${platform}_${arch}.tar.gz
base=$repo_url/releases/download/$release
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/$tool-install.XXXXXXXX") || fail 'Could not create a temporary directory.'
printf 'Installing %s %s (%s %s)...\n' "$tool" "$release" "$platform" "$arch"
fetch "$base/checksums.txt" --output "$work_dir/checksums.txt" || fail 'Could not download release checksums.'
fetch "$base/$asset" --output "$work_dir/$asset" || fail "Could not download $asset."
expected=$(awk -v name="$asset" '$2 == name || $2 == "*" name { count++; digest=$1 } END { if (count == 1) print digest }' "$work_dir/checksums.txt")
printf '%s\n' "$expected" | LC_ALL=C grep -Eq '^[a-f0-9]{64}$' || fail 'The archive needs exactly one valid release checksum.'
if [ "$checksum_tool" = sha256sum ]; then
    actual=$(sha256sum "$work_dir/$asset" | awk '{print $1}')
else
    actual=$(shasum -a 256 "$work_dir/$asset" | awk '{print $1}')
fi
[ "$actual" = "$expected" ] || fail 'Checksum verification failed; the installed binary was not changed.'
gh attestation verify "$work_dir/$asset" --repo nicodes/komizo \
    --signer-workflow nicodes/komizo/.github/workflows/release.yml \
    --source-ref refs/heads/main --deny-self-hosted-runners \
    || fail 'Release attestation verification failed; the installed binary was not changed.'
# Extract only one regular executable, never the rest of the archive.
entry_type=$(tar -tvzf "$work_dir/$asset" "$tool" | cut -c1)
[ "$entry_type" = '-' ] || fail 'The archive must contain exactly one regular executable.'
tar --no-same-owner -xzf "$work_dir/$asset" -C "$work_dir" "$tool" || fail 'The executable could not be extracted.'
[ -f "$work_dir/$tool" ] && [ ! -L "$work_dir/$tool" ] || fail 'The archive does not contain a regular executable.'
mkdir -p "$install_dir" || fail 'Choose a writable install directory.'
[ ! -d "$install_dir/$tool" ] || fail 'The install destination is a directory.'
stage_dir=$(mktemp -d "$install_dir/.$tool-install.XXXXXXXX") || fail 'Could not stage the executable.'
cp "$work_dir/$tool" "$stage_dir/$tool"
chmod 755 "$stage_dir/$tool"
mv -f "$stage_dir/$tool" "$install_dir/$tool"
printf 'Installed %s %s at %s/%s\n' "$tool" "$release" "$install_dir" "$tool"
case ":$PATH:" in
    *":$install_dir:"*) ;;
    *) printf 'Add %s to your PATH to run %s by name.\n' "$install_dir" "$tool" ;;
esac
