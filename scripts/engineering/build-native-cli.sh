#!/usr/bin/env bash
set -euo pipefail
os_label="$(uname -s)"
case "$(uname -m)" in x86_64|amd64) arch_label=x86_64 ;; aarch64|arm64) arch_label=arm64 ;; *) exit 1 ;; esac
case "$os_label/$arch_label" in
  Linux/x86_64) rust_target=x86_64-unknown-linux-musl ;;
  Linux/arm64) rust_target=aarch64-unknown-linux-musl ;;
  Darwin/x86_64) rust_target=x86_64-apple-darwin ;;
  Darwin/arm64) rust_target=aarch64-apple-darwin ;;
  *) exit 1 ;;
esac
for platform in Linux_x86_64 Linux_arm64; do
  python3 scripts/engineering/native-receipt.py ".artifacts/native-host/komizo-box_$platform"
done
python3 scripts/engineering/api-payload.py ".artifacts/native-api/komizo-api_${os_label}_${arch_label}"
rustup target add --toolchain 1.94.0 "$rust_target"
if [ "$os_label" = Linux ]; then
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
  export CC_x86_64_unknown_linux_musl=musl-gcc
  export CC_aarch64_unknown_linux_musl=musl-gcc
fi
export KOMIZO_VERSION="${VERSION:-dev}"
export KOMIZO_API_PAYLOAD="$PWD/.artifacts/native-api/payload.gz"
export KOMIZO_HOST_AMD64="$PWD/.artifacts/native-host/komizo-box_Linux_x86_64"
export KOMIZO_HOST_ARM64="$PWD/.artifacts/native-host/komizo-box_Linux_arm64"
cargo build --locked --release --bin komizo --target "$rust_target"
mkdir -p .artifacts/native-cli
cp "${CARGO_TARGET_DIR:-target}/$rust_target/release/komizo" ".artifacts/native-cli/komizo_${os_label}_${arch_label}"
python3 scripts/engineering/write-native-receipt.py ".artifacts/native-cli/komizo_${os_label}_${arch_label}"
python3 scripts/engineering/api-smoke.py ".artifacts/native-cli/komizo_${os_label}_${arch_label}"
