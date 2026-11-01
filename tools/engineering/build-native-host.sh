#!/usr/bin/env bash
set -euo pipefail
os_label="$(uname -s)"
case "$(uname -m)" in x86_64|amd64) arch_label=x86_64 ;; aarch64|arm64) arch_label=arm64 ;; *) echo 'Unsupported native architecture.' >&2; exit 1 ;; esac
case "$os_label/$arch_label" in
  Linux/x86_64) rust_target=x86_64-unknown-linux-musl ;;
  Linux/arm64) rust_target=aarch64-unknown-linux-musl ;;
  Darwin/x86_64) rust_target=x86_64-apple-darwin ;;
  Darwin/arm64) rust_target=aarch64-apple-darwin ;;
  *) echo 'The host tools support Linux and macOS.' >&2; exit 1 ;;
esac
rustup target add --toolchain 1.94.0 "$rust_target"
if [ "$os_label" = Linux ]; then
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
  export CC_x86_64_unknown_linux_musl=musl-gcc
  export CC_aarch64_unknown_linux_musl=musl-gcc
fi
export KOMIZO_API_PAYLOAD="$PWD/internal/nativeapi/payload.gz"
cargo build --locked --release --bin komizo-box --target "$rust_target"
mkdir -p .artifacts/native-host
cp "${CARGO_TARGET_DIR:-target}/$rust_target/release/komizo-box" ".artifacts/native-host/komizo-box_${os_label}_${arch_label}"
