#!/usr/bin/env bash
set -euo pipefail

arch=${1:?architecture required (x86_64 or aarch64)}
release_tag=${2:?release tag required}
output=${3:?output path required}

case "$arch" in
  x86_64) target=x86_64-unknown-linux-musl; zig_target=x86_64-linux-musl; expected='X86-64' ;;
  aarch64) target=aarch64-unknown-linux-musl; zig_target=aarch64-linux-musl; expected=AArch64 ;;
  *) echo "unsupported server architecture: $arch" >&2; exit 2 ;;
esac

: "${CC:?CC must point to the Zig C wrapper}"
: "${CXX:?CXX must point to the Zig C++ wrapper}"
export ZIG_TARGET="$zig_target"
export TT_ENDPOINT_VERSION="$release_tag"

cargo zigbuild --release --locked --target "$target" --bin trusttunnel_endpoint
mkdir -p "$(dirname "$output")"
llvm-strip -o "$output" "target/$target/release/trusttunnel_endpoint"
chmod 755 "$output"
header_dump=$(mktemp)
trap 'rm -f "$header_dump"' EXIT
llvm-readelf -h "$output" >"$header_dump"
grep -Fq "$expected" "$header_dump"
