#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
HEADLESS_DIR=$(dirname "$SCRIPT_DIR")
REPOSITORY_DIR=$(dirname "$HEADLESS_DIR")
ENGINE_BUILD_DIR="$REPOSITORY_DIR/build/headless-engine"

cmake -S "$REPOSITORY_DIR" -B "$ENGINE_BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_USE_STATIC_LIBS=TRUE \
  -DBUILD_TESTING=OFF
cmake --build "$ENGINE_BUILD_DIR" --config Release --parallel
cargo build --manifest-path "$HEADLESS_DIR/Cargo.toml" --release

MANAGER="$HEADLESS_DIR/target/release/openfortivpn-manager-headless"
if [ "$(/usr/bin/id -u)" -eq 0 ]; then
  "$MANAGER" install --engine "$ENGINE_BUILD_DIR/openfortivpn"
else
  /usr/bin/sudo "$MANAGER" install --engine "$ENGINE_BUILD_DIR/openfortivpn"
fi
