#!/usr/bin/env sh
set -eu

BUNDLE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MANAGER="$BUNDLE_DIR/bin/openfortivpn-manager-headless"
ENGINE="$BUNDLE_DIR/libexec/openfortivpn"

if [ ! -x "$MANAGER" ] || [ ! -x "$ENGINE" ]; then
  echo "安装包缺少 openfortivpn-manager-headless 或 openfortivpn" >&2
  exit 1
fi

if [ "$(/usr/bin/id -u)" -eq 0 ]; then
  exec "$MANAGER" install --engine "$ENGINE"
else
  exec /usr/bin/sudo "$MANAGER" install --engine "$ENGINE"
fi
