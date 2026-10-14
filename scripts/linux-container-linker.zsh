#!/bin/zsh
# Optional macOS -> Linux Rust linker. All containers have networking disabled.
set -eu
ofv_repo="${0:A:h:h}"
ofv_cargo="${CARGO_HOME:-$HOME/.cargo}"
ofv_rustup="${RUSTUP_HOME:-$HOME/.rustup}"
ofv_temp="${TMPDIR:-/tmp}"
ofv_tool="${OFV_LINUX_CONTAINER_TOOL:-gcc}"
case "$ofv_tool" in gcc|ar) ;; *) exit 2 ;; esac
exec rtk proxy docker run --rm --network none \
  -v "$ofv_repo:$ofv_repo" \
  -v "${ofv_cargo}:${ofv_cargo}:ro" \
  -v "${ofv_rustup}:${ofv_rustup}:ro" \
  -v "$ofv_temp:$ofv_temp" \
  -w "$PWD" golang:1.26.6-bookworm "$ofv_tool" "$@"
