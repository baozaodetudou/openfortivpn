#!/bin/zsh
set -eu
OFV_LINUX_CONTAINER_TOOL=ar exec "${0:A:h}/linux-container-linker.zsh" "$@"
