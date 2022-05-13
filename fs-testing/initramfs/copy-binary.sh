#!/usr/bin/env bash

set -eu

# Usage: copy-binary.sh <binary> <initramfs root>

binary=${1:?need binary}
initramfs=${2:?need initramfs root}

cp "$binary" "$initramfs/bin/"

# Copy libraries from host system.
ldd "$binary" | \
  awk '/ => \// { print $3 } /ld-linux/ { print $1 }' | \
  xargs cp -t "$initramfs/lib"
    