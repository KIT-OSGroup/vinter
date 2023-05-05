#!/bin/bash
set -e
set -o pipefail
set -x

mkdir -p panda/build
cd panda/build
LLVM_CONFIG_BINARY=false ../build.sh --python x86_64-softmmu --disable-werror --disable-xen --disable-sdl --disable-gtk --disable-spice --disable-opengl
