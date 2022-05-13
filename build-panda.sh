#!/bin/bash
set -e
set -o pipefail
set -x

mkdir -p panda/build
cd panda/build
../build.sh --python x86_64-softmmu --disable-werror --disable-xen
