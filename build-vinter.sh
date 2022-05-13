#!/usr/bin/env bash

set -eux

cargo build --release

# link vinter_trace to the Panda plugin directory
ln -fs release/libvinter_trace.so target/panda_vinter_trace.so
ln -fsrt panda/build/x86_64-softmmu/panda/plugins/ target/panda_vinter_trace.so 
# link vinter_trace.py for vinter_trace2img
ln -fsrt target/release vinter_rust/vinter_trace/vinter_trace.py

# build fs-dump
(cd fs-testing/fs-dump && cargo build --release --target=x86_64-unknown-linux-musl)

# build hypercall
(cd vinter_python && ./build_hypercall.sh)

# build initramfs
make -C fs-testing/initramfs
