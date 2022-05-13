#!/usr/bin/env bash
set -eu

# Usage: create-initramfs.sh [folder with extra files] > initramfs.cpio.gz

cd "$( dirname "${BASH_SOURCE[0]}" )"

rm -rf initramfs

# put extra stuff in $1
if [[ -n "${1:-}" ]]; then
	cp -rH "$1" initramfs
fi

mkdir -p initramfs/{bin,mnt,proc,sys}

cp init initramfs
"${BUSYBOX:-./busybox}" --install initramfs/bin
cp ../../vinter_python/hypercall initramfs/bin
cp ../fs-dump/target/x86_64-unknown-linux-musl/release/fs-dump initramfs/bin

(cd initramfs && find . -print0 | cpio --owner root:root --null -ov --format=newc | gzip -9)
