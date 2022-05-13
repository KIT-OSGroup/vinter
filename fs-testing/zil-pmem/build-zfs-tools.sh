#!/usr/bin/env bash

set -eux

zfs=openzfs

rm -rf initramfs_zsh
mkdir initramfs_zsh

pushd "$zfs"
[[ -f ./configure ]] || sh ./autogen.sh
./configure --with-config=user
make DESTDIR="$PWD/../initramfs_zsh" install -j$(nproc)
popd

pushd initramfs_zsh

# Remove unnecessary folders.
rm -r usr/local/share

# Copy libraries from host system.
LD_LIBRARY_PATH=usr/local/lib ldd usr/local/sbin/zpool | \
  awk '/ => \// { print $3 } /ld-linux/ { print $1 }' | \
  xargs cp -t lib

# Link required binaries to /bin
mkdir bin
ln -st bin ../sbin/mount.zfs ../usr/local/sbin/zpool
ln -s lib lib64

# Fix library path for ZFS tools.
mkdir init.d
echo "export LD_LIBRARY_PATH=/usr/local/lib" > init.d/zfs_path

popd

du -sh initramfs_zfs