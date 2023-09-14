# Analyzing ZIL-PMEM

https://github.com/openzfs/zfs/pull/12731

## Building

Clone ZFS (with ZIL-PMEM) into openzfs/ and a suitable Linux version into linux/ (e.g., 5.11).

```sh
# upstream
git clone -b zil-pmem/upstreaming https://github.com/problame/zfs/ openzfs
# with some patches (e.g., smaller chunk size) to ease analysis
git clone -b zil-pmem/vinter https://github.com/lluchs/zfs/ openzfs
```

Build the kernel:

```sh
./build-zfs-builtin.sh
# builds linux_build/arch/x86/boot/bzImage
```

Build the ZFS tools:

```sh
./build-zfs-tools.sh
# builds initramfs_zfs/
```

Build the initramfs:

```sh
make -C../initramfs initramfs_zilpmem.cpio.gz
```
