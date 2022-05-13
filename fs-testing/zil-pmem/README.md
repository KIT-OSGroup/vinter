# Analyzing ZIL-PMEM

https://github.com/openzfs/zfs/pull/12731

## Building

Clone ZFS into openzfs/ and a suitable Linux version into linux/ (e.g., 5.11).

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
