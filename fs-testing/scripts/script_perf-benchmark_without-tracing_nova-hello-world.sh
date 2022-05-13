#!/bin/bash
set -e -o pipefail
set -x

outdir="perf-benchmark_without-tracing/"
rm -rf "$outdir"
mkdir "$outdir"

for i in {0..20} ; do # perform 21 runs (first will be discarded)
	sleep 10
	"$(dirname "$0")"/../../panda/build/x86_64-softmmu/panda-system-x86_64 -cpu max -monitor stdio -vnc :1 -serial telnet:127.0.0.1:4444,server,nowait -m 139M -kernel "$(dirname "$0")"/../linux/nova_build/arch/x86/boot/bzImage -initrd "$(dirname "$0")"/../initramfs/initramfs.cpio.gz -append 'console=ttyS0,115200n8 memmap=5M!128M memmap=123M!133M' \
		& sleep 3 && { cat <(echo 'cat /proc/uptime ; cat /proc/uptime ; cat /proc/uptime ; mount -tNOVA -oinit /dev/pmem0 /mnt && sync && hypercall checkpoint 0 && sync && hypercall checkpoint 1 && echo HelloWorld > /mnt/myfile && hypercall checkpoint 2 && sync && hypercall checkpoint 3 && hypercall success ; cat /proc/uptime') ; sleep 3 ; } | nc localhost 4444 > "${outdir}/log${i}"; killall panda-system-x86_64
done
rm "${outdir}/log0"
#echo success
