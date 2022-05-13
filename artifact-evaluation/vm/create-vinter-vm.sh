#!/usr/bin/env bash

if [[ "$#" != 2 ]]; then
	echo "Usage: $0 <Fedora cloud base image> <output image>"
	exit 1
fi

fail() {
	echo "error: $@"
	cleanup
	exit 1
}

cleanup() {
	[[ -e "$mountpath" ]] && sudo umount "$mountpath" && rm -r "$mountpath"
	sudo qemu-nbd -d /dev/nbd0
}

scriptdir=$(dirname "${BASH_SOURCE[0]}")
vinterdir=$(git -C "$scriptdir" rev-parse --show-toplevel)

img=$2
cp --reflink=auto "$1" "$img" || fail "could not copy base image"
chmod +w "$img"

echo "Resizing image..."
qemu-img resize "$img" 200G || fail "could not resize image"

echo "Mounting image (needs root)..."
[[ -e /dev/nbd0 ]] || sudo modprobe nbd || fail "could not load nbd kernel module"
sudo qemu-nbd -c /dev/nbd0 "$img" || fail "could not connect image to nbd"
sudo blkid /dev/nbd0p1 | grep -q ext4 || fail "image does not look like a Fedora 34 image"
sudo growpart /dev/nbd0 1 || fail "could not grow partition (install cloud-utils-growpart)"
sudo resize2fs /dev/nbd0p1 || fail "could not resize file system"
mountpath=$(mktemp -d)
sudo mount /dev/nbd0p1 "$mountpath" || fail "could not mount image"

password=vinter
echo "Setting up VM..."
echo " => root password: $password"
echo "root:$password" | sudo chroot "$mountpath" /usr/sbin/chpasswd || fail "could not set root password"
echo " => copying repositories"
sudo mkdir "$mountpath/home/vinter"
sudo cp "$scriptdir/install-vinter.sh" "$mountpath/home/vinter"

cleanup

echo "Start VM to continue installation:"
echo "  qemu-kvm -m 16G -smp $(nproc) -display none -serial mon:stdio $img"
echo "  bash /home/vinter/install-vinter.sh"
