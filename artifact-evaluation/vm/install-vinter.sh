#!/usr/bin/env bash

set -eux

fail() {
	echo "error: $@"
	exit 1
}

script=$0

setup_root() {
	useradd vinter
	find /etc/skel -type f | xargs cp -t /home/vinter
	echo vinter | passwd --stdin vinter
	chown -R vinter:vinter /home/vinter

	dnf install -y '@C Development Tools and Libraries' podman git zip zstd bc time jq qemu-img python3-pip python3-mypy python3-capstone glibc-static elfutils-libelf-devel dtc capstone-devel libdwarf-devel glib2-devel pixman-devel protobuf-devel protobuf-c-devel curl-devel jsoncpp-devel chrpath datamash telnet
	pip install yq sortedcontainers

	# Disable SELinux so that podman works.
	setenforce 0

	sudo -iu vinter "$script"
}

setup_vinter() {
	# install Rust
	curl https://sh.rustup.rs -sSf | sh -s -- -y
	. "$HOME/.cargo/env"
	rustup target add x86_64-unknown-linux-musl

	git clone --recursive https://github.com/KIT-OSGroup/vinter
	git clone https://github.com/KIT-OSGroup/linux --bare linux.git
	git -C "linux.git" worktree add "../vinter/fs-testing/linux/nova" vinter-nova
	git -C "linux.git" worktree add "../vinter/fs-testing/linux/pmfs" vinter-pmfs

	cd vinter
	./build-panda.sh
	./build-vinter.sh
	fs-testing/linux/build-kernel.sh nova
	podman run --rm -v"$PWD/fs-testing/linux:/mnt" docker.io/library/gcc:4 sh -c 'apt-get update && apt-get install bc && /mnt/build-kernel.sh pmfs'
}

case "$(whoami)" in
	root)
		setup_root
		;;
	vinter)
		setup_vinter
		;;
	*)
		fail "run this script in the Vinter VM!"
esac
