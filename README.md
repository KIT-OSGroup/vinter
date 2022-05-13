# Vinter: Automatic Non-Volatile Memory Crash Consistency Testing for Full Systems

This is the source code of Vinter, a tool for automated NVM crash consistency testing.

## Source Code Overview

Short overview over the main components of Vinter:

* `vinter_python/`: The original implementation of Vinter that was used for the
  analysis in the paper.
  * `pmemtrace.py`: The "Tracer" component of Vinter.
  * `trace2img.py`: The "Crash Image Generator" and "Tester" components of Vinter.
  * `trace-and-analyze.sh`: Main script for running the full testing pipeline.
  * `report-results.py`: Script for analyzing output from the testing pipeline.
* `vinter_rust/`: A reimplementation of Vinter in Rust, with the intention of
  improved performance and to provide a clean base for future extensions.
  * `vinter_trace/`: The "Tracer" component of Vinter.
  * `vinter_trace2img/`: The "Crash Image Generator" and "Tester" components
    of Vinter. Runs the full testing pipeline.
* `fs-testing/`: Everything related to the analysis of file systems.
  * `scripts/`: Helper scripts, VM definitions, and test case definitions.
  * `initramfs/`: Busybox-based userspace of the test VMs.
  * `fs-dump/`: State extraction program for file systems.
  * `linux/`: Source code and binaries of the Linux kernels we test.
* `panda/`: The underlying hypervisor based on QEMU.

## Setup

Note that we provide a virtual machine image with Vinter and its dependencies
installed. See "Artifact Evaluation" below.

```sh
# install dependencies
# on Fedora:
sudo dnf install python3-pip python3-mypy python3-capstone glibc-static elfutils-libelf-devel dtc capstone-devel libdwarf-devel glib2-devel pixman-devel protobuf-devel protobuf-c-devel curl-devel jsoncpp-devel chrpath datamash telnet
pip install yq sortedcontainers

# Rust via rustup (see https://rustup.rs)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add x86_64-unknown-linux-musl

# build panda and vinter
./build-panda.sh
./build-vinter.sh

# build kernels
git clone https://github.com/NVSL/linux-nova fs-testing/linux/nova
git -C fs-testing/linux/nova checkout 593f927a78a6900d7cfec58199fb0a4a4fd1d646
fs-testing/linux/build-kernel.sh nova

git clone https://github.com/linux-pmfs/pmfs fs-testing/linux/pmfs
# Note: Building PMFS requires gcc4, build from a suitable container. For example:
podman run --rm -v"$PWD/fs-testing/linux:/mnt" docker.io/library/gcc:4 sh -c 'apt-get update && apt-get install bc && /mnt/build-kernel.sh pmfs'

```

## Artifact Evaluation

Information for artifact evaluation is in `artifact-evaluation/README.md`.

## License

Vinter is released under the MIT license, see `LICENSE` for details.
