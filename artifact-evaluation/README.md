# Information for Artifact Evaluation

We provide a virtual machine image for evaluating Vinter. It contains a
binaries for Vinter as well as the kernels we tested in the paper.

## Getting Started Instructions

Download the virtual machine image `vinter.qcow2` [from doi:10.5281/zenodo.6544868](https://doi.org/10.5281/zenodo.6544868).

Start the virtual machine in a suitable hypervisor. Vinter can optionally run
its analysis in parallel, so make sure to provide plenty of memory (`-m`) and
vCPUs (`-smp`). As a rough guideline, provide 2 GB of memory per vCPU. For
example with QEMU/KVM:
```
qemu-kvm -m 16G -smp 8 -display none -serial mon:stdio -device e1000,netdev=net0 \
    -netdev user,id=net0,hostfwd=tcp::2222-:22 vinter.qcow2
```

Connect to the virtual machine via SSH. The password for the users vinter and
root is "vinter". Note that the SSH server does not allow direct login as root,
use `su` instead. It is also possible to interact with the VM via the serial
console, but we strongly recommend SSH to avoid glitches.
```
ssh -p 2222 vinter@localhost
```

Inside the VM, you can find Vinter in `/home/vinter/vinter`. To verify that
Vinter is set up correctly, we provide a script that runs Vinter (both Python
and Rust versions) with one test case on each kernel. This will take around
five minutes to complete.
```
cd ~/vinter
fs-testing/scripts/run_getting-started.sh
```

The script will put results into the directory `results_getting-started`. View
a short summary of these results with the following commands:
```
vinter_python/report-results.py analyze \
    results_getting-started/vinter_python/vm_nova/getting-started/test_hello-world
vinter_python/report-results.py analyze \
    results_getting-started/vinter_python/vm_pmfs/getting-started/test_hello-world
```

You can see that Vinter reports a violation of *single final state* for the
test on NOVA, but not on PMFS.

Note that the remainder of our artifact evaluation walkthrough focuses on the
original `vinter_python` implementation that was used for the analysis in the
paper.

## Detailed Instructions

We organize our detailed walkthrough in multiple separate files for each major
claim. We claim the following:

* Vinter can find new bugs in file systems and can help developers with finding
  the root cause. In `walkthrough_bugs.md`, we provide instructions for
  reproducing Figures 4-6 as well as Section 5.3 of our paper.
* Vinter can reproduce previously fixed bugs in NOVA. In
  `walkthrough_completeness.md`, we provide instructions for reproducing
  Section 6.1 of our paper.
* Vinter's heuristic is effective at reducing the number of generated crash
  images without missing semantic states. In
  `walkthrough_heuristic-effectiveness.md`, we provide instructions for
  reproducing Section 6.2 of our paper.
* Vinter is sufficiently fast for analyzing file systems. In
  `walkthrough_performance-benchmarks.md`, we provide instructions for
  reproducing Figures 8 and 9 of our paper.
