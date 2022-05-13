Completeness
============

In Section 6.1 of the paper, we describe that Vinter can find
previously-reported crash consistency bugs in NOVA. We identified four relevant
patches for NOVA and verified that Vinter detects additional issues before each
of these patches. We reproduce this analysis here.

General Approach
----------------

For each patch fixing a crash consistency issue, we identify the git commit
before and after the crash. The analysis then works as follows:

* For each commit (before, after):
  * Build the corresponding kernel.
  * Analyze NOVA with Vinter.
  * Summarize results to a file.
* Finally, compare summarized results to see whether Vinter detected the issue.

**Important**: The script will check out and compile different NOVA versions.
Make sure to return to the initial version once you are finished!

```
git -C fs-testing/linux/nova checkout vinter-nova
fs-testing/linux/build-kernel.sh nova

```

## [PR #89](https://github.com/NVSL/linux-nova/pull/89)

Analyze with:
```
# run from Vinter root directory
# arguments: <vm name> <bug id> <commit before patch> <commit after patch>
# run analysis in parallel with -P <number>
fs-testing/scripts/script_reproduce-nova-bug.sh -P 8 vm_nova 89 a1bd8d84faf4 f9d7abcd1e13
# results in results_completeness/89_{before,after}.txt
```

In the diff, we can see that state extraction failed frequently before the
patch. Looking at one of these states (e.g., `cat results_completeness/vm_nova/a1bd8d84faf4/test_chmod/semantic_states/state01.txt`),
we can see that the error message matches the one in the original bug report
[#88](https://github.com/NVSL/linux-nova/issues/88).


## [PR #92](https://github.com/NVSL/linux-nova/pull/92)

Analyze with:
```
fs-testing/scripts/script_reproduce-nova-bug.sh -P 8 vm_nova 92 f9d7abcd1e13 9c85760ab8f7
```

Similar to the previous issue, we can see that the patch fixed some cases of
failing state extraction. Again, the error message
(e.g., `cat results_completeness/vm_nova/f9d7abcd1e13/test_chmod/semantic_states/state00.txt`)
matches the one in the original bug report [#91](https://github.com/NVSL/linux-nova/issues/91).

## [PR #95](https://github.com/NVSL/linux-nova/pull/95)

Analyze with:
```
fs-testing/scripts/script_reproduce-nova-bug.sh -P 8 vm_nova 95 9c85760ab8f7 41d37f1c5a5d
```

Again, Vinter detects kernel crashes that the patch fixes
(e.g., `cat results_completeness/vm_nova/9c85760ab8f7/test_rename/semantic_states/state04.txt`).

## [PR #109](https://github.com/NVSL/linux-nova/pull/109) for NOVA-Fortis

Analyze with:
```
fs-testing/scripts/script_reproduce-nova-bug.sh -P 8 vm_nova-protection 109 587e25223ee4 593f927a78a6
```

Matching the bug report [#100](https://github.com/NVSL/linux-nova/issues/100),
Vinter detects crash images where writing a file after recovery returns ENOSPC
errors ("sh: write error: No space left on device"), for example in
`results_completeness/vm_nova-protection/587e25223ee4/test_hello-world/semantic_states/state02.txt`.

Note that the shell error message might not print to the terminal (e.g., with
`cat`) because it ends with a carriage return (^M).

Cleanup
-------

Remember to return to the initial NOVA version, as detailed above!
