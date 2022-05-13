Bug Walkthrough
===============

Figure 4 of the paper shows the bugs in NOVA, NOVA-Fortis, and PMFS that we
found with Vinter. In this walkthrough, we reproduce the underlying data of
this figure and the details in Section 5.3. As explained in the paper, this
process is only partially automated.

General notes
-------------

* State extraction works by communicating with the virtual machine over a
  serial console. The output sometimes also captures part of the state
  extraction command at the top. As that command is identical within a test, it
  has no effect on the analysis.

* `report-results.py` outputs ANSI color codes, use `less -R` if you want to
  view the results in a pager.

  * States printed in green by `report-results.py` have at least one image of
    the "fully persisted" type. States in purple are those found exclusively by
    the heuristic.

* VM execution is not entirely deterministic, so some identifiers may vary.

* Timestamps in the file metadata may lead to non-determinism and extra
  semantic states reported by Vinter.

Running the analysis
--------------------

Run the full analysis with the command below. Choose the number of parallel
jobs appropriately for your environment (option `-P`).

```
# From vinter repository root
fs-testing/scripts/script_run-parallel-all.sh -P 8 --trace-metadata walkthrough_bugs
```

The script will write results to `results/vm_{nova,nova-protection,pmfs}/walkthrough_bugs/`.
In the following, we walk through the manual analysis of these results.

NOVA
----

Run:
```
vinter_python/report-results.py analyze results/vm_nova/walkthrough_bugs/*
```

The tool summarizes the results by reading `crash_images/index.yaml` and
`semantic_states/index.yaml` for each test directory.

From the output, we can immediately identify test cases that do not detect
bugs, marked by "single final state" and "atomic" in green text, and a
checkmark in Figure 4:

(syntax: \<name in Figure 4> = \<test name>)

* append = test_append
* atime = test_atime
* [cm]time = test_ctime-mtime
* chmod = test_chmod
* chown = test_chown
* mkdir/rmdir = test_mkdir-rmdir
* unlink = test_unlink

We now go through the test cases where `report-results.py` reported multiple
final states or atomicity violations.

### write = test_hello-world: multiple final states, data loss

Run:
```
vinter_python/report-results.py analyze --diff results/vm_nova/walkthrough_bugs/test_hello-world
```

We can see multiple final states:

* state03: content `HelloWorld\n` (correct)
* state04: content `HelloWor\0\0\0`
* state05: content `HelloWorl\0\0`
* state06: content `HelloWorld\0`

The last three bytes of file content may thus be lost.

We now reproduce the root-cause analysis given in Section 5.3.1 in the paper.
The output of `report-results.py analyze --verbose` includes the numbers of
dirty lines at the checkpoint (e.g., 46784, the memory layout varies across
runs so the number may differ). Run the following:

```
vinter_python/report-results.py analyze --verbose results/vm_nova/walkthrough_bugs/test_hello-world
vinter_python/report-results.py trace-lines results/vm_nova/walkthrough_bugs/test_hello-world 46784
```

The last few lines of the output should match Figure 5 and Figure 6, for
example (without stack traces):

```
304192 NT-write line 46784 + 0
        content: b'HelloWor'
        metadata: True!T __copy_user_nocache!
304193 write line 46784 + 8
        content: b'l'
        metadata: True!T __copy_user_nocache!
304194 write line 46784 + 9
        content: b'd'
        metadata: True!T __copy_user_nocache!
304195 write line 46784 + 10
        content: b'\n'
        metadata: True!T __copy_user_nocache!
```

The syntax of the metadata is as follows:

`<in kernel mode?>!<function at instruction pointer>!<call stack>`

### link = test_link-hard: atomicity violation

Run:
```
vinter_python/report-results.py analyze --diff results/vm_nova/walkthrough_bugs/test_link-hard
```

We can see that Vinter identifies three states between checkpoint 2 and 3 where
the test code deletes a hardlink. From the diff output, we can see that in the
second state, the deleted file disappears, and then in the third state, the
hard link counter `st_nlink` of the hardlink is decreased. Thus, the deletion
of the hard link is not atomic.

### symlink = test_link-sym: multiple final states, data loss

Run:
```
vinter_python/report-results.py analyze --diff results/vm_nova/walkthrough_bugs/test_link-sym
```

Vinter identifies four final states that differ in the link target (/mnt/myf,
/mnt/myfi, /mnt/myfil, /mnt/myfile).

With an analysis similar to the "write" test, we can see that this bug shares
the same root cause.

```
vinter_python/report-results.py analyze --verbose results/vm_nova/walkthrough_bugs/test_link-sym
vinter_python/report-results.py trace-lines results/vm_nova/walkthrough_bugs/test_link-sym 81088
```

### rename overwrite = test_rename: atomicity violation, data loss

Run:
```
vinter_python/report-results.py analyze --diff results/vm_nova/walkthrough_bugs/test_rename
```

The code creates two files `/mnt/myfile` and `/mnt/myfile2` and then renames
myfile2 to myfile, which should atomically replace the latter file.

Vinter identifies four crash states. From the diffs, we can see:

* state01: /mnt/myfile has disappeared
* state02: /mnt/myfile2 has disappeared. At that point, we have data loss as
  both files are now gone.
* state03: The renamed /mnt/myfile has reappeared.

We visualize these states in Figure 7 of the paper. For a correct atomic
rename, we would expect only states state00 and state03.

In Section 5.3.2 of the paper, we note that all states have at least one crash
image of type "fully persisted". The `report-results` tool prints such states
in green.

### rename directory = test_rename-dir: atomicity violation, data loss

Run:
```
vinter_python/report-results.py analyze --diff results/vm_nova/walkthrough_bugs/test_rename-dir
```

Checkpoint 1 -> 2 creates a directory and is correct.
Checkpoint 2 -> 3 creates a file and writes to that file, which is not expected to be atomic.

Checkpoint 3 -> 4 moves /mnt/newdir to /mnt/newdir2. Vinter identifies three states:

* state04: initial state
* state05: /mnt/newdir disappears, including its content. At this point, we have data loss.
* state06: /mnt/newdir reappears with its content in /mnt/newdir2.

For atomic directory rename, we would expect only state04 and state06.


### rename long name = test_rename-long-name: atomicity violation, data loss, read/write fails after recovery

Run:
```
vinter_python/report-results.py analyze --diff results/vm_nova/walkthrough_bugs/test_rename-long-name
```

Vinter reports state extraction failure for state03 and state04. Looking at the
error messages (see semantic_states/state0[34].txt), we can see that the
extraction program cannot access the files, even though they are listed in the
directory.

The remaining states also show issues:

* state01: /mnt/myfile disappears completely, resulting in data loss
* state02: the file reappears

For atomic rename, we would only expect state00 and state02 (and no errors).

### touch = test_touch: correct

Run:
```
vinter_python/report-results.py analyze --diff results/vm_nova/walkthrough_bugs/test_touch
```

Vinter reports an extra state (state02) occuring during the `touch` operation,
where `st_blocks` (the number of blocks allocated by the file system for the
file) increases from 0 to 8. We do not consider this a violation of atomicity.

### long name = test_touch-long-name: read/write fails after recovery

Run:
```
vinter_python/report-results.py analyze results/vm_nova/walkthrough_bugs/test_touch-long-name
```

We can see that state extraction fails with three distinct errors (look at
`semantic_states/stateXX.txt`):

* state02: accessing file /mnt/eizAKifFfyOn72ieKYxbCraXxNonCfH8CargS4xDIbOGGW6BPBCPEc1RYyNyZWZg
* state03: accessing file /mnt/eizAKifFfyOn72ieKYxbCraXxNonCfH8CargS4xDIbOGGW6BPBCPEc1RYyNyZWZgX
* state04: accessing file /mnt/eizAKifFfyOn72ieKYxbCraXxNonCfH8CargS4xDIbOGGW6BPBCPEc1RYyNyZWZgXX

(note the extra X at the end - the correct file has three X)

### update = test_update-middle: correct\*

Vinter reports multiple final states. We refer to *write* which shares the same
root-cause (unaligned data is not persisted correctly). We thus mark this test
case as "correct", since there is no bug specific to updating (as opposed to
writing/appending) to a file.



NOVA-Fortis
-----------

Run:
```
vinter_python/report-results.py analyze results/vm_nova-protection/walkthrough_bugs/*
```

Again, we can immediately detect tests without bugs:

* atime = test_atime
* chmod = test_chmod
* chown = test_chown

Since NOVA-Fortis is an extension of NOVA, we focus on the differences here.

### write = test_hello-world: read/write fails

Run:
```
vinter_python/report-results.py analyze --diff results/vm_nova-protection/walkthrough_bugs/test_hello-world
```

Vinter reports a single final state, so the unpersisted data bug from NOVA does
not occur in NOVA-Fortis. The test creates a file and writes to it which is
inherently not atomic. However, we see crash images where writing to another
file fails after recovery.

Note that the shell command performing this write is not shown in the output of
`report-results.py` and can be found in `fs-testing/scripts/test_hello-world.yaml`.

### append = test_append, update = update-middle: data loss

Run:
```
vinter_python/report-results.py analyze --diff results/vm_nova-protection/walkthrough_bugs/test_{append,update-middle}
```

For both test cases, we can see an additional state where the complete
content of the file is missing, resulting in data loss.

### [cm]time, link, mkdir/rmdir, unlink, rename (all variants)

We can see that there are crash images for which the state extraction fails.
Looking at the output file (`semantic_states/stateXX.txt`) we can see that our
state extraction tool reports an I/O error while reading the directory.

### touch, long name

Similar to the previous bug, we see crash images here where *writing* to a file
after recovery fails.


PMFS
----

Run:
```
vinter_python/report-results.py analyze results/vm_pmfs/walkthrough_bugs/*
```

Again, we can immediately detect tests without bugs:

* append = test_append
* atime = test_atime
* chmod = test_chmod
* chown = test_chown
* link = test_link-hard
* symlink = test_link-sym
* rename long name = test_rename-long-name
* touch = test_touch

### write = test_hello-world: correct

Run:
```
vinter_python/report-results.py analyze --diff results/vm_pmfs/walkthrough_bugs/test_hello-world
```

The tested operation `echo HelloWorld > /mnt/myfile` creates a file, then
writes to it. We can see that these two steps are atomic, so there are no
issues.

### [cm]time, mkdir/rmdir, rename overwrite, unlink: atomicity violation, crash

Run:
```
vinter_python/report-results.py analyze --diff results/vm_pmfs/walkthrough_bugs/test_{ctime-mtime,mkdir-rmdir,rename,unlink}
```

We can see that deleting a file (or directory) first updates that file's ctime
and mtime, then removes it from the directory. This could be considered a minor
violation of atomicity.

For mkdir/rmdir, rename overwrite, and unlink, Vinter generates crash images
where state extraction fails with a Linux kernel crash ("kernel BUG at
/mnt/pmfs/fs/pmfs/balloc.c:70!").

### rename directory = test_rename-dir: correct

Run:
```
vinter_python/report-results.py analyze --diff results/vm_pmfs/walkthrough_bugs/test_rename-dir
```

Between checkpoints 2 and 3, the test creates a new file and writes to it.
These are two operations, so the atomicity violation that Vinter reports is
correct, but not an issue.

### long name = test_touch-long-name: atomicity violation

Run:
```
vinter_python/report-results.py analyze --diff results/vm_pmfs/walkthrough_bugs/test_touch-long-name
```

We can see that when writing to a file, file timestamps are updated separately
from the remaining metadata and contents, violating atomicity.

### update = test_update-middle: correct

PMFS updates the file contents byte-by-byte. Since the semantics of such a
write are not clear, we consider this correct behavior.

