This walkthrough reproduces §6.2 "Effectiveness of Heuristic".

Execute in a shell (you may ignore the stdout/stderr output):
```
cd fs-testing/scripts
# We stay in this directory for the entirety of this walkthrough.

# Change -P10 to another number to adjust the degree of concurrency depending
# on the number of CPU cores and memory available on your machine.

# The following executes all test cases on NOVA normally. (Might take around 10 minutes to execute depending on degree of parallelity.)
echo test_*.yaml | xargs -n1 -P10 ../../vinter_python/trace-and-analyze.sh effectiveness_with-heuristic vm_nova.yaml ; echo $?
# The last line of the output should be `0`. If not, the programs did not execute successfully (e.g., crash due to out of memory) and the results are likely to be inaccurate.

# The following runs all test cases on NOVA while ignoring our heuristic's
# post-failure reads, and instead considers all dirty cache lines for crash image
# generation (but still chooses random subsets of dirty lines once a threshold
# is exceeded).
# (The neutralized heuristic results in more work, hence the following might take a few dozen minutes depending on degree of parallelity.)
echo test_*.yaml | xargs -n1 -P10 ../../vinter_python/trace-and-analyze.sh --evaluate-heuristic-effectiveness effectiveness_without-heuristic vm_nova.yaml ; echo $?
# The last line of the output should be `0`. If not, the programs did not execute successfully (e.g., crash due to out of memory) and the results are likely to be inaccurate.
```

Now we count the total number of (already deduplicated) generated crash images for both of the experiments we just ran:
```
$ find vm_nova/effectiveness_with-heuristic -path '*/test_*/crash_images/img*.zst' | wc -l
438
$ find vm_nova/effectiveness_without-heuristic -path '*/test_*/crash_images/img*.zst' | wc -l
2466
```
These numbers should be very close to the ones written in §6.2.
(Minor deviation is possible due to nondeterministic VM execution, such as nondeterministic fence operations.)

Now we verify that even though the second experiment (with the neutralized
heuristic) results in a relatively high number of crash images, they do not
exhibit any additional semantic states and thus do not find new crash
consistency bugs.

To do so, compare the output of:
```
./script_aggregate-results.sh vm_nova/effectiveness_with-heuristic
```
with the output of:
```
./script_aggregate-results.sh vm_nova/effectiveness_without-heuristic
```
We suggest using a diff tool to compare their output (e.g., a graphical tool like Meld, or vimdiff).
The output should be the same.
Exceptions apply:
 * In rare cases, it might be possible that timestamps from the serialized file system have changed, resulting in more states in one of the experiments.
 * In test cases with "UNsuccessful recovery" listings, the listed number of crash images may differ due to nondeterministic VM execution. This does however not imply additional semantic states (unsuccessful recoveries are also recorded as semantic states and the number of semantic states should be the same).

Note that comparing these outputs only compares the number of reported semantic states.
To ensure that not only their number but also their contents match, one will need to compare the `test_*/semantic_states/state*.txt` files between `vm_nova/effectiveness_with-heuristic` and `vm_nova/effectiveness_without-heuristic`.
