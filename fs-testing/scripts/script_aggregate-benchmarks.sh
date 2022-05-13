#!/bin/bash
# Aggregate benchmarks. Run this in a directory where you have moved (manually!) multiple (exactly 20) runs of only the *same* benchmark run (with only *one* test_*.yaml run!), i.e. contains for example 20 directories paper-benchmark_run_1, paper-benchmark_run_2, etc.

set -e -o pipefail

# The `grep -a -P '^20\s'` commands ensure that actually 20 benchmark results are found (otherwise the experiment is broken).

function timing() {
	grep -a --no-filename -P "TIMING:$2:" $(find . -name "$1") | cut -f3,3 -d: | datamash count 1 mean 1 sstdev 1 $3
	# removed (also in other datamash commands): `min 1 max 1`
}
function elapsedtime() {
	tail -n2 $(find . -name "$1") | grep -a user | cut -f3,3 -d' ' | sed -e 's/elapsed//' | awk -F: '{ print $1 * 60 + $2 }' | datamash count 1 mean 1 sstdev 1 | grep -a -P '^20\s'
}

echo '== Figure 8 (pmemtrace.py) results =='

echo $'\tcount\tmean\tsstdev'
echo -n $'total elapsed tracer process time:\t'
elapsedtime pmemtrace.out
echo -n $'->boot (only minimal instrumentation):\t'
timing pmemtrace.out boot | grep -a -P '^20\s'
echo -n $'->trace (from outside):\t'
timing pmemtrace.out trace | grep -a -P '^20\s'

echo -n $'->->trace (in guest, portion of command):\t'
for path in $(find . -name pmemtrace.out) ; do
	uptimes=($(grep -a -P '^\d+\.\d+ \d+\.\d+' "$path" | cut -f1,1 -d\ ))
	if [[ ${#uptimes} != 4 ]] ; then echo 'wrong #uptimes' ; exit 1 ; fi
	bc -l <<< "${uptimes[-1]} - ${uptimes[-2]}"
done | datamash count 1 mean 1 sstdev 1 | grep -a -P '^20\s'

echo -n $'execution in guest with raw PANDA:\t'
for path in perf-benchmark_without-tracing/log* ; do
	uptimes=($(grep -aP '^\d+\.\d+ \d+\.\d+' "$path" | cut -f1,1 -d\ ))
	if [[ ${#uptimes} != 4 ]] ; then echo 'wrong #uptimes' ; exit 1 ; fi
	bc -l <<< "${uptimes[-1]} - ${uptimes[-2]}"
done | datamash count 1 mean 1 sstdev 1 | grep -P '^20\s'

echo $'\n== Figure 9 (trace2img.py) results =='
echo $'\tcount\tmean\tsstdev'

echo -n $'total elapsed process time:\t'
elapsedtime trace2img.out
echo -n $'->boot:\t'
timing trace2img.out boot | grep -a -P '^20\s'
echo -n $'->crash image generator:\t'
timing trace2img.out crashimggen | grep -a -P '^20\s'
echo -n $'->->cross-failure tracing (heuristic):\t'
( cd paper-benchmark_run-1/test_* && timing trace2img.out heuristic-trace )
echo -n $'->tester:\t'
timing trace2img.out tester | grep -a -P '^20\s'
echo -n $'->->reset to snapshot & load image:\t'
( cd paper-benchmark_run-1/test_* && timing trace2img.out dump-loadsnapshot-loadpmem )
echo -n $'->->run dumper command (PANDA):\t'
( cd paper-benchmark_run-1/test_* && timing trace2img.out dumpercmd )

function grep_stats() {
	grep -a --no-filename -P "$1" $(find . -name trace2img.out) | sort -u | cut -d= -f2,2
}

echo
echo "The tester processes $(grep_stats '^len\(imgs\)=') unique crash images
that stem from $(grep_stats '^#originating_crashes_sum=') origins (§3.3)
and result in $(grep_stats '^#len\(results_by_dump\)=') unique semantic crash states."

echo
echo success
