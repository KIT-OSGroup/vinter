#!/bin/bash
# This script reproduces the benchmark results from the paper's figures 8 and 9.
set -e -o pipefail

script=$0
scriptdir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
base=$scriptdir/../..
results=results_paper-benchmark

rm -rf "$results"
mkdir "$results"
cd "$results"

for i in {0..20} ; do # perform 21 runs (first will be discarded)
	echo "== Performing benchmark run $i/20"
	sleep 10 # Add some delays between tests to make hardware timings more deterministic
	"$base/vinter_python/trace-and-analyze.sh" "paper-benchmark_run-$i" "$scriptdir/vm_nova.yaml" "$scriptdir/test_hello-world.yaml" > /dev/null
done

cd vm_nova
# Discard first benchmark run in case it took longer to prefill OS's page cache
rm -r paper-benchmark_run-0

echo $'\n== Performing benchmark in raw panda'
"$scriptdir/script_perf-benchmark_without-tracing_nova-hello-world.sh"

echo $'\n== Performed benchmarks. Now aggregating the results:\n'
"$scriptdir/script_aggregate-benchmarks.sh" | column -Lts$'\t'
