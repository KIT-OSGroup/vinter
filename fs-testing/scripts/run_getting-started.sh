#!/usr/bin/env bash
set -eu -o pipefail

script=$0
scriptdir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
base=$scriptdir/../..
results=results_getting-started

rm -rf "$results"
mkdir -p "$results"/{vinter_python,vinter_rust}

test=test_hello-world
vms=("vm_nova" "vm_pmfs")

# Analysis with vinter_python
for vm in "${vms[@]}"; do
  echo "Running vinter_python with test $test on $vm..."
  (cd "$results/vinter_python" && \
    "$base/vinter_python/trace-and-analyze.sh" getting-started "$scriptdir/$vm.yaml" "$scriptdir/$test.yaml")
done

# Analysis with vinter_rust
for vm in "${vms[@]}"; do
  echo "Running vinter_rust with test $test on $vm..."
  "$base/target/release/vinter_trace2img" analyze --output-dir "$results/vinter_rust" \
    "$scriptdir/$vm.yaml" "$scriptdir/$test.yaml"
done
