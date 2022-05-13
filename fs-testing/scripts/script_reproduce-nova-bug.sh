#!/usr/bin/env bash

set -eu

script=$0
scriptdir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
base=$scriptdir/../..
results=results_completeness

usage() {
  echo "Usage: $script [options] <vm name> <bug id> <commit before> <commit after>"
  echo "Options:"
  echo " -P <num>: Analyze with <num> parallel instances (default 1)"
}

parallel=1

while [[ "${1-}" = -* ]]; do
	case "$1" in
		-P)
      parallel=$2
      shift
			;;
		--help|-h|*)
			usage
      exit 0
	esac

	shift
done

if [[ $# != 4 ]]; then
  usage
  exit 1
fi

mkdir -p "$results"

vm=$1
bugid=$2
commit_before=$3
commit_after=$4

build_and_analyze() {
  commit=$1
  if [[ -d "$results/$vm/$commit" ]]; then
    echo "NOVA commit $commit has already been analyzed, skipping..."
    return
  fi
  echo "Checking out NOVA commit $commit..."
  git -C "$base/fs-testing/linux/nova" checkout "$commit"
  echo "Building NOVA..."
  fs-testing/linux/build-kernel.sh nova
  echo "Running analysis..."
  (cd "$results" && \
    find "$base/fs-testing/scripts" -name 'test_*.yaml' | \
      xargs -I{} -P"$parallel" "$base/vinter_python/trace-and-analyze.sh" "$commit" "$base/fs-testing/scripts/$vm.yaml" '{}')
}

echo "Analyzing before bug fix..."
build_and_analyze "$commit_before"
echo
echo "Analyzing after bug fix..."
build_and_analyze "$commit_after"
echo
echo "Creating summaries..."
"$base/vinter_python/report-results.py" analyze "$results/$vm/$commit_before"/* > "$results/${bugid}_before.txt"
"$base/vinter_python/report-results.py" analyze "$results/$vm/$commit_after"/* > "$results/${bugid}_after.txt"
echo
echo "Diff of results:"
diff -u "$results/${bugid}_before.txt" "$results/${bugid}_after.txt"