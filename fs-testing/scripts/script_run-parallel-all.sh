#!/usr/bin/env bash
set -eu -o pipefail

script=$0
scriptdir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
base=$scriptdir/../..
results=results

usage() {
	echo "Usage: $script [options] <identifier>"
	echo "Options:"
	echo " -P <num>: Analyze with <num> parallel instances (default 1)"
	echo " --trace-metadata: Enable tracing of metadata"
}

parallel=1
options=()

while [[ "${1-}" = -* ]]; do
	case "$1" in
		-P)
			parallel=$2
			shift
			;;
		--trace-metadata)
			options+=("--trace-metadata" "--debug")
			;;
		--help|-h|*)
			usage
			exit 0
	esac

	shift
done

if [[ $# != 1 ]]; then
	usage
	exit 1
fi

identifier=$1

for vm in vm_pmfs.yaml vm_nova.yaml vm_nova-protection.yaml ; do
	echo "$scriptdir"/test_*.yaml | xargs -n1 -P "$parallel" "$base/vinter_python/trace-and-analyze.sh" "${options[@]}" "$identifier" "$scriptdir/$vm" || true
done
