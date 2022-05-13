#!/bin/bash
set -e -o pipefail

usage() {
	echo "usage: $0 [options] <mid-output-path> <vm yaml> <test case yaml>"
	echo "Options:"
	echo " --trace-metadata: Enable metadata tracing"
	echo " --debug: Enable debug output"
	echo " --evaluate-heuristic-effectiveness: Ignore heuristic's results for the evaluation of its effectiveness"
	exit 1
}

PMEMTRACE_OPTS=()
TRACE2IMG_OPTS=()
DEBUG=0

while [[ "$1" = -* ]]; do
	case "$1" in
		--trace-metadata)
			PMEMTRACE_OPTS+=("--trace-metadata")
			;;
		--debug)
			DEBUG=1
			;;
		--evaluate-heuristic-effectiveness)
			TRACE2IMG_OPTS+=("--evaluate-heuristic-effectivenes")
			;;
		--help|-h|*)
			usage
	esac

	shift
done

if [[ "$#" != 3 ]] ; then
	usage
fi

# note that newlines in yaml strings would break this
IFS=$'\n' read -rd '' TRACE_CMD_PREFIX RECOVERY_CMD DUMP_CMD_PREFIX \
	<<< "$(yq -cr '.commands.trace_cmd_prefix, .commands.recovery_cmd, .commands.dump_cmd_prefix' "$2")" \
	|| true
IFS=$'\n' read -rd '' TRACE_CMD_SUFFIX DUMP_CMD_SUFFIX CHECKPOINT_FROM CHECKPOINT_TO \
	<<< "$(yq -cr '.trace_cmd_suffix, .dump_cmd_suffix, .checkpoint_range[0], .checkpoint_range[1]' "$3")" \
	|| true
TRACE_CMD="cat /proc/uptime ; cat /proc/uptime ; cat /proc/uptime ; $TRACE_CMD_PREFIX && $TRACE_CMD_SUFFIX && hypercall success ; cat /proc/uptime"
DUMP_CMD="$DUMP_CMD_PREFIX && $DUMP_CMD_SUFFIX && hypercall success"


SCRIPTPATH="$(dirname "${BASH_SOURCE[0]}")"
vm_yaml="$(realpath "$2")"
test_yaml="$(realpath "$3")"
OUTDIR="$PWD/$(basename "$vm_yaml" .yaml)/$1/$(basename "$test_yaml" .yaml)/"
TRACE="$OUTDIR/trace"
IMGPATH="$OUTDIR/crash_images"
STATEPATH="$OUTDIR/semantic_states"
TRACERIMGDIR="$OUTDIR/checkpoint_images"
mkdir -p "$IMGPATH" "$TRACERIMGDIR" "$STATEPATH"
cp -a "$SCRIPTPATH" "$OUTDIR/trace-and-analyze.sh.archive"
cp -a "$vm_yaml" "$test_yaml" "$OUTDIR"

if [[ "$DEBUG" = 1 ]]; then
	PMEMTRACE_OPTS+=("--debug" "$OUTDIR/pmemtrace.dbg")
fi

#mypy "$SCRIPTPATH"/*.py --allow-redefinition --check-untyped-defs

set -x
command time "$SCRIPTPATH"/pmemtrace.py --vm "$2" --trace-out "$TRACE" \
	"${PMEMTRACE_OPTS[@]}" \
	--checkpoint-mem-prefix "$TRACERIMGDIR/checkpoint" \
	"$TRACE_CMD" \
	|& tee "$OUTDIR/pmemtrace.out"

# We now use cpython instead of pypy due to presumably lower memory usage
command time python3 \
	"$SCRIPTPATH"/trace2img.py --vm "$2" crashgen \
	"${TRACE2IMG_OPTS[@]}" \
	--img-dir "$IMGPATH"  --state-dir "$STATEPATH" \
	--checkpoints "$CHECKPOINT_FROM" "$CHECKPOINT_TO" \
	--cmp-checkpoint-mem-prefix "$TRACERIMGDIR/checkpoint" \
	--recovery-cmd "$RECOVERY_CMD" \
	--dump-cmd "$DUMP_CMD" \
	"$TRACE" |& tee "$OUTDIR/trace2img.out"

set +x
sed -e '1,/^===== RESULTS/d' "$OUTDIR/trace2img.out" | tail -n+3 > "$OUTDIR/trace2img.results"
zstd --rm "$IMGPATH/img"* "$TRACE" "$TRACERIMGDIR/checkpoint"*
[ -f "$TRACE.dbg" ] && zstd --rm "$TRACE.dbg"

echo $'Success. Enter results via:\n'"cd $(realpath "$OUTDIR")"
