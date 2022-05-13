#!/bin/bash
set -e -o pipefail
if [[ $# != 1 ]] ; then
	echo "usage: $0 <vm_dir>"
	exit 1
fi

cd "$1"

for dir in test_*/ ; do
	( cd "$dir" && echo "$(find semantic_states -name 'state*.txt' | wc -l) semantic states" ; grep -aP '(^Checkpoints .*(?<!\[\])$|^[^0].* images with )|Traceback|^\s*raise |WARN:' trace2img.out || true) | sed -e "s/^/${dir//\//}: /"
done
