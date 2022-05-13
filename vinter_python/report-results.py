#!/usr/bin/env python3
import argparse
import functools
import itertools
import math
import subprocess
import yaml
from collections import defaultdict
from pathlib import Path

from trace import parse_trace

# Always flush output so that interleaving with diff output is correct.
print = functools.partial(print, flush=True)

# TODO: make configurable
LINE_GRANULARITY = 64

# Color codes
BLACK = "\033[0;30m"
RED = "\033[0;31m"
GREEN = "\033[0;32m"
BROWN = "\033[0;33m"
BLUE = "\033[0;34m"
PURPLE = "\033[0;35m"
CYAN = "\033[0;36m"
LIGHT_GRAY = "\033[0;37m"
DARK_GRAY = "\033[1;30m"
LIGHT_RED = "\033[1;31m"
LIGHT_GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
LIGHT_BLUE = "\033[1;34m"
LIGHT_PURPLE = "\033[1;35m"
LIGHT_CYAN = "\033[1;36m"
LIGHT_WHITE = "\033[1;37m"
BOLD = "\033[1m"
FAINT = "\033[2m"
ITALIC = "\033[3m"
UNDERLINE = "\033[4m"
BLINK = "\033[5m"
NEGATIVE = "\033[7m"
CROSSED = "\033[9m"
END = "\033[0m"

def diff(file1, file2):
    subprocess.run(['git', '--no-pager', 'diff', '-U1', '--color', '--no-index', '--', file1, file2])

def print_diffs_first(files):
    it = iter(files)
    first = next(it)
    for file in it:
        if file != first:
            diff(str(first), str(file))

def print_diffs_consecutive(files):
    it = iter(files)
    prev = next(it)
    for file in it:
        diff(prev, file)
        prev = file

# Analyze an output directory for atomicity and SFS.
def analyze(dir: Path, diff=False, verbose=False):
    print(f'{BOLD}Test: {dir.name}{END}\n')
    
    with open(dir / f'{dir.name}.yaml', 'r') as f:
        test = yaml.safe_load(f)
    with open(dir / 'crash_images/index.yaml', 'r') as f:
        images = yaml.safe_load(f)
    with open(dir / 'semantic_states/index.yaml', 'r') as f:
        states = yaml.safe_load(f)
    
    print(f'Command: {test["trace_cmd_suffix"]}\n')
    checkpoint_start = test['checkpoint_range'][0]
    checkpoint_end = test['checkpoint_range'][1]

    # Map checkpoint id to states.
    checkpoint_states = defaultdict(set)
    # Map checkpoint id to (first fence id, states at first fence, relevant images, dirty lines at fence)
    checkpoint_first_fence = defaultdict(lambda: (math.inf, None, None, None))
    # Does this state result from at least one "fully persisted" image?
    state_has_fully_persisted = defaultdict(lambda: False)
    for name, state in states.items():
        if not state['successful']:
            print(f'{RED}{name}: state extraction not successful{END}')
        for image_name in state['originating_images']:
            for crash in images[image_name]['originating_crashes']:
                if 'FullyPersisted' in crash['persistence_type']:
                    state_has_fully_persisted[name] = True
                id = crash['checkpoint_id']
                checkpoint_states[id].add(name)
                if checkpoint_first_fence[id][0] > crash['fence_id']:
                    checkpoint_first_fence[id] = (crash['fence_id'], set(), set(), set())
                if checkpoint_first_fence[id][0] == crash['fence_id']:
                    checkpoint_first_fence[id][1].add(name)
                    # If the heuristic was performed on this image, we need to find the resulting additional images.
                    if 'HeuristicApplied' in images[image_name]['heuristic'] and \
                       'FullyPersisted' in crash['persistence_type']:
                        checkpoint_first_fence[id][2].add(image_name)

    # For each image created at a checkpoint, add all relevant states found via the heuristic.
    for checkpoint, item in checkpoint_first_fence.items():
        additional_images = set()
        for image_name in item[2]:
            heuristic_fences = set()
            dirty_lines = set()
            for crash in images[image_name]['originating_crashes']:
                if crash['fence_id'] == item[0] and 'FullyPersisted' in crash['persistence_type']:
                    dirty_lines = set(crash['persistence_type']['FullyPersisted']['dirty_lines'])
                if 'FullyPersisted' in crash['persistence_type']:
                    heuristic_fences.add(crash['fence_id'])
            item[3].update(dirty_lines)
            for heuristic_image_name in images[image_name]['heuristic']['HeuristicApplied']['heuristic_images']:
                for crash in images[heuristic_image_name]['originating_crashes']:
                    if crash['fence_id'] in heuristic_fences and 'StrictSubsetPersisted' in crash['persistence_type']:
                        if set(crash['persistence_type']['StrictSubsetPersisted']['dirty_lines']).issubset(dirty_lines):
                            additional_images.add(heuristic_image_name)
        for name, state in states.items():
            if name in item[1]:
                continue
            for image_name in state['originating_images']:
                if image_name in additional_images:
                    item[1].add(name)
                    break

    def format_state(state_name):
        if state_has_fully_persisted[state_name]:
            return f'{LIGHT_GREEN}{state_name}{END}'
        return f'{LIGHT_PURPLE}{state_name}{END}'
    
    for checkpoint, states in sorted(checkpoint_states.items(), key=lambda item: item[0]):
        if checkpoint < checkpoint_start or checkpoint >= checkpoint_end:
            continue
        print(f'checkpoint {checkpoint} -> {checkpoint+1}:')
        if verbose:
            print(f'  {LIGHT_GRAY}trace line {checkpoint_first_fence[checkpoint][0]} -> {checkpoint_first_fence[checkpoint+1][0]}{END}')
        # TODO: Also add heuristic-based initial states here
        print(f'  {len(states)} states: {", ".join(sorted(map(format_state, states)))}')
        final_states, _, dirty_lines = checkpoint_first_fence[checkpoint+1][1:4]
        if len(final_states) > 1:
            print(f'  {RED}{len(final_states)} final states{END}: {", ".join(sorted(final_states))}')
            if verbose:
                print(f'  {LIGHT_GRAY}Dirty lines at checkpoint: {dirty_lines}{END}')
            if diff:
                print_diffs_first([dir / f'semantic_states/{name}.txt' for name in sorted(final_states)])
        else:
            print(f'  {GREEN}single final state{END}: {next(iter(final_states))}')
        # TODO: Does this match our definition of atomic?
        if len(states) <= 2:
            if len(final_states) > 1:
                print(f'  {YELLOW}(atomic){END}')
            else:
                print(f'  {GREEN}atomic{END}')
        else:
            print(f'  {RED}not atomic{END}')
            if diff:
                print_diffs_consecutive([dir / f'semantic_states/{name}.txt' for name in sorted(states)])
        print()

def unzstd(path):
    p = subprocess.Popen(["zstd", "-d", path, "--stdout"], stdout=subprocess.PIPE, text=True)
    return p.stdout

def trace_lines(trace, lines, offset=0, since=0):
    for entry in itertools.islice(parse_trace(trace, offset), since, None):
        operation, id_ = entry[:2]
        if operation == 'write':
            address, size, content, non_temporal, metadata = entry[2:]
            line = address // LINE_GRANULARITY
            off = address % LINE_GRANULARITY
            if line in lines:
                print(f"{LIGHT_GRAY}{id_}{END}\t{BOLD}{'NT-' if non_temporal else ''}write{END} line {line} + {off}")
                print(f"\tcontent: {content}")
                if metadata:
                    print(f"\tmetadata: {metadata}")
        elif operation == 'flush':
            insn, address, metadata = entry[2:]
            line = address // LINE_GRANULARITY
            if line in lines:
                print(f"{LIGHT_GRAY}{id_}{END}\t{BOLD}flush{END} line {line}")
                if metadata:
                    print(f"\tmetadata: {metadata}")


def get_origins(dir, state):
    print(f'{BOLD}State: {dir.name} / {state}{END}\n')

    with open(next(dir.glob("vm_*.yaml")), "r") as vm_file:
        config = yaml.safe_load(vm_file)
    with open(dir / 'crash_images/index.yaml', 'r') as f:
        images = yaml.safe_load(f)
    with open(dir / 'semantic_states/index.yaml', 'r') as f:
        states = yaml.safe_load(f)

    if state not in states:
        print(f'{RED}Error: state {state} does not exist for {dir.name}{END}\n')
        return

    # Collect all crashes.
    crashes = list()
    for image_name in states[state]['originating_images']:
        for crash in images[image_name]['originating_crashes']:
            crashes.append(crash)
    crashes.sort(key=lambda c: c['fence_id'])

    trace = parse_trace(unzstd(dir / 'trace.zst'), offset=config['vm']['pmem_start'])
    entry = next(trace)
    for crash in crashes:
        if entry[1] == crash['fence_id']:
            continue
        while entry[1] < crash['fence_id']:
            try:
                entry = next(trace)
            except StopIteration:
                return
        if entry[0] == 'fence':
            print(f"Crash after checkpoint {crash['checkpoint_id']}, fence {entry[1]}")
            print(f"{LIGHT_GRAY}Metadata: {entry[2]}{END}\n")
        elif entry[0] == 'hypercall' and entry[2] == 'checkpoint':
            print(f"Crash {ITALIC}at{END} checkpoint {crash['checkpoint_id']}, fence {entry[1]}")
        else:
            print(entry)

def main() -> None:
    arg_parser = argparse.ArgumentParser()
    subparsers = arg_parser.add_subparsers(dest='subparser')

    analyze_parser = subparsers.add_parser('analyze', help='Analyze results from trace2img')
    analyze_parser.add_argument('directories', nargs='*')
    analyze_parser.add_argument('--diff', action='store_true', help='print diffs for potentially invalid states')
    analyze_parser.add_argument('--verbose', '-v', action='store_true', help='enable extra output')

    trace_line_parser = subparsers.add_parser('trace-lines', help='Read a trace and print entries related to a line')
    trace_line_parser.add_argument('--since', type=int, help='start reading trace at that entry')
    trace_line_parser.add_argument('directory', type=str)
    trace_line_parser.add_argument('lines', nargs='*', type=int)
    
    get_origins_parser = subparsers.add_parser('get-origins', help='Print origins of a semantic state')
    get_origins_parser.add_argument('directory', type=str)
    get_origins_parser.add_argument('states', nargs='*', type=str)

    args = arg_parser.parse_args()
    if args.subparser == 'analyze':
        if len(args.directories) == 0:
            analyze_parser.print_help()
        for dir in args.directories:
            analyze(Path(dir), diff=args.diff, verbose=args.verbose)
    elif args.subparser == 'trace-lines':
        if len(args.lines) == 0:
            trace_line_parser.print_help()
            return
        dir = Path(args.directory)
        with open(next(dir.glob("vm_*.yaml")), "r") as vm_file:
            config = yaml.safe_load(vm_file)
        trace_lines(unzstd(dir / "trace.zst"), set(args.lines), offset=config['vm']['pmem_start'], since=args.since)
    elif args.subparser == 'get-origins':
        if len(args.states) == 0:
            get_origins_parser.print_help()
        for state in args.states:
            get_origins(Path(args.directory), state)
    else:
        arg_parser.print_help()

if __name__ == '__main__':
    main()
