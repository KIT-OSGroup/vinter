#!/usr/bin/env python3
import argparse
import copy
import dataclasses
import enum
import fileinput
import glob
import itertools
import json
import math
import os
import tempfile
import time
import yaml
from collections import defaultdict
from functools import reduce
from itertools import chain
from operator import mul
from pathlib import Path
from typing import Any, Callable, cast, Dict, Iterable, List, NamedTuple, Optional, Sequence, Tuple

import random

from pmem import X86PersistentMemory

import pmem
import pmemtrace
from trace import parse_trace
from utils import KeyProvidingDefaultDict, powerset, random_subset


class MemoryReplayer:
    mem: pmem.X86PersistentMemory
    offset: int

    def __init__(self, mem: pmem.X86PersistentMemory, offset: int) -> None:
        self.mem = mem
        self.offset = offset

    def process_files(self, files,
                      before_write_callback: Callable[[int, int, int, bytes, bool], None] = None,
                      before_fence_callback: Callable[[int, str], None] = None,
                      read_callback: Callable[[int, int, int, bytes], None] = None,
                      hypercall_callback: Callable[[int, str, str], None] = None
                     ) -> int:  # returns last used ID
        address: Optional[int]
        with fileinput.FileInput(files=files) as input:
            for entry in parse_trace(input, self.offset):
                operation, id_ = entry[:2]
                if operation == 'write':
                    address, size, content, non_temporal, metadata = entry[2:]
                    if before_write_callback:
                        before_write_callback(id_, address, size, content, non_temporal)
                    self.mem.write(address, content, non_temporal, metadata)
                elif operation == 'fence':
                    metadata = entry[2]
                    if before_fence_callback:
                        before_fence_callback(id_, metadata)
                    self.mem.fence()
                elif operation == 'flush':
                    insn, address, metadata = entry[2:]
                    if insn == 'clwb':
                        assert(address is not None)
                        self.mem.clwb(address)
                    elif insn == 'clflush':
                        assert(address is not None)
                        self.mem.clwb(address)
                        self.mem.fence()
                        # ^ Note that this fence is not completely correct (in that we may lose bugs), as clflushes are only ordered among
                        # themselves (and some other things), but *not* among CLFLUSHOPT and CLWB.
                        # However applications usually don't mix those anyway.
                    else:
                        # clflushopt currently unsupported
                        raise Exception()
                elif operation == 'read':
                    if read_callback:
                        address, size, content = entry[2:]
                        read_callback(id_, address, size, content)
                elif operation == 'hypercall':
                    if hypercall_callback:
                        hypercall_callback(id_, entry[2], entry[3])
                else:
                    raise Exception(f'operation {operation} unsupported')
        return id_


class CrashPersistenceType(enum.Enum):
    NOTHING_PERSISTED = enum.auto()
    FULLY_PERSISTED = enum.auto()
    STRICT_SUBSET_PERSISTED = enum.auto()


@dataclasses.dataclass(frozen=True)
class CrashMetaData:
    fence_id: int
    checkpoint_id: int
    persistence_type: CrashPersistenceType

    # for STRICT_SUBSET_PERSISTED:
    strict_subset_lines: Optional[List[int]] = None  # stores all writes that were considered
    partial_write_indices: Optional[Sequence[int]] = None

    # for FULLY_PERSISTED and STRICT_SUBSET_PERSISTED:
    # Stores all lines that are part of the image, but not properly persisted.
    # We need those to figure out whether a subset image is still relevant at a later fence.
    dirty_lines: Optional[List[int]] = None

class PostRecoveryDump(NamedTuple):
    output: str
    successful: bool

class HeuristicState(enum.Enum):
    # Post-recovery tracing has happened
    HEURISTIC_APPLIED = enum.auto()
    NOT_CONSIDERED = enum.auto()

@dataclasses.dataclass
class CrashImage:
    """Describes a crash image and all CrashMetaData that have been discovered to lead to this crash image"""
    img: bytes
    post_recovery_dump: Optional[PostRecoveryDump] = None  # better name might be: post_failure_dump
    originating_crashes: List[CrashMetaData] = dataclasses.field(default_factory=list)
    filename: str = ''

    heuristic: HeuristicState = HeuristicState.NOT_CONSIDERED
    # for HEURISTIC_APPLIED:
    heuristic_images: Optional[List['CrashImage']] = None
    read_lines: Optional[int] = None


@dataclasses.dataclass
class HeuristicCrashImageGenerator:
    pre_failure_replayer: MemoryReplayer
    pre_failure_files: Any
    tracer: pmemtrace.PersistentMemoryTracer
    evaluate_heuristic_effectiveness: bool
    post_failure_recovery_cmd: str
    post_failure_dump_cmd: str  # is *not* executed in post failure recovery (i.e., its reads will *not* be traced for heuristics; consider including the same command also in post_failure_recovery_cmd)
    MAX_UNPERSISTED_SUBSETS = 20
    PARTIAL_FLUSHES_THRESHOLD = 20

    def _new_replayer(self) -> MemoryReplayer:
        mem = pmem.X86PersistentMemory(image_size=len(self.pre_failure_replayer.mem.memory_content), line_granularity=self.pre_failure_replayer.mem.line_granularity)
        return MemoryReplayer(mem=mem, offset=self.pre_failure_replayer.offset)

    @staticmethod
    def _post_failure_reads(replayer: MemoryReplayer, files) -> List[Tuple[int, int]]:
        reads = []
        success = False

        def read_callback(id_: int, address: int, size: int, content: bytes) -> None:
            # TODO We should make sure that the memory hasn't been overwritten by the post failure execution
            #      before adding it to our list.
            # (If we don't implement that, we don't really need to simulate memory and could just extract read
            #  operations from the trace.)
            reads.append((address, size))

        def hypercall_callback(id_: int, action: str, value: str) -> None:
            nonlocal success
            if success:
                raise Exception('multiple "success" hypercalls')
            if action == 'success':
                success = True
            else:
                assert False

        replayer.process_files(files=files, read_callback=read_callback, hypercall_callback=hypercall_callback)

        if not success:
            print('WARN: _post_failure_reads unsuccessful')  # If the recovery cmd is part of the trace cmd, this will result in an unsuccessful dump later on which is presented in the results. So not too bad, just ignore the failure here.
        return reads

    def replay(self, checkpoint_range: Optional[range], generated_img_dir: str, semantic_state_dir: str, cmp_checkpoint_mem_prefix: str = None) -> None:
        imgs: dict[bytes, CrashImage] = KeyProvidingDefaultDict(lambda key_: CrashImage(img=key_))
        current_writes = False
        fences_with_writes = 0
        last_hypercall_checkpoint: int = -1
        pre_failure_success = False
        checkpoint_ids: Dict[int, int] = {}  # maps checkpoint number (as given to hypercall) to operation id
        random_generator = random.Random(1633634632)  # make randomness deterministic across analyses of the same trace

        def before_fence_callback(id_: int, metadata: str = '', *, force_processing=False) -> None:
            nonlocal current_writes, fences_with_writes
            if (current_writes or force_processing) and (not checkpoint_range or last_hypercall_checkpoint in checkpoint_range
                    or (force_processing and checkpoint_range.stop == last_hypercall_checkpoint)):  # run once when end of the checkpoint interval is reached
                # Optimization: If no writes have occurred, ignore.
                # Even if there were `clwb`s in the previous iteration, they only restrict which crash images we can generate, and not allow any new ones.
                # Though depends on our heuristic if we generate these.

                mem_bytes = bytes(self.pre_failure_replayer.mem.memory_content)
                imgs[mem_bytes].originating_crashes.append(
                    CrashMetaData(fence_id=id_, persistence_type=CrashPersistenceType.NOTHING_PERSISTED, checkpoint_id=last_hypercall_checkpoint)
                )

                fully_persisted_mem = copy.deepcopy(self.pre_failure_replayer.mem)
                fully_persisted_mem.persist_unpersisted()
                fully_persisted_mem_bytes = bytes(fully_persisted_mem.memory_content)
                fully_persisted_img = imgs[fully_persisted_mem_bytes]
                fully_persisted_img.originating_crashes.append(
                    CrashMetaData(
                        fence_id=id_,
                        persistence_type=CrashPersistenceType.FULLY_PERSISTED,
                        dirty_lines=list(self.pre_failure_replayer.mem.unpersisted_content.keys()),
                        checkpoint_id=last_hypercall_checkpoint
                    )
                )

                # correctness testing
                if cmp_checkpoint_mem_prefix is not None and metadata.startswith('at_beginning_of_checkpoint='):
                    with open(cmp_checkpoint_mem_prefix + str(last_hypercall_checkpoint), 'rb') as f:
                        if f.read() != fully_persisted_mem_bytes:
                            raise Exception('buggy trace/replay?!')

                # debug
                print(f'==========\nadding image at fence=#{id_}, checkpoint={last_hypercall_checkpoint}, metadata={metadata}')
                self.pre_failure_replayer.mem.print_unpersisted()
                print('verbose:')
                self.pre_failure_replayer.mem.print_unpersisted_verbose()

                if fully_persisted_img.heuristic == HeuristicState.NOT_CONSIDERED:
                    fully_persisted_img.heuristic = HeuristicState.HEURISTIC_APPLIED
                    fully_persisted_img.heuristic_images = list()
                    self.tracer.load_snapshot('boot')
                    self.tracer.load_pmem_image(fully_persisted_mem_bytes)
                    with tempfile.NamedTemporaryFile('w+') as post_failure_trace:
                        previous_trace_out = self.tracer.trace_out
                        self.tracer.trace_out = post_failure_trace
                        begin = time.perf_counter()
                        print(self.tracer.perform_trace(self.post_failure_recovery_cmd))
                        print(f'TIMING:heuristic-trace:{time.perf_counter() - begin}')

                        self.tracer.trace_out.flush()  # important
                        post_failure_replayer = self._new_replayer()
                        post_failure_reads = self._post_failure_reads(post_failure_replayer, post_failure_trace.name)
                        self.tracer.trace_out = previous_trace_out
                    unpersisted_reads: set[Tuple[int, int]] = set()
                    unpersisted_reads_lines: set[int] = set()
                    pre_failure_mem = self.pre_failure_replayer.mem
                    post_failure_mem = post_failure_replayer.mem
                    line_granularity = post_failure_mem.line_granularity

                    if self.evaluate_heuristic_effectiveness:  # evaluation of heuristic effectiveness -> ignore heuristic's results
                        unpersisted_reads_lines = set(self.pre_failure_replayer.mem.unpersisted_content.keys())
                    else:
                        for address, size in post_failure_reads:
                            min_line_number = address // line_granularity
                            max_line_number = (address + size - 1) // line_granularity
                            for line_number in range(min_line_number, max_line_number + 1):
                                if (line := pre_failure_mem.unpersisted_content.get(line_number)) \
                                        and any(pmem.range_overlap(write.address_range, range(address, address + size)) for write in line.writes):
                                    unpersisted_reads.add((address, size))
                                    unpersisted_reads_lines.add(line_number)

                    fully_persisted_img.read_lines = len(unpersisted_reads_lines)
                    print(f'fence #{id_}: {len(post_failure_reads)} reads to {len(set(address for address, _ in post_failure_reads))} different start addresses (post),\n'
                          f'unpersisted_reads (post): #={len(unpersisted_reads)}, {[(hex(a), b) for a, b in sorted(unpersisted_reads)]},\n'
                          f'number of unpersisted lines (pre): {len(pre_failure_mem.unpersisted_content)}, \n'
                          f'number of unpersisted writes (pre): {sum(len(line.writes) for line in pre_failure_mem.unpersisted_content.values())}')
                          # f'number of unpersisted lines: {len(post_failure_mem.unpersisted_content)}, '
                          # f'number of unpersisted writes: {sum(len(line.writes) for line in post_failure_mem.unpersisted_content.values())}')

                    subset_count = 0
                    if len(unpersisted_reads_lines) >= 1:  # also consider == 1 because we may be able to do partial line flushes
                        if (2 ** len(unpersisted_reads_lines)) <= self.MAX_UNPERSISTED_SUBSETS:
                            # do NOT use strict subset -- we also consider partial line writes below, and those are relevant even for the full lines set
                            random_lines_gen: Iterable[Iterable[int]] = powerset(unpersisted_reads_lines, strict=False)
                        else:
                            random_lines_gen = (random_subset(unpersisted_reads_lines, random_generator) for _ in range(self.MAX_UNPERSISTED_SUBSETS))  # TODO includes duplicates

                        # debug stats
                        unpersisted_lines_lengths = [len(self.pre_failure_replayer.mem.unpersisted_content[line_number].writes) for line_number in unpersisted_reads_lines]
                        print(f'STATS: #unpersisted_reads={len(unpersisted_reads)}, #unpersisted_reads_lines={len(unpersisted_reads_lines)}, their lengths: {unpersisted_lines_lengths}, max={max(unpersisted_lines_lengths)}, avg={sum(unpersisted_lines_lengths) / len(unpersisted_lines_lengths)}')

                        for random_lines in map(lambda l: list(l), random_lines_gen):  # using lambda due to mypy bug https://github.com/python/mypy/issues/8113
                            partial_flushes_combinations = reduce(mul, (len(self.pre_failure_replayer.mem.unpersisted_content[line_number].writes) for line_number in random_lines), 1)
                            if partial_flushes_combinations > self.PARTIAL_FLUSHES_THRESHOLD:
                                lines_with_more_than_one_write = [line_number for line_number in random_lines if len(self.pre_failure_replayer.mem.unpersisted_content[line_number].writes) > 1]
                                lines_to_consider_for_partial_flushes = random_generator.sample(lines_with_more_than_one_write, min(int(math.log2(self.PARTIAL_FLUSHES_THRESHOLD)), len(lines_with_more_than_one_write)))
                            line_partial_writes: List[Sequence[int]] = []
                            # Possibility for improvement: Maybe only consider writes in a line that are overlapping with unpersisted reads
                            for line_number in random_lines:
                                writes_count = len(self.pre_failure_replayer.mem.unpersisted_content[line_number].writes)
                                if partial_flushes_combinations > self.PARTIAL_FLUSHES_THRESHOLD:  # note that this can lead to up to self.PARTIAL_FLUSHES_THRESHOLD * self.MAX_UNPERSISTED_SUBSETS images (thus `MAX_UNPERSISTED_SUBSETS` is a bit misleadingly named)
                                    # Always test the case that *all* pending stores in the line are applied. Further, if possible with the set self.PARTIAL_FLUSHES_THRESHOLD, test at least one strict prefix of the pending stores in the line. If it's not possible for every line, then choose a random subset of lines to apply this (via lines_to_consider_for_partial_flushes).
                                    line_partial_writes.append(
                                        [writes_count]
                                        + ([] if (writes_count <= 1 or line_number not in lines_to_consider_for_partial_flushes)
                                           else random_generator.sample(range(1, writes_count), 1))  # if ever changing the sample size of 1, update log2 to another basis above (`math.log2(self.PARTIAL_FLUSHES_THRESHOLD)`)
                                    )
                                else:
                                    line_partial_writes.append(range(1, writes_count + 1))
                            assert(len(line_partial_writes) == len(random_lines))

                            #print(f'STATS: line_partial_writes_combinations={reduce(mul, (len(w) for w in line_partial_writes), 1)}')
                            for partial_write_indices in itertools.product(*line_partial_writes):
                                subset_count += 1
                                mem = copy.deepcopy(self.pre_failure_replayer.mem)
                                for line_number, flush_writes_limit in zip(random_lines, partial_write_indices):
                                    mem.clwb(line_number * line_granularity, flush_writes_limit)
                                    mem.fence((line_number,))
                                random_crash_img = imgs[bytes(mem.memory_content)]
                                random_crash_img.originating_crashes.append(CrashMetaData(
                                    fence_id=id_,
                                    persistence_type=CrashPersistenceType.STRICT_SUBSET_PERSISTED,  # TODO not necessarily strict subset currently (as random_lines_gen includes nonstrict subsets)
                                    checkpoint_id=last_hypercall_checkpoint,
                                    strict_subset_lines=random_lines,
                                    partial_write_indices=partial_write_indices,
                                    # Dirty lines are all lines that are not (fully) persisted in this image.
                                    # First, all lines that are not in random_lines at all.
                                    dirty_lines=list(set(self.pre_failure_replayer.mem.unpersisted_content.keys()).difference(random_lines)) +
                                    # Then, all lines that are partially included (i.e., not with all writes).
                                                [line for line, writes_limit in zip(random_lines, partial_write_indices)
                                                      if len(self.pre_failure_replayer.mem.unpersisted_content[line].writes) > writes_limit],
                                ))
                                fully_persisted_img.heuristic_images.append(random_crash_img)
                    print(f'generated {subset_count} subsets')

                fences_with_writes += 1
                current_writes = False

        def before_write_callback(id_: int, address: int, size: int, content: bytes, non_temporal: bool) -> None:
            nonlocal current_writes
            current_writes = True

        def pre_failure_hypercall_callback(id_: int, action: str, value: str) -> None:
            nonlocal last_hypercall_checkpoint, pre_failure_success
            if action == 'checkpoint':
                last_hypercall_checkpoint = int(value)
                if last_hypercall_checkpoint in checkpoint_ids:
                    raise Exception('duplicate checkpoint id')
                checkpoint_ids[last_hypercall_checkpoint] = id_
                before_fence_callback(id_, metadata=f'at_beginning_of_checkpoint={last_hypercall_checkpoint}', force_processing=True)
                # (TODO) We could abort the replay when we're past checkpoint_range.stop
            elif action == 'success':
                if pre_failure_success:
                    raise Exception('multiple "success" hypercalls')
                pre_failure_success = True
            else:
                assert False

        begin_crashimggen = time.perf_counter()
        last_id = self.pre_failure_replayer.process_files(files=self.pre_failure_files, before_fence_callback=before_fence_callback, before_write_callback=before_write_callback, hypercall_callback=pre_failure_hypercall_callback)
        if not pre_failure_success:
            raise Exception('pre-failure execution unsuccessful')  # not necessarily a problem with the program as it might show a bug, so reconsider this

        if checkpoint_range and last_hypercall_checkpoint < checkpoint_range.stop - 1:
            raise Exception('last checkpoint has not been reached')

        # For completeness, also generate an image with everything persisted.
        current_writes = True
        if checkpoint_range:
            last_id += 1
            before_fence_callback(last_id, metadata=f'at_end_of_checkpoint_range', force_processing=True)

        print(f'len(imgs)={len(imgs)}')
        print(f'#originating_crashes_sum={sum(len(img.originating_crashes) for img in imgs.values())}')
        print(f'fences_with_writes={fences_with_writes}')
        print(f'TIMING:crashimggen:{time.perf_counter() - begin_crashimggen}')

        ### Here begins Vinter's "Tester" component

        begin_tester = time.perf_counter()
        # Run self.post_recovery_dump on all images
        dump_successful: bool
        def dump_hypercall_callback(action: str, value: str) -> None:
            nonlocal dump_successful
            if dump_successful:
                raise Exception('multiple "success" hypercalls')
            if action == 'success':
                dump_successful = True
            else:
                assert False
        begin = time.perf_counter()
        for img, crash_img in imgs.items():
            dump_successful = False
            assert crash_img.post_recovery_dump is None
            print(f'==== running post_failure_dump_cmd, originating from {crash_img.originating_crashes}')
            begin = time.perf_counter()
            self.tracer.load_snapshot('boot')
            self.tracer.load_pmem_image(img)
            print(f'TIMING:dump-loadsnapshot-loadpmem:{time.perf_counter() - begin}')
            begin = time.perf_counter()
            crash_img.post_recovery_dump = PostRecoveryDump(
                output=self.tracer.run_without_tracing(self.post_failure_dump_cmd, hypercall_callback=dump_hypercall_callback),
                successful=dump_successful
            )
            print(f'TIMING:dumpercmd:{time.perf_counter() - begin}')
            # print('DEBUG: crash_img output:\n' + crash_img.post_recovery_dump.output)   # debug hung dmesg extractions with this
            if not any(substr in crash_img.post_recovery_dump.output for substr in ('invalid opcode: ', 'RIP: ')):  # otherwise kernel crash -> VM hung ('invalid opcode' can appear for user space crashes, however if init crashes we cannot input anything anymore)
                # hack for manually debugging NOVA
                dmesg = self.tracer.run_without_tracing("dmesg | grep -q 'nova err' && dmesg | grep ^nova").strip()
                if dmesg:
                    print('nova dmesg (as "nova err" matches):')
                    print(dmesg)

        duration = time.perf_counter() - begin
        print(f'post_failure_dump_cmd took {duration}s for {len(imgs)} dumps, avg={duration / len(imgs)}s')

        for pathname in itertools.chain(glob.glob(generated_img_dir + '/*'),
                                        glob.glob(semantic_state_dir + '/*')):
            os.remove(pathname)

        results_by_dump: defaultdict[PostRecoveryDump, List[CrashImage]] = defaultdict(list)
        dumps_by_checkpoint: dict[int, set[PostRecoveryDump]] = {}
        final_dumps_by_checkpoint: dict[int, set[PostRecoveryDump]] = {}

        for checkpoint_id in checkpoint_ids:
            final_dumps_by_checkpoint[checkpoint_id] = set()
            dumps_by_checkpoint[checkpoint_id] = set()
        image_index = dict()
        img_items = imgs.items()
        # First, assign a name to all images.
        for i, (img, crash_img) in enumerate(img_items):
            with open(f'{generated_img_dir}/img{i}', 'wb') as f:
                f.write(img)
            crash_img.filename = f'img{i}'
        # Then, we can refer to these names in 'heuristic_images'
        for i, (img, crash_img) in enumerate(img_items):
            image_index[crash_img.filename] = {
                'heuristic':
                    {'HeuristicApplied': {
                        'heuristic_images': [hi.filename for hi in crash_img.heuristic_images],
                        'read_lines': crash_img.read_lines,
                    }} if crash_img.heuristic == HeuristicState.HEURISTIC_APPLIED else 'NotConsidered',
                'originating_crashes': [{
                        'fence_id': cmd.fence_id,
                        'checkpoint_id': cmd.checkpoint_id,
                        'persistence_type':
                            {'FullyPersisted': {
                                'dirty_lines': cmd.dirty_lines,
                            }} if cmd.persistence_type == CrashPersistenceType.FULLY_PERSISTED else
                            'NothingPersisted' if cmd.persistence_type == CrashPersistenceType.NOTHING_PERSISTED else
                            {'StrictSubsetPersisted': {
                                'strict_subset_lines': cmd.strict_subset_lines,
                                'partial_write_indices': cmd.partial_write_indices,
                                'dirty_lines': cmd.dirty_lines,
                            }},
                    } for cmd in crash_img.originating_crashes],
            }
            with open(f'{generated_img_dir}/dump{i}', 'w') as f:
                assert(crash_img.post_recovery_dump is not None)
                f.write(crash_img.post_recovery_dump.output)
            assert(isinstance(crash_img.post_recovery_dump, PostRecoveryDump))  # for mypy
            results_by_dump[crash_img.post_recovery_dump].append(crash_img)
            for crash in crash_img.originating_crashes:
                dumps_by_checkpoint[crash.checkpoint_id].add(crash_img.post_recovery_dump)
                if crash.fence_id == checkpoint_ids[crash.checkpoint_id]:
                    final_dumps_by_checkpoint[crash.checkpoint_id].add(crash_img.post_recovery_dump)
                    break
        with open(f'{generated_img_dir}/index.yaml', 'w') as f:
            yaml.safe_dump(image_index, f)
        print(f'#len(results_by_dump)={len(results_by_dump)}')

        state_index = dict()
        for i, (dump, images) in enumerate(results_by_dump.items()):
            name = f'state{i:02}'
            state_index[name] = {
                'successful': dump.successful,
                'originating_images': [image.filename for image in images]
            }
            with open(f'{semantic_state_dir}/{name}.txt', 'w') as f:
                f.write(dump.output)
        with open(f'{semantic_state_dir}/index.yaml', 'w') as f:
            yaml.safe_dump(state_index, f)

        print('\n\n===== RESULTS')
        for dump, results in sorted(results_by_dump.items(), key=lambda item: min(crash.fence_id for crash in chain.from_iterable(result.originating_crashes for result in item[1]))):  # ugliness award
            print(f'\n\n{"UN" if not dump.successful else ""}successful dump resulting from {[(result.filename, result.originating_crashes) for result in results]}\n'
                  f'(distinct checkpoint_ids: {set(crash.checkpoint_id for crash in chain.from_iterable(result.originating_crashes for result in results))}, '
                  f'distinct types: {set(crash.persistence_type for crash in chain.from_iterable(result.originating_crashes for result in results))}):\n{dump.output}')

        print(f'\nLast operation id is {last_id}')
        print(f'Checkpoint to ID mapping: {checkpoint_ids}')
        checkpoints_with_duplicates = [checkpoint_id for checkpoint_id, dumps in final_dumps_by_checkpoint.items() if len(dumps) > 1]
        print(f'Checkpoints with more than one dump at the beginning: {checkpoints_with_duplicates}')
        nonatomic_checkpoints = [checkpoint_id for checkpoint_id, dumps in dumps_by_checkpoint.items() if len(dumps) > 2]
        print(f'Checkpoints with more than two dumps (nonatomic; considers interval `[checkpoint, checkpoint + 1)`): {nonatomic_checkpoints}')
        print(f'{sum(1 for result in imgs.values() if not cast(PostRecoveryDump, result.post_recovery_dump).successful)} images with UNsuccessful recovery')
        print(f'TIMING:tester:{time.perf_counter() - begin_tester}')


def main() -> None:
    arg_parser = argparse.ArgumentParser()
    subparsers = arg_parser.add_subparsers(dest='subparser')
    simple_parser = subparsers.add_parser('simple', help='Go through the whole trace and generate a single ouptut image with either all unpersisted writes left out or included.')
    crashgen_parser = subparsers.add_parser('crashgen', help='Generate crash images using heuristics.')
    arg_parser.add_argument('--vm', type=argparse.FileType('r'), required=True)
    arg_parser.add_argument('--debug', '-d', action='store_true')

    simple_parser.add_argument('--persist-unpersisted', '-p', action='store_true')
    simple_parser.add_argument('--img-out', type=argparse.FileType('wb'), required=True)
    crashgen_parser.add_argument('--checkpoints', nargs=2, metavar=('from', 'to'),
                                 help='only generate images for fences between checkpoints `from` to `to` (i.e., `to` is exclusive)', type=int)
    crashgen_parser.add_argument('--recovery-cmd', required=True)
    crashgen_parser.add_argument('--dump-cmd', required=True)
    crashgen_parser.add_argument('--img-dir', required=True, help='output dir for crash images')
    crashgen_parser.add_argument('--state-dir', required=True, help='output dir for unique semantic states')
    crashgen_parser.add_argument('--cmp-checkpoint-mem-prefix')
    crashgen_parser.add_argument('--evaluate-heuristic-effectiveness', action='store_true')
    for parser in (simple_parser, crashgen_parser):
        parser.add_argument('traces', nargs='*')

    args = arg_parser.parse_args()
    config = yaml.safe_load(args.vm)
    config['vm']['basepath'] = Path(args.vm.name).parent

    mem = pmem.X86PersistentMemory(image_size=config['vm']['pmem_len'])
    replayer = MemoryReplayer(mem=mem, offset=config['vm']['pmem_start'])

    if args.subparser == 'simple':
        read_callback = None
        if args.debug:
            def read_callback(id_, address, size, content):
                assert(content == mem.read(address, size))

        replayer.process_files(files=args.traces, read_callback=read_callback)
        mem.print_unpersisted()
        if args.persist_unpersisted:
            mem.persist_unpersisted()
        args.img_out.write(mem.memory_content)

    elif args.subparser == 'crashgen':
        with open(os.devnull, 'w') as devnull,\
                pmemtrace.PersistentMemoryTracer(trace_out=devnull, vm=config['vm']) as tracer:
            tracer.boot()
            tracer.init_plugins_hooks()
            gen = HeuristicCrashImageGenerator(pre_failure_files=args.traces, pre_failure_replayer=replayer,
                                               post_failure_recovery_cmd=args.recovery_cmd,
                                               post_failure_dump_cmd=args.dump_cmd,
                                               tracer=tracer,
                                               evaluate_heuristic_effectiveness=args.evaluate_heuristic_effectiveness,
                                               )
            gen.replay(checkpoint_range=range(*args.checkpoints) if args.checkpoints else None,
                       generated_img_dir=args.img_dir, semantic_state_dir=args.state_dir,
                       cmp_checkpoint_mem_prefix=args.cmp_checkpoint_mem_prefix)

    else:
        assert False


if __name__ == '__main__':
    main()
