import collections
import dataclasses
from typing import Dict, Iterable, List, Optional, Set


def range_overlap(r1: range, r2: range) -> Optional[range]:  # assumes r1.step == r2.step == 1
    overlap = range(max(r1.start, r2.start), min(r1.stop, r2.stop))
    return overlap if len(overlap) else None


@dataclasses.dataclass(frozen=True)
class MemoryWrite:
    address_start: int
    value: bytes
    metadata: Optional[str] = None

    @property
    def address_stop(self) -> int:  # exclusive
        return self.address_start + len(self.value)

    @property
    def address_range(self) -> range:
        return range(self.address_start, self.address_stop)

    def __str__(self) -> str:
        return f'{self.address_start:#x}={self.value!r}'  # {" " + self.metadata if self.metadata else ""}

    def copy(self, *args):
        return self  # we're immutable

    __deepcopy__ = copy


class OrderedWriteLine:
    writes: List[MemoryWrite]
    flushed_index: int  # everything up until but excluding this index has been marked for flushing
    # if adding anything, update __deepcopy__

    def __init__(self):
        self.writes = []
        self.flushed_index = 0

    def flush_all(self):
        self.flushed_index = len(self.writes)

    def flushed_writes(self):
        # ~ assert(0 <= self.flushed_index <= len(self.writes))
        return self.writes[0:self.flushed_index]

    def unflushed_writes(self):
        return self.writes[self.flushed_index:]

    def clean_flushed_writes(self):
        self.writes = self.writes[self.flushed_index:]
        self.flushed_index = 0

    def __deepcopy__(self, memodict):
        # extremely improves performance
        copy = OrderedWriteLine()
        copy.writes = self.writes[:]  # MemoryWrite is immutable
        copy.flushed_index = self.flushed_index
        return copy


class X86PersistentMemory:
    memory_content: bytearray
    pending_lines: Set[int]  # just a performance improvement
    unpersisted_content: Dict[int, OrderedWriteLine]  # maps line number (== address // line_granularity) to OrderedWriteLine
    line_granularity: int

    def __init__(self, image_size: int, line_granularity: int = 64) -> None:
        assert(image_size >= 0)

        # Aligned 8-byte stores are powerfail atomic, we want to simulate at least that
        # Also, ordering of writes in cache line is guaranteed. To simulate that, choose 64.
        assert(line_granularity in (8, 64))

        self.memory_content = bytearray(image_size)
        self.pending_lines = set()
        self.unpersisted_content = collections.defaultdict(OrderedWriteLine)
        self.line_granularity = line_granularity

    def write(self, address: int, value: bytes, non_temporal: bool, metadata: str = None) -> None:
        assert(len(value) in (1, 2, 4, 8))  # test to see if we even get larger stores

        # Split into a maximum of (if possible aligned) 8-byte writes, since (aligned?!) 8 byte writes are powerfail-atomic.
        # Make sure that 8 byte boundaries are never crossed.
        address_stop = address + len(value)
        split_address_ranges = (range(max(a, address), min(a + 8, address_stop)) for a in range(address - (address % 8), address_stop if address_stop % 8 == 0 else address_stop + 8 - (address_stop % 8), 8))

        for address_range in split_address_ranges:
            line_number = address_range.start // self.line_granularity
            self.unpersisted_content[line_number].writes.append(
                    MemoryWrite(address_start=address_range.start, value=value[(address_range.start - address):(address_range.stop - address)], metadata=metadata))
            if non_temporal:  # approximation of non-temporal stores
                self.pending_lines.add(line_number)
                self.unpersisted_content[line_number].flush_all()  # note that if self.line_granularity == 64 (cache line), this is probably not quite correct

    def clwb(self, address: int, flush_writes_limit: int = None) -> None:  # flush_writes_limit is a *count*, not an index (makes a difference of 1)
        cache_line_base = (address >> 6) << 6

        for a in range(cache_line_base, cache_line_base + 64, self.line_granularity):
            # mark all writes to this address/line as "flushed"
            line_number = a // self.line_granularity
            if line := self.unpersisted_content.get(line_number):
                self.pending_lines.add(line_number)
                if flush_writes_limit:
                    line.flushed_index = flush_writes_limit
                else:
                    line.flush_all()

    def fence(self, lines: Iterable[int] = None) -> None:
        if lines is None:
            lines = self.pending_lines

        for line_number in lines:
            assert(self.unpersisted_content[line_number])
            assert(self.unpersisted_content[line_number].flushed_index > 0)
            for write in self.unpersisted_content[line_number].flushed_writes():  # go through all flushed writes in case they overlap
                self.memory_content[write.address_start:write.address_stop] = write.value
            self.unpersisted_content[line_number].clean_flushed_writes()
            assert(self.unpersisted_content[line_number].flushed_writes() == [])
            if not self.unpersisted_content[line_number].writes:
                self.unpersisted_content.pop(line_number)
            if lines is not self.pending_lines:
                self.pending_lines.remove(line_number)
        if lines is self.pending_lines:
            assert isinstance(lines, set)
            lines.clear()

    def read(self, address, size) -> bytes:
        """Reads current value from memory (independent of persistency semantics)"""

        line_number = address // self.line_granularity
        if address + size > len(self.memory_content):
            raise ValueError('address + size > len(self.memory_content)')
        content = self.memory_content[address:(address + size)]

        requested_range = range(address, address + size)
        if line := self.unpersisted_content.get(line_number):
            for write in line.writes:
                if overlap := range_overlap(requested_range, write.address_range):
                    content[(overlap.start - address):(overlap.stop - address)] = write.value[(overlap.start - write.address_start):(overlap.stop - write.address_start)]

        assert(len(content) == size)
        return content

    def persist_unpersisted(self) -> None:
        for line_number in self.unpersisted_content.keys():  # invariant: all lines are part of exactly one cache line
            self.clwb(line_number * self.line_granularity)
        self.fence()
        assert(not self.unpersisted_content)
        assert(not self.pending_lines)

    def print_unpersisted(self) -> None:
        for line_number, line in sorted(self.unpersisted_content.items()):
            print(f'unpersisted line {line_number}: {", ".join(map(str, line.writes))}')

    def print_unpersisted_verbose(self) -> None:
        for line_number, line in sorted(self.unpersisted_content.items()):
            print(f'unpersisted line {line_number} flushed from {line.flushed_index} (verbose):')
            for write in line.writes:
                print(f'{write}, metadata: {write.metadata}')
