use std::cmp::{max, min};
use std::collections::{HashMap, HashSet};
use std::ops::Range;

use anyhow::Result;

use crate::{MemoryImage, MemoryImageMmap};
use vinter_common::trace::Metadata;

#[derive(Debug, Clone)]
pub struct MemoryWrite {
    pub address_start: usize,
    pub value: Vec<u8>,
    pub metadata: Metadata,
}

impl MemoryWrite {
    pub fn address_end(&self) -> usize {
        self.address_start + self.value.len()
    }

    pub fn address_range(&self) -> Range<usize> {
        self.address_start..self.address_end()
    }
}

#[derive(Clone)]
pub struct OrderedWriteLine {
    writes: Vec<MemoryWrite>,
    /// everything up until but excluding this index has been marked for flushing
    flushed_index: usize,
}

impl Default for OrderedWriteLine {
    fn default() -> Self {
        Self::new()
    }
}

impl OrderedWriteLine {
    pub fn new() -> Self {
        OrderedWriteLine {
            writes: Vec::new(),
            flushed_index: 0,
        }
    }

    pub fn flush_all(&mut self) {
        self.flushed_index = self.writes.len();
    }

    pub fn all_writes(&self) -> &[MemoryWrite] {
        &self.writes
    }

    pub fn flushed_writes(&self) -> &[MemoryWrite] {
        &self.writes[0..self.flushed_index]
    }

    pub fn unflushed_writes(&self) -> &[MemoryWrite] {
        &self.writes[self.flushed_index..]
    }

    pub fn drain_flushed_writes(&mut self) -> std::vec::Drain<'_, MemoryWrite> {
        let idx = self.flushed_index;
        self.flushed_index = 0;
        self.writes.drain(0..idx)
    }

    /// Do any pending writes overlap with an access at the specified address and size?
    pub fn overlaps_access(&self, address: usize, size: usize) -> bool {
        let access_range = address..(address + size);
        self.writes
            .iter()
            .any(|w| !range_overlap(&w.address_range(), &access_range).is_empty())
    }
}

pub enum LineGranularity {
    Word,
    Cacheline,
}

impl std::convert::From<LineGranularity> for usize {
    fn from(lg: LineGranularity) -> usize {
        match lg {
            LineGranularity::Word => 8,
            LineGranularity::Cacheline => 64,
        }
    }
}

pub struct X86PersistentMemory {
    pub image: MemoryImageMmap,
    pending_lines: HashSet<usize>,
    /// maps line number (== address / line_granularity) to OrderedWriteLine
    pub unpersisted_content: HashMap<usize, OrderedWriteLine>,
    /// 8 or 64
    line_granularity: usize,
}

impl X86PersistentMemory {
    pub fn new(image: MemoryImageMmap, line_granularity: LineGranularity) -> Result<Self> {
        Ok(X86PersistentMemory {
            image,
            pending_lines: HashSet::new(),
            unpersisted_content: HashMap::new(),
            line_granularity: line_granularity.into(),
        })
    }

    /// Try to clone the memory content. Can fail due to I/O errors.
    pub fn try_clone(&self) -> Result<Self> {
        Ok(X86PersistentMemory {
            image: self.image.try_clone()?,
            pending_lines: self.pending_lines.clone(),
            unpersisted_content: self.unpersisted_content.clone(),
            line_granularity: self.line_granularity,
        })
    }

    pub fn memory_content(&self) -> &[u8] {
        &self.image
    }

    pub fn pmem_len(&self) -> usize {
        self.image.len()
    }

    pub fn line_granularity(&self) -> LineGranularity {
        match self.line_granularity {
            8 => LineGranularity::Word,
            64 => LineGranularity::Cacheline,
            other => panic!("BUG: invalid line granularity {}", other),
        }
    }

    pub fn write(&mut self, address: usize, value: &[u8], non_temporal: bool, metadata: &Metadata) {
        // test to see if we even get larger stores
        assert!(matches!(value.len(), 1 | 2 | 4 | 8));
        let address_stop = address + value.len();
        let split_address_ranges = {
            let start = address - address % 8;
            let stop = if address_stop % 8 == 0 {
                address_stop
            } else {
                address_stop + 8 - (address_stop % 8)
            };
            (start..stop)
                .step_by(8)
                .map(|a| max(a, address)..min(a + 8, address_stop))
        };

        for address_range in split_address_ranges {
            let line_number = address_range.start / self.line_granularity;
            let line = self
                .unpersisted_content
                .entry(line_number)
                .or_insert_with(OrderedWriteLine::new);
            line.writes.push(MemoryWrite {
                address_start: address_range.start,
                value: value[(address_range.start - address)..(address_range.end - address)].into(),
                metadata: metadata.clone(),
            });

            // approximation of non-temporal stores
            if non_temporal {
                self.pending_lines.insert(line_number);
                // note that for cache line granularity, this is probably not quite correct
                line.flush_all();
            }
        }
    }

    // TODO: what do we need flush_writes_limit for?
    pub fn clwb(&mut self, address: usize, flush_writes_limit: Option<usize>) {
        let cache_line_base = (address >> 6) << 6;
        for a in (cache_line_base..(cache_line_base + 64)).step_by(self.line_granularity) {
            let line_number = a / self.line_granularity;
            if let Some(line) = self.unpersisted_content.get_mut(&line_number) {
                self.pending_lines.insert(line_number);
                if let Some(limit) = flush_writes_limit {
                    line.flushed_index = limit;
                } else {
                    line.flush_all();
                }
            }
        }
    }

    pub fn fence(&mut self) {
        // A fence consumes all pending lines. Swap in a new set to avoid double borrow of self.
        let mut pending_lines = HashSet::new();
        std::mem::swap(&mut pending_lines, &mut self.pending_lines);
        for line in pending_lines {
            self.fence_line(line);
        }
    }

    pub fn fence_line(&mut self, line: usize) {
        if let Some(content) = self.unpersisted_content.get_mut(&line) {
            assert!(content.flushed_index > 0);
            for write in content.drain_flushed_writes() {
                self.image[write.address_range()].copy_from_slice(&write.value);
            }
            if content.writes.is_empty() {
                self.unpersisted_content.remove(&line);
            }
            self.pending_lines.remove(&line);
        } else {
            unreachable!();
        }
    }

    /// Reads current value from memory (independent of persistency semantics).
    /// Note: result is only correct if it fits in one line (size and alignment).
    pub fn read(&self, address: usize, size: usize) -> Vec<u8> {
        let line_number = address / self.line_granularity;
        assert!(address + size <= self.image.len());
        let range = address..(address + size);
        let mut content: Vec<u8> = self.image[range.clone()].into();

        if let Some(line) = self.unpersisted_content.get(&line_number) {
            for write in &line.writes {
                let overlap = range_overlap(&range, &write.address_range());
                if !overlap.is_empty() {
                    content[(overlap.start - address)..(overlap.end - address)].copy_from_slice(
                        &write.value[(overlap.start - write.address_start)
                            ..(overlap.end - write.address_end())],
                    );
                }
            }
        }

        content
    }

    pub fn persist_unpersisted(&mut self) {
        let lines: Vec<usize> = self.unpersisted_content.keys().copied().collect();
        for line_number in lines {
            self.clwb(line_number * self.line_granularity, None);
        }
        self.fence();
        assert!(self.unpersisted_content.is_empty());
        assert!(self.pending_lines.is_empty());
    }

    pub fn print_unpersisted(&self) {
        let mut lines: Vec<(&usize, &OrderedWriteLine)> = self.unpersisted_content.iter().collect();
        lines.sort_by_key(|(line_number, _)| *line_number);
        for (line_number, line) in lines {
            println!("unpersisted line {}: {:?}", *line_number, line.writes);
        }
    }

    /// Hash the memory contents with blake3.
    pub fn blake3(&self) -> blake3::Hash {
        blake3::hash(&self.image)
    }
}

fn range_overlap<T>(r1: &Range<T>, r2: &Range<T>) -> Range<T>
where
    T: std::cmp::Ord + Copy,
{
    Range {
        start: max(r1.start, r2.start),
        end: min(r1.end, r2.end),
    }
}
