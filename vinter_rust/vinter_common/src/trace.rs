use std::io::{BufRead, Read, Write};

use anyhow::{bail, Context, Result};
use bincode::{Decode, Encode};

const BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();

#[derive(Debug, Default, Clone, Encode, Decode)]
pub struct Metadata {
    /// current program counter
    pub pc: u64,
    /// currently in kernel mode?
    pub in_kernel: bool,
    /// kernel stack trace (frame pointer walk)
    pub kernel_stacktrace: Vec<u64>,
}

#[derive(Debug, Encode, Decode)]
pub enum TraceEntry {
    Write {
        id: usize,
        address: usize,
        size: usize,
        content: Vec<u8>,
        non_temporal: bool,
        metadata: Metadata,
    },
    Fence {
        id: usize,
        mnemonic: String,
        metadata: Metadata,
    },
    Flush {
        id: usize,
        mnemonic: String,
        address: usize,
        metadata: Metadata,
    },
    Read {
        id: usize,
        address: usize,
        size: usize,
        content: Vec<u8>,
    },
    Hypercall {
        id: usize,
        action: String,
        value: String,
    },
}

impl TraceEntry {
    pub fn decode_from_std_read<R: std::io::Read>(
        src: &mut R,
    ) -> std::result::Result<TraceEntry, bincode::error::DecodeError> {
        bincode::decode_from_std_read(src, BINCODE_CONFIG)
    }

    pub fn encode_into_std_write<W: std::io::Write>(
        &self,
        dst: &mut W,
    ) -> std::result::Result<usize, bincode::error::EncodeError> {
        bincode::encode_into_std_write(self, dst, BINCODE_CONFIG)
    }
}

/// Helper to make filter_map() work with error handling.
fn lift_option<T>(r: Result<Option<T>>) -> Option<Result<T>> {
    match r {
        Ok(None) => None,
        Ok(Some(o)) => Some(Ok(o)),
        Err(e) => Some(Err(e)),
    }
}

pub struct BinTraceIterator<R: Read> {
    file: R,
}

impl<R: Read> Iterator for BinTraceIterator<R> {
    type Item = Result<TraceEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        use bincode::error::DecodeError;
        match TraceEntry::decode_from_std_read(&mut self.file) {
            Ok(e) => Some(Ok(e)),
            Err(DecodeError::UnexpectedEnd) => None,
            Err(e) => Some(Err(e.into())),
        }
    }
}

pub type TraceWriter<W> = snap::write::FrameEncoder<W>;

/// Create a trace writer with compression.
pub fn new_trace_writer_bin<W: Write>(file: W) -> TraceWriter<W> {
    snap::write::FrameEncoder::new(file)
}

/// Parse a binary trace file.
pub fn parse_trace_file_bin<R: BufRead>(file: R) -> BinTraceIterator<snap::read::FrameDecoder<R>> {
    BinTraceIterator {
        file: snap::read::FrameDecoder::new(file),
    }
}

/// Parse a textual trace file.
pub fn parse_trace_file_text(file: impl BufRead) -> impl Iterator<Item = Result<TraceEntry>> {
    file.lines().enumerate().filter_map(move |(id, line)| {
        lift_option((move || {
            let line = line?;
            let lineno = id + 1;
            let cols: Vec<&str> = line.split(",").collect();
            Ok(match cols[0] {
                "write" => {
                    if cols.len() != 6 {
                        bail!("line {}: wrong number of write arguments", lineno);
                    }
                    let address: usize = cols[1]
                        .parse::<usize>()
                        .with_context(|| format!("line {}: invalid address", lineno))?;
                    let size: usize = cols[2]
                        .parse::<usize>()
                        .with_context(|| format!("line {}: invalid size", lineno))?;
                    let content = hex::decode(cols[3])
                        .with_context(|| format!("line {}: invalid content", lineno))?;
                    let non_temporal = match cols[4] {
                        "True" | "true" => true,
                        "False" | "false" => false,
                        other => {
                            bail!("line {}: invalid NT flag {}", lineno, other);
                        }
                    };
                    Some(TraceEntry::Write {
                        id,
                        address,
                        size,
                        content,
                        non_temporal,
                        metadata: Default::default(),
                    })
                }
                "insn" => {
                    if cols.len() != 4 {
                        bail!("line {}: wrong number of insn arguments", lineno);
                    }
                    let insn = cols[1];
                    let address = if cols[2] == "" {
                        None
                    } else {
                        // address might be outside of PMEM area, skip these silently ("performance bug")
                        Some(
                            cols[2]
                                .parse::<usize>()
                                .with_context(|| format!("line {}: invalid address", lineno))?,
                        )
                    };
                    match insn {
                        "mfence" | "sfence" | "wbinvd" | "xchg" => Some(TraceEntry::Fence {
                            id,
                            mnemonic: insn.to_string(),
                            metadata: Default::default(),
                        }),
                        "clwb" | "clflush" => address.map(|address| TraceEntry::Flush {
                            id,
                            mnemonic: insn.to_string(),
                            address,
                            metadata: Default::default(),
                        }),
                        other => {
                            bail!("line {}: unsupported instruction {}", lineno, other);
                        }
                    }
                }
                "read" => {
                    if cols.len() != 4 {
                        bail!("line {}: wrong number of read arguments", lineno);
                    }
                    let address: usize = cols[1]
                        .parse::<usize>()
                        .with_context(|| format!("line {}: invalid address", lineno))?;
                    let size: usize = cols[2]
                        .parse::<usize>()
                        .with_context(|| format!("line {}: invalid size", lineno))?;
                    let content = hex::decode(cols[3])
                        .with_context(|| format!("line {}: invalid content", lineno))?;
                    Some(TraceEntry::Read {
                        id,
                        address,
                        size,
                        content,
                    })
                }
                "hypercall" => {
                    if cols.len() != 3 {
                        bail!("line {}: wrong number of hypercall arguments", lineno);
                    }
                    Some(TraceEntry::Hypercall {
                        id,
                        action: cols[1].into(),
                        value: cols[2].into(),
                    })
                }
                op => {
                    bail!("unsupported operation {}", op);
                }
            })
        })())
    })
}
