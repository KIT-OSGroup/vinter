use anyhow::{bail, Context, Result};
use crossbeam_channel::select;
use lazy_static::lazy_static;
use panda::prelude::*;
use panda::regs::Reg as PandaReg;
use panda::Callback;
use std::fs::File;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use vinter_common::trace::{new_trace_writer_bin, Metadata, TraceEntry};

mod disasm;
use disasm::disassemble_at;

lazy_static! {
    static ref ARGS: Args = Args::from_panda_args();
}

#[derive(PandaArgs)]
#[name = "vinter_trace"]
struct Args {
    #[arg(default = "vinter_trace.bin", about = "File to log trace results")]
    out_trace_file: String,

    #[arg(about = "Verbose print")]
    debug: bool,

    #[arg(about = "Physical address where PMEM starts")]
    pmem_start: u64,

    #[arg(about = "Length of PMEM area")]
    pmem_len: u64,

    #[arg(
        default = "all",
        about = "What to trace. Comma-separated list of: read, write, hypercall, fence, flush"
    )]
    trace: String,

    #[arg(
        default = "none",
        about = "What metadata to record. Comma-separated list of: kernel_stacktrace"
    )]
    metadata: String,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            out_trace_file: "vinter_trace.bin".to_string(),
            debug: false,
            pmem_start: 0,
            pmem_len: 0,
            trace: "all".to_string(),
            metadata: "none".to_string(),
        }
    }
}

/// State to keep between init and uninit
static mut TRACER_STATE: Option<TracerState> = None;

#[panda::init]
fn panda_init(_: &mut PluginHandle) -> bool {
    lazy_static::initialize(&ARGS);
    match init() {
        Ok(state) => {
            unsafe {
                TRACER_STATE = Some(state);
            }
            true
        }
        Err(err) => {
            eprintln!("{}", err);
            false
        }
    }
}

#[panda::uninit]
fn panda_uninit(_: &mut PluginHandle) {
    let state = unsafe { std::mem::take(&mut TRACER_STATE) };
    uninit(state.unwrap()).expect("uninit failed");
}

const CPUID_HYPERCALL_MAGIC: u64 = 0x40000000; // see hypercall.c

// from std::ptr::copy documentation
/// # Safety
///
/// * `ptr` must be correctly aligned for its type and non-zero.
/// * `ptr` must be valid for reads of `elts` contiguous elements of type `T`.
/// * Those elements must not be used after calling this function unless `T: Copy`.
unsafe fn from_buf_raw<T>(ptr: *const T, elts: usize) -> Vec<T> {
    let mut dst = Vec::with_capacity(elts);

    // SAFETY: Our precondition ensures the source is aligned and valid,
    // and `Vec::with_capacity` ensures that we have usable space to write them.
    std::ptr::copy(ptr, dst.as_mut_ptr(), elts);

    // SAFETY: We created it with this much capacity earlier,
    // and the previous `copy` has initialized these elements.
    dst.set_len(elts);
    dst
}

/// What to trace, for selective tracing.
#[derive(Debug, Clone, Copy)]
struct TraceWhat {
    read: bool,
    write: bool,
    flush: bool,
    fence: bool,
    hypercall: bool,
}

impl TraceWhat {
    pub fn all() -> TraceWhat {
        TraceWhat {
            read: true,
            write: true,
            flush: true,
            fence: true,
            hypercall: true,
        }
    }

    pub fn none() -> TraceWhat {
        TraceWhat {
            read: false,
            write: false,
            flush: false,
            fence: false,
            hypercall: false,
        }
    }

    pub fn enable(&mut self, s: &str) -> Result<()> {
        match s {
            "read" => self.read = true,
            "write" => self.write = true,
            "flush" => self.flush = true,
            "fence" => self.fence = true,
            "hypercall" => self.hypercall = true,
            s => bail!("unknown trace option {}", s),
        }
        Ok(())
    }
}

/// What to record as metadata.
#[derive(Debug, Clone, Copy)]
struct MetadataWhat {
    /// Record a kernel stacktrace, based on a frame pointer walk.
    kernel_stacktrace: bool,
}

impl MetadataWhat {
    pub fn all() -> MetadataWhat {
        MetadataWhat {
            kernel_stacktrace: true,
        }
    }

    pub fn none() -> MetadataWhat {
        MetadataWhat {
            kernel_stacktrace: false,
        }
    }

    pub fn enable(&mut self, s: &str) -> Result<()> {
        match s {
            "kernel_stacktrace" => self.kernel_stacktrace = true,
            s => bail!("unknown metadata option {}", s),
        }
        Ok(())
    }
}

/// Maximum length of a metadata stacktrace.
const MAX_STACKTRACE_LEN: usize = 20;

/// Collect metadata about the current CPU state.
fn metadata(cpu: &mut CPUState, what: MetadataWhat) -> Metadata {
    let mut m = Metadata {
        pc: cpu.panda_guest_pc,
        in_kernel: panda::in_kernel_mode(cpu),
        ..Default::default()
    };
    if what.kernel_stacktrace && m.in_kernel {
        let mut st = Vec::new();
        let mut fp = panda::regs::get_reg(cpu, PandaReg::RBP);
        let mut buf = [0u8; 16];
        // fp with LSB set is not a frame pointer, see ENCODE_FRAME_POINTER in Linux.
        while fp != 0 && fp & 1 == 0 && st.len() < MAX_STACKTRACE_LEN {
            if panda::mem::virtual_memory_read_into(cpu, fp, &mut buf).is_err() {
                break;
            }
            fp = u64::from_le_bytes(buf[0..8].try_into().unwrap());
            st.push(u64::from_le_bytes(buf[8..16].try_into().unwrap()));
        }
        m.kernel_stacktrace = st;
    }
    m
}

struct TracerState {
    writer_thread: thread::JoinHandle<()>,
    done_send: crossbeam_channel::Sender<()>,
}

fn init() -> Result<TracerState> {
    let mut trace_out = new_trace_writer_bin(
        File::create(&ARGS.out_trace_file).context("could not open out_trace_file")?,
    );
    let (trace_send, trace_recv) = crossbeam_channel::unbounded::<TraceEntry>();
    let (done_send, done_recv) = crossbeam_channel::bounded(0);
    let writer_thread = std::thread::spawn(move || loop {
        select! {
            recv(trace_recv) -> entry => {
                entry
                    .unwrap()
                    .encode_into_std_write(&mut trace_out)
                    .expect("failed writing trace");
            }
            recv(done_recv) -> _ => {
                break;
            }
        }
    });

    let id = Arc::new(AtomicUsize::new(0));
    // We only need to record fences if there are any new writes or flushes.
    let have_writes = Arc::new(AtomicBool::new(false));

    let trace_enabled = if ARGS.trace == "all" {
        TraceWhat::all()
    } else {
        let mut tw = TraceWhat::none();
        for s in ARGS.trace.split(',') {
            tw.enable(s)?;
        }
        tw
    };

    let metadata_what = match ARGS.metadata.as_ref() {
        "all" => MetadataWhat::all(),
        "none" => MetadataWhat::none(),
        list => {
            let mut mw = MetadataWhat::none();
            for s in list.split(',') {
                mw.enable(s)?;
            }
            mw
        }
    };

    if trace_enabled.read {
        let trace_send = trace_send.clone();
        let id = id.clone();
        Callback::new().phys_mem_after_read(
            move |_cpu_state: &mut CPUState,
                  _pc: target_ptr_t,
                  addr: target_ptr_t,
                  size: usize,
                  buf: *mut u8| {
                if addr < ARGS.pmem_start || addr >= ARGS.pmem_start + ARGS.pmem_len {
                    return;
                }
                trace_send
                    .send(TraceEntry::Read {
                        id: id.fetch_add(1, Ordering::Relaxed),
                        address: (addr - ARGS.pmem_start).try_into().unwrap(),
                        size,
                        content: unsafe { from_buf_raw(buf, size) },
                    })
                    .expect("failed writing trace");
            },
        );
    }

    if trace_enabled.write {
        let trace_send = trace_send.clone();
        let id = id.clone();
        let have_writes = have_writes.clone();
        Callback::new().phys_mem_after_write(
            move |cpu_state: &mut CPUState,
                  pc: target_ptr_t,
                  addr: target_ptr_t,
                  size: usize,
                  buf: *mut u8| {
                if addr < ARGS.pmem_start || addr >= ARGS.pmem_start + ARGS.pmem_len {
                    return;
                }
                have_writes.store(true, Ordering::Relaxed);

                let insn = match disassemble_at(cpu_state, pc) {
                    Ok(insn) => insn,
                    Err(err) => {
                        eprintln!("could not disassemble instruction at 0x{:x}: {}", pc, err);
                        return;
                    }
                };

                trace_send
                    .send(TraceEntry::Write {
                        id: id.fetch_add(1, Ordering::Relaxed),
                        address: (addr - ARGS.pmem_start).try_into().unwrap(),
                        size,
                        content: unsafe { from_buf_raw(buf, size) },
                        non_temporal: insn.is_nt(),
                        metadata: metadata(cpu_state, metadata_what),
                    })
                    .expect("failed writing trace");
            },
        );
    }

    if trace_enabled.fence || trace_enabled.flush {
        Callback::new().insn_translate(move |cpu_state: &mut CPUState, pc: target_ptr_t| {
            let insn = match disassemble_at(cpu_state, pc) {
                Ok(insn) => insn,
                Err(err) => {
                    eprintln!("could not disassemble instruction at 0x{:x}: {}", pc, err);
                    return false;
                }
            };

            insn.is_fence() && trace_enabled.fence || insn.is_flush() && trace_enabled.flush
        });
    }

    if trace_enabled.fence || trace_enabled.flush {
        let trace_send = trace_send.clone();
        let id = id.clone();
        Callback::new().insn_exec(move |cpu_state: &mut CPUState, pc: target_ptr_t| {
            let insn = match disassemble_at(cpu_state, pc) {
                Ok(insn) => insn,
                Err(err) => {
                    eprintln!("could not disassemble instruction at 0x{:x}: {}", pc, err);
                    return;
                }
            };

            let mnemonic = format!("{:?}", insn.instr.mnemonic()).to_lowercase();

            if insn.is_fence() {
                if have_writes
                    .compare_exchange(true, false, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    trace_send
                        .send(TraceEntry::Fence {
                            id: id.fetch_add(1, Ordering::Relaxed),
                            mnemonic,
                            metadata: metadata(cpu_state, metadata_what),
                        })
                        .expect("failed writing trace");
                }
            } else if insn.is_flush() {
                have_writes.store(true, Ordering::Relaxed);
                // Record the physical address for cache flushes.
                let address: Option<usize> = if insn.need_va() {
                    if let Some(virtual_addr) = insn.va(cpu_state) {
                        match panda::mem::virt_to_phys(cpu_state, virtual_addr) {
                            Some(physical_addr) => {
                                if physical_addr >= ARGS.pmem_start
                                    && physical_addr < ARGS.pmem_start + ARGS.pmem_len
                                {
                                    Some((physical_addr - ARGS.pmem_start).try_into().unwrap())
                                } else {
                                    // Don't trace flushes outside of the PMEM area.
                                    return;
                                }
                            }
                            None => {
                                eprintln!(
                                    "could not translate memory operand at 0x{:x}: {:?}",
                                    pc,
                                    insn.instr.mnemonic()
                                );
                                return;
                            }
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                trace_send
                    .send(TraceEntry::Flush {
                        id: id.fetch_add(1, Ordering::Relaxed),
                        // wbinvd does not have an address, assume everything else works.
                        address: address.unwrap_or(0),
                        mnemonic,
                        metadata: metadata(cpu_state, metadata_what),
                    })
                    .expect("failed writing trace");
            }
        });
    }

    if trace_enabled.hypercall {
        let trace_send = trace_send.clone();
        Callback::new().guest_hypercall(move |cpu_state: &mut CPUState| {
            let rax = panda::regs::get_reg(cpu_state, PandaReg::RAX);
            if rax & 0xFFFFFFFF != CPUID_HYPERCALL_MAGIC {
                return false;
            }

            let rbx = panda::regs::get_reg(cpu_state, PandaReg::RBX);
            let rcx = panda::regs::get_reg(cpu_state, PandaReg::RCX);
            let action = cpu_state.mem_read_string(rbx);
            let value = cpu_state.mem_read_string(rcx);
            trace_send
                .send(TraceEntry::Hypercall {
                    id: id.fetch_add(1, Ordering::Relaxed),
                    action,
                    value,
                })
                .expect("failed writing trace");
            // return value
            panda::regs::set_reg(cpu_state, PandaReg::RAX, 0);
            // prevent further processing of cpuid
            true
        });
    }

    unsafe {
        if trace_enabled.read || trace_enabled.write {
            panda::sys::panda_enable_memcb();
        }
        if trace_enabled.read || trace_enabled.write || trace_enabled.fence || trace_enabled.flush {
            panda::sys::panda_enable_precise_pc();
        }
    }

    Ok(TracerState {
        writer_thread,
        done_send,
    })
}

fn uninit(state: TracerState) -> Result<()> {
    state.done_send.send(())?;
    state
        .writer_thread
        .join()
        .expect("could not join writer thread");
    Ok(())
}
