//! Functions for disassembling relevant instructions.

use anyhow::{anyhow, bail, Result};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, Register};
use panda::prelude::*;
use panda::regs::Reg as PandaReg;

// https://stackoverflow.com/a/14698559/1543768
const X64_MAX_INSN_LEN: usize = 15;

pub struct DisassembledInsn {
    pub instr: Instruction,
}

impl DisassembledInsn {
    /// Return whether the instruction is non-temporal.
    pub fn is_nt(&self) -> bool {
        matches!(
            self.instr.mnemonic(),
            Mnemonic::Movntdq
                | Mnemonic::Movntdqa
                | Mnemonic::Movnti
                | Mnemonic::Movntpd
                | Mnemonic::Movntps
                | Mnemonic::Movntq
                | Mnemonic::Movntsd
                | Mnemonic::Movntss
        )
    }

    /// Return whether the instruction is a cache flush.
    pub fn is_flush(&self) -> bool {
        matches!(
            self.instr.mnemonic(),
            Mnemonic::Clflush | Mnemonic::Clflushopt | Mnemonic::Clwb | Mnemonic::Wbinvd
        )
    }

    /// Return whether the instruction is a memory fence.
    pub fn is_fence(&self) -> bool {
        matches!(
            self.instr.mnemonic(),
            Mnemonic::Mfence | Mnemonic::Sfence | Mnemonic::Xchg
        )
    }

    /// Do we need the virtual address for this instruction?
    pub fn need_va(&self) -> bool {
        matches!(
            self.instr.mnemonic(),
            Mnemonic::Clflush | Mnemonic::Clflushopt | Mnemonic::Clwb
        )
    }

    pub fn va(&self, cpu: &mut CPUState) -> Option<u64> {
        self.instr
            .virtual_address(0, 0, |register, _element_index, _element_size| {
                match register {
                    // The base address of ES, CS, SS and DS is always 0 in 64-bit mode
                    Register::ES | Register::CS | Register::SS | Register::DS => Some(0),
                    reg => match reg {
                        Register::RAX => Some(PandaReg::RAX),
                        Register::RCX => Some(PandaReg::RCX),
                        Register::RDX => Some(PandaReg::RDX),
                        Register::RBX => Some(PandaReg::RBX),
                        Register::RSP => Some(PandaReg::RSP),
                        Register::RBP => Some(PandaReg::RBP),
                        Register::RSI => Some(PandaReg::RSI),
                        Register::RDI => Some(PandaReg::RDI),
                        Register::R8 => Some(PandaReg::R8),
                        Register::R9 => Some(PandaReg::R9),
                        Register::R10 => Some(PandaReg::R10),
                        Register::R11 => Some(PandaReg::R11),
                        Register::R12 => Some(PandaReg::R12),
                        Register::R13 => Some(PandaReg::R13),
                        Register::R14 => Some(PandaReg::R14),
                        Register::R15 => Some(PandaReg::R15),
                        _ => None,
                    }
                    .map(|r| panda::regs::get_reg(cpu, r)),
                }
            })
    }
}

pub fn disassemble_at(cpu: &mut CPUState, pc: target_ptr_t) -> Result<DisassembledInsn> {
    //let mem = cpu.mem_read(pc, X64_MAX_INSN_LEN);
    let mem = panda::mem::virtual_memory_read(cpu, pc, X64_MAX_INSN_LEN)
        .map_err(|err| anyhow!("reading code at 0x{:x} failed: {:?}", pc, err))?;
    let mut decoder = Decoder::new(64, &mem, DecoderOptions::NONE);
    let instr = decoder.decode();
    if instr.is_invalid() {
        bail!(
            "could not disassemble at {}: {:?}",
            pc,
            decoder.last_error()
        );
    }

    Ok(DisassembledInsn { instr })
}
