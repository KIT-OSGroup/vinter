#!/usr/bin/env python3
import argparse
import collections
import json
import re
import subprocess
import time
import yaml
from pathlib import Path
from typing import Any, Callable, ContextManager, Dict, IO, List, Optional

# DO NOT use capstone from Ubuntu 20.04's python3-capstone package, it doesn't disassemble clwb and clflushopt correctly!
import capstone  # type: ignore
import sortedcontainers  # type: ignore
import tempfile

import pandare  # type: ignore
from panda_helpers import register_syscall_tracer, unregister_syscall_tracer


DisassembledInsn = collections.namedtuple('DisassembledInsn', 'mnemonic, op_str')
#import cProfile
# profile_pmem_write = cProfile.Profile()


class PersistentMemoryTracer(ContextManager):
    CPUID_HYPERCALL_MAGIC = 0x40000000  # see hypercall.c
    X64_MAX_INSN_LEN = 15  # https://stackoverflow.com/a/14698559/1543768

    debug_file: Optional[IO[str]]
    pmem_start: int  # physical address
    pmem_length: int
    panda: pandare.Panda
    disas_cache: Dict[int, DisassembledInsn]  # maps physical address to DisassembledInsn
    # TODO ^ Does not consider changing memory/code. For a correct implementation, we should probably clean this after basic block flushes etc.
    #        (though for hooking probably not necessary, as our post-instruction-execution hook is only called if we have trapped a wanted instruction)
    trace_out: IO[Any]
    trace_metadata: bool
    _tracing: bool
    _hypercall_callback: Optional[Callable[[str, str], None]] = None  # _hypercall_callback(action, value); a bit of a hack because we currently don't expose a general way to get callbacks other than tracing to file (trace_out)

    def __init__(self, *, trace_out: IO[Any], vm, debug_file: Optional[IO[str]] = None, trace_metadata=False) -> None:
        self.qcow_tmp = tempfile.NamedTemporaryFile(suffix='.qcow2', dir='/var/tmp/')
        subprocess.check_call(('qemu-img', 'create', '-f', 'qcow2', self.qcow_tmp.name, '500M'))

        # Resolve paths relative to the VM definition file.
        def relative_path(path):
            p = Path(path)
            if not p.is_absolute():
                return str(vm['basepath'] / p)
            return path

        self.panda = pandare.Panda(arch='x86_64',
                                   mem=vm['mem'],
                                   expect_prompt=vm['prompt'],
                                   serial_kwargs={'unansi': False},
                                   qcow=self.qcow_tmp.name,
                                   extra_args=[
                                       *(vm['qemu_args'] or []),
                                       '-kernel', relative_path(vm['kernel']),
                                       '-initrd', relative_path(vm['initrd']),
                                       '-display', 'none'
                                   ],
                                  )
        self.pmem_start = vm['pmem_start']
        self.pmem_length = vm['pmem_len']
        self.debug_file = debug_file
        self.X64_REGISTERS = list(map(str.lower, self.panda.arch.registers.keys()))
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.disas_cache = {}  # maps physical address to DisassembledInsn
        self.trace_out = trace_out
        self.trace_metadata = trace_metadata
        self._tracing = False

        # kallsyms
        if (debug_file or trace_metadata) and not 'system_map' in vm:
            raise Exception('must set vm.system_map when passing debug_file or trace_metadata')
        if 'system_map' in vm:
            with open(relative_path(vm['system_map'])) as f:
                self.kallsyms = sortedcontainers.SortedDict([(int((s := l.split(' ', 1))[0], 16), s[1]) for l in f.read().splitlines()])

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        # note that this class is supposed to be used only once in a `with` statement, we currently don't enforce this
        self.qcow_tmp.close()

    def _debug(self, msg: object) -> None:
        # We have a large volume of debug messages, and Python logging appears to be very slow, even with
        # logging.handlers.MemoryHandler with large in-memory cache (and no flushing in between),
        # our execution time can be 2x the one with print to file
        print(msg, file=self.debug_file)

    def boot(self) -> None:
        @self.panda.queue_blocking
        def run_cmd():
            self.panda.serial_console.expect(timeout=None)  # wait for shell to load
            self.panda.stop_run()

        begin = time.perf_counter()
        self.panda.run(unload_plugins=False)
        print(f'TIMING:boot:{time.perf_counter() - begin}')

        # Boot process may have written to pmem memory, zero it to make things more deterministic, and allow for better comparison with trace2img's reconstructed images.
        self.panda.physical_memory_write(self.pmem_start, b'\0' * self.pmem_length)

        self.save_snapshot('boot')

    def init_plugins_hooks(self) -> None:
        if self.debug_file:
            self.panda.load_plugin('callstack_instr')
        # callstack_instr loads "osi" plugin if OS family is set; we currently don't provide the required files, so we first load the plugin and *then* set the OS family (instead of setting os_version in Panda's constructor) so that syscalls2 works.
        self.panda.os = 'linux-64-myown'
        self.panda.set_os_name('linux-64-myown')
        if self.debug_file:
            self.panda.load_plugin('syscalls2', {'load-info': True}) # this slows down execution even if we don't define syscalls2 callbacks
        self._register_hooks()
        self.panda.flush_tb()  # dismiss translated blocks because later we want to hook certain instructions, also because we enable precise pc below
        self.panda.enable_precise_pc()

    def load_snapshot(self, name: str) -> None:  # note that this is insecure if "name" can contain control characters such as \n
        def run_cmd():
            self.panda.revert_sync(name)
            self.panda.stop_run()
        self.panda.queue_blocking(run_cmd)
        self.panda.run(unload_plugins=False)

    def save_snapshot(self, name: str) -> None:  # note that this is insecure if "name" can contain control characters such as \n
        def run_cmd():
            self.panda.run_monitor_cmd('savevm ' + name)
            self.panda.stop_run()
        self.panda.queue_blocking(run_cmd)
        self.panda.run(unload_plugins=False)

    def load_pmem_image(self, content: bytes) -> None:
        if len(content) > self.pmem_length:
            raise ValueError('content longer than pmem')
        self.panda.physical_memory_write(self.pmem_start, content)

    def get_kernel_symbol(self, address: int) -> str:
        # TODO handle multiple symbols with same address
        # TODO bug when address is very small (i.e. < first entry), then it chooses last entry
        return self.kallsyms.peekitem(self.kallsyms.bisect_right(address) - 1)[1]

    def disas_physical_address(self, physical_address: int, size: int = X64_MAX_INSN_LEN) -> DisassembledInsn:
        # TODO this function breaks if the virtual address range crosses a page boundary. We would need to be passed the virtual address to fix it (to read from 2 physical pages). (We currently have assertions in place in callees of disas_physical_address.)

        insn = self.disas_cache.get(physical_address)
        if not insn:
            mem = b''
            try:
                mem = self.panda.physical_memory_read(physical_address, size)
                _, _, mnemonic, op_str = next(self.cs.disasm_lite(mem, 0))
                insn = DisassembledInsn(mnemonic, op_str)
                # (note that if we use the on_after callback, the above code might be wrong for self-modifying code)
            except StopIteration:
                # rdpkru and wrpkru not supported by capstone: https://github.com/aquynh/capstone/issues/1076
                if mem == b'\x0f\x01\xee':
                    insn = DisassembledInsn('rdpkru', '')
                elif mem == b'\x0f\x01\xef':
                    insn = DisassembledInsn('wrpkru', '')
                elif mem == b'\xf3\x48\x0f\x1e\xc8': # Intel CET will be in capstone v5 (#1346)
                    insn = DisassembledInsn('rdsspq', 'rax')
                elif mem == b'\xf3\x48\x0f\x1e\xce':
                    insn = DisassembledInsn('rdsspq', 'rsi')
                else:
                    raise RuntimeError(f'could not disassemble instruction: {mem.hex() if mem else "not mem"}')
            self.disas_cache[physical_address] = insn
        return insn

    def _metadata_str(self, cpu_state) -> str:
        if self.trace_metadata:
            kernel_symbol = self.get_kernel_symbol(cpu_state.panda_guest_pc)
            callstack_str = self._possibly_return_callstack(kernel_symbol, cpu_state) or '' if self.debug_file else ''
            callstack_str = callstack_str.replace('\n', ' -> ').replace(',', '،')
            return f'{self.panda.in_kernel_code_linux(cpu_state)}!{kernel_symbol}!{callstack_str}'
        else:
            return ''

    def _possibly_return_callstack(self, kernel_symbol, cpu_state) -> Optional[str]:  # TODO refactor + rename
        symbol = kernel_symbol.split(' ', maxsplit=1)[1]
        callers = self.panda.callstack_callers(20, cpu_state)
        return str([(f'{c:#x}', self.get_kernel_symbol(c)) for c in callers])

    def _register_hooks(self) -> None:
        @self.panda.hook_phys_mem_write(start_address=self.pmem_start, end_address=(self.pmem_start + self.pmem_length), on_before=False, on_after=True)  # end_address appears to be exclusive
        # if we would use on_before=True, it sounds like it would also be called in case of unsuccessful writes -- not sure if this would a problem for us
        def pmem_write(cpu_state, memory_access_desc):
            if not self._tracing:  # workaround as memory callbacks currently can't be properly disabled
                return

            # profile_pmem_write.enable()
            pc = cpu_state.panda_guest_pc  # available because of `self.panda.enable_precise_pc()` (`self.panda.arch.get_pc(cpu_state)` would be imprecise pc)
            physical_pc = self.panda.virt_to_phys(cpu_state, pc)
            # TODO check physical_pc for -1 (also in other places where we use virt_to_phys)
            insn = self.disas_physical_address(physical_pc)
            if physical_pc // 4096 != (physical_pc + self.X64_MAX_INSN_LEN - 1) // 4096 and \
                    physical_pc // 4096 != self.panda.virt_to_phys(cpu_state, pc + self.X64_MAX_INSN_LEN - 1) // 4096 - 1:
                breakpoint()  # bug in disas_physical_address triggered: page boundary crossed but not consecutively mapped to physical memory (we should read from virtual memory instead and let panda handle the rest)
            mnemonic = insn.mnemonic
            if self.debug_file:
                insn_str = f'{mnemonic} {insn.op_str}'
                kernel_symbol = self.get_kernel_symbol(pc)
                self._debug(f'write from {pc:#x} to {memory_access_desc.addr:#x} size {memory_access_desc.size} insn `{insn_str}` in_kernel_code_linux={self.panda.in_kernel_code_linux(cpu_state)} content {bytes(memory_access_desc.buf[0:memory_access_desc.size])!r}{" " + kernel_symbol if self.panda.in_kernel_code_linux(cpu_state) else ""}')
                if callstack := self._possibly_return_callstack(kernel_symbol, cpu_state):
                    self._debug(callstack)

            non_temporal = mnemonic in ('movnti', 'movntqi', 'movntdq', 'movntps', 'movntpd')
            # TODO there are other non-temporal instructions like MOVNTDQA, vmovntdq(a), MOVDIR64B etc.
            # MOVDIR64B has guarantees for 64 byte atomicity; but panda doesn't support this insn anyway (see https://groups.google.com/g/pmem/c/6_5daOuEI00/m/hG8xsnXCCAAJ)
            if self.debug_file and not non_temporal and 'nt' in mnemonic:
                breakpoint()
                raise RuntimeError(f'possible NT instruction that we missed hooking? {mnemonic}')

            metadata_str = self._metadata_str(cpu_state)
            print(f'write,{memory_access_desc.addr},{memory_access_desc.size},{bytes(memory_access_desc.buf[0:memory_access_desc.size]).hex()},{non_temporal},{metadata_str}', file=self.trace_out)


        @self.panda.hook_phys_mem_read(start_address=self.pmem_start, end_address=(self.pmem_start + self.pmem_length), on_before=False, on_after=True)  # end_address appears to be exclusive
        def pmem_read(cpu_state, memory_access_desc):
            if not self._tracing:  # workaround as memory callbacks currently can't be properly disabled
                return
            print(f'read,{memory_access_desc.addr},{memory_access_desc.size},{bytes(memory_access_desc.buf[0:memory_access_desc.size]).hex()}', file=self.trace_out)

            if self.debug_file:
                insn = self.disas_physical_address(self.panda.virt_to_phys(cpu_state, cpu_state.panda_guest_pc))
                if cpu_state.panda_guest_pc // 4096 != (cpu_state.panda_guest_pc + self.X64_MAX_INSN_LEN - 1) // 4096 and \
                        self.panda.virt_to_phys(cpu_state, cpu_state.panda_guest_pc) // 4096 != self.panda.virt_to_phys(cpu_state, cpu_state.panda_guest_pc + self.X64_MAX_INSN_LEN - 1) // 4096 - 1:
                    breakpoint()  # bug in disas_physical_address triggered: page boundary crossed but not consecutively mapped to physical memory (we should read from virtual memory instead and let panda handle the rest)

                insn_str = f'{insn.mnemonic} {insn.op_str}'
                kernel_symbol = self.get_kernel_symbol(cpu_state.panda_guest_pc)
                self._debug(f'read from {cpu_state.panda_guest_pc:#x} to {memory_access_desc.addr:#x} size {memory_access_desc.size} insn `{insn_str}` in_kernel_code_linux={self.panda.in_kernel_code_linux(cpu_state)} content {bytes(memory_access_desc.buf[0:memory_access_desc.size])!r}{" " + kernel_symbol if self.panda.in_kernel_code_linux(cpu_state) else ""}')
                if callstack := self._possibly_return_callstack(kernel_symbol, cpu_state):
                    self._debug(callstack)


        # @self.panda.cb_insn_translate(enabled=False)
        # def pmem_insn_translate(cpu_state, pc):
        #     self.pc_before_translate = pc
        #     return False


        # we leave pmem_after_insn_translate enabled, see comment in self.perform_trace
        @self.panda.cb_after_insn_translate(enabled=True)
        def pmem_after_insn_translate(cpu_state, pc, previous_pc):
            # note that this is probably not called for jump instructions (which we don't care about anyway)
            # assert(self.pc_before_translate == previous_pc)  # appears successful
            physical_previous_pc = self.panda.virt_to_phys(cpu_state, previous_pc)
            assert(pc > previous_pc)
            insn = self.disas_physical_address(physical_previous_pc, pc - previous_pc)

            if physical_previous_pc // 4096 != (physical_previous_pc + pc - previous_pc - 1) // 4096 and \
                    physical_previous_pc // 4096 != self.panda.virt_to_phys(cpu_state, pc - 1) // 4096 - 1:
                breakpoint()  # bug in disas_physical_address triggered: page boundary crossed but not consecutively mapped to physical memory (we should read from virtual memory instead and let panda handle the rest)

            # TODO support instruction prefixes such as LOCK and support LOCK-prefixed instructions
            # TODO INVD would need to be hooked as it clears caches without writing back
            if insn.mnemonic in ('clflush', 'clflushopt', 'clwb', 'mfence', 'sfence', 'wbinvd', 'xchg'):
                if self.debug_file:
                    self._debug(f'hooked `{insn.mnemonic} {insn.op_str}` at {pc:#x} {self.get_kernel_symbol(pc)}')
                return True

            return False

        byte_ptr_regex = re.compile(r'^byte ptr \[(' + '|'.join(map(re.escape, self.X64_REGISTERS)) + r')(?: \+ (' + '|'.join(map(re.escape, self.X64_REGISTERS)) + r'))?\]$')  # TODO reimplement properly with capstone

        @self.panda.cb_after_insn_exec(enabled=False)
        def pmem_after_insn_exec(cpu_state, pc, previous_pc):
            insn = self.disas_cache[self.panda.virt_to_phys(cpu_state, previous_pc)]
            operand_str = ''
            physical_address = ''

            if insn.mnemonic not in ('mfence', 'sfence', 'wbinvd', 'xchg'):
                match = byte_ptr_regex.match(insn.op_str)
                # capstone (at least the C API) does have an API for this: https://github.com/aquynh/capstone/blob/c72fc8185ed4088c3486f621d150fbcf5f980aa0/include/capstone/capstone.h#L288 https://github.com/aquynh/capstone/blob/c72fc8185ed4088c3486f621d150fbcf5f980aa0/include/capstone/x86.h#L312 https://github.com/aquynh/capstone/blob/c72fc8185ed4088c3486f621d150fbcf5f980aa0/include/capstone/x86.h#L267
                if not match:
                    raise RuntimeError(f'FIXME insn did not match regex: {insn.mnemonic} {insn.op_str}')
                virtual_address = self.panda.arch.get_reg(cpu_state, match[1])
                if match[2] is not None:
                    virtual_address += self.panda.arch.get_reg(cpu_state, match[2])
                physical_address = self.panda.virt_to_phys(cpu_state, virtual_address)
                operand_str = f', rax={virtual_address:#x}, phys={physical_address:#x}'
            metadata_str = self._metadata_str(cpu_state)

            print(f'insn,{insn.mnemonic},{physical_address},{metadata_str}', file=self.trace_out)

            if self.debug_file:
                kernel_symbol = self.get_kernel_symbol(pc)
                self._debug(f'cb_after_insn_exec {pc:#x} `{insn.mnemonic} {insn.op_str}`{operand_str} in_kernel_code_linux={self.panda.in_kernel_code_linux(cpu_state)}{" " + kernel_symbol if self.panda.in_kernel_code_linux(cpu_state) else ""}')
                if callstack := self._possibly_return_callstack(kernel_symbol, cpu_state):
                    self._debug(callstack)

            return False


        @self.panda.cb_guest_hypercall(enabled=False)
        def guest_hypercall(cpu_state):
            assert self._tracing or self._hypercall_callback
            if (rax := self.panda.arch.get_reg(cpu_state, 'rax') & 0xFFFFFFFF) != PersistentMemoryTracer.CPUID_HYPERCALL_MAGIC:
                if self.debug_file:
                    self._debug(f'guest_hypercall: cpuid with rax={rax}, ignoring')
                return False

            rbx = self.panda.arch.get_reg(cpu_state, 'rbx')
            rcx = self.panda.arch.get_reg(cpu_state, 'rcx')
            action = self.panda.read_str(cpu_state, rbx)
            value = self.panda.read_str(cpu_state, rcx)
            if self._tracing:
                print(f'hypercall,{action},{value}', file=self.trace_out)
            if self._hypercall_callback:
                self._hypercall_callback(action, value)
            self.panda.arch.set_reg(cpu_state, 'rax', 0)  # return value
            return True  # prevent further processing of cpuid

        # don't run self.panda.disable_memcb() memcbs, because otherwise newly translated blocks don't include memory
        # callbacks and we would have to flush the entire translation cache when reenabling them

    def perform_trace(self, cmd: str, hypercall_callback: Callable[[str, str], None] = None) -> str:
        self._tracing = True
        self.panda.enable_all_callbacks()
        self.panda.enable_memcb()
        if self.debug_file:
            register_syscall_tracer(self.panda, self._debug)

        try:
            return self.run_without_tracing(cmd, hypercall_callback=hypercall_callback)
        finally:
            self._tracing = False
            if self.debug_file:
                unregister_syscall_tracer(self.panda)
            self.panda.disable_all_callbacks()
            # We leave pmem_after_insn_translate enabled, because otherwise we would need to flush_tb() when running a
            # trace again
            self.panda.enable_callback('pmem_after_insn_translate')

            # TODO currently, memory hooks with mem_hooks can't be disabled (applies to pmem_write, pmem_read)
            #      We could run self.panda.disable_memcb and then self.panda.flush_tb, however that would be relatively
            #      expensive. flush_tb would also need to be called after reenabling memory callbacks.

    def run_without_tracing(self, cmd: str, hypercall_callback: Callable[[str, str], None] = None) -> str:
        serial_output = ''

        @self.panda.queue_blocking
        def run_cmd():
            nonlocal serial_output
            if self.debug_file:
                self._debug(f'Running serial cmd: {cmd}')
            serial_output = self.panda.run_serial_cmd(cmd, no_timeout=True)
            if self.debug_file:
                self._debug(f'Serial output: ' + serial_output)
            self.panda.stop_run()

        if hypercall_callback:
            assert self._hypercall_callback is None
            self._hypercall_callback = hypercall_callback
            self.panda.enable_callback('guest_hypercall')

        try:
            self.panda.run(unload_plugins=False)
        finally:
            if hypercall_callback:
                self._hypercall_callback = None
                self.panda.disable_callback('guest_hypercall')
        return serial_output


def main() -> None:
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('--vm', type=argparse.FileType('r'), required=True)
    arg_parser.add_argument('--trace-out', type=argparse.FileType('w', 2**20), required=True)
    arg_parser.add_argument('--checkpoint-mem-prefix')
    arg_parser.add_argument('--trace-metadata', action='store_true')
    arg_parser.add_argument('--debug', '-d', type=argparse.FileType('w'))
    arg_parser.add_argument('trace_cmd')
    args = arg_parser.parse_args()

    config = yaml.safe_load(args.vm)
    config['vm']['basepath'] = Path(args.vm.name).parent

    with args.trace_out, \
            PersistentMemoryTracer(trace_out=args.trace_out, debug_file=args.debug, trace_metadata=args.trace_metadata,
                                   vm=config['vm']) as tracer:
        tracer.boot()
        tracer.init_plugins_hooks()

        def dump_pmem(file) -> None:
            file.write(tracer.panda.physical_memory_read(tracer.pmem_start, tracer.pmem_length))

        def hypercall_checkpoint_dump(action: str, value: str) -> None:
            if action == 'checkpoint':
                with open(args.checkpoint_mem_prefix + value, 'wb') as f:
                    dump_pmem(f)

        begin = time.perf_counter()
        print(tracer.perform_trace(args.trace_cmd, hypercall_callback=hypercall_checkpoint_dump))
        print(f'TIMING:trace:{time.perf_counter() - begin}')


if __name__ == '__main__':
    main()
