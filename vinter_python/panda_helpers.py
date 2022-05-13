from typing import Any, Callable

import pandare  # type: ignore

# This file is licensed under GNU General Public License, version 2, because it reuses code from PANDA (https://github.com/panda-re/panda).
# You should have received a copy of the GNU General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.


def register_syscall_tracer(panda: pandare.Panda, logger: Callable[[str], Any]) -> None:
    # based on https://github.com/panda-re/panda/pull/1016/files commit 4de77e7fab5f157f73da47a3fdb9950c166dce0a
    @panda.ppp('syscalls2', 'on_all_sys_enter2', name='syscall_tracer_enter')
    def all_sys(cpu, pc, call, rp):
        args = panda.ffi.cast('target_ulong**', rp.args)

        log_str = f'on_all_sys_enter2: {pc:#08x} (from block starting at {panda.current_pc(cpu):#08x}): {panda.ffi.string(call.name).decode()}('
        if call.nargs == 0:
            log_str += ')'

        for i in range(call.nargs):
            log_str += f'{panda.ffi.string(call.argn[i]).decode()}='
            sep = ', ' if i != call.nargs - 1 else ')'

            if call.argt[i] not in [0x20, 0x21, 0x22]:
                # ~ val = int(panda.ffi.cast('unsigned int', args[i]))
                val = int(panda.ffi.cast('unsigned long int', args[i]))  # x64
                log_str += hex(val)
            else:
                # ~ addr = int(panda.ffi.cast('unsigned int', args[i]))
                addr = int(panda.ffi.cast('unsigned long int', args[i]))  # x64
                if addr < 0xFFFF:
                    # Probably not a pointer?
                    log_str += hex(addr)
                else:
                    try:
                        mem = panda.virtual_memory_read(cpu, addr, 8)
                    except ValueError:
                        # ignore other args until fault is resolved
                        log_str += f'{addr:#x} => Can\'t read - INJECT PANDA PAGE FAULT\n'

                        # DO FAULT
                        # ~ panda.libpanda.panda_page_fault(cpu, addr, pc)
                        # After fault is handled, we'll then re-run the syscall insn (and the TCG-based callback)
                        break

                    # No fault
                    log_str += f'{addr:#x} => {repr(panda.read_str(cpu, addr))}'

            log_str += sep  # , or )
        else:
            log_str += '\n'
        logger(log_str)

    # based on https://github.com/panda-re/panda/pull/1016/files
    @panda.ppp('syscalls2', 'on_all_sys_return2', name='syscall_tracer_return')
    def all_ret(cpu, pc, call, rp):
        rv = panda.arch.get_return_value(cpu)
        logger(f'on_all_sys_return2: \t\t==> {rv:#x}')


def unregister_syscall_tracer(panda: pandare.Panda) -> None:
    panda.disable_ppp('syscall_tracer_enter')
    panda.disable_ppp('syscall_tracer_return')
