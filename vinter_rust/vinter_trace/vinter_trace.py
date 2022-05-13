#!/usr/bin/env python3

import argparse
import io
import subprocess
import sys
import tempfile
import time
import yaml
from pathlib import Path
from typing import Any, Callable, ContextManager, Dict, IO, List, Optional

import pandare  # type: ignore

class PersistentMemoryTracer(ContextManager):
    def __init__(self, vm, *, qcow=None):
        self.vm = vm

        if not qcow:
            self.qcow_tmp = tempfile.NamedTemporaryFile(suffix='.qcow2', dir='/var/tmp/')
            qcow = self.qcow_tmp.name
            subprocess.check_call(('qemu-img', 'create', '-f', 'qcow2', self.qcow_tmp.name, '500M'))

        # Resolve paths relative to the VM definition file.
        def relative_path(path):
            p = Path(path)
            if not p.is_absolute():
                return str(vm['basepath'] / p)
            return path

        print('Initializing Panda', flush=True)
        self.panda = pandare.Panda(arch='x86_64',
                                   mem=vm['mem'],
                                   expect_prompt=vm['prompt'],
                                   serial_kwargs={'unansi': False},
                                   qcow=qcow,
                                   extra_args=[
                                       *(vm['qemu_args'] or []),
                                       '-kernel', relative_path(vm['kernel']),
                                       '-initrd', relative_path(vm['initrd']),
                                       '-display', 'none'
                                   ],
                                  )

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        # note that this class is supposed to be used only once in a `with` statement, we currently don't enforce this
        if hasattr(self, 'qcow_tmp'):
            self.qcow_tmp.close()

    def boot(self) -> None:
        @self.panda.queue_blocking
        def run_cmd():
            print("waiting for shell...", flush=True)
            #self.panda.serial_console.set_logging("/dev/stdout")
            self.panda.serial_console.expect(timeout=30)
            self.panda.stop_run()

        # boot without hooks and panda plugins
        print('booting panda...')
        begin = time.perf_counter()
        self.panda.run()
        print(f'TIMING:boot:{time.perf_counter() - begin}')

        # Boot process may have written to pmem memory, zero it to make things
        # more deterministic, and allow for better comparison with trace2img's
        # reconstructed images.
        zero_bytes = b'\0' * 4096
        assert(self.vm['pmem_len'] % 4096 == 0)
        for addr in range(self.vm['pmem_start'], self.vm['pmem_start'] + self.vm['pmem_len'], len(zero_bytes)):
            self.panda.physical_memory_write(addr, zero_bytes)

        self.save_snapshot('boot')

    def load_pmem(self, file: IO[bytes]) -> None:
        page = bytearray(4096)
        addr = self.vm['pmem_start']
        addr_end = self.vm['pmem_start'] + self.vm['pmem_len']
        reader = io.BufferedReader(file)
        while n := reader.readinto(page):
            assert(n == len(page) and addr < addr_end)
            self.panda.physical_memory_write(addr, bytes(page))
            addr += len(page)
        assert(addr == addr_end)

    def save_pmem(self, file: IO[bytes]) -> None:
        n = 4096
        for addr in range(self.vm['pmem_start'], self.vm['pmem_start'] + self.vm['pmem_len'], n):
            page = self.panda.physical_memory_read(addr, n)
            file.write(page)

    # note that this is insecure if "name" can contain control characters such
    # as \n
    def load_snapshot(self, name: str) -> None:
        @self.panda.queue_blocking
        def run_cmd():
            self.panda.revert_sync(name)
            self.panda.stop_run()
        self.panda.run()

    # note that this is insecure if "name" can contain control characters such
    # as \n
    def save_snapshot(self, name: str) -> None:
        @self.panda.queue_blocking
        def run_cmd():
            self.panda.run_monitor_cmd('savevm ' + name)
            self.panda.stop_run()
        self.panda.run()


    def init_tracing(self, trace_out, trace_what, metadata) -> None:
        self.panda.os = 'linux-64-myown'
        self.panda.set_os_name('linux-64-myown')

        self.panda.load_plugin('vinter_trace', {
            'pmem_start': self.vm['pmem_start'],
            'pmem_len': self.vm['pmem_len'],
            'out_trace_file': trace_out,
            'trace': trace_what or 'all',
            'metadata': metadata or 'none',
        })
        # flush translated blocks so that instruction hooks work
        self.panda.flush_tb()

    # for debugging VM interactions
    def interact(self) -> None:
        @self.panda.queue_blocking
        def run_cmd():
            # For some reason, Panda really wants to decode the prompt.
            prompt = self.panda.expect_prompt
            self.panda.expect_prompt = prompt.encode("utf8")
            self.panda.interact()
            self.panda.expect_prompt = prompt
        self.panda.run()

    def run_command(self, cmd: str) -> str:
        serial_output = ''

        @self.panda.queue_blocking
        def run_cmd():
            nonlocal serial_output
            print(f'Running serial cmd: {cmd}')
            serial_output = self.panda.run_serial_cmd(cmd, no_timeout=True)
            print(f'Serial output: ' + serial_output)
            self.panda.stop_run()

        self.panda.run()
        return serial_output


def main() -> int:
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('--qcow', type=str, help='attach the given disk (also used for snapshots)')
    arg_parser.add_argument('--interact', action='store_true', help='interact with serial console for debugging')
    arg_parser.add_argument('--cmd', type=str, help='run a command from the config file')
    arg_parser.add_argument('--run', type=str, help='run an arbitrary command')
    arg_parser.add_argument('--cmd-output', type=argparse.FileType('wb'), help='output file for --cmd or --run output')
    arg_parser.add_argument('--save-snapshot', type=str, help='create a snapshot after running commands')
    arg_parser.add_argument('--load-snapshot', type=str, help='load a snapshot')
    arg_parser.add_argument('--save-pmem', type=argparse.FileType('wb'), help='save PMEM contents after running commands')
    arg_parser.add_argument('--load-pmem', type=argparse.FileType('rb'), help='load PMEM contents')
    arg_parser.add_argument('--trace', type=str, help='enable tracing to the given file')
    arg_parser.add_argument('--trace-what', type=str, help='enable selective tracing. Comma-separated list of: read, write, hypercall, fence, flush')
    arg_parser.add_argument('--metadata', type=str, help='enable metadata. Comma-separated list of: kernel_stacktrace')
    arg_parser.add_argument('config', type=argparse.FileType('r'), help='yaml file with VM configuration')
    args = arg_parser.parse_args()

    config = yaml.safe_load(args.config)
    config['vm']['basepath'] = Path(args.config.name).parent

    with PersistentMemoryTracer(config['vm'], qcow=args.qcow) as tracer:
        if args.load_snapshot:
            print(f"Loading snapshot {args.load_snapshot}")
            tracer.load_snapshot(args.load_snapshot)
        if args.interact:
            tracer.interact()
            return 0
        if not args.load_snapshot:
            tracer.boot()
        if args.load_pmem:
            print(f"Loading PMEM image {args.load_pmem.name}")
            tracer.load_pmem(args.load_pmem)
        if args.trace:
            print(f"Tracing to {args.trace}")
            tracer.init_tracing(args.trace, args.trace_what, args.metadata)
        cmd_output = ''
        if args.cmd:
            try:
                command = config['commands'][args.cmd]
            except:
                print(f"command {args.cmd} not defined in config file")
                return 1
            cmd_output += tracer.run_command(command)
        if args.run:
            cmd_output += tracer.run_command(args.run)
        if args.cmd_output:
            print(f"Writing output file {args.cmd_output.name}")
            args.cmd_output.write(cmd_output.encode('utf8'))
            args.cmd_output.close()
        if args.save_snapshot:
            print(f"Saving snapshot {args.save_snapshot}")
            tracer.save_snapshot(args.save_snapshot)
        if args.save_pmem:
            print(f"Saving PMEM image {args.save_pmem.name}")
            tracer.save_pmem(args.save_pmem)
            args.save_pmem.close()

    return 0

if __name__ == '__main__':
    sys.exit(main())
