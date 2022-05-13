def parse_trace(input, offset):
    for id_, line in enumerate(input):
        cols = line.rstrip('\n').split(',')
        assert(len(cols) >= 1)
        operation = cols[0]
        if operation == 'write':
            assert(len(cols) == 6)
            assert(cols[4] in ('True', 'False', 'true', 'false'))
            address, size, content, non_temporal = int(cols[1]) - offset, int(cols[2]), bytes.fromhex(cols[3]), cols[4].lower() == 'true'
            metadata = cols[5] if cols[5] else None
            assert(address >= 0)
            yield (operation, id_, address, size, content, non_temporal, metadata)
        elif operation == 'insn':
            assert(len(cols) == 4)
            insn = cols[1]
            address = int(cols[2]) - offset if cols[2] != '' else None
            metadata = cols[3]
            if insn == 'clwb' and address is not None and address < 0:
                continue  # clwb outside of PMEM area
            assert(address is None or address >= 0)
            if insn in ('mfence', 'sfence', 'wbinvd', 'xchg'):
                yield ('fence', id_, metadata)
            elif insn == 'clwb' or insn == 'clflush' or insn == 'clflushopt':
                assert(address is not None)
                yield ('flush', id_, insn, address, metadata)
            else:
                raise Exception(f"unknown instruction {insn}")
        elif operation == 'read':
            assert(len(cols) == 4)
            address, size, content = int(cols[1]) - offset, int(cols[2]), bytes.fromhex(cols[3])
            assert(address >= 0)
            yield (operation, id_, address, size, content)
        elif operation == 'hypercall':
            yield (operation, id_, cols[1], cols[2])
        else:
            raise Exception(f'operation {operation} unsupported')
