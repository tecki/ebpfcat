from struct import pack, unpack

from .ebpf import FuncId, Map, Memory, Opcode, SubProgram
from .bpf import create_map, lookup_elem, MapType, update_elem


class ArrayGlobalVarDesc:
    def __init__(self, map, size, signed):
        self.map = map
        self.signed = signed
        self.size = size
        self.fmt = {1: "B", 2: "H", 4: "I", 8: "Q"}[size]
        if signed:
            self.fmt = self.fmt.lower()

    def __get__(self, ebpf, owner):
        if ebpf is None:
            return self
        position = ebpf.__dict__[self.name]
        if isinstance(ebpf, SubProgram):
            ebpf = ebpf.ebpf
        if ebpf.loaded:
            data = ebpf.__dict__[self.map.name].data[
                    position : position+self.size]
            return unpack(self.fmt, data)[0]
        return Memory(ebpf, Memory.bits_to_opcode[self.size * 8],
                      ebpf.r0 + position, self.signed)

    def __set_name__(self, owner, name):
        self.name = name

    def __set__(self, ebpf, value):
        position = ebpf.__dict__[self.name]
        if isinstance(ebpf, SubProgram):
            ebpf = ebpf.ebpf
        if ebpf.loaded:
            ebpf.__dict__[self.map.name].data[
                    position : position + self.size] = pack(self.fmt, value)
        else:
            getattr(ebpf, f"m{self.size * 8}")[ebpf.r0 + position] = value


class ArrayMapAccess:
    def __init__(self, fd, size):
        self.fd = fd
        self.size = size

    def read(self):
        self.data = lookup_elem(self.fd, b"\0\0\0\0", self.size)

    def write(self):
        update_elem(self.fd, b"\0\0\0\0", self.data, 0)


class ArrayMap(Map):
    def globalVar(self, signed=False, size=4):
        return ArrayGlobalVarDesc(self, size, signed)

    def add_program(self, owner, prog):
        position = getattr(owner, self.name)
        for k, v in prog.__class__.__dict__.items():
            if not isinstance(v, ArrayGlobalVarDesc):
                continue
            prog.__dict__[k] = position
            position = (position + 2 * v.size - 1) & -v.size
        setattr(owner, self.name, position)

    def __set_name__(self, owner, name):
        self.name = name

    def init(self, ebpf):
        setattr(ebpf, self.name, 0)
        self.add_program(ebpf, ebpf)
        for prog in ebpf.subprograms:
            self.add_program(ebpf, prog)
        size = getattr(ebpf, self.name)
        fd = create_map(MapType.ARRAY, 4, size, 1)
        setattr(ebpf, self.name, ArrayMapAccess(fd, size))
        with ebpf.save_registers(list(range(6))), ebpf.get_stack(4) as stack:
            ebpf.append(Opcode.ST, 10, 0, stack, 0)
            ebpf.r1 = ebpf.get_fd(fd)
            ebpf.r2 = ebpf.r10 + stack
            ebpf.call(FuncId.map_lookup_elem)
            with ebpf.If(ebpf.r0 == 0):
                ebpf.exit()
        ebpf.owners.add(0)
