from struct import pack, unpack

from .ebpf import Map, Memory, Opcode
from . import bpf


class ArrayGlobalVarDesc:
    def __init__(self, map, position, size, signed):
        self.map = map
        self.position = position
        self.signed = signed
        self.size = size
        self.fmt = {1: "B", 2: "H", 4: "I", 8: "Q"}[size]
        if signed:
            self.fmt = self.fmt.lower()

    def __get__(self, ebpf, owner):
        if ebpf is None:
            return self
        if ebpf.loaded:
            data = ebpf.__dict__[self.map.name].data[
                    self.position:self.position + self.size]
            return unpack(self.fmt, data)[0]
        return Memory(ebpf, Memory.bits_to_opcode[self.size * 8],
                      ebpf.r0 + self.position, self.signed)

    def __set_name__(self, owner, name):
        self.name = name

    def __set__(self, ebpf, value):
        if ebpf.loaded:
            ebpf.__dict__[self.map.name].data[
                    self.position:self.position + self.size] = \
                            pack(self.fmt, value)
        else:
            getattr(ebpf, f"m{self.size * 8}")[ebpf.r0 + self.position] = value


class ArrayMapAccess:
    def __init__(self, fd, size):
        self.fd = fd
        self.size = size

    def read(self):
        self.data = bpf.lookup_elem(self.fd, b"\0\0\0\0", self.size)

    def write(self):
        bpf.update_elem(self.fd, b"\0\0\0\0", self.data, 0)


class ArrayMap(Map):
    position = 0

    def __init__(self):
        self.vars = []

    def globalVar(self, signed=False, size=4):
        ret = ArrayGlobalVarDesc(self, self.position, size, signed)
        self.position = (self.position + 2 * size - 1) & -size
        self.vars.append(ret)
        return ret

    def __set_name__(self, owner, name):
        self.name = name

    def init(self, ebpf):
        fd = bpf.create_map(2, 4, self.position, 1)
        setattr(ebpf, self.name, ArrayMapAccess(fd, self.position))
        with ebpf.save_registers(list(range(6))), ebpf.get_stack(4) as stack:
            ebpf.append(Opcode.ST, 10, 0, stack, 0)
            ebpf.r1 = ebpf.get_fd(fd)
            ebpf.r2 = ebpf.r10 + stack
            ebpf.call(1)
            with ebpf.If(ebpf.r0 == 0):
                ebpf.exit()
        ebpf.owners.add(0)
