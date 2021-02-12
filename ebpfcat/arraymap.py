from struct import pack_into, unpack_from, calcsize

from .ebpf import FuncId, Map, Memory, MemoryDesc, Opcode
from .bpf import create_map, lookup_elem, MapType, update_elem


class ArrayGlobalVarDesc(MemoryDesc):
    base_register = 0

    def __init__(self, map, fmt):
        self.map = map
        self.fmt = fmt

    def fmt_addr(self, ebpf):
        return self.fmt, ebpf.__dict__[self.name]

    def __set_name__(self, owner, name):
        self.name = name

    def __get__(self, instance, owner):
        if instance is None:
            return self
        fmt, addr = self.fmt_addr(instance)
        if instance.ebpf.loaded:
            data = instance.ebpf.__dict__[self.map.name].data
            return unpack_from(fmt, data, addr)[0]
        else:
            return super().__get__(instance, owner)

    def __set__(self, instance, value):
        fmt, addr = self.fmt_addr(instance)
        if instance.ebpf.loaded:
            pack_into(fmt, instance.ebpf.__dict__[self.map.name].data,
                      addr, value)
        else:
            super().__set__(instance, value)


class ArrayMapAccess:
    def __init__(self, fd, size):
        self.fd = fd
        self.size = size

    def read(self):
        self.data = lookup_elem(self.fd, b"\0\0\0\0", self.size)

    def write(self):
        update_elem(self.fd, b"\0\0\0\0", self.data, 0)


class ArrayMap(Map):
    def globalVar(self, fmt="I"):
        return ArrayGlobalVarDesc(self, fmt)

    def add_program(self, owner, prog):
        position = getattr(owner, self.name)
        for k, v in prog.__class__.__dict__.items():
            if not isinstance(v, ArrayGlobalVarDesc):
                continue
            prog.__dict__[k] = position
            size = calcsize(v.fmt)
            position = (position + 2 * size - 1) & -size
        setattr(owner, self.name, position)

    def __set_name__(self, owner, name):
        self.name = name

    def init(self, ebpf):
        setattr(ebpf, self.name, 0)
        self.add_program(ebpf, ebpf)
        for prog in ebpf.subprograms:
            self.add_program(ebpf, prog)
        size = getattr(ebpf, self.name)
        if not size:  # nobody is actually using the map
            return
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
