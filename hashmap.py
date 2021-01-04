from contextlib import contextmanager
from struct import pack, unpack, unpack

from .ebpf import AssembleError, Expression, Opcode, Map
from . import bpf


class HashGlobalVar(Expression):
    def __init__(self, ebpf, count, signed):
        self.ebpf = ebpf
        self.count = count
        self.signed = signed

    @contextmanager
    def get_address(self, dst, long, signed, force=False):
        if long:
            raise AssembleError("HashMap is only for words")
        if signed != self.signed:
            raise AssembleError("HashMap variable has wrong signedness")
        with self.ebpf.save_registers([i for i in range(6) if i != dst]), \
                self.ebpf.get_stack(4) as stack:
            self.ebpf.append(Opcode.ST, 10, 0, stack, self.count)
            self.ebpf.r1 = self.ebpf.get_fd(self.fd)
            self.ebpf.r2 = self.ebpf.r10 + stack
            self.ebpf.call(1)
            with self.ebpf.If(self.ebpf.r0 == 0):
                self.ebpf.exit()
            if dst != 0 and force:
                self.ebpf.append(Opcode.MOV + Opcode.LONG + Opcode.REG, dst, 0, 0, 0)
            else:
                dst = 0
        yield dst, Opcode.W


class HashGlobalVarDesc:
    def __init__(self, count, signed, default=0):
        self.count = count
        self.signed = signed
        self.default = default

    def __get__(self, instance, owner):
        if instance is None:
            return self
        if instance.loaded:
            fd = instance.__dict__[self.name].fd
            ret = bpf.lookup_elem(fd, pack("B", self.count), 4)
            return unpack("i" if self.signed else "I", ret)[0]
        ret = instance.__dict__.get(self.name, None)
        if ret is None:
            ret = HashGlobalVar(instance, self.count, self.signed)
            instance.__dict__[self.name] = ret
        return ret

    def __set_name__(self, owner, name):
        self.name = name

    def __set__(self, ebpf, value):
        if ebpf.loaded:
            fd = ebpf.__dict__[self.name].fd
            bpf.update_elem(fd, pack("B", self.count),
                            pack("i" if self.signed else "I", value), 0)
            return
        with ebpf.save_registers([3]):
            with value.get_address(3, False, self.signed, True):
                with ebpf.save_registers([0, 1, 2, 4, 5]), \
                        ebpf.get_stack(4) as stack:
                    ebpf.r1 = ebpf.get_fd(ebpf.__dict__[self.name].fd)
                    ebpf.append(Opcode.ST, 10, 0, stack, self.count)
                    ebpf.r2 = ebpf.r10 + stack
                    ebpf.r4 = 0
                    ebpf.call(2)


class HashMap(Map):
    count = 0

    def __init__(self):
        self.vars = []

    def globalVar(self, signed=False, default=0):
        self.count += 1
        ret = HashGlobalVarDesc(self.count, signed, default)
        self.vars.append(ret)
        return ret

    def init(self, ebpf):
        fd = bpf.create_map(1, 1, 4, self.count)
        for v in self.vars:
            getattr(ebpf, v.name).fd = fd

    def load(self, ebpf):
        for v in self.vars:
            setattr(ebpf, v.name, ebpf.__class__.__dict__[v.name].default)