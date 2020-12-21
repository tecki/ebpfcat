from collections import namedtuple
from struct import pack

from .bpf import prog_load

Instruction = namedtuple("Instruction",
                         ["opcode", "dst", "src", "off", "imm"])

def augassign(opcode):
    def ret(self, value):
        if isinstance(value, int):
            return Instruction(opcode + 3 * self.long, self.no, 0, 0, value)
        elif isinstance(value, Register) and self.long == value.long:
            return Instruction(opcode + 8 + 3 * self.long,
                               self.no, value.no, 0, 0)
        else:
            return NotImplemented
    return ret


def comparison(uposop, unegop, sposop=None, snegop=None):
    def ret(self, value):
        if self.signed and sposop is not None:
            return Comparison(self.no, value, sposop, snegop)
        else:
            return Comparison(self.no, value, uposop, unegop)
    return ret


class Comparison:
    def __init__(self, dst, src, posop, negop):
        self.dst = dst
        self.src = src
        self.posop = posop
        self.negop = negop

    def target(self):
        assert self.ebpf.opcodes[self.origin] is None
        if isinstance(self.src, int):
            inst = Instruction(
                self.opcode, self.dst, 0,
                len(self.ebpf.opcodes) - self.origin - 1, self.src)
        elif isinstance(self.src, Register):
            inst = Instruction(
                self.opcode + 8, self.dst, self.src.no,
                len(self.ebpf.opcodes) - self.origin - 1, 0)
        else:
            return NotImplemented
        self.ebpf.opcodes[self.origin] = inst

    def __enter__(self):
        self.origin = len(self.ebpf.opcodes)
        self.ebpf.opcodes.append(None)
        return self

    def __exit__(self, exc_type, exc, tb):
        self.target()

    def Else(self):
        op, dst, src, off, imm = self.ebpf.opcodes[self.origin]
        self.ebpf.opcodes[self.origin] = Instruction(op, dst, src, off+1, imm)
        self.src = self.dst = 0
        self.opcode = 5
        return self


class Sum:
    def __init__(self, no, offset):
        self.no = no
        self.offset = offset

    def __add__(self, value):
        if isinstance(value, int):
            return Sum(self.no, self.offset + value)
        else:
            return NotImplemented

    __radd__ = __add__

    def __sub__(self, value):
        if isinstance(value, int):
            return Sum(self.no, self.offset - value)
        else:
            return NotImplemented


class Register:
    offset = 0

    def __init__(self, no, ebpf, long, signed):
        self.no = no
        self.ebpf = ebpf
        self.long = long
        self.signed = signed

    __iadd__ = augassign(4)
    __isub__ = augassign(0x14)
    __imul__ = augassign(0x24)
    __itruediv__ = augassign(0x34)
    __ior__ = augassign(0x44)
    __iand__ = augassign(0x54)
    __ilshift__ = augassign(0x64)
    __imod__ = augassign(0x94)
    __ixor__ = augassign(0xa4)

    def __irshift__(self, value):
        if isinstance(value, int):
            return Instruction(0x74 + 3 * self.long + 0x50 * self.signed,
                               self.no, 0, 0, value)
        elif isinstance(value, Register) and self.long == value.long:
            return Instruction(0x7c + 3 * self.long + 0x50 * self.signed,
                               self.no, value.no, 0, 0)
        else:
            return NotImplemented

    def __add__(self, value):
        if isinstance(value, int) and self.long:
            return Sum(self.no, value)
        else:
            return NotImplemented

    __radd__ = __add__

    def __sub__(self, value):
        if isinstance(value, int) and self.long:
            return Sum(self.no, -value)
        else:
            return NotImplemented

    __eq__ = comparison(0x15, 0x55)
    __gt__ = comparison(0x25, 0xb5, 0x65, 0xd5)
    __ge__ = comparison(0x35, 0xa5, 0x75, 0xc5)
    __lt__ = comparison(0xa5, 0x35, 0xc5, 0x75)
    __le__ = comparison(0xb5, 0x25, 0xd5, 0x65)
    __ne__ = comparison(0x55, 0x15)
    __and__ = __rand__ = comparison(0x45, None)


class Memory:
    def __init__(self, ebpf, bits):
        self.ebpf = ebpf
        self.bits = bits

    def __setitem__(self, addr, value):
        if isinstance(value, int):
            self.ebpf.append(0x62 + self.bits, addr.no, 0, addr.offset, value)
        elif isinstance(value, Register):
            self.ebpf.append(0x63 + self.bits, addr.no, value.no,
                             addr.offset, 0)
        else:
            raise RuntimeError("cannot compile")

    def __getitem__(self, addr):
        ret = addr + 0
        ret.bits = self.bits
        return ret


class RegisterDesc:
    def __init__(self, no, long, signed=False):
        self.no = no
        self.long = long
        self.signed = signed

    def __get__(self, instance, owner=None):
        if instance is None:
            return self
        else:
            return Register(self.no, instance, self.long, self.signed)

    def __set__(self, instance, value):
        if isinstance(value, int):
            instance.append(0xb4 + 3 * self.long, self.no, 0, 0, value)
        elif isinstance(value, Register) and self.long == value.long:
            instance.append(0xbc + 3 * self.long, self.no, value.no, 0, 0)
        elif isinstance(value, Sum) and self.long:
            instance.append(0x61 + value.bits, self.no, value.no,
                            value.offset, 0)
        elif isinstance(value, Instruction):
            instance.opcodes.append(value)
        else:
            raise RuntimeError("cannot compile")
        

class EBPF:
    def __init__(self, prog_type=0, license="", kern_version=0):
        self.opcodes = []
        self.prog_type = prog_type
        self.license = license
        self.kern_version = kern_version

        self.m8 = Memory(self, 0x10)
        self.m16 = Memory(self, 0x8)
        self.m32 = Memory(self, 0)
        self.m64 = Memory(self, 0x18)

    def append(self, opcode, dst, src, off, imm):
        self.opcodes.append(Instruction(opcode, dst, src, off, imm))

    def assemble(self):
        return b"".join(
            pack("<BBhi", i.opcode, i.dst | i.src << 4, i.off, i.imm)
            for i in self.opcodes)

    def load(self, log_level=0, log_size=4096):
        return prog_load(self.prog_type, self.assemble(), self.license,
                         log_level, log_size, self.kern_version)

    def jumpIf(self, comp):
        comp.origin = len(self.opcodes)
        comp.ebpf = self
        comp.opcode = comp.posop
        self.opcodes.append(None)
        return comp

    def jump(self):
        comp = Comparison(0, 0, None, None)
        comp.origin = len(self.opcodes)
        comp.ebpf = self
        comp.opcode = 5
        self.opcodes.append(None)
        return comp

    def If(self, comp):
        comp.opcode = comp.negop
        comp.ebpf = self
        return comp

    def isZero(self, comp):
        comp.opcode = comp.negop
        comp.ebpf = self
        return comp

    def exit(self):
        self.append(0x95,0, 0, 0, 0)


for i in range(10):
    setattr(EBPF, f"r{i}", RegisterDesc(i, True))

for i in range(10):
    setattr(EBPF, f"sr{i}", RegisterDesc(i, True, True))

for i in range(10):
    setattr(EBPF, f"s{i}", RegisterDesc(i, False))
