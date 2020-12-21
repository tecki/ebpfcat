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

    def __init__(self, no, ebpf, long):
        self.no = no
        self.ebpf = ebpf
        self.long = long

    __iadd__ = augassign(4)
    __isub__ = augassign(0x14)
    __imul__ = augassign(0x24)
    __itruediv__ = augassign(0x34)
    __ior__ = augassign(0x44)
    __iand__ = augassign(0x54)
    __ilshift__ = augassign(0x64)
    __irshift__ = augassign(0x74)
    __imod__ = augassign(0x94)
    __ixor__ = augassign(0xa4)

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
        pass


class RegisterDesc:
    def __init__(self, no, long):
        self.no = no
        self.long = long

    def __get__(self, instance, owner=None):
        if instance is None:
            return self
        else:
            return Register(self.no, instance, self.long)

    def __set__(self, instance, value):
        if isinstance(value, int):
            instance.append(0xb4 + 3 * self.long, self.no, 0, 0, value)
        elif isinstance(value, Register) and self.long == value.long:
            instance.append(0xbc + 3 * self.long, self.no, value.no, 0, 0)
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

    def append(self, opcode, dst, src, off, imm):
        self.opcodes.append(Instruction(opcode, dst, src, off, imm))

    def assemble(self):
        return b"".join(
            pack("<BBHI", i.opcode, i.dst | i.src << 4, i.off, i.imm)
            for i in self.opcodes)

    def load(self, log_level=0, log_size=4096):
        return prog_load(self.prog_type, self.assemble(), self.license,
                         log_level, log_size, self.kern_version)

    def exit(self):
        self.append(0x95,0, 0, 0, 0)


for i in range(10):
    setattr(EBPF, f"r{i}", RegisterDesc(i, True))

for i in range(10):
    setattr(EBPF, f"s{i}", RegisterDesc(i, False))
