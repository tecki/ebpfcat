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


def binary(opcode, symetric=False):
    def ret(self, value):
        #if symetric and isinstance(value, Register):
        #    return Binary(self.ebpf, value, self, opcode)
        return Binary(self.ebpf, self, value, opcode)
    return ret


class Expression:
    __radd__ = __add__ = binary(4, True)
    __sub__ = binary(0x14)
    __rmul__ = __mul__ = binary(0x24, True)
    __truediv__ = binary(0x34)
    __ror__ = __or__ = binary(0x44, True)
    __rand__ = __and__ = binary(0x54, True)
    __lshift__ = binary(0x64)
    __rshift__ = binary(0x74)
    __mod__ = binary(0x94)
    __rxor__ = __xor__ = binary(0xa4, True)


class Binary(Expression):
    def __init__(self, ebpf, left, right, operator):
        self.ebpf = ebpf
        self.left = left
        self.right = right
        self.operator = operator

    def calculate(self, dst, long, signed, force=False):
        if dst is None:
            raise RuntimeError("cannot compile")
        dst, long, signed = self.left.calculate(dst, long, signed, True)
        if self.operator == 0x74 and signed:  # >>=
            operator = 0xc4
        else:
            operator = self.operator
        if isinstance(self.right, int):
            self.ebpf.append(operator + (3 if long is None else 3 * long),
                             dst, 0, 0, self.right)
        else:
            src, long, signed = self.right.calculate(None, long, signed)
            self.ebpf.append(operator + 3 * long + 8, dst, src, 0, 0)
        return dst, long, signed


class Sum(Binary):
    def __init__(self, ebpf, left, right):
        super().__init__(ebpf, left, right, 4)

    def __add__(self, value):
        if isinstance(value, int):
            return Sum(self.ebpf, self.left, self.right + value)
        else:
            return super().__add__(value)

    __radd__ = __add__

    def __sub__(self, value):
        if isinstance(value, int):
            return Sum(self.ebpf, self.left, self.right - value)
        else:
            return super().__sub__(value)


class Register(Expression):
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
            return Sum(self.ebpf, self, value)
        else:
            return super().__add__(value)

    __radd__ = __add__

    def __sub__(self, value):
        if isinstance(value, int) and self.long:
            return Sum(self.ebpf, self, -value)
        else:
            return super().__sub__(value)

    __eq__ = comparison(0x15, 0x55)
    __gt__ = comparison(0x25, 0xb5, 0x65, 0xd5)
    __ge__ = comparison(0x35, 0xa5, 0x75, 0xc5)
    __lt__ = comparison(0xa5, 0x35, 0xc5, 0x75)
    __le__ = comparison(0xb5, 0x25, 0xd5, 0x65)
    __ne__ = comparison(0x55, 0x15)
    __and__ = __rand__ = comparison(0x45, None)


    def calculate(self, dst, long, signed, force=False):
        if long is not None and long != self.long:
            raise RuntimeError("cannot compile")
        if dst != self.no and force:
            self.ebpf.append(0xbc + 3 * self.long, dst, self.no, 0, 0)
            return dst, self.long, signed
        else:
            return self.no, self.long, signed


class Memory(Expression):
    def __init__(self, ebpf, bits, address):
        self.ebpf = ebpf
        self.bits = bits
        self.address = address

    def calculate(self, dst, long, signed, force):
        if not long and self.bits == 0x18:
            raise RuntimeError("cannot compile")
        self.ebpf.append(0x61 + self.bits, dst, self.address.left.no,
                         self.address.right, 0)
        return dst, long, signed


class MemoryDesc:
    def __init__(self, ebpf, bits):
        self.ebpf = ebpf
        self.bits = bits

    def __setitem__(self, addr, value):
        if isinstance(addr, Sum):
            dst = addr.left.no
            offset = addr.right
        else:
            dst, _, _ = addr.calculate(None, None, None)
            offset = 0
        if isinstance(value, int):
            self.ebpf.append(0x62 + self.bits, dst, 0, offset, value)
        else:
            src, _, _ = value.calculate(None, None, None)
            self.ebpf.append(0x63 + self.bits, dst, src, offset, 0)

    def __getitem__(self, addr):
        ret = addr + 0
        if not isinstance(ret, Sum):
            raise RuntimeError("cannot compile")
        return Memory(self.ebpf, self.bits, ret)


class PseudoFd(Expression):
    def __init__(self, ebpf, fd):
        self.ebpf = ebpf
        self.fd = fd

    def calculate(self, dst, long, signed, force):
        self.ebpf.append(0x18, dst, 1, 0, self.fd)
        self.ebpf.append(0, 0, 0, 0, 0)
        return dst, long, signed


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
            if -0x80000000 <= value < 0x80000000:
                instance.append(0xb4 + 3 * self.long, self.no, 0, 0, value)
            else:
                instance.append(0x18, self.no, 0, 0, value & 0xffffffff)
                instance.append(0, 0, 0, 0, value >> 32)
        elif isinstance(value, Expression):
            value.calculate(self.no, self.long, self.signed, True)
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

        self.m8 = MemoryDesc(self, 0x10)
        self.m16 = MemoryDesc(self, 0x8)
        self.m32 = MemoryDesc(self, 0)
        self.m64 = MemoryDesc(self, 0x18)

    def append(self, opcode, dst, src, off, imm):
        self.opcodes.append(Instruction(opcode, dst, src, off, imm))

    def assemble(self):
        return b"".join(
            pack("<BBHI", i.opcode, i.dst | i.src << 4,
                 i.off % 0x10000, i.imm % 0x100000000)
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

    def get_fd(self, fd):
        return PseudoFd(self, fd)

    def call(self, no):
        self.append(0x85, 0, 0, 0, no)

    def exit(self):
        self.append(0x95, 0, 0, 0, 0)


for i in range(11):
    setattr(EBPF, f"r{i}", RegisterDesc(i, True))

for i in range(10):
    setattr(EBPF, f"sr{i}", RegisterDesc(i, True, True))

for i in range(10):
    setattr(EBPF, f"s{i}", RegisterDesc(i, False))
