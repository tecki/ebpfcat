from collections import namedtuple
from struct import pack
from enum import Enum

from .bpf import prog_load

Instruction = namedtuple("Instruction",
                         ["opcode", "dst", "src", "off", "imm"])

class Opcode(Enum):
    ADD = 4
    SUB = 0x14
    MUL = 0x24
    DIV = 0x34
    OR = 0x44
    AND = 0x54
    LSH = 0x64
    RSH = 0x74
    NEG = 0x84
    MOD = 0x94
    XOR = 0xa4
    MOV = 0xb4
    ARSH = 0xc4

    JMP = 5
    JEQ = 0x15
    JGT = 0x25
    JGE = 0x35
    JSET = 0x45
    JNE = 0x55
    JSGT = 0x65
    JSGE = 0x75
    JLT = 0xa5
    JLE = 0xb5
    JSLT = 0xc5
    JSLE = 0xd5

    CALL = 0x85
    EXIT = 0x95

    REG = 8
    LONG = 3

    W = 0
    H = 8
    B = 0x10
    DW = 0x18

    LD = 0x61
    ST = 0x62
    STX = 0x63

    def __mul__(self, value):
        if value:
            return OpcodeFlags({self})
        else:
            return OpcodeFlags(set())

    def __add__(self, value):
        return OpcodeFlags({self}) + value

    def __repr__(self):
        return 'O.' + self.name

class OpcodeFlags:
    def __init__(self, opcodes):
        self.opcodes = opcodes

    @property
    def value(self):
        return sum(op.value for op in self.opcodes)

    def __add__(self, value):
        if isinstance(value, Opcode):
            return OpcodeFlags(self.opcodes | {value})
        else:
            return OpcodeFlags(self.opcodes | value.opcodes)

    def __repr__(self):
        return "+".join(repr(op) for op in self.opcodes)

    def __eq__(self, value):
        return self.value == value.value


class AssembleError(Exception):
    pass

def augassign(opcode):
    def ret(self, value):
        if isinstance(value, int):
            return Instruction(opcode + Opcode.LONG * self.long, self.no,
                               0, 0, value)
        elif isinstance(value, Register) and self.long == value.long:
            return Instruction(opcode + Opcode.REG + Opcode.LONG * self.long,
                               self.no, value.no, 0, 0)
        else:
            return NotImplemented
    return ret


def comparison(uposop, unegop, sposop=None, snegop=None):
    if sposop is None:
        sposop = uposop
        snegop = unegop
    def ret(self, value):
        return SimpleComparison(self.ebpf, self, value,
                                (uposop, unegop, sposop, snegop))
    return ret


class Comparison:
    def __init__(self, ebpf):
        self.ebpf = ebpf
        self.invert = None
        self.else_origin = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.else_origin is None:
            self.target()
            return
        assert self.ebpf.opcodes[self.else_origin] is None
        self.ebpf.opcodes[self.else_origin] = Instruction(
                Opcode.JMP, 0, 0,
                len(self.ebpf.opcodes) - self.else_origin - 1, 0)
        self.ebpf.owners, self.owners = \
                self.ebpf.owners & self.owners, self.ebpf.owners

        if self.invert is not None:
            olen = len(self.ebpf.opcodes)
            assert self.ebpf.opcodes[self.invert].opcode == Opcode.JMP
            self.ebpf.opcodes[self.invert:self.invert] = \
                    self.ebpf.opcodes[self.else_origin+1:]
            del self.ebpf.opcodes[olen-1:]
            op, dst, src, off, imm = self.ebpf.opcodes[self.invert - 1]
            self.ebpf.opcodes[self.invert - 1] = \
                    Instruction(op, dst, src,
                                len(self.ebpf.opcodes) - self.else_origin + 1, imm)

    def Else(self):
        op, dst, src, off, imm = self.ebpf.opcodes[self.origin]
        if op == Opcode.JMP:
            self.invert = self.origin
        else:
            self.ebpf.opcodes[self.origin] = \
                    Instruction(op, dst, src, off+1, imm)
        self.else_origin = len(self.ebpf.opcodes)
        self.ebpf.opcodes.append(None)
        return self

    def invert_result(self):
        origin = len(self.ebpf.opcodes)
        self.ebpf.opcodes.append(None)
        self.target()
        self.origin = origin
        self.right = self.dst = 0
        self.opcode = Opcode.JMP

    def __and__(self, value):
        return AndOrComparison(self.ebpf, self, value, True)

    def __or__(self, value):
        return AndOrComparison(self.ebpf, self, value, False)

    def __invert__(self):
        return InvertComparison(self.ebpf, self)


class SimpleComparison(Comparison):
    def __init__(self, ebpf, left, right, opcode):
        super().__init__(ebpf)
        self.left = left
        self.right = right
        self.opcode = opcode

    def compare(self, negative):
        self.dst, _, lsigned, lfree = self.left.calculate(None, None, None)
        if not isinstance(self.right, int):
            self.src, _, rsigned, rfree = \
                    self.right.calculate(None, None, None)
            if rsigned != rsigned:
                raise AssembleError("need same signedness for comparison")
        else:
            rfree = False
        self.origin = len(self.ebpf.opcodes)
        self.ebpf.opcodes.append(None)
        self.opcode = self.opcode[negative + 2 * lsigned]
        if lfree:
            self.ebpf.owners.discard(self.dst)
        if rfree:
            self.ebpf.owners.discard(self.src)
        self.owners = self.ebpf.owners.copy()

    def target(self):
        assert self.ebpf.opcodes[self.origin] is None
        if isinstance(self.right, int):
            inst = Instruction(
                self.opcode, self.dst, 0,
                len(self.ebpf.opcodes) - self.origin - 1, self.right)
        else:
            inst = Instruction(
                self.opcode + Opcode.REG, self.dst, self.src,
                len(self.ebpf.opcodes) - self.origin - 1, 0)
        self.ebpf.opcodes[self.origin] = inst
        self.ebpf.owners, self.owners = \
                self.ebpf.owners & self.owners, self.ebpf.owners


class AndOrComparison(Comparison):
    def __init__(self, ebpf, left, right, is_and):
        super().__init__(ebpf)
        self.left = left
        self.right = right
        self.is_and = is_and
        self.targetted = False

    def compare(self, negative):
        self.left.compare(self.is_and != negative)
        self.right.compare(self.is_and != negative)
        if self.is_and != negative:
            self.invert_result()
            self.owners = self.ebpf.owners.copy()

    def target(self):
        if self.targetted:
            super().target()
        else:
            self.left.target()
            self.right.target()
            self.targetted = True


class InvertComparison(Comparison):
    def __init__(self, ebpf, value):
        self.ebpf = ebpf
        self.value = value

    def compare(self, negative):
        self.value.compare(not negative)


def binary(opcode):
    def ret(self, value):
        return Binary(self.ebpf, self, value, opcode)
    return ret

def rbinary(opcode):
    def ret(self, value):
        return ReverseBinary(self.ebpf, value, self, opcode)
    return ret


class Expression:
    __radd__ = __add__ = binary(Opcode.ADD)
    __sub__ = binary(Opcode.SUB)
    __rsub__ = rbinary(Opcode.SUB)
    __rmul__ = __mul__ = binary(Opcode.MUL)
    __truediv__ = binary(Opcode.DIV)
    __rtruediv__ = rbinary(Opcode.DIV)
    __ror__ = __or__ = binary(Opcode.OR)
    __lshift__ = binary(Opcode.LSH)
    __rlshift__ = rbinary(Opcode.LSH)
    __rshift__ = binary(Opcode.RSH)
    __rrshift__ = rbinary(Opcode.RSH)
    __mod__ = binary(Opcode.MOD)
    __rmod__ = rbinary(Opcode.MOD)
    __rxor__ = __xor__ = binary(Opcode.XOR)

    __eq__ = comparison(Opcode.JEQ, Opcode.JNE)
    __gt__ = comparison(Opcode.JGT, Opcode.JLE, Opcode.JSGT, Opcode.JSLE)
    __ge__ = comparison(Opcode.JGE, Opcode.JLT, Opcode.JSGE, Opcode.JSLT)
    __lt__ = comparison(Opcode.JLT, Opcode.JGE, Opcode.JSLT, Opcode.JSGE)
    __le__ = comparison(Opcode.JLE, Opcode.JGT, Opcode.JSLE, Opcode.JSGT)
    __ne__ = comparison(Opcode.JNE, Opcode.JEQ)

    def __and__(self, value):
        return AndExpression(self.ebpf, self, value)

    __rand__ = __and__

    def __neg__(self):
        return Negate(self.ebpf, self)


class Binary(Expression):
    def __init__(self, ebpf, left, right, operator):
        self.ebpf = ebpf
        self.left = left
        self.right = right
        self.operator = operator

    def calculate(self, dst, long, signed, force=False):
        orig_dst = dst
        if dst is None or (not isinstance(self.right, int)
                           and self.right.contains(dst)):
            dst = self.ebpf.get_free_register()
            self.ebpf.owners.add(dst)
            free = True
        else:
            free = False
        dst, long, signed, _ = self.left.calculate(dst, long, signed, True)
        if self.operator is Opcode.RSH and signed:  # >>=
            operator = Opcode.ARSH
        else:
            operator = self.operator
        if isinstance(self.right, int):
            self.ebpf.append(operator + (Opcode.LONG if long is None
                                         else Opcode.LONG * long),
                             dst, 0, 0, self.right)
        else:
            src, long, _, rfree = self.right.calculate(None, long, None)
            self.ebpf.append(operator + Opcode.LONG * long + Opcode.REG,
                             dst, src, 0, 0)
            if rfree:
                self.ebpf.owners.discard(src)
        if orig_dst is None or orig_dst == dst:
            return dst, long, signed, free
        else:
            self.ebpf.append(Opcode.MOV + Opcode.LONG * long, orig_dst, dst,
                             0, 0)
            self.ebpf.owners.discard(dst)
            return orig_dst, long, signed, False

    def contains(self, no):
        return self.left.contains(no) or (not isinstance(self.right, int)
                                          and self.right.contains(no))


class ReverseBinary(Expression):
    def __init__(self, ebpf, left, right, operator):
        self.ebpf = ebpf
        self.left = left
        self.right = right
        self.operator = operator

    def calculate(self, dst, long, signed, force=False):
        if dst is None:
            dst = self.ebpf.get_free_register()
            self.ebpf.owners.add(dst)
            free = True
        else:
            free = False
        self.ebpf._load_value(dst, self.left)
        if self.operator is Opcode.RSH and self.left < 0:  # >>=
            operator = Opcode.ARSH
        else:
            operator = self.operator

        src, long, _, rfree = self.right.calculate(None, long, None)
        self.ebpf.append(operator + Opcode.LONG * long + Opcode.REG,
                         dst, src, 0, 0)
        return dst, long, signed, free

    def contains(self, no):
        return self.right.contains(no)


class Negate(Expression):
    def __init__(self, ebpf, arg):
        self.ebpf = ebpf
        self.arg = arg

    def calculate(self, dst, long, signed, force=False):
        dst, long, signed, free = self.arg.calculate(dst, long, signed, force)
        self.ebpf.append(Opcode.NEG + Opcode.LONG * long, dst, 0, 0, 0)
        return dst, long, signed, free

    def contains(self, no):
        return self.arg.contains(no)


class Sum(Binary):
    def __init__(self, ebpf, left, right):
        super().__init__(ebpf, left, right, Opcode.ADD)

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


class AndExpression(Binary, SimpleComparison):
    def __init__(self, ebpf, left, right):
        Binary.__init__(self, ebpf, left, right, Opcode.AND)
        SimpleComparison.__init__(self, ebpf, left, right, Opcode.JSET)
        self.opcode = (Opcode.JSET, None, Opcode.JSET, None)

    def compare(self, negative):
        super().compare(False)
        if negative:
            self.invert_result()

class Register(Expression):
    offset = 0

    def __init__(self, no, ebpf, long, signed):
        self.no = no
        self.ebpf = ebpf
        self.long = long
        self.signed = signed

    __iadd__ = augassign(Opcode.ADD)
    __isub__ = augassign(Opcode.SUB)
    __imul__ = augassign(Opcode.MUL)
    __itruediv__ = augassign(Opcode.DIV)
    __ior__ = augassign(Opcode.OR)
    __iand__ = augassign(Opcode.AND)
    __ilshift__ = augassign(Opcode.LSH)
    __imod__ = augassign(Opcode.MOD)
    __ixor__ = augassign(Opcode.XOR)

    def __irshift__(self, value):
        opcode = Opcode.ARSH if self.signed else Opcode.RSH
        if isinstance(value, int):
            return Instruction(opcode + Opcode.LONG * self.long, self.no,
                               0, 0, value)
        elif isinstance(value, Register) and self.long == value.long:
            return Instruction(opcode + Opcode.REG + Opcode.LONG * self.long,
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

    def calculate(self, dst, long, signed, force=False):
        if long is not None and long != self.long:
            raise AssembleError("cannot compile")
        if signed is not None and signed != self.signed:
            raise AssembleError("cannot compile")
        if self.no not in self.ebpf.owners:
            raise AssembleError("register has no value")
        if dst != self.no and force:
            self.ebpf.append(Opcode.MOV + Opcode.REG + Opcode.LONG * self.long,
                             dst, self.no, 0, 0)
            return dst, self.long, self.signed, False
        else:
            return self.no, self.long, self.signed, False

    def contains(self, no):
        return self.no == no


class Memory(Expression):
    def __init__(self, ebpf, bits, address):
        self.ebpf = ebpf
        self.bits = bits
        self.address = address

    def calculate(self, dst, long, signed, force=False):
        if not long and self.bits == Opcode.DW:
            raise AssembleError("cannot compile")
        if dst is None:
            dst = self.ebpf.get_free_register()
            free = True
        else:
            free = False
        if isinstance(self.address, Sum):
            self.ebpf.append(Opcode.LD + self.bits, dst, self.address.left.no,
                             self.address.right, 0)
        else:
            src, _, _, rfree = self.address.calculate(None, None, None)
            self.ebpf.append(Opcode.LD + self.bits, dst, src, 0, 0)
            if rfree:
                self.ebpf.owners.discard(src)
        return dst, long, signed, free

    def contains(self, no):
        return self.address.contains(no)


class MemoryDesc:
    def __init__(self, ebpf, bits):
        self.ebpf = ebpf
        self.bits = bits

    def __setitem__(self, addr, value):
        if isinstance(addr, Sum):
            dst = addr.left.no
            offset = addr.right
            afree = False
        else:
            dst, _, _, afree = addr.calculate(None, None, None)
            offset = 0
        if isinstance(value, int):
            self.ebpf.append(Opcode.ST + self.bits, dst, 0, offset, value)
        else:
            src, _, _, free = value.calculate(None, None, None)
            self.ebpf.append(Opcode.STX + self.bits, dst, src, offset, 0)
            if free:
                self.ebpf.owners.discard(src)
        if afree:
            self.ebpf.owners.discard(dst)

    def __getitem__(self, addr):
        if isinstance(addr, Register):
            addr = addr + 0
        return Memory(self.ebpf, self.bits, addr)


class PseudoFd(Expression):
    def __init__(self, ebpf, fd):
        self.ebpf = ebpf
        self.fd = fd

    def calculate(self, dst, long, signed, force):
        if dst is None:
            dst = self.ebpf.get_free_register()
            free = True
        else:
            free = False
        self.ebpf.append(Opcode.DW, dst, 1, 0, self.fd)
        self.ebpf.append(Opcode.W, 0, 0, 0, 0)
        return dst, long, signed, free


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
        instance.owners.add(self.no)
        if isinstance(value, int):
            instance._load_value(self.no, value)
        elif isinstance(value, Expression):
            value.calculate(self.no, self.long, self.signed, True)
        elif isinstance(value, Instruction):
            instance.opcodes.append(value)
        else:
            raise AssembleError("cannot compile")
        

class EBPF:
    def __init__(self, prog_type=0, license="", kern_version=0):
        self.opcodes = []
        self.prog_type = prog_type
        self.license = license
        self.kern_version = kern_version

        self.m8 = MemoryDesc(self, Opcode.B)
        self.m16 = MemoryDesc(self, Opcode.H)
        self.m32 = MemoryDesc(self, Opcode.W)
        self.m64 = MemoryDesc(self, Opcode.DW)

        self.owners = {1, 10}

    def append(self, opcode, dst, src, off, imm):
        self.opcodes.append(Instruction(opcode, dst, src, off, imm))

    def assemble(self):
        return b"".join(
            pack("<BBHI", i.opcode.value, i.dst | i.src << 4,
                 i.off % 0x10000, i.imm % 0x100000000)
            for i in self.opcodes)

    def load(self, log_level=0, log_size=4096):
        return prog_load(self.prog_type, self.assemble(), self.license,
                         log_level, log_size, self.kern_version)

    def jumpIf(self, comp):
        comp.compare(False)
        return comp

    def jump(self):
        comp = SimpleComparison(self, None, 0, Opcode.JMP)
        comp.origin = len(self.opcodes)
        comp.dst = 0
        comp.owners = self.owners.copy()
        self.owners = set(range(11))
        self.opcodes.append(None)
        return comp

    def If(self, comp):
        comp.compare(True)
        return comp

    def get_fd(self, fd):
        return PseudoFd(self, fd)

    def call(self, no):
        self.append(Opcode.CALL, 0, 0, 0, no)
        self.owners.add(0)
        self.owners -= set(range(1, 6))

    def exit(self):
        self.append(Opcode.EXIT, 0, 0, 0, 0)

    def get_free_register(self):
        for i in range(10):
            if i not in self.owners:
                return i
        raise AssembleError("not enough registers")

    def _load_value(self, no, value):
        if -0x80000000 <= value < 0x80000000:
            self.append(Opcode.MOV + Opcode.LONG, no, 0, 0, value)
        else:
            self.append(Opcode.DW, no, 0, 0, value & 0xffffffff)
            self.append(Opcode.W, 0, 0, 0, value >> 32)

for i in range(11):
    setattr(EBPF, f"r{i}", RegisterDesc(i, True))

for i in range(10):
    setattr(EBPF, f"sr{i}", RegisterDesc(i, True, True))

for i in range(10):
    setattr(EBPF, f"w{i}", RegisterDesc(i, False))
