from collections import namedtuple
from struct import pack

from .bpf import prog_load

Instruction = namedtuple("Instruction",
                         ["opcode", "dst", "src", "off", "imm"])

class AssembleError(Exception):
    pass

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
    if sposop is None:
        sposop = uposop
        snegop = unegop
    def ret(self, value):
        return Comparison(self.ebpf, self, value,
                          (uposop, unegop, sposop, snegop))
    return ret


class Comparison:
    def __init__(self, ebpf, left, right, opcode):
        self.ebpf = ebpf
        self.left = left
        self.right = right
        self.opcode = opcode

    def calculate(self, negative):
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
                self.opcode + 8, self.dst, self.src,
                len(self.ebpf.opcodes) - self.origin - 1, 0)
        self.ebpf.opcodes[self.origin] = inst
        self.ebpf.owners, self.owners = \
                self.ebpf.owners & self.owners, self.ebpf.owners

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.target()

    def Else(self):
        op, dst, src, off, imm = self.ebpf.opcodes[self.origin]
        self.ebpf.opcodes[self.origin] = Instruction(op, dst, src, off+1, imm)
        self.origin = len(self.ebpf.opcodes)
        self.ebpf.opcodes.append(None)
        self.right = self.dst = 0
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

    __eq__ = comparison(0x15, 0x55)
    __gt__ = comparison(0x25, 0xb5, 0x65, 0xd5)
    __ge__ = comparison(0x35, 0xa5, 0x75, 0xc5)
    __lt__ = comparison(0xa5, 0x35, 0xc5, 0x75)
    __le__ = comparison(0xb5, 0x25, 0xd5, 0x65)
    __ne__ = comparison(0x55, 0x15)
    __and__ = __rand__ = comparison(0x45, None)


class Binary(Expression):
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
        dst, long, signed, _ = self.left.calculate(dst, long, signed, True)
        if self.operator == 0x74 and signed:  # >>=
            operator = 0xc4
        else:
            operator = self.operator
        if isinstance(self.right, int):
            self.ebpf.append(operator + (3 if long is None else 3 * long),
                             dst, 0, 0, self.right)
        else:
            src, long, _, rfree = self.right.calculate(None, long, None)
            self.ebpf.append(operator + 3 * long + 8, dst, src, 0, 0)
            if rfree:
                self.ebpf.owners.discard(src)
        return dst, long, signed, free


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

    def calculate(self, dst, long, signed, force=False):
        if long is not None and long != self.long:
            raise AssembleError("cannot compile")
        if signed is not None and signed != self.signed:
            raise AssembleError("cannot compile")
        if self.no not in self.ebpf.owners:
            raise AssembleError("register has no value")
        if dst != self.no and force:
            self.ebpf.append(0xbc + 3 * self.long, dst, self.no, 0, 0)
            return dst, self.long, self.signed, False
        else:
            return self.no, self.long, self.signed, False


class Memory(Expression):
    def __init__(self, ebpf, bits, address):
        self.ebpf = ebpf
        self.bits = bits
        self.address = address

    def calculate(self, dst, long, signed, force=False):
        if not long and self.bits == 0x18:
            raise AssembleError("cannot compile")
        if dst is None:
            dst = self.ebpf.get_free_register()
            free = True
        else:
            free = False
        if isinstance(self.address, Sum):
            self.ebpf.append(0x61 + self.bits, dst, self.address.left.no,
                             self.address.right, 0)
        else:
            src, _, _, rfree = self.address.calculate(None, None, None)
            self.ebpf.append(0x61 + self.bits, dst, src, 0, 0)
            if rfree:
                self.ebpf.owners.discard(src)
        return dst, long, signed, free


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
            self.ebpf.append(0x62 + self.bits, dst, 0, offset, value)
        else:
            src, _, _, free = value.calculate(None, None, None)
            self.ebpf.append(0x63 + self.bits, dst, src, offset, 0)
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
        self.ebpf.append(0x18, dst, 1, 0, self.fd)
        self.ebpf.append(0, 0, 0, 0, 0)
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
            raise AssembleError("cannot compile")
        

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

        self.owners = {1, 10}

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
        comp.calculate(False)
        return comp

    def jump(self):
        comp = Comparison(self, None, 0, 5)
        comp.origin = len(self.opcodes)
        comp.dst = 0
        comp.owners = self.owners.copy()
        self.owners = set(range(11))
        self.opcodes.append(None)
        return comp

    def If(self, comp):
        comp.calculate(True)
        return comp

    def isZero(self, comp):
        comp.calculate(False)
        return comp

    def get_fd(self, fd):
        return PseudoFd(self, fd)

    def call(self, no):
        self.append(0x85, 0, 0, 0, no)
        self.owners.add(0)
        self.owners -= set(range(1, 6))

    def exit(self):
        self.append(0x95, 0, 0, 0, 0)

    def get_free_register(self):
        for i in range(10):
            if i not in self.owners:
                return i
        raise AssembleError("not enough registers")


for i in range(11):
    setattr(EBPF, f"r{i}", RegisterDesc(i, True))

for i in range(10):
    setattr(EBPF, f"sr{i}", RegisterDesc(i, True, True))

for i in range(10):
    setattr(EBPF, f"w{i}", RegisterDesc(i, False))
