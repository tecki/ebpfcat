# ebpfcat, A Python-based EBPF generator and EtherCAT master
# Copyright (C) 2025
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

"""Human readable disassembly for :mod:`ebpfcat.ebpf` instructions."""

from collections import namedtuple
from enum import Enum
from struct import pack


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
    SHORT = 1

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
    XADD = 0xc3
    LE = 0xd4
    BE = 0xdc

    SIGNED = 0x80
    ABS = 0x20
    IND = 0x40
    JCOND = 0xe0

    def __mul__(self, value):
        if value:
            return OpcodeFlags({self})
        else:
            return OpcodeFlags(set())

    def __add__(self, value):
        return OpcodeFlags({self}) + value

    def __repr__(self):
        return 'O.' + self.name

    def __hash__(self):
        return hash(self.value & 0xf8)


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


BaseInstruction = namedtuple("BaseInstruction",
                             ["opcode", "dst", "src", "off", "imm"])


class Comparer:
    def __init__(self, mask, opcode):
        self.mask = mask
        self.opcode = opcode

    def __eq__(self, value):
        return self.opcode.value & self.mask == value.value & self.mask

    def __hash__(self):
        return hash(self.opcode.value & self.mask)

    def __index__(self):
        return self.opcode.value & self.mask

    def __repr__(self):
        return f'<{self.opcode} {self.opcode.value:x} {self.mask}>'


class CompareDesc:
    def __init__(self, mask):
        self.mask = mask

    def __get__(self, instance, owner):
        if instance is None:
            return self
        return Comparer(self.mask, instance.opcode)


class Instruction(BaseInstruction):
    opcode_size = 1

    def set_position(self, position):
        pass

    def assemble(self):
        return pack("<BBHI", self.opcode.value, self.dst | self.src << 4,
                    self.off % 0x10000, self.imm % 0x100000000)

    opclass = CompareDesc(7)
    opsize = CompareDesc(0x18)
    opmode = CompareDesc(0xe0)
    op = CompareDesc(0xf0)

    @property
    def opsrc(self):
        return self.opcode.value & 8 != 0

    @property
    def size_str(self):
        return size_str[self.opsize]

    def __str__(self):
        return (
                self.format_ld, self.format_ldx, self.format_st,
                self.format_stx, self.format_alu, self.format_jmp,
                self.format_jmp, self.format_alu
                )[self.opclass]()

    def format_alu(self):
        if self.op == Opcode.LE:
            if self.opclass == Opcode.ADD:  # not long
                return f"r{self.dst} = bswap{self.imm} r{self.dst}"
            else:
                endian = "le" if self.opsrc else "be"
                return f"w{self.dst} = {endian}{self.imm} w{self.dst}"
        if self.opclass == Opcode.ADD:  # not long
            reg = 'w'
        else:
            reg = 'r'
        if self.op == Opcode.NEG:
            return f"{reg}{self.dst} = -{reg}{self.dst}"
        if self.opcode == Opcode.MOV + Opcode.LONG + Opcode.REG:
            if self.off == 1:
                hi = (self.imm >> 16) & 0xFFFFFFFF
                lo = self.imm & 0xFFFF
                return f"r{self.dst} = addr_space_cast(r{self.src}, {hi}, {lo})"
            elif self.off == -1:
                return f"r{self.dst} = &(void __percpu *)(r{self.src})"
        op_str = alu_string.get(self.op, "??")
        if self.off == 1:
            op_str = 's' + op_str
        if not self.opsrc:
            return f"{reg}{self.dst} {op_str} {self.imm}"
        suffix = f"(s{insn.off})" if self.off else ''
        return f"{reg}{self.dst} {op_str} {suffix}{reg}{self.src}"

    def format_stx(self):
        if self.opmode == Opcode.STX:
            return f"*(u{self.size_str} *)(r{self.dst} {self.off:+d}) = r{self.src}"
        if self.imm == 0:
            return f"lock *(u{self.size_str} *)(r{self.dst} {self.off:+d}) += r{self.src}"
        immopcode = Opcode(inst.imm + 2)
        atomic = "64" if self.opsize == Opcode.DW else ""
        if immopcode in {Opcode.ADD, Opcode.AND, Opcode.OR, Opcode.H}:
            op = opcode.name.lower()
            return (
                f"r{self.src} = atomic{atomic}_fetch_{op}("
                "(u{self.size_str} *)(r{self.dst} {self.off:+d}), r{self.src})"
            )
        if self.imm == BPF_CMPXCHG:
            return (
                f"r0 = atomic{atomic}_cmpxchg("
                f"(u{self.size_str} *)(r{self.dst} {self.off:+d}), r0, r{self.src})"
            )
        if insn.imm == BPF_XCHG:
            return (
                f"r{self.src} = atomic{atomic}_xchg("
                f"(u{self.size_str} *)(r{insn.dst} {insn.off:+d}), r{insn.src})"
            )
        raise RuntimeError('unknown instruction')

    def format_st(self):
        if self.opmode == Opcode.ST:
            return f"*(u{self.size_str} *)(r{self.dst} {self.off:+d}) = {self.imm}"
        if self.opmode == Opcode.XADD:
            return f"nospec"
        raise RuntimeError('unknown instruction')

    def format_ldx(self):
        signed = 's' if self.opmode == Opcode.SIGNED else 'u'
        return f"r{self.dst} = *({signed}{self.size_str} *)(r{self.src} {self.off:+d})"

    def format_ld(self):
        if self.opmode == Opcode.ABS:
            return f"r0 = *({self.size_str} *)skb[{self.imm}]"
        if self.opmode == Opcode.IND:
            return f"r0 = *({size} *)skb[r{self.src} + {self.imm}]"
        raise RuntimeError('unknown instruction')

    def format_jmp(self):
        if self.op == Opcode.CALL:
            if self.src == 1:
                return f"call pc{self.imm:+d}"
            elif self.src == 2:
                return f"call kernel-function"
            return f"call #{self.imm}"
        if self.opcode == Opcode.JMP:
            return f"goto pc{self.off:+d}"
        if self.opcode == Opcode.JMP + Opcode.REG:
            return f"gotox r{self.dst}"
        if self.opcode == Opcode.JCOND and self.src == 0:
            return f"may_goto pc{self.off:+d}"
        if self.opcode == Opcode.JMP + Opcode.SHORT:
            return f"gotol pc{self.imm:+d}"
        if self.opcode == Opcode.EXIT:
            return f"exit"
        cmp = jmp_string.get(self.op, "??")
        reg = "r" if self.opclass == Opcode.JMP else "w"  # not SHORT
        if self.opsrc:
            return f"if {reg}{self.dst} {cmp} {reg}{self.src} goto pc{self.off:+d}"
        else:
            return f"if {reg}{self.dst} {cmp} 0x{self.imm:x} goto pc{self.off:+d}"


class HugeInstruction(Instruction):
    opcode_size = 2

    def assemble(self):
        return pack("<BB2xIB3xI", Opcode.DW.value, self.dst | self.src << 4,
                    self.imm & 0xffffffff, Opcode.W.value, self.imm >> 32)

    def __str__(self):
        if self.src:
            return f"r{self.dst} = FD#{self.imm}"
        else:
            return f"r{self.dst} = {self.imm:#x}"


alu_string = {
    Opcode.ADD: "+=",
    Opcode.SUB: "-=",
    Opcode.MUL: "*=",
    Opcode.DIV: "/=",
    Opcode.OR: "|=",
    Opcode.AND: "&=",
    Opcode.LSH: "<<=",
    Opcode.RSH: ">>=",
    Opcode.MOD: "%=",
    Opcode.XOR: "^=",
    Opcode.MOV: "=",
    Opcode.ARSH: "s>>=",
}

size_str = {
    Opcode.B: "8",
    Opcode.H: "16",
    Opcode.W: "32",
    Opcode.DW: "64"
}

jmp_string = {
    Opcode.JEQ: "==",
    Opcode.JGT: ">",
    Opcode.JGE: ">=",
    Opcode.JSET: "&",
    Opcode.JNE: "!=",
    Opcode.JSGT: "s>",
    Opcode.JSGE: "s>=",
    Opcode.JLT: "<",
    Opcode.JLE: "<=",
    Opcode.JSLT: "s<",
    Opcode.JSLE: "s<=",
}
