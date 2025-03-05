# ebpfcat, A Python-based EBPF generator and EtherCAT master
# Copyright (C) 2021 Martin Teichmann <martin.teichmann@gmail.com>
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

from unittest import TestCase, main

from . import ebpf
from .arraymap import ArrayMap
from .ebpf import (
    AssembleError, EBPF, FuncId, Opcode, OpcodeFlags, Opcode as O, LocalVar,
    SimulatedEBPF, SubProgram, ktime)
from .hashmap import HashMap
from .xdp import XDP, PacketVar
from .bpf import ProgType


opcodes = list((v.value, v) for v in Opcode)
opcodes.sort(reverse=True)


def Instruction(opcode, dst, src, off, imm):
    if isinstance(opcode, (Opcode, OpcodeFlags)):
        return ebpf.Instruction(opcode, dst, src, off, imm)
    bigger = [(k, v) for k, v in opcodes if opcode >= k]
    for bk, bv in bigger:
        parts = {bv}
        lo = opcode - bk
        for k, v in opcodes[:-1]:
            if lo >= k:
                lo -= k
                parts.add(v)
        if lo == 0:
            break
    else:
        raise RuntimeError
    return ebpf.Instruction(OpcodeFlags(parts), dst, src, off, imm)

class Tests(TestCase):
    def test_assemble(self):
        e = EBPF()
        e.append(Opcode.MUL, 3, 4, 0x2c3d, 0x2d3e4f5e)
        self.assertEqual(e.assemble(), b"$C=,^O>-")

    def test_assign(self):
        e = EBPF()
        e.owners = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
        e.r5 = 7
        e.r6 = e.r3
        self.assertEqual(e.opcodes,
            [Instruction(0xb7, 5, 0, 0, 7),
             Instruction(0xbf, 6, 3, 0, 0)])

    def test_word(self):
        e = EBPF()
        e.owners |= {6}
        e.w3 = 7
        e.w4 = e.w1
        e.w2 += 3
        e.w5 += e.w6
        self.assertEqual(e.opcodes,
            [Instruction(O.MOV+O.LONG, 3, 0, 0, 7),
             Instruction(0xbc, 4, 1, 0, 0),
             Instruction(opcode=4, dst=2, src=0, off=0, imm=3),
             Instruction(opcode=0xc, dst=5, src=6, off=0, imm=0)])

    def test_augassign(self):
        e = EBPF()
        e.owners |= {4, 6, 7}
        e.r5 += 7
        e.r3 += e.r6
        e.r4 -= 3
        e.r4 -= e.r7
        e.r4 *= 3
        e.r4 *= e.r7
        e.r4 //= 3
        e.r4 //= e.r7
        e.r4 |= 3
        e.r4 |= e.r7
        e.r4 &= 3
        e.r4 &= e.r7
        e.r4 <<= 3
        e.r4 <<= e.r7
        e.r4 >>= 3
        e.r4 >>= e.r7
        e.r4 %= 3
        e.r4 %= e.r7
        e.r4 ^= 3
        e.r4 ^= e.r7
        e.sr4 >>= 3
        e.sr4 >>= e.r7

        self.assertEqual(e.opcodes,
            [Instruction(opcode=7, dst=5, src=0, off=0, imm=7),
             Instruction(opcode=15, dst=3, src=6, off=0, imm=0),
             Instruction(opcode=7, dst=4, src=0, off=0, imm=-3),
             Instruction(opcode=0x1f, dst=4, src=7, off=0, imm=0),
             Instruction(opcode=0x27, dst=4, src=0, off=0, imm=3),
             Instruction(opcode=0x2f, dst=4, src=7, off=0, imm=0),
             Instruction(opcode=0x37, dst=4, src=0, off=0, imm=3),
             Instruction(opcode=0x3f, dst=4, src=7, off=0, imm=0),
             Instruction(opcode=0x47, dst=4, src=0, off=0, imm=3),
             Instruction(opcode=0x4f, dst=4, src=7, off=0, imm=0),
             Instruction(opcode=0x57, dst=4, src=0, off=0, imm=3),
             Instruction(opcode=0x5f, dst=4, src=7, off=0, imm=0),
             Instruction(opcode=0x67, dst=4, src=0, off=0, imm=3),
             Instruction(opcode=0x6f, dst=4, src=7, off=0, imm=0),
             Instruction(opcode=0x77, dst=4, src=0, off=0, imm=3),
             Instruction(opcode=0x7f, dst=4, src=7, off=0, imm=0),
             Instruction(opcode=0x97, dst=4, src=0, off=0, imm=3),
             Instruction(opcode=0x9f, dst=4, src=7, off=0, imm=0),
             Instruction(opcode=0xa7, dst=4, src=0, off=0, imm=3),
             Instruction(opcode=0xaf, dst=4, src=7, off=0, imm=0),
             Instruction(opcode=0xc7, dst=4, src=0, off=0, imm=3),
             Instruction(opcode=0xcf, dst=4, src=7, off=0, imm=0)])

    def test_memory(self):
        e = EBPF()
        e.owners = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
        e.mB[e.r5] = 7
        e.mH[e.r3 + 2] = 3
        e.mI[7 + e.r8] = 5
        e.mQ[e.r3 - 7] = 2
        e.mB[e.r5] = e.r1
        e.mH[e.r3 + 2] = e.r2
        e.mI[7 + e.r8] = e.r3
        e.mQ[e.r3 - 7] = e.r4
        e.r2 = e.mB[e.r5]
        e.r3 = e.mH[e.r3 + 2]
        e.r4 = e.mI[7 + e.r8]
        e.r5 = e.mQ[e.r3 - 7]
        e.r5 = e.mb[e.r3] >> 2
        e.r5 = e.mB[e.r3] >> 2
        self.assertEqual(e.opcodes,
            [Instruction(opcode=114, dst=5, src=0, off=0, imm=7),
             Instruction(opcode=106, dst=3, src=0, off=2, imm=3),
             Instruction(opcode=98, dst=8, src=0, off=7, imm=5),
             Instruction(opcode=122, dst=3, src=0, off=-7, imm=2),
             Instruction(opcode=115, dst=5, src=1, off=0, imm=0),
             Instruction(opcode=107, dst=3, src=2, off=2, imm=0),
             Instruction(opcode=99, dst=8, src=3, off=7, imm=0),
             Instruction(opcode=123, dst=3, src=4, off=-7, imm=0),
             Instruction(opcode=113, dst=2, src=5, off=0, imm=0),
             Instruction(opcode=105, dst=3, src=3, off=2, imm=0),
             Instruction(opcode=97, dst=4, src=8, off=7, imm=0),
             Instruction(opcode=121, dst=5, src=3, off=-7, imm=0),
             Instruction(opcode=O.B+O.LD, dst=5, src=3, off=0, imm=0),
             Instruction(opcode=O.LSH+O.LONG, dst=5, src=0, off=0, imm=56),
             Instruction(opcode=O.ARSH+O.LONG, dst=5, src=0, off=0, imm=56),
             Instruction(opcode=O.LONG+O.ARSH, dst=5, src=0, off=0, imm=2),
             Instruction(opcode=O.B+O.LD, dst=5, src=3, off=0, imm=0),
             Instruction(opcode=O.LONG+O.RSH, dst=5, src=0, off=0, imm=2),
            ])

    def test_fixed(self):
        e = EBPF()
        e.owners = {0, 1, 2, 3, 4, 5, 6}
        e.x1 = e.r2 + 3
        e.x3 = e.r4 + 3.5
        e.x5 = e.x6 + 3
        e.r1 = e.r2 + e.x3
        e.x4 = e.x5 + e.x6
        e.r1 = 2 - e.x2
        e.r3 = 3.4 - e.r4
        e.r5 = e.x6 % 4

        e.x1 = e.r2 * 3
        e.x3 = e.r4 * 3.5
        e.x5 = e.x6 * 3
        e.r1 = e.r2 * e.x3
        e.x4 = e.x5 * e.x6

        e.x1 = e.r2 / 3
        e.x3 = e.r4 / 3.5
        e.x5 = e.x6 / 3
        e.r1 = e.r2 / e.x3
        e.x4 = e.x5 / e.x6

        e.x1 = e.r2 // 3
        e.x3 = e.r4 // 3.5
        e.x5 = e.x6 // 3
        e.r1 = e.r2 // e.x3
        e.x4 = e.x5 // e.x6

        e.x1 = 3 / e.r2
        e.x3 = 3.5 / e.r4
        e.x5 = 3 / e.x6
        e.x4 = 4.5 / e.x6

        e.x1 = 3 // e.r2
        e.x3 = 3.5 // e.r4
        e.x5 = 3 // e.x6
        e.x4 = 4.5 // e.x6


        self.assertEqual(e.opcodes, [
           Instruction(opcode=O.REG+O.MOV+O.LONG, dst=1, src=2, off=0, imm=0),
           Instruction(opcode=O.ADD+O.LONG, dst=1, src=0, off=0, imm=3),
           Instruction(opcode=O.MUL+O.LONG, dst=1, src=0, off=0, imm=100000),
           Instruction(opcode=O.REG+O.MOV+O.LONG, dst=3, src=4, off=0, imm=0),
           Instruction(opcode=O.MUL+O.LONG, dst=3, src=0, off=0, imm=100000),
           Instruction(opcode=O.ADD+O.LONG, dst=3, src=0, off=0, imm=350000),
           Instruction(opcode=O.REG+O.MOV+O.LONG, dst=5, src=6, off=0, imm=0),
           Instruction(opcode=O.ADD+O.LONG, dst=5, src=0, off=0, imm=300000),
           Instruction(opcode=O.REG+O.MOV+O.LONG, dst=1, src=2, off=0, imm=0),
           Instruction(opcode=O.LONG+O.MUL, dst=1, src=0, off=0, imm=100000),
           Instruction(opcode=O.REG+O.ADD+O.LONG, dst=1, src=3, off=0, imm=0),
           Instruction(opcode=O.DIV+O.LONG, dst=1, src=0, off=0, imm=100000),
           Instruction(opcode=O.REG+O.MOV+O.LONG, dst=4, src=5, off=0, imm=0),
           Instruction(opcode=O.REG+O.ADD+O.LONG, dst=4, src=6, off=0, imm=0),
           Instruction(opcode=O.MOV+O.LONG, dst=1, src=0, off=0, imm=200000),
           Instruction(opcode=O.REG+O.SUB+O.LONG, dst=1, src=2, off=0, imm=0),
           Instruction(opcode=O.LONG+O.DIV, dst=1, src=0, off=0, imm=100000),
           Instruction(opcode=O.MOV+O.LONG, dst=3, src=0, off=0, imm=340000),
           Instruction(opcode=O.REG+O.MOV+O.LONG, dst=7, src=4, off=0, imm=0),
           Instruction(opcode=O.LONG+O.MUL, dst=7, src=0, off=0, imm=100000),
           Instruction(opcode=O.REG+O.SUB+O.LONG, dst=3, src=7, off=0, imm=0),
           Instruction(opcode=O.DIV+O.LONG, dst=3, src=0, off=0, imm=100000),
           Instruction(opcode=O.REG+O.LONG+O.MOV, dst=5, src=6, off=0, imm=0),
           Instruction(opcode=O.LONG+O.MOD, dst=5, src=0, off=0, imm=400000),
           Instruction(opcode=O.LONG+O.DIV, dst=5, src=0, off=0, imm=100000),

           Instruction(opcode=O.REG+O.MOV+O.LONG, dst=1, src=2, off=0, imm=0),
           Instruction(opcode=O.LONG+O.MUL, dst=1, src=0, off=0, imm=3),
           Instruction(opcode=O.LONG+O.MUL, dst=1, src=0, off=0, imm=100000),
           Instruction(opcode=O.REG+O.MOV+O.LONG, dst=3, src=4, off=0, imm=0),
           Instruction(opcode=O.LONG+O.MUL, dst=3, src=0, off=0, imm=350000),
           Instruction(opcode=O.REG+O.MOV+O.LONG, dst=5, src=6, off=0, imm=0),
           Instruction(opcode=O.LONG+O.MUL, dst=5, src=0, off=0, imm=3),
           Instruction(opcode=O.REG+O.MOV+O.LONG, dst=1, src=2, off=0, imm=0),
           Instruction(opcode=O.REG+O.LONG+O.MUL, dst=1, src=3, off=0, imm=0),
           Instruction(opcode=O.DIV+O.LONG, dst=1, src=0, off=0, imm=100000),
           Instruction(opcode=O.REG+O.MOV+O.LONG, dst=4, src=5, off=0, imm=0),
           Instruction(opcode=O.REG+O.LONG+O.MUL, dst=4, src=6, off=0, imm=0),
           Instruction(opcode=O.DIV+O.LONG, dst=4, src=0, off=0, imm=100000),

           Instruction(opcode=O.LONG+O.REG+O.MOV, dst=1, src=2, off=0, imm=0),
           Instruction(opcode=O.MUL+O.LONG, dst=1, src=0, off=0, imm=100000),
           Instruction(opcode=O.DIV+O.LONG, dst=1, src=0, off=0, imm=3),
           Instruction(opcode=O.LONG+O.REG+O.MOV, dst=3, src=4, off=0, imm=0),
           Instruction(opcode=O.DW, dst=7, src=0, off=0, imm=1410065408),
           Instruction(opcode=O.W, dst=0, src=0, off=0, imm=2),
           Instruction(opcode=O.MUL+O.REG+O.LONG, dst=3, src=7, off=0, imm=0),
           Instruction(opcode=O.DIV+O.LONG, dst=3, src=0, off=0, imm=350000),
           Instruction(opcode=O.LONG+O.REG+O.MOV, dst=5, src=6, off=0, imm=0),
           Instruction(opcode=O.DIV+O.LONG, dst=5, src=0, off=0, imm=3),
           Instruction(opcode=O.LONG+O.REG+O.MOV, dst=1, src=2, off=0, imm=0),
           Instruction(opcode=O.DW, dst=7, src=0, off=0, imm=1410065408),
           Instruction(opcode=O.W, dst=0, src=0, off=0, imm=2),
           Instruction(opcode=O.REG+O.LONG+O.MUL, dst=1, src=7, off=0, imm=0),
           Instruction(opcode=O.DIV+O.LONG+O.REG, dst=1, src=3, off=0, imm=0),
           Instruction(opcode=O.DIV+O.LONG, dst=1, src=0, off=0, imm=100000),
           Instruction(opcode=O.LONG+O.REG+O.MOV, dst=4, src=5, off=0, imm=0),
           Instruction(opcode=O.MUL+O.LONG, dst=4, src=0, off=0, imm=100000),
           Instruction(opcode=O.DIV+O.LONG+O.REG, dst=4, src=6, off=0, imm=0),

           Instruction(opcode=O.LONG+O.REG+O.MOV, dst=1, src=2, off=0, imm=0),
           Instruction(opcode=O.DIV+O.LONG, dst=1, src=0, off=0, imm=3),
           Instruction(opcode=O.MUL+O.LONG, dst=1, src=0, off=0, imm=100000),
           Instruction(opcode=O.LONG+O.REG+O.MOV, dst=3, src=4, off=0, imm=0),
           Instruction(opcode=O.MUL+O.LONG, dst=3, src=0, off=0, imm=100000),
           Instruction(opcode=O.DIV+O.LONG, dst=3, src=0, off=0, imm=350000),
           Instruction(opcode=O.MUL+O.LONG, dst=3, src=0, off=0, imm=100000),
           Instruction(opcode=O.LONG+O.REG+O.MOV, dst=5, src=6, off=0, imm=0),
           Instruction(opcode=O.DIV+O.LONG, dst=5, src=0, off=0, imm=300000),
           Instruction(opcode=O.MUL+O.LONG, dst=5, src=0, off=0, imm=100000),
           Instruction(opcode=O.LONG+O.REG+O.MOV, dst=1, src=2, off=0, imm=0),
           Instruction(opcode=O.MUL+O.LONG, dst=1, src=0, off=0, imm=100000),
           Instruction(opcode=O.DIV+O.LONG+O.REG, dst=1, src=3, off=0, imm=0),
           Instruction(opcode=O.LONG+O.REG+O.MOV, dst=4, src=5, off=0, imm=0),
           Instruction(opcode=O.DIV+O.LONG+O.REG, dst=4, src=6, off=0, imm=0),
           Instruction(opcode=O.LONG+O.MUL, dst=4, src=0, off=0, imm=100000),

           Instruction(opcode=O.LONG+O.MOV, dst=1, src=0, off=0, imm=300000),
           Instruction(opcode=O.DIV+O.REG+O.LONG, dst=1, src=2, off=0, imm=0),
           Instruction(opcode=O.LONG+O.MOV, dst=3, src=0, off=0, imm=350000),
           Instruction(opcode=O.DIV+O.REG+O.LONG, dst=3, src=4, off=0, imm=0),
           Instruction(opcode=O.DW, dst=5, src=0, off=0, imm=4230196224),
           Instruction(opcode=O.W, dst=0, src=0, off=0, imm=6),
           Instruction(opcode=O.DIV+O.REG+O.LONG, dst=5, src=6, off=0, imm=0),
           Instruction(opcode=O.DW, dst=4, src=0, off=0, imm=2050327040),
           Instruction(opcode=O.W, dst=0, src=0, off=0, imm=10),
           Instruction(opcode=O.DIV+O.REG+O.LONG, dst=4, src=6, off=0, imm=0),
           Instruction(opcode=O.LONG+O.MOV, dst=1, src=0, off=0, imm=3),
           Instruction(opcode=O.DIV+O.REG+O.LONG, dst=1, src=2, off=0, imm=0),
           Instruction(opcode=O.LONG+O.MUL, dst=1, src=0, off=0, imm=100000),
           Instruction(opcode=O.MOV+O.LONG, dst=3, src=0, off=0, imm=3),
           Instruction(opcode=O.REG+O.LONG+O.DIV, dst=3, src=4, off=0, imm=0),
           Instruction(opcode=O.LONG+O.MUL, dst=3, src=0, off=0, imm=100000),
           Instruction(opcode=O.LONG+O.MOV, dst=5, src=0, off=0, imm=300000),
           Instruction(opcode=O.DIV+O.REG+O.LONG, dst=5, src=6, off=0, imm=0),
           Instruction(opcode=O.LONG+O.MUL, dst=5, src=0, off=0, imm=100000),
           Instruction(opcode=O.LONG+O.MOV, dst=4, src=0, off=0, imm=450000),
           Instruction(opcode=O.DIV+O.REG+O.LONG, dst=4, src=6, off=0, imm=0),
           Instruction(opcode=O.LONG+O.MUL, dst=4, src=0, off=0, imm=100000),
        ])

    def test_local(self):
        class Local(EBPF):
            a = LocalVar('b')
            b = LocalVar('H')
            c = LocalVar('i')
            d = LocalVar('Q')
            lx = LocalVar('x')

        e = Local(ProgType.XDP, "GPL")
        e.a = 5
        e.b = e.c >> 3
        e.d = e.r1
        e.lx = 7
        e.b = e.x1

        self.assertEqual(e.opcodes, [
            Instruction(opcode=O.B+O.ST, dst=10, src=0, off=-1, imm=5),
            Instruction(opcode=O.W+O.LD, dst=0, src=10, off=-8, imm=0),
            Instruction(opcode=O.ARSH, dst=0, src=0, off=0, imm=3),
            Instruction(opcode=O.REG+O.STX, dst=10, src=0, off=-4, imm=0),
            Instruction(opcode=O.DW+O.STX, dst=10, src=1, off=-16, imm=0),
            Instruction(opcode=O.DW+O.ST, dst=10, src=0, off=-24, imm=700000),
            Instruction(opcode=O.LONG+O.REG+O.MOV, dst=0, src=1, off=0, imm=0),
            Instruction(opcode=O.DIV, dst=0, src=0, off=0, imm=100000),
            Instruction(opcode=O.REG+O.STX, dst=10, src=0, off=-4, imm=0),
        ])

    def test_local_bits(self):
        class Local(EBPF):
            a = LocalVar((5, 1))
            b = LocalVar((3, 4))

        e = Local(ProgType.XDP, "GPL")

        with e.a:
            e.a = 1

        e.b = e.a

        with ~e.a:
            e.b = 3

        with e.b:
            e.a = 0

        e.a = e.b

        self.assertEqual(e.opcodes, [
           Instruction(opcode=O.LD+O.B, dst=0, src=10, off=-1, imm=0),
            Instruction(opcode=O.JSET, dst=0, src=0, off=1, imm=32),
            Instruction(opcode=O.JMP, dst=0, src=0, off=3, imm=0),
            Instruction(opcode=O.LD+O.B, dst=0, src=10, off=-1, imm=0),
            Instruction(opcode=O.OR, dst=0, src=0, off=0, imm=32),
            Instruction(opcode=O.B+O.STX, dst=10, src=0, off=-1, imm=0),
            Instruction(opcode=O.LD+O.B, dst=0, src=10, off=-1, imm=0),
            Instruction(opcode=O.AND+O.LONG, dst=0, src=0, off=0, imm=32),
            Instruction(opcode=O.RSH+O.LONG, dst=0, src=0, off=0, imm=5),
            Instruction(opcode=O.LSH, dst=0, src=0, off=0, imm=3),
            Instruction(opcode=O.AND, dst=0, src=0, off=0, imm=120),
            Instruction(opcode=O.LD+O.B, dst=2, src=10, off=-2, imm=0),
            Instruction(opcode=O.AND, dst=2, src=0, off=0, imm=-121),
            Instruction(opcode=O.REG+O.OR, dst=0, src=2, off=0, imm=0),
            Instruction(opcode=O.B+O.STX, dst=10, src=0, off=-2, imm=0),
            Instruction(opcode=O.LD+O.B, dst=0, src=10, off=-1, imm=0),
            Instruction(opcode=O.JSET, dst=0, src=0, off=4, imm=32),
            Instruction(opcode=O.LD+O.B, dst=0, src=10, off=-2, imm=0),
            Instruction(opcode=O.AND, dst=0, src=0, off=0, imm=-121),
            Instruction(opcode=O.OR, dst=0, src=0, off=0, imm=24),
            Instruction(opcode=O.B+O.STX, dst=10, src=0, off=-2, imm=0),
            Instruction(opcode=O.LD+O.B, dst=0, src=10, off=-2, imm=0),
            Instruction(opcode=O.JSET, dst=0, src=0, off=1, imm=120),
            Instruction(opcode=O.JMP, dst=0, src=0, off=3, imm=0),
            Instruction(opcode=O.LD+O.B, dst=0, src=10, off=-1, imm=0),
            Instruction(opcode=O.AND, dst=0, src=0, off=0, imm=-33),
            Instruction(opcode=O.STX+O.B, dst=10, src=0, off=-1, imm=0),
            Instruction(opcode=O.LD+O.B, dst=2, src=10, off=-2, imm=0),
            Instruction(opcode=O.JSET, dst=2, src=0, off=3, imm=120),
            Instruction(opcode=O.LD+O.B, dst=0, src=10, off=-1, imm=0),
            Instruction(opcode=O.AND, dst=0, src=0, off=0, imm=-33),
            Instruction(opcode=O.JMP, dst=0, src=0, off=2, imm=0),
            Instruction(opcode=O.LD+O.B, dst=0, src=10, off=-1, imm=0),
            Instruction(opcode=O.OR, dst=0, src=0, off=0, imm=32),
            Instruction(opcode=O.B+O.STX, dst=10, src=0, off=-1, imm=0)])

    def test_bits_and_or(self):
        class Local(EBPF):
            a = LocalVar((5, 1))

        e = Local(ProgType.XDP, "GPL")

        with e.stmp:
            with (e.a != 0) & (e.stmp > 0) | (e.a == 0) & (e.stmp < 0):
                e.stmp = 0

        self.assertEqual(e.opcodes, [
            Instruction(opcode=O.LD+O.B, dst=2, src=10, off=-1, imm=0),
            Instruction(opcode=O.JSET, dst=2, src=0, off=1, imm=32),
            Instruction(opcode=O.JMP, dst=0, src=0, off=1, imm=0),
            Instruction(opcode=O.JSGT, dst=0, src=0, off=3, imm=0),
            Instruction(opcode=O.LD+O.B, dst=2, src=10, off=-1, imm=0),
            Instruction(opcode=O.JSET, dst=2, src=0, off=2, imm=32),
            Instruction(opcode=O.JSGE, dst=0, src=0, off=1, imm=0),
            Instruction(opcode=O.MOV+O.LONG, dst=0, src=0, off=0, imm=0),
            ])

    def test_local_subprog(self):
        class Local(EBPF):
            a = LocalVar('I')

        class Sub(SubProgram):
            b = LocalVar('I')

            def program(self):
                self.b *= 3

        s1 = Sub()
        s2 = Sub()
        e = Local(ProgType.XDP, "GPL", subprograms=[s1, s2])
        e.a = 5
        s1.b = 3
        e.r3 = s1.b
        s2.b = 7
        self.assertEqual(e.opcodes, [
            Instruction(opcode=O.W+O.ST, dst=10, src=0, off=-4, imm=5),
            Instruction(opcode=O.W+O.ST, dst=10, src=0, off=-12, imm=3),
            Instruction(opcode=O.W+O.LD, dst=3, src=10, off=-12, imm=0),
            Instruction(opcode=O.W+O.ST, dst=10, src=0, off=-12, imm=7)])

    def test_sign_extend(self):
        class Local(EBPF):
            a = LocalVar('b')
            b = LocalVar('H')
            c = LocalVar('i')
            d = LocalVar('Q')

        e = Local(ProgType.XDP, "GPL")
        e.b = e.a + e.c
        e.d = e.b + e.c

        self.assertEqual(e.opcodes, [
            Instruction(opcode=O.LD+O.B, dst=0, src=10, off=-1, imm=0),
            Instruction(opcode=O.LSH, dst=0, src=0, off=0, imm=24),
            Instruction(opcode=O.ARSH, dst=0, src=0, off=0, imm=24),
            Instruction(opcode=O.W+O.LD, dst=2, src=10, off=-8, imm=0),
            Instruction(opcode=O.REG+O.ADD, dst=0, src=2, off=0, imm=0),
            Instruction(opcode=O.REG+O.STX, dst=10, src=0, off=-4, imm=0),
            Instruction(opcode=O.REG+O.LD, dst=0, src=10, off=-4, imm=0),
            Instruction(opcode=O.W+O.LD, dst=2, src=10, off=-8, imm=0),
            Instruction(opcode=O.LSH+O.LONG, dst=2, src=0, off=0, imm=32),
            Instruction(opcode=O.ARSH+O.LONG, dst=2, src=0, off=0, imm=32),
            Instruction(opcode=O.REG+O.ADD+O.LONG, dst=0, src=2, off=0, imm=0),
            Instruction(opcode=O.STX+O.DW, dst=10, src=0, off=-16, imm=0),
        ])

    def test_lock_add(self):
        class Local(EBPF):
            a = LocalVar('I')
            b = LocalVar('q')
            c = LocalVar('h')
            d = LocalVar('x')

        e = Local(ProgType.XDP, "GPL")
        e.a += 3
        e.mI[e.r1] += e.r1
        e.a -= 3
        e.b += 3
        e.mQ[e.r1] += e.r1

        # do not generate XADD for bytes and words
        e.c += 3
        e.mB[e.r1] += e.r1

        e.d -= 5
        e.d += e.r1

        self.assertEqual(e.opcodes, [
           Instruction(opcode=O.LONG+O.MOV, dst=0, src=0, off=0, imm=3),
           Instruction(opcode=O.XADD+O.W, dst=10, src=0, off=-4, imm=0),
           Instruction(opcode=O.XADD+O.W, dst=1, src=1, off=0, imm=0),
           Instruction(opcode=O.LONG+O.MOV, dst=0, src=0, off=0, imm=-3),
           Instruction(opcode=O.XADD+O.W, dst=10, src=0, off=-4, imm=0),
           Instruction(opcode=O.LONG+O.MOV, dst=0, src=0, off=0, imm=3),
           Instruction(opcode=O.XADD+O.DW, dst=10, src=0, off=-16, imm=0),
           Instruction(opcode=O.XADD+O.DW, dst=1, src=1, off=0, imm=0),
           Instruction(opcode=O.LD+O.REG, dst=0, src=10, off=-18, imm=0),
           Instruction(opcode=O.LSH, dst=0, src=0, off=0, imm=16),
           Instruction(opcode=O.ARSH, dst=0, src=0, off=0, imm=16),
           Instruction(opcode=O.ADD, dst=0, src=0, off=0, imm=3),
           Instruction(opcode=O.STX+O.REG, dst=10, src=0, off=-18, imm=0),
           Instruction(opcode=O.B+O.LD, dst=0, src=1, off=0, imm=0),
           Instruction(opcode=O.ADD+O.REG, dst=0, src=1, off=0, imm=0),
           Instruction(opcode=O.STX+O.B, dst=1, src=0, off=0, imm=0),
           Instruction(opcode=O.LONG+O.MOV, dst=0, src=0, off=0, imm=-500000),
           Instruction(opcode=O.XADD+O.DW, dst=10, src=0, off=-32, imm=0),
           Instruction(opcode=O.REG+O.LONG+O.MOV, dst=0, src=1, off=0, imm=0),
           Instruction(opcode=O.MUL+O.LONG, dst=0, src=0, off=0, imm=100000),
           Instruction(opcode=O.XADD+O.DW, dst=10, src=0, off=-32, imm=0),
        ])


    def test_jump(self):
        e = EBPF()
        e.owners = set(range(11))
        target = e.jump()
        e.r0 = 1
        target.target()
        t1 = e.jumpIf(e.r5 > 3)
        t2 = e.jumpIf(e.r1 > e.r2)
        t3 = e.jumpIf(e.r7 >= 2)
        t4 = e.jumpIf(e.r4 >= e.r3)
        e.r0 = 1
        t1.target()
        t2.target()
        t3.target()
        t4.target()
        t1 = e.jumpIf(e.r5 < 3)
        t2 = e.jumpIf(e.r1 < e.r2)
        t3 = e.jumpIf(e.r7 <= 2)
        t4 = e.jumpIf(e.r4 <= e.r3)
        e.r0 = 1
        t1.target()
        t2.target()
        t3.target()
        t4.target()
        t1 = e.jumpIf(e.sr5 > 3)
        t2 = e.jumpIf(e.sr1 > e.sr2)
        t3 = e.jumpIf(e.sr7 >= 2)
        t4 = e.jumpIf(e.sr4 >= e.sr3)
        e.r0 = 1
        t1.target()
        t2.target()
        t3.target()
        t4.target()
        t1 = e.jumpIf(e.sr5 < 3)
        t2 = e.jumpIf(e.sr1 < e.sr2)
        t3 = e.jumpIf(e.sr7 <= 2)
        t4 = e.jumpIf(e.sr4 <= e.sr3)
        e.r0 = 1
        t1.target()
        t2.target()
        t3.target()
        t4.target()
        t1 = e.jumpIf(e.sr5 == 3)
        t2 = e.jumpIf(e.sr1 == e.sr2)
        t3 = e.jumpIf(e.sr7 != 2)
        t4 = e.jumpIf(e.sr4 != e.sr3)
        e.r0 = 1
        t1.target()
        t2.target()
        t3.target()
        t4.target()
        t1 = e.jumpIf(e.sr5 & 3)
        t2 = e.jumpIf(e.sr1 & e.sr2)
        e.r0 = 1
        t1.target()
        t2.target()
        self.assertEqual(e.opcodes,
            [Instruction(opcode=5, dst=0, src=0, off=1, imm=0),
             Instruction(opcode=0xb7, dst=0, src=0, off=0, imm=1),
             Instruction(opcode=0x25, dst=5, src=0, off=4, imm=3),
             Instruction(opcode=0x2d, dst=1, src=2, off=3, imm=0),
             Instruction(opcode=0x35, dst=7, src=0, off=2, imm=2),
             Instruction(opcode=0x3d, dst=4, src=3, off=1, imm=0),
             Instruction(opcode=0xb7, dst=0, src=0, off=0, imm=1),
             Instruction(opcode=0xa5, dst=5, src=0, off=4, imm=3),
             Instruction(opcode=0xad, dst=1, src=2, off=3, imm=0),
             Instruction(opcode=0xb5, dst=7, src=0, off=2, imm=2),
             Instruction(opcode=0xbd, dst=4, src=3, off=1, imm=0),
             Instruction(opcode=0xb7, dst=0, src=0, off=0, imm=1),
             Instruction(opcode=0x65, dst=5, src=0, off=4, imm=3),
             Instruction(opcode=0x6d, dst=1, src=2, off=3, imm=0),
             Instruction(opcode=0x75, dst=7, src=0, off=2, imm=2),
             Instruction(opcode=0x7d, dst=4, src=3, off=1, imm=0),
             Instruction(opcode=0xb7, dst=0, src=0, off=0, imm=1),
             Instruction(opcode=0xc5, dst=5, src=0, off=4, imm=3),
             Instruction(opcode=0xcd, dst=1, src=2, off=3, imm=0),
             Instruction(opcode=0xd5, dst=7, src=0, off=2, imm=2),
             Instruction(opcode=0xdd, dst=4, src=3, off=1, imm=0),
             Instruction(opcode=0xb7, dst=0, src=0, off=0, imm=1),
             Instruction(opcode=0x15, dst=5, src=0, off=4, imm=3),
             Instruction(opcode=0x1d, dst=1, src=2, off=3, imm=0),
             Instruction(opcode=0x55, dst=7, src=0, off=2, imm=2),
             Instruction(opcode=0x5d, dst=4, src=3, off=1, imm=0),
             Instruction(opcode=0xb7, dst=0, src=0, off=0, imm=1),
             Instruction(opcode=0x45, dst=5, src=0, off=2, imm=3),
             Instruction(opcode=0x4d, dst=1, src=2, off=1, imm=0),
             Instruction(opcode=0xb7, dst=0, src=0, off=0, imm=1)])

    def test_with(self):
        e = EBPF()
        e.owners = set(range(9))
        with e.r2 > 3 as Else:
            e.r2 = 5
        with Else:
            e.r6 = 7
        with e.r2:
            e.r3 = 2
        with e.r4 > 3 as Else:
            e.r5 = 7
        with Else:
            e.r7 = 8
        with e.x4 > 3:
            pass
        with 3 > e.x4:
            pass
        with e.r4 > 3.5:
            pass
        with e.x4 > e.x2:
            pass
        self.assertEqual(e.opcodes, [
             Instruction(opcode=0xb5, dst=2, src=0, off=2, imm=3),
             Instruction(opcode=0xb7, dst=2, src=0, off=0, imm=5),
             Instruction(opcode=0x5, dst=0, src=0, off=1, imm=0),
             Instruction(opcode=O.MOV+O.LONG, dst=6, src=0, off=0, imm=7),
             Instruction(opcode=O.JEQ, dst=2, src=0, off=1, imm=0),
             Instruction(opcode=O.MOV+O.LONG, dst=3, src=0, off=0, imm=2),
             Instruction(opcode=O.JLE, dst=4, src=0, off=2, imm=3),
             Instruction(opcode=O.MOV+O.LONG, dst=5, src=0, off=0, imm=7),
             Instruction(opcode=O.JMP, dst=0, src=0, off=1, imm=0),
             Instruction(opcode=O.MOV+O.LONG, dst=7, src=0, off=0, imm=8),
             Instruction(opcode=O.JSLE, dst=4, src=0, off=0, imm=300000),
             Instruction(opcode=O.JSGE, dst=4, src=0, off=0, imm=300000),
             Instruction(opcode=O.REG+O.MOV+O.LONG, dst=9, src=4, off=0, imm=0),
             Instruction(opcode=O.MUL+O.LONG, dst=9, src=0, off=0, imm=100000),
             Instruction(opcode=O.JLE, dst=9, src=0, off=0, imm=350000),
             Instruction(opcode=O.REG+O.JSLE, dst=4, src=2, off=0, imm=0),
        ])

    def test_with_inversion(self):
        e = EBPF()
        with e.r1 & 1 as cond:
            e.r0 = 2
        with e.r1 & 7 as Else:
            e.r0 = 2
            e.r1 = 4
        with Else:
            e.r0 = 3
        self.assertEqual(e.opcodes, [
            Instruction(opcode=69, dst=1, src=0, off=1, imm=1),
            Instruction(opcode=5, dst=0, src=0, off=1, imm=0),
            Instruction(opcode=183, dst=0, src=0, off=0, imm=2),
            Instruction(opcode=69, dst=1, src=0, off=2, imm=7),
            Instruction(opcode=183, dst=0, src=0, off=0, imm=3),
            Instruction(opcode=5, dst=0, src=0, off=2, imm=0),
            Instruction(opcode=183, dst=0, src=0, off=0, imm=2),
            Instruction(opcode=183, dst=1, src=0, off=0, imm=4)])

    def test_with_and(self):
        e = EBPF()
        e.owners = set(range(11))
        with (e.r2 > 3) & (e.r3 > 2) as Else:
            e.r1 = 5
        with (e.r2 > 2) & (e.r1 < 2) as Else:
            e.r2 = 5
        with Else:
            e.r3 = 7
        self.assertEqual(e.opcodes, [
            Instruction(opcode=O.JLE, dst=2, src=0, off=2, imm=3),
            Instruction(opcode=O.JLE, dst=3, src=0, off=1, imm=2),
            Instruction(opcode=O.MOV+O.LONG, dst=1, src=0, off=0, imm=5),
            Instruction(opcode=O.JLE, dst=2, src=0, off=3, imm=2),
            Instruction(opcode=O.JGE, dst=1, src=0, off=2, imm=2),
            Instruction(opcode=O.MOV+O.LONG, dst=2, src=0, off=0, imm=5),
            Instruction(opcode=O.JMP, dst=0, src=0, off=1, imm=0),
            Instruction(opcode=O.MOV+O.LONG, dst=3, src=0, off=0, imm=7)])

    def test_with_or(self):
        e = EBPF()
        e.owners = set(range(11))
        with (e.r2 > 3) | (e.r3 > 2) as Else:
            e.r1 = 5
        with (e.r2 > 2) | (e.r1 > 2) as Else:
            e.r2 = 5
            e.r5 = 4
        with Else:
            e.r3 = 7
            e.r4 = 3
        self.assertEqual(e.opcodes, [
            Instruction(opcode=O.JGT, dst=2, src=0, off=1, imm=3),
            Instruction(opcode=O.JLE, dst=3, src=0, off=1, imm=2),
            Instruction(opcode=O.MOV+O.LONG, dst=1, src=0, off=0, imm=5),
            Instruction(opcode=O.JGT, dst=2, src=0, off=1, imm=2),
            Instruction(opcode=O.JLE, dst=1, src=0, off=3, imm=2),
            Instruction(opcode=O.MOV+O.LONG, dst=2, src=0, off=0, imm=5),
            Instruction(opcode=O.MOV+O.LONG, dst=5, src=0, off=0, imm=4),
            Instruction(opcode=O.JMP, dst=0, src=0, off=2, imm=0),
            Instruction(opcode=O.MOV+O.LONG, dst=3, src=0, off=0, imm=7),
            Instruction(opcode=O.MOV+O.LONG, dst=4, src=0, off=0, imm=3)])

    def test_comp_binary(self):
        e = EBPF()
        e.owners = {1, 2, 3, 5}
        with e.r1 + e.r3 > 3 as Else:
            e.r0 = 5
        with Else:
            e.r0 = 7

        tgt = e.jumpIf(e.r0 < e.r2 + e.r5)
        e.r0 = 8
        tgt.target()

        self.assertEqual(e.opcodes, [
            Instruction(opcode=191, dst=0, src=1, off=0, imm=0),
            Instruction(opcode=O.ADD+O.REG+O.LONG, dst=0, src=3, off=0, imm=0),
            Instruction(opcode=181, dst=0, src=0, off=2, imm=3),
            Instruction(opcode=183, dst=0, src=0, off=0, imm=5),
            Instruction(opcode=5, dst=0, src=0, off=1, imm=0),
            Instruction(opcode=183, dst=0, src=0, off=0, imm=7),
            Instruction(opcode=191, dst=4, src=2, off=0, imm=0),
            Instruction(opcode=15, dst=4, src=5, off=0, imm=0),
            Instruction(opcode=173, dst=0, src=4, off=1, imm=0),
            Instruction(opcode=183, dst=0, src=0, off=0, imm=8)])

    def test_huge(self):
        e = EBPF()
        e.r3 = 0x1234567890
        e.r4 = e.get_fd(7)
        e.r3 = e.r4 + 0x1234567890
        e.r3 = 0x90000000

        self.assertEqual(e.opcodes, [
            Instruction(opcode=24, dst=3, src=0, off=0, imm=878082192),
            Instruction(opcode=0, dst=0, src=0, off=0, imm=18),
            Instruction(opcode=24, dst=4, src=1, off=0, imm=7),
            Instruction(opcode=0, dst=0, src=0, off=0, imm=0),
            Instruction(opcode=O.REG+O.LONG+O.MOV, dst=3, src=4, off=0, imm=0),
            Instruction(opcode=O.DW, dst=0, src=0, off=0, imm=878082192),
            Instruction(opcode=O.W, dst=0, src=0, off=0, imm=18),
            Instruction(opcode=O.LONG+O.REG+O.ADD, dst=3, src=0, off=0, imm=0),
            Instruction(opcode=O.DW, dst=3, src=0, off=0, imm=2415919104),
            Instruction(opcode=O.W, dst=0, src=0, off=0, imm=0),

        ])

    def test_simple_binary(self):
        e = EBPF()
        e.owners = {0, 1, 2, 3}
        e.r0 = e.r1 * e.r2 + e.r3
        e.r0 = e.r1 * e.r2 + 3
        e.r0 = e.r1 * 2 + 3
        e.r0 = 2 * e.r1 + 3
        e.r0 = 3 + 2 * e.r1
        e.sr0 = e.sr1 >> 2
        e.sr0 = e.sr1 >> e.r2
        e.w0 = e.w1 + e.w2
        e.r0 = e.r1 & e.r2  # attention, special case
        self.assertEqual(e.opcodes, [
            Instruction(opcode=191, dst=0, src=1, off=0, imm=0),
            Instruction(opcode=47, dst=0, src=2, off=0, imm=0),
            Instruction(opcode=15, dst=0, src=3, off=0, imm=0),
            Instruction(opcode=191, dst=0, src=1, off=0, imm=0),
            Instruction(opcode=47, dst=0, src=2, off=0, imm=0),
            Instruction(opcode=7, dst=0, src=0, off=0, imm=3),
            Instruction(opcode=191, dst=0, src=1, off=0, imm=0),
            Instruction(opcode=39, dst=0, src=0, off=0, imm=2),
            Instruction(opcode=7, dst=0, src=0, off=0, imm=3),
            Instruction(opcode=191, dst=0, src=1, off=0, imm=0),
            Instruction(opcode=39, dst=0, src=0, off=0, imm=2),
            Instruction(opcode=7, dst=0, src=0, off=0, imm=3),
            Instruction(opcode=191, dst=0, src=1, off=0, imm=0),
            Instruction(opcode=39, dst=0, src=0, off=0, imm=2),
            Instruction(opcode=7, dst=0, src=0, off=0, imm=3),
            Instruction(opcode=191, dst=0, src=1, off=0, imm=0),
            Instruction(opcode=199, dst=0, src=0, off=0, imm=2),
            Instruction(opcode=191, dst=0, src=1, off=0, imm=0),
            Instruction(opcode=207, dst=0, src=2, off=0, imm=0),
            Instruction(opcode=188, dst=0, src=1, off=0, imm=0),
            Instruction(opcode=12, dst=0, src=2, off=0, imm=0),
            Instruction(opcode=191, dst=0, src=1, off=0, imm=0),
            Instruction(opcode=95, dst=0, src=2, off=0, imm=0)])

    def test_mixed_binary(self):
        e = EBPF()
        e.owners = {0, 1, 2, 3}
        e.w1 = e.r2 + e.w3
        e.r1 = e.w2 + e.w3
        e.w1 = e.w2 + e.w3
        self.assertEqual(e.opcodes, [
            Instruction(opcode=O.MOV+O.LONG+O.REG, dst=1, src=2, off=0, imm=0),
            Instruction(opcode=O.REG+O.ADD, dst=1, src=3, off=0, imm=0),
            Instruction(opcode=O.MOV+O.REG, dst=1, src=2, off=0, imm=0),
            Instruction(opcode=O.LONG+O.REG+O.ADD, dst=1, src=3, off=0, imm=0),
            Instruction(opcode=O.MOV+O.REG, dst=1, src=2, off=0, imm=0),
            Instruction(opcode=O.REG+O.ADD, dst=1, src=3, off=0, imm=0)])

    def test_mixed_compare(self):
        e = EBPF()
        e.owners = {0, 1, 2, 3}
        with e.r1 > e.sr2:
            pass
        with (e.r1 + e.sr2) > 3:
            pass
        self.assertEqual(e.opcodes, [
            Instruction(opcode=O.JSLE+O.REG, dst=1, src=2, off=0, imm=0),
            Instruction(opcode=O.MOV+O.LONG+O.REG, dst=4, src=1, off=0, imm=0),
            Instruction(opcode=O.ADD+O.LONG+O.REG, dst=4, src=2, off=0, imm=0),
            Instruction(opcode=O.JSLE, dst=4, src=0, off=0, imm=3)])


    def test_reverse_binary(self):
        e = EBPF()
        e.owners = {0, 1, 2, 3}
        e.r3 = 7 // (e.r2 + 2)
        e.r3 = 7 << e.r2
        e.r3 = 7 % (e.r2 + 3)
        e.r3 = 7 >> e.r2
        e.r3 = -7 >> e.r2
        self.assertEqual(e.opcodes, [
            Instruction(opcode=O.MOV+O.LONG, dst=3, src=0, off=0, imm=7),
            Instruction(opcode=O.REG+O.LONG+O.MOV, dst=4, src=2, off=0, imm=0),
            Instruction(opcode=O.ADD+O.LONG, dst=4, src=0, off=0, imm=2),
            Instruction(opcode=O.REG+O.LONG+O.DIV, dst=3, src=4, off=0, imm=0),
            Instruction(opcode=O.MOV+O.LONG, dst=3, src=0, off=0, imm=7),
            Instruction(opcode=O.LSH+O.REG+O.LONG, dst=3, src=2, off=0, imm=0),
            Instruction(opcode=O.MOV+O.LONG, dst=3, src=0, off=0, imm=7),
            Instruction(opcode=O.MOV+O.LONG+O.REG, dst=4, src=2, off=0, imm=0),
            Instruction(opcode=O.ADD+O.LONG, dst=4, src=0, off=0, imm=3),
            Instruction(opcode=O.REG+O.MOD+O.LONG, dst=3, src=4, off=0, imm=0),
            Instruction(opcode=O.MOV+O.LONG, dst=3, src=0, off=0, imm=7),
            Instruction(opcode=O.REG+O.RSH+O.LONG, dst=3, src=2, off=0, imm=0),
            Instruction(opcode=O.MOV+O.LONG, dst=3, src=0, off=0, imm=-7),
            Instruction(opcode=O.REG+O.LONG+O.ARSH, dst=3, src=2, off=0, imm=0)
            ])

    def test_negation(self):
        e = EBPF()
        e.r7 = -e.r1
        self.assertEqual(e.opcodes, [
            Instruction(opcode=O.LONG+O.REG+O.MOV, dst=7, src=1, off=0, imm=0),
            Instruction(opcode=O.LONG+O.NEG, dst=7, src=0, off=0, imm=0)])

    def test_absolute(self):
        e = EBPF()
        e.r7 = abs(e.r1)
        e.x3 = abs(e.x1)
        self.assertEqual(e.opcodes, [
            Instruction(opcode=O.LONG+O.REG+O.MOV, dst=7, src=1, off=0, imm=0),
            Instruction(opcode=O.JSGE, dst=7, src=0, off=1, imm=0),
            Instruction(opcode=O.LONG+O.NEG, dst=7, src=0, off=0, imm=0),
            Instruction(opcode=O.REG+O.MOV+O.LONG, dst=3, src=1, off=0, imm=0),
            Instruction(opcode=O.JSGE, dst=3, src=0, off=1, imm=0),
            Instruction(opcode=O.NEG+O.LONG, dst=3, src=0, off=0, imm=0),
        ])

    def test_jump_data(self):
        e = EBPF()
        t1 = e.jumpIf(e.r1 > 0)
        e.r2 = 3
        e.r3 = 5
        t2 = e.jump()

        t1.target()
        with self.assertRaises(AssembleError):
            e.r0 = e.r2
        e.r3 = 5
        e.r4 = 7
        t2.target()
        e.r0 = e.r3
        with self.assertRaises(AssembleError):
            e.r0 = e.r2
        with self.assertRaises(AssembleError):
            e.r0 = e.r4

    def test_with_data(self):
        e = EBPF()
        with e.r1 > 0 as Else:
            e.r2 = 3
            e.r3 = 5
        with Else:
            with self.assertRaises(AssembleError):
                e.r0 = e.r2
            e.r3 = 5
            e.r4 = 7
        e.r0 = e.r3
        with self.assertRaises(AssembleError):
            e.r0 = e.r2
        with self.assertRaises(AssembleError):
            e.r0 = e.r4

    def test_call(self):
        e = EBPF()
        e.r8 = 23
        e.call(FuncId.ktime_get_ns)
        self.assertEqual(e.opcodes, [
            Instruction(opcode=183, dst=8, src=0, off=0, imm=23),
            Instruction(opcode=133, dst=0, src=0, off=0, imm=5)])
        e.r7 = e.r0
        e.r5 = e.r8
        with self.assertRaises(AssembleError):
            e.r8 = e.r3
        with self.assertRaises(AssembleError):
            e.r8 = e.r1

    def test_binary_alloc(self):
        e = EBPF()
        e.r3 = e.r1 - (2 * e.r10)
        e.mH[e.r10 - 10] = 2 * e.r3
        e.mH[e.r10 + e.r3] = 2 * e.r3
        e.r5 = e.mH[e.r10 + e.r3]
        e.r0 = (e.r1 * e.r3) - (e.r10 * e.r5)
        e.r5 = (e.r1 * e.r3) + e.mI[e.r10 + e.r0]
        e.r5 = e.r3 + e.r5
        self.assertEqual(e.opcodes, [
            Instruction(opcode=191, dst=3, src=1, off=0, imm=0),
            Instruction(opcode=191, dst=0, src=10, off=0, imm=0),
            Instruction(opcode=39, dst=0, src=0, off=0, imm=2),
            Instruction(opcode=31, dst=3, src=0, off=0, imm=0),
            Instruction(opcode=191, dst=0, src=3, off=0, imm=0),
            Instruction(opcode=O.MUL, dst=0, src=0, off=0, imm=2),
            Instruction(opcode=107, dst=10, src=0, off=-10, imm=0),
            Instruction(opcode=191, dst=0, src=10, off=0, imm=0),
            Instruction(opcode=15, dst=0, src=3, off=0, imm=0),
            Instruction(opcode=191, dst=2, src=3, off=0, imm=0),
            Instruction(opcode=O.MUL, dst=2, src=0, off=0, imm=2),
            Instruction(opcode=107, dst=0, src=2, off=0, imm=0),

            Instruction(opcode=191, dst=5, src=10, off=0, imm=0),
            Instruction(opcode=O.ADD+O.REG+O.LONG, dst=5, src=3, off=0, imm=0),
            Instruction(opcode=105, dst=5, src=5, off=0, imm=0),

            Instruction(opcode=191, dst=0, src=1, off=0, imm=0),
            Instruction(opcode=47, dst=0, src=3, off=0, imm=0),
            Instruction(opcode=191, dst=2, src=10, off=0, imm=0),
            Instruction(opcode=47, dst=2, src=5, off=0, imm=0),
            Instruction(opcode=31, dst=0, src=2, off=0, imm=0),
            Instruction(opcode=191, dst=5, src=1, off=0, imm=0),
            Instruction(opcode=47, dst=5, src=3, off=0, imm=0),
            Instruction(opcode=191, dst=2, src=10, off=0, imm=0),
            Instruction(opcode=15, dst=2, src=0, off=0, imm=0),
            Instruction(opcode=97, dst=2, src=2, off=0, imm=0),
            Instruction(opcode=15, dst=5, src=2, off=0, imm=0),
            Instruction(opcode=O.LONG+O.MOV+O.REG, dst=2, src=3, off=0, imm=0),
            Instruction(opcode=O.LONG+O.ADD+O.REG, dst=2, src=5, off=0, imm=0),
            Instruction(opcode=O.LONG+O.MOV+O.REG, dst=5, src=2, off=0, imm=0)
            ])
        with self.assertRaises(AssembleError):
            e.r8 = e.r2

    def test_temporary(self):
        e = EBPF()
        e.r0 = 7
        with e.tmp:
            e.tmp = 3
            e.r3 = e.tmp
            with e.tmp:
                e.tmp = 5
                e.r7 = e.tmp
            e.tmp = 2
            e.r3 = e.tmp
        with e.xtmp:
            e.xtmp = 3
            e.r3 = e.xtmp
            e.xtmp = e.r3 * 3.5
        self.assertEqual(e.opcodes, [
            Instruction(opcode=O.MOV+O.LONG, dst=0, src=0, off=0, imm=7),
            Instruction(opcode=O.MOV+O.LONG, dst=2, src=0, off=0, imm=3),
            Instruction(opcode=O.MOV+O.LONG+O.REG, dst=3, src=2, off=0, imm=0),
            Instruction(opcode=O.MOV+O.LONG, dst=4, src=0, off=0, imm=5),
            Instruction(opcode=O.MOV+O.LONG+O.REG, dst=7, src=4, off=0, imm=0),
            Instruction(opcode=O.MOV+O.LONG, dst=2, src=0, off=0, imm=2),
            Instruction(opcode=O.MOV+O.LONG+O.REG, dst=3, src=2, off=0, imm=0),
            Instruction(opcode=O.MOV+O.LONG, dst=2, src=0, off=0, imm=300000),
            Instruction(opcode=O.MOV+O.REG+O.LONG, dst=3, src=2, off=0, imm=0),
            Instruction(opcode=O.DIV+O.LONG, dst=3, src=0, off=0, imm=100000),
            Instruction(opcode=O.MOV+O.REG+O.LONG, dst=2, src=3, off=0, imm=0),
            Instruction(opcode=O.LONG+O.MUL, dst=2, src=0, off=0, imm=350000),
            ])

    def test_ktime(self):
        e = EBPF()
        e.r0 = 3
        e.r3 = ktime(e)
        self.assertEqual(e.opcodes, [
            Instruction(opcode=O.LONG+O.MOV, dst=0, src=0, off=0, imm=3),
            Instruction(opcode=O.REG+O.MOV+O.LONG, dst=6, src=0, off=0, imm=0),
            Instruction(opcode=O.REG+O.MOV+O.LONG, dst=7, src=1, off=0, imm=0),
            Instruction(opcode=O.CALL, dst=0, src=0, off=0, imm=5),
            Instruction(opcode=O.REG+O.MOV+O.LONG, dst=3, src=0, off=0, imm=0),
            Instruction(opcode=O.REG+O.MOV+O.LONG, dst=0, src=6, off=0, imm=0),
            Instruction(opcode=O.REG+O.MOV+O.LONG, dst=1, src=7, off=0, imm=0)
            ])

    def test_xdp(self):
        e = XDP(license="GPL")
        with e.packetSize > 100 as p:
            e.r3 = p.pH[22]
        with p.Else:
            e.r3 = 77
        self.assertEqual(e.opcodes, [
            Instruction(opcode=O.LD+O.W, dst=9, src=1, off=0, imm=0),
            Instruction(opcode=O.LD+O.W, dst=0, src=1, off=4, imm=0),
            Instruction(opcode=O.LD+O.W, dst=2, src=1, off=0, imm=0),
            Instruction(opcode=O.ADD+O.LONG, dst=2, src=0, off=0, imm=100),
            Instruction(opcode=O.REG+O.JLE, dst=0, src=2, off=2, imm=0),
            Instruction(opcode=O.REG+O.LD, dst=3, src=9, off=22, imm=0),
            Instruction(opcode=O.JMP, dst=0, src=0, off=1, imm=0),
            Instruction(opcode=O.MOV+O.LONG, dst=3, src=0, off=0, imm=77)])

    def test_endian(self):
        class P(XDP):
            minimumPacketSize = 100

            ph = PacketVar(20, "<H")
            pi = PacketVar(28, ">i")
            pq = PacketVar(36, "!q")

            pp = PacketVar(100, "Q")

            def program(self):
                self.ph = 3
                self.pi = 5
                self.pq = 7

                self.ph += 3
                self.pi += 5
                self.pq = self.ph

        e = P(license="GPL")
        e.assemble()
        self.assertEqual(e.opcodes, [
            Instruction(opcode=O.W+O.LD, dst=9, src=1, off=0, imm=0),
            Instruction(opcode=O.W+O.LD, dst=0, src=1, off=4, imm=0),
            Instruction(opcode=O.W+O.LD, dst=2, src=1, off=0, imm=0),
            Instruction(opcode=O.LONG+O.ADD, dst=2, src=0, off=0, imm=100),
            Instruction(opcode=O.JLE+O.REG, dst=0, src=2, off=19, imm=0),
            Instruction(opcode=O.ST+O.REG, dst=9, src=0, off=20, imm=3),
            Instruction(opcode=O.W+O.ST, dst=9, src=0, off=28, imm=83886080),
            Instruction(opcode=O.DW, dst=0, src=0, off=0, imm=0),
            Instruction(opcode=O.W, dst=0, src=0, off=0, imm=117440512),
            Instruction(opcode=O.DW+O.STX, dst=9, src=0, off=36, imm=0),
            Instruction(opcode=O.LD+O.REG, dst=0, src=9, off=20, imm=0),
            Instruction(opcode=O.LE, dst=0, src=0, off=0, imm=16),
            Instruction(opcode=O.ADD, dst=0, src=0, off=0, imm=3),
            Instruction(opcode=O.LE, dst=0, src=0, off=0, imm=16),
            Instruction(opcode=O.REG+O.STX, dst=9, src=0, off=20, imm=0),
            Instruction(opcode=O.W+O.LD, dst=0, src=9, off=28, imm=0),
            Instruction(opcode=O.BE, dst=0, src=0, off=0, imm=32),
            Instruction(opcode=O.ADD, dst=0, src=0, off=0, imm=5),
            Instruction(opcode=O.BE, dst=0, src=0, off=0, imm=32),
            Instruction(opcode=O.W+O.STX, dst=9, src=0, off=28, imm=0),
            Instruction(opcode=O.LD+O.REG, dst=0, src=9, off=20, imm=0),
            Instruction(opcode=O.LE, dst=0, src=0, off=0, imm=16),
            Instruction(opcode=O.BE, dst=0, src=0, off=0, imm=64),
            Instruction(opcode=O.DW+O.STX, dst=9, src=0, off=36, imm=0),
            Instruction(opcode=O.LONG+O.MOV, dst=0, src=0, off=0, imm=2),
            Instruction(opcode=O.EXIT, dst=0, src=0, off=0, imm=0),
        ])


    def test_xdp_minsize(self):
        class P(XDP):
            minimumPacketSize = 100

            pv = PacketVar(20, "H")

            def program(self):
                self.pv = self.pH[22]

        p = P(license="GPL")
        p.assemble()
        self.assertEqual(p.opcodes, [
            Instruction(opcode=O.W+O.LD, dst=9, src=1, off=0, imm=0),
            Instruction(opcode=O.W+O.LD, dst=0, src=1, off=4, imm=0),
            Instruction(opcode=O.W+O.LD, dst=2, src=1, off=0, imm=0),
            Instruction(opcode=O.LONG+O.ADD, dst=2, src=0, off=0, imm=100),
            Instruction(opcode=O.JLE+O.REG, dst=0, src=2, off=2, imm=0),
            Instruction(opcode=O.REG+O.LD, dst=0, src=9, off=22, imm=0),
            Instruction(opcode=O.REG+O.STX, dst=9, src=0, off=20, imm=0),
            Instruction(opcode=O.LONG+O.MOV, dst=0, src=0, off=0, imm=2),
            Instruction(opcode=O.EXIT, dst=0, src=0, off=0, imm=0),
        ])


class KernelTests(TestCase):
    def test_hashmap(self):
        class Global(EBPF):
            map = HashMap()
            a = map.globalVar(default=5)
            b = map.globalVar()

        e = Global(ProgType.XDP, "GPL")
        e.b = e.a
        e.a += 7
        e.exit()

        e.load(log_level=1)
        e.test_run(1000, 1000, 0, 0, 1)
        e.a *= 2
        e.test_run(1000, 1000, 0, 0, 1)
        self.assertEqual(e.a, 31)
        self.assertEqual(e.b, 24)

    def test_arraymap(self):
        class Global(EBPF):
            map = ArrayMap()
            ar = map.globalVar()
            aw = map.globalVar("h")

        class Sub(SubProgram):
            br = Global.map.globalVar()
            bw = Global.map.globalVar("h")
            bf = Global.map.globalVar("x")

            def program(self):
                self.bw = 4
                self.br -= -33
                self.bw = self.br + 3
                self.bf = self.br / 3.5 + self.bf

        s1 = Sub()
        s2 = Sub()
        e = Global(ProgType.XDP, "GPL", subprograms=[s1, s2])
        e.ar = e.aw + 7
        e.aw += 11
        s1.program()
        s2.program()
        e.r0 = 55
        e.exit()

        e.load(log_level=1)
        e.test_run(1000, 1000, 100, 100, 1)
        self.assertEqual(e.ar, 7)
        self.assertEqual(e.aw, 11)
        self.assertEqual(s1.br, 33)
        self.assertEqual(s1.bw, 36)
        self.assertEqual(s2.bf, 9.42857)
        s1.br = 3
        s2.br *= 5
        e.ar = 1111
        s2.bf = 1.3
        self.assertEqual(e.ar, 1111)
        self.assertEqual(e.aw, 11)
        self.assertEqual(s1.br, 3)
        self.assertEqual(s1.bw, 36)
        self.assertEqual(s2.br, 165)
        self.assertEqual(s2.bw, 36)
        e.test_run(1000, 1000, 0, 0, 1)
        self.assertEqual(e.ar, 18)
        self.assertEqual(e.aw, 22)
        self.assertEqual(s1.br, 36)
        self.assertEqual(s1.bw, 39)
        self.assertEqual(s2.br, 198)
        self.assertEqual(s2.bw, 201)
        self.assertEqual(s2.bf, 57.87142)

    def test_minimal(self):
        class Local(EBPF):
            a = LocalVar('I')

        e = Local(ProgType.XDP, "GPL")
        e.a = 7
        e.a += 3
        e.mI[e.r10 - 4] += e.r1
        e.a -= 3
        e.exit()
        print(e.opcodes)
        print(e.load(log_level=1)[1])


class ProcessProgram(SimulatedEBPF):
    map = ArrayMap()
    a = map.globalVar()

    def get_array(self, size):
        from multiprocessing import Array
        return Array('B', size).get_obj()

    def program(self):
        self.a += 3
        for p in self.subprograms:
            p.program()


class ProcessSubProgram(SubProgram):
    b = ProcessProgram.map.globalVar('I')

    def program(self):
        self.b += 7


class SimulatedTests(TestCase):
    def test_minimal(self):
        class Program(SimulatedEBPF):
            map = ArrayMap()
            a = map.globalVar()

            def get_array(self, size):
                return bytearray(size)

            def program(self):
                self.a += 3

        p = Program()
        self.assertEqual(p.a, 0)
        p.program()
        self.assertEqual(p.a, 3)
        p.program()
        self.assertEqual(p.a, 6)
        p.a = 7
        self.assertEqual(p.a, 7)
        p.program()
        self.assertEqual(p.a, 10)

    def test_inheritance(self):
        class A(SimulatedEBPF):
            map = ArrayMap()
            a = map.globalVar()

            def get_array(self, size):
                return bytearray(size)

        class B(A):
            b = A.map.globalVar()

            def program(self):
                self.a += 3
                self.b += 4

        p = B()
        self.assertEqual(p.a, 0)
        self.assertEqual(p.b, 0)
        p.program()
        self.assertEqual(p.a, 3)
        self.assertEqual(p.b, 4)

    def test_process(self):
        from multiprocessing import get_context
        ctx = get_context('spawn')
        p = ProcessProgram()
        self.assertEqual(p.a, 0)
        proc = ctx.Process(target=p.program)
        proc.start()
        proc.join()
        self.assertEqual(p.a, 3)

    def test_subprogram(self):
        from multiprocessing import get_context
        ctx = get_context('spawn')
        s = ProcessSubProgram()
        p = ProcessProgram(subprograms=[s])
        self.assertEqual(p.a, 0)
        self.assertEqual(s.b, 0)
        proc = ctx.Process(target=p.program)
        proc.start()
        proc.join()
        self.assertEqual(p.a, 3)
        self.assertEqual(s.b, 7)


if __name__ == "__main__":
    main()
