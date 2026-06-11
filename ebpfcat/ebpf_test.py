# ebpfcat, A Python-based EBPF generator and EtherCAT master
# Copyright (C) 2021 Martin Teichmann <martin.teichmann@xfel.eu>
# Copyright (C) 2026 European XFEL GmbH
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
from .arraymap import ArrayMap, PerCPUArrayMap
from .ebpf import (
    AssembleError, EBPF, FuncId, LocalVar, Member, Opcode, Structure,
    SubProgram, ktime)
from .simulated import ProcessEBPF, SimulatedEBPF
from .hashmap import HashMap, Dict
from .xdp import XDP, PacketVar
from .bpf import ProgType


class Tests(TestCase):
    def assertOpcodesEqual(self, program, expected):
        program.assemble()
        self.assertEqual([str(op) for op in program.opcodes], expected)

    def test_assemble(self):
        e = EBPF()
        e.append(Opcode.MUL, 3, 4, 0x2c3d, 0x2d3e4f5e)
        self.assertEqual(e.assemble(), b"$C=,^O>-")

    def test_assemble_long(self):
        e = EBPF()
        e.r5 = 0x3333333344444444
        self.assertEqual(e.assemble(),
                         b'\x18\x05\x00\x00DDDD\x00\x00\x00\x003333')

    def test_assign(self):
        e = EBPF()
        e.owners = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
        e.r5 = 7
        e.r6 = e.r3
        self.assertOpcodesEqual(e, [
            "r5 = 7",
            "r6 = r3",
        ])

    def test_word(self):
        e = EBPF()
        e.owners |= {6}
        e.w3 = 7
        e.w4 = e.w1
        e.w2 += 3
        e.w5 += e.w6
        self.assertOpcodesEqual(e, [
            "r3 = 7",
            "w4 = w1",
            "w2 += 3",
            "w5 += w6",
        ])

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

        self.assertOpcodesEqual(e, [
            "r5 += 7",
            "r3 += r6",
            "r4 += -3",
            "r4 -= r7",
            "r4 *= 3",
            "r4 *= r7",
            "r4 /= 3",
            "r4 /= r7",
            "r4 |= 3",
            "r4 |= r7",
            "r4 &= 3",
            "r4 &= r7",
            "r4 <<= 3",
            "r4 <<= r7",
            "r4 >>= 3",
            "r4 >>= r7",
            "r4 %= 3",
            "r4 %= r7",
            "r4 ^= 3",
            "r4 ^= r7",
            "r4 s>>= 3",
            "r4 s>>= r7",
        ])

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
        self.assertOpcodesEqual(e, [
            "*(u8 *)(r5 +0) = 7",
            "*(u16 *)(r3 +2) = 3",
            "*(u32 *)(r8 +7) = 5",
            "*(u64 *)(r3 -7) = 2",
            "*(u8 *)(r5 +0) = r1",
            "*(u16 *)(r3 +2) = r2",
            "*(u32 *)(r8 +7) = r3",
            "*(u64 *)(r3 -7) = r4",
            "r2 = *(u8 *)(r5 +0)",
            "r3 = *(u16 *)(r3 +2)",
            "r4 = *(u32 *)(r8 +7)",
            "r5 = *(u64 *)(r3 -7)",
            "r5 = *(u8 *)(r3 +0)",
            "r5 <<= 56",
            "r5 s>>= 56",
            "r5 s>>= 2",
            "r5 = *(u8 *)(r3 +0)",
            "r5 >>= 2",
            ])

    def test_double_add(self):
        e = EBPF()
        e.owners = {1, 2}
        e.mI[(e.r1 + 3) + 7] = 3
        e.mI[7 + (e.r1 + 3)] = 3
        e.mI[(e.r1 + 3) + e.r2] = 5
        e.mI[(e.r1 + 3) - 7] = 3
        e.mI[7 - (e.r1 + 3)] = 3
        e.mI[(e.r1 + 3) - e.r2] = 5

        self.assertOpcodesEqual(e, [
            "*(u32 *)(r1 +10) = 3",
            "*(u32 *)(r1 +10) = 3",
            "r0 = r1",
            "r0 += 3",
            "r0 += r2",
            "*(u32 *)(r0 +0) = 5",
            "*(u32 *)(r1 -4) = 3",
            "r0 = 7",
            "r3 = r1",
            "r3 += 3",
            "r0 -= r3",
            "*(u32 *)(r0 +0) = 3",
            "r0 = r1",
            "r0 += 3",
            "r0 -= r2",
            "*(u32 *)(r0 +0) = 5",
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


        self.assertOpcodesEqual(e, [
            "r1 = r2",
            "r1 += 3",
            "r1 *= 100000",
            "r3 = r4",
            "r3 *= 100000",
            "r3 += 350000",
            "r5 = r6",
            "r5 += 300000",
            "r1 = r2",
            "r1 *= 100000",
            "r1 += r3",
            "r1 /= 100000",
            "r4 = r5",
            "r4 += r6",
            "r1 = 200000",
            "r1 -= r2",
            "r1 /= 100000",
            "r3 = 340000",
            "r7 = r4",
            "r7 *= 100000",
            "r3 -= r7",
            "r3 /= 100000",
            "r5 = r6",
            "r5 %= 400000",
            "r5 /= 100000",

            "r1 = r2",
            "r1 *= 3",
            "r1 *= 100000",
            "r3 = r4",
            "r3 *= 350000",
            "r5 = r6",
            "r5 *= 3",
            "r1 = r2",
            "r1 *= r3",
            "r1 /= 100000",
            "r4 = r5",
            "r4 *= r6",
            "r4 /= 100000",

            "r1 = r2",
            "r1 *= 100000",
            "r1 /= 3",
            "r3 = r4",
            "r7 = 0x2540be400",
            "r3 *= r7",
            "r3 /= 350000",
            "r5 = r6",
            "r5 /= 3",
            "r1 = r2",
            "r7 = 0x2540be400",
            "r1 *= r7",
            "r1 /= r3",
            "r1 /= 100000",
            "r4 = r5",
            "r4 *= 100000",
            "r4 /= r6",

            "r1 = r2",
            "r1 /= 3",
            "r1 *= 100000",
            "r3 = r4",
            "r3 *= 100000",
            "r3 /= 350000",
            "r3 *= 100000",
            "r5 = r6",
            "r5 /= 300000",
            "r5 *= 100000",
            "r1 = r2",
            "r1 *= 100000",
            "r1 /= r3",
            "r4 = r5",
            "r4 /= r6",
            "r4 *= 100000",

            "r1 = 300000",
            "r1 /= r2",
            "r3 = 350000",
            "r3 /= r4",
            "r5 = 0x6fc23ac00",
            "r5 /= r6",
            "r4 = 0xa7a358200",
            "r4 /= r6",
            "r1 = 3",
            "r1 /= r2",
            "r1 *= 100000",
            "r3 = 3",
            "r3 /= r4",
            "r3 *= 100000",
            "r5 = 300000",
            "r5 /= r6",
            "r5 *= 100000",
            "r4 = 450000",
            "r4 /= r6",
            "r4 *= 100000",
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

        self.assertOpcodesEqual(e, [
            "*(u8 *)(r10 -1) = 5",
            "r0 = *(u32 *)(r10 -8)",
            "w0 s>>= 3",
            "*(u16 *)(r10 -4) = r0",
            "*(u64 *)(r10 -16) = r1",
            "*(u64 *)(r10 -24) = 700000",
            "r0 = r1",
            "w0 /= 100000",
            "*(u16 *)(r10 -4) = r0",
        ])

    def test_short_comparison(self):
        e = EBPF()
        e.owners = {3, 4}

        with e.sw3 < 100:
            pass
        with e.sw3 > e.sr4:
            pass
        with e.sr3 == e.sw4:
            pass
        with 100 < e.sw3:
            pass

        self.assertOpcodesEqual(e, [
            "if w3 s>= 0x64 goto pc+0",

            "r3 <<= 32",
            "r3 s>>= 32",
            "if r3 s<= r4 goto pc+0",

            "if r3 != r4 goto pc+0",

            "if w3 s<= 0x64 goto pc+0",
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

        self.assertOpcodesEqual(e, [
            "r0 = *(u8 *)(r10 -1)",
            "if r0 & 0x20 goto pc+1",
            "goto pc+3",
            "r0 = *(u8 *)(r10 -1)",
            "w0 |= 32",
            "*(u8 *)(r10 -1) = r0",
            "r0 = *(u8 *)(r10 -1)",
            "r0 &= 32",
            "r0 >>= 5",
            "w0 <<= 3",
            "w0 &= 120",
            "r2 = *(u8 *)(r10 -2)",
            "w2 &= -121",
            "w0 |= w2",
            "*(u8 *)(r10 -2) = r0",
            "r0 = *(u8 *)(r10 -1)",
            "if r0 & 0x20 goto pc+4",
            "r0 = *(u8 *)(r10 -2)",
            "w0 &= -121",
            "w0 |= 24",
            "*(u8 *)(r10 -2) = r0",
            "r0 = *(u8 *)(r10 -2)",
            "if r0 & 0x78 goto pc+1",
            "goto pc+3",
            "r0 = *(u8 *)(r10 -1)",
            "w0 &= -33",
            "*(u8 *)(r10 -1) = r0",
            "r2 = *(u8 *)(r10 -2)",
            "if r2 & 0x78 goto pc+3",
            "r0 = *(u8 *)(r10 -1)",
            "w0 &= -33",
            "goto pc+2",
            "r0 = *(u8 *)(r10 -1)",
            "w0 |= 32",
            "*(u8 *)(r10 -1) = r0",
        ])

    def test_bits_and_or(self):
        class Local(EBPF):
            a = LocalVar((5, 1))

        e = Local(ProgType.XDP, "GPL")

        with e.stmp:
            with (e.a != 0) & (e.stmp > 0) | (e.a == 0) & (e.stmp < 0):
                e.stmp = 0

        self.assertOpcodesEqual(e, [
            "r2 = *(u8 *)(r10 -1)",
            "if r2 & 0x20 goto pc+1",
            "goto pc+1",
            "if r0 s> 0x0 goto pc+3",
            "r2 = *(u8 *)(r10 -1)",
            "if r2 & 0x20 goto pc+2",
            "if r0 s>= 0x0 goto pc+1",
            "r0 = 0",
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
        self.assertOpcodesEqual(e, [
            "*(u32 *)(r10 -4) = 5",
            "*(u32 *)(r10 -12) = 3",
            "r3 = *(u32 *)(r10 -12)",
            "*(u32 *)(r10 -12) = 7",
        ])

    def test_sign_extend(self):
        class Local(EBPF):
            a = LocalVar('b')
            b = LocalVar('H')
            c = LocalVar('i')
            d = LocalVar('Q')

        e = Local(ProgType.XDP, "GPL")
        e.b = e.a + e.c
        e.d = e.b + e.c

        self.assertOpcodesEqual(e, [
            "r0 = *(u8 *)(r10 -1)",
            "w0 <<= 24",
            "w0 s>>= 24",
            "r2 = *(u32 *)(r10 -8)",
            "w0 += w2",
            "*(u16 *)(r10 -4) = r0",
            "r0 = *(u16 *)(r10 -4)",
            "r2 = *(u32 *)(r10 -8)",
            "r2 <<= 32",
            "r2 s>>= 32",
            "r0 += r2",
            "*(u64 *)(r10 -16) = r0",
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

        self.assertOpcodesEqual(e, [
            "r0 = 3",
            "lock *(u32 *)(r10 -4) += r0",
            "lock *(u32 *)(r1 +0) += r1",
            "r0 = -3",
            "lock *(u32 *)(r10 -4) += r0",
            "r0 = 3",
            "lock *(u64 *)(r10 -16) += r0",
            "lock *(u64 *)(r1 +0) += r1",
            "r0 = *(u16 *)(r10 -18)",
            "w0 <<= 16",
            "w0 s>>= 16",
            "w0 += 3",
            "*(u16 *)(r10 -18) = r0",
            "r0 = *(u8 *)(r1 +0)",
            "w0 += w1",
            "*(u8 *)(r1 +0) = r0",
            "r0 = -500000",
            "lock *(u64 *)(r10 -32) += r0",
            "r0 = r1",
            "r0 *= 100000",
            "lock *(u64 *)(r10 -32) += r0",
        ])

    def test_array(self):
        class Local(EBPF):
            ar = LocalVar('5B')

        e = Local(ProgType.XDP, "GPL")
        e.ar[1] = 3
        e.r1 = e.ar[3]
        e.ar[e.r1] = 7
        e.r2 = e.ar[e.r1]

        self.assertOpcodesEqual(e, [
            "*(u8 *)(r10 -4) = 3",
            "r1 = *(u8 *)(r10 -2)",
            "r0 = r10",
            "r0 += -5",
            "r0 += r1",
            "*(u8 *)(r0 +0) = 7",
            "r2 = r10",
            "r2 += -5",
            "r2 += r1",
            "r2 = *(u8 *)(r2 +0)",
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
        self.assertOpcodesEqual(e, [
            "goto pc+1",
            "r0 = 1",
            "if r5 > 0x3 goto pc+4",
            "if r1 > r2 goto pc+3",
            "if r7 >= 0x2 goto pc+2",
            "if r4 >= r3 goto pc+1",
            "r0 = 1",
            "if r5 < 0x3 goto pc+4",
            "if r1 < r2 goto pc+3",
            "if r7 <= 0x2 goto pc+2",
            "if r4 <= r3 goto pc+1",
            "r0 = 1",
            "if r5 s> 0x3 goto pc+4",
            "if r1 s> r2 goto pc+3",
            "if r7 s>= 0x2 goto pc+2",
            "if r4 s>= r3 goto pc+1",
            "r0 = 1",
            "if r5 s< 0x3 goto pc+4",
            "if r1 s< r2 goto pc+3",
            "if r7 s<= 0x2 goto pc+2",
            "if r4 s<= r3 goto pc+1",
            "r0 = 1",
            "if r5 == 0x3 goto pc+4",
            "if r1 == r2 goto pc+3",
            "if r7 != 0x2 goto pc+2",
            "if r4 != r3 goto pc+1",
            "r0 = 1",
            "if r5 & 0x3 goto pc+2",
            "if r1 & r2 goto pc+1",
            "r0 = 1",
        ])

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
        self.assertOpcodesEqual(e, [
            "if r2 <= 0x3 goto pc+2",
            "r2 = 5",
            "goto pc+1",
            "r6 = 7",
            "if r2 == 0x0 goto pc+1",
            "r3 = 2",
            "if r4 <= 0x3 goto pc+2",
            "r5 = 7",
            "goto pc+1",
            "r7 = 8",
            "if r4 s<= 0x493e0 goto pc+0",
            "if r4 s>= 0x493e0 goto pc+0",
            "r9 = r4",
            "r9 *= 100000",
            "if r9 <= 0x55730 goto pc+0",
            "if r4 s<= r2 goto pc+0",
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
        self.assertOpcodesEqual(e, [
            "if r1 & 0x1 goto pc+1",
            "goto pc+1",
            "r0 = 2",
            "if r1 & 0x7 goto pc+2",
            "r0 = 3",
            "goto pc+2",
            "r0 = 2",
            "r1 = 4",
        ])

    def test_with_and(self):
        e = EBPF()
        e.owners = set(range(11))
        with (e.r2 > 3) & (e.r3 > 2) as Else:
            e.r1 = 5
        with (e.r2 > 2) & (e.r1 < 2) as Else:
            e.r2 = 5
        with Else:
            e.r3 = 7
        self.assertOpcodesEqual(e, [
            "if r2 <= 0x3 goto pc+2",
            "if r3 <= 0x2 goto pc+1",
            "r1 = 5",
            "if r2 <= 0x2 goto pc+3",
            "if r1 >= 0x2 goto pc+2",
            "r2 = 5",
            "goto pc+1",
            "r3 = 7",
        ])

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
        self.assertOpcodesEqual(e, [
            "if r2 > 0x3 goto pc+1",
            "if r3 <= 0x2 goto pc+1",
            "r1 = 5",
            "if r2 > 0x2 goto pc+1",
            "if r1 <= 0x2 goto pc+3",
            "r2 = 5",
            "r5 = 4",
            "goto pc+2",
            "r3 = 7",
            "r4 = 3",
        ])

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

        self.assertOpcodesEqual(e, [
            "r0 = r1",
            "r0 += r3",
            "if r0 <= 0x3 goto pc+2",
            "r0 = 5",
            "goto pc+1",
            "r0 = 7",
            "r4 = r2",
            "r4 += r5",
            "if r0 < r4 goto pc+1",
            "r0 = 8",
        ])

    def test_huge(self):
        e = EBPF()
        e.r3 = 0x1234567890
        e.r4 = e.get_fd(7)
        with e.r3 == 0:
            e.r3 = e.r4 + 0x1234567890
        e.r3 = 0x90000000

        self.assertOpcodesEqual(e, [
            "r3 = 0x1234567890",
            "r4 = FD#7",
            "if r3 != 0x0 goto pc+4",
            "r3 = r4",
            "r0 = 0x1234567890",
            "r3 += r0",
            "r3 = 0x90000000",
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
        self.assertOpcodesEqual(e, [
            "r0 = r1",
            "r0 *= r2",
            "r0 += r3",
            "r0 = r1",
            "r0 *= r2",
            "r0 += 3",
            "r0 = r1",
            "r0 *= 2",
            "r0 += 3",
            "r0 = r1",
            "r0 *= 2",
            "r0 += 3",
            "r0 = r1",
            "r0 *= 2",
            "r0 += 3",
            "r0 = r1",
            "r0 s>>= 2",
            "r0 = r1",
            "r0 s>>= r2",
            "w0 = w1",
            "w0 += w2",
            "r0 = r1",
            "r0 &= r2",
        ])

    def test_mixed_binary(self):
        e = EBPF()
        e.owners = {0, 1, 2, 3}
        e.w1 = e.r2 + e.w3
        e.r1 = e.w2 + e.w3
        e.w1 = e.w2 + e.w3
        self.assertOpcodesEqual(e, [
            "r1 = r2",
            "w1 += w3",
            "w1 = w2",
            "r1 += r3",
            "w1 = w2",
            "w1 += w3",
        ])

    def test_mixed_compare(self):
        e = EBPF()
        e.owners = {0, 1, 2, 3}
        with e.r1 > e.sr2:
            pass
        with (e.r1 + e.sr2) > 3:
            pass
        self.assertOpcodesEqual(e, [
            "if r1 s<= r2 goto pc+0",
            "r4 = r1",
            "r4 += r2",
            "if r4 s<= 0x3 goto pc+0",
        ])


    def test_reverse_binary(self):
        e = EBPF()
        e.owners = {0, 1, 2, 3}
        e.r3 = 7 // (e.r2 + 2)
        e.r3 = 7 << e.r2
        e.r3 = 7 % (e.r2 + 3)
        e.r3 = 7 >> e.r2
        e.r3 = -7 >> e.r2
        self.assertOpcodesEqual(e, [
            "r3 = 7",
            "r4 = r2",
            "r4 += 2",
            "r3 /= r4",
            "r3 = 7",
            "r3 <<= r2",
            "r3 = 7",
            "r4 = r2",
            "r4 += 3",
            "r3 %= r4",
            "r3 = 7",
            "r3 >>= r2",
            "r3 = -7",
            "r3 s>>= r2",
            ])

    def test_negation(self):
        e = EBPF()
        e.r7 = -e.r1
        e.r7 = -e.r7
        self.assertOpcodesEqual(e, [
            "r7 = r1",
            "r7 = -r7",
            "r7 = -r7",
        ])

    def test_absolute(self):
        e = EBPF()
        e.r7 = abs(e.r1)
        with abs(e.r7) > 3:
            e.x3 = abs(e.x1)
        self.assertOpcodesEqual(e, [
            "r7 = r1",
            "if r7 s>= 0x0 goto pc+1",
            "r7 = -r7",

            "r0 = r7",
            "if r0 s>= 0x0 goto pc+1",
            "r0 = -r0",
            "if r0 <= 0x3 goto pc+3",

            "r3 = r1",
            "if r3 s>= 0x0 goto pc+1",
            "r3 = -r3",
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
        self.assertOpcodesEqual(e, [
            "r8 = 23",
            "call #5",
        ])
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
        self.assertOpcodesEqual(e, [
            "r3 = r1",
            "r0 = r10",
            "r0 *= 2",
            "r3 -= r0",
            "r0 = r3",
            "w0 *= 2",
            "*(u16 *)(r10 -10) = r0",
            "r0 = r10",
            "r0 += r3",
            "r2 = r3",
            "w2 *= 2",
            "*(u16 *)(r0 +0) = r2",

            "r5 = r10",
            "r5 += r3",
            "r5 = *(u16 *)(r5 +0)",

            "r0 = r1",
            "r0 *= r3",
            "r2 = r10",
            "r2 *= r5",
            "r0 -= r2",
            "r5 = r1",
            "r5 *= r3",
            "r2 = r10",
            "r2 += r0",
            "r2 = *(u32 *)(r2 +0)",
            "r5 += r2",
            "r2 = r3",
            "r2 += r5",
            "r5 = r2",
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
        self.assertOpcodesEqual(e, [
            "r0 = 7",
            "r2 = 3",
            "r3 = r2",
            "r4 = 5",
            "r7 = r4",
            "r2 = 2",
            "r3 = r2",
            "r2 = 300000",
            "r3 = r2",
            "r3 /= 100000",
            "r2 = r3",
            "r2 *= 350000",
            ])

    def test_ktime(self):
        e = EBPF()
        e.r0 = 3
        e.r3 = ktime(e)
        self.assertOpcodesEqual(e, [
            "r0 = 3",
            "r6 = r0",
            "r7 = r1",
            "call #5",
            "r3 = r0",
            "r0 = r6",
            "r1 = r7",
            ])

    def test_xdp(self):
        e = XDP(license="GPL")
        with e.packetSize > 100 as p:
            e.r3 = p.pH[22]
        with p.Else:
            e.r3 = 77
        self.assertOpcodesEqual(e, [
            "r9 = *(u32 *)(r1 +0)",
            "r0 = *(u32 *)(r1 +4)",
            "r2 = *(u32 *)(r1 +0)",
            "r2 += 100",
            "if r0 <= r2 goto pc+2",
            "r3 = *(u16 *)(r9 +22)",
            "goto pc+1",
            "r3 = 77",
        ])

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
        self.assertOpcodesEqual(e, [
            "r9 = *(u32 *)(r1 +0)",
            "r0 = *(u32 *)(r1 +4)",
            "r2 = *(u32 *)(r1 +0)",
            "r2 += 100",
            "if r0 <= r2 goto pc+19",
            "*(u16 *)(r9 +20) = 3",
            "*(u32 *)(r9 +28) = 83886080",
            "r0 = 0x700000000000000",
            "*(u64 *)(r9 +36) = r0",
            "r0 = *(u16 *)(r9 +20)",
            "r0 = bswap16 r0",
            "w0 += 3",
            "r0 = bswap16 r0",
            "*(u16 *)(r9 +20) = r0",
            "r0 = *(u32 *)(r9 +28)",
            "r0 = bswap32 r0",
            "w0 += 5",
            "r0 = bswap32 r0",
            "*(u32 *)(r9 +28) = r0",
            "r0 = *(u16 *)(r9 +20)",
            "r0 = bswap16 r0",
            "r0 = bswap64 r0",
            "*(u64 *)(r9 +36) = r0",
            "r0 = 2",
            "exit",
        ])


    def test_xdp_minsize(self):
        class P(XDP):
            minimumPacketSize = 100

            pv = PacketVar(20, "H")

            def program(self):
                self.pv = self.pH[22]

        p = P(license="GPL")
        self.assertOpcodesEqual(p, [
            "r9 = *(u32 *)(r1 +0)",
            "r0 = *(u32 *)(r1 +4)",
            "r2 = *(u32 *)(r1 +0)",
            "r2 += 100",
            "if r0 <= r2 goto pc+2",
            "r0 = *(u16 *)(r9 +22)",
            "*(u16 *)(r9 +20) = r0",
            "r0 = 2",
            "exit",
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
        e.assemble()
        print(e.opcodes)
        print(e.load(log_level=1)[1])

    def test_attach(self):
        import asyncio

        class Local(XDP):
            license = 'GPL'
            minimumPacketSize = 100

        e = Local()
        async def run():
            async with e.run('lo'):
                pass
        asyncio.run(run())

    def test_percpumap(self):
        class Global(EBPF):
            cpumap = PerCPUArrayMap()
            ar = cpumap.globalVar()

        e = Global(ProgType.XDP, "GPL")
        e.ar = 7
        e.exit()

        e.load(log_level=1)
        e.test_run(1000, 1000, 100, 100, 1)
        e.cpumap.read()
        e.ar.index(7)

    def test_hashtable_structure(self):
        class Key(Structure):
            keyI = Member("I")
            keyB = Member("B")

        class Value(Structure):
            valueI = Member("I")
            valueB = Member("B")

        class Program(EBPF):
            ht1 = Dict(key=Key, value=Value, size=2)
            ht2 = Dict(key=Key, value=Value)
            ht4 = Dict(key=Key, value=Value, lru=True)

            map = ArrayMap()
            ar = map.globalVar("i")


            def program(self):
                self.ht1.key.keyB = self.ar
                self.ht1.key.keyI = 7
                self.ht1.value.valueB = 3
                self.ht1.value.valueI = 9
                self.ht1.update()
                with self.r0 != 0:
                    self.ar = self.r0
                    self.exit()
                self.ht2.key.keyB = 8
                self.ht2.key.keyI = 1
                with self.ht2.lookup() as (value, Else):
                    value.valueB += 3
                    value.valueI += 7
                with Else:
                    self.ar = 7
                self.exit()

        e = Program(ProgType.XDP, "GPL")
        e.load(log_level=1)
        e.test_run(1000, 1000, 100, 100, 1)
        self.assertEqual(e.ar, 7)
        k = Key()
        k.keyB = 8
        k.keyI = 1
        v = Value()
        v.valueB = 2
        v.valueI = 1
        e.ht2[k] = v
        v = e.ht2[k]
        self.assertEqual(v.valueB, 2)
        with self.assertRaises(KeyError):
            e.ht1[k]
        e.ar = 5
        e.test_run(1000, 1000, 100, 100, 1)
        v = e.ht2[k]
        self.assertEqual(v.valueB, 5)
        self.assertEqual(v.valueI, 8)
        k.keyB = 5
        k.keyI = 7
        v = e.ht1[k]
        self.assertEqual(v.valueB, 3)
        self.assertEqual(v.valueI, 9)
        k.keyI = 2
        with self.assertRaises(IndexError):
            e.ht1[k] = v
        e.ar = 100
        e.test_run(1000, 1000, 100, 100, 1)
        self.assertEqual(e.ar, -7)

        e.ht2[k] = v
        del e.ht2[k]
        with self.assertRaises(KeyError):
            e.ht2[k]
        self.assertEqual(e.ht2.pop(k, 8), 8)
        e.ht2[k] = v
        v = e.ht2.pop(k)
        self.assertEqual(v.valueI, 9)
        self.assertEqual(set(k.keyB for k in e.ht2), {5, 8})
        list(e.ht2.values())

        self.assertEqual(e.ht2[2, 5], (9, 3))
        e.ht2[2, 5] = (8, 1)
        self.assertEqual(e.ht2[2, 5], (8, 1))

    def test_hashtable(self):
        class Program(EBPF):
            ht1 = Dict(key='i', value='q', size=4)

            map = ArrayMap()
            ar = map.globalVar("i")

            def program(self):
                self.ht1.key = self.ar
                self.ht1.value = 3
                self.ht1.update()
                with self.r0 != 0:
                    self.ar = self.r0
                    self.exit()
                self.ht1.key = 54
                self.ht1.key += 1
                with self.ht1.lookup() as (value, Else):
                    value.value += 3
                    self.ar = value
                    value.value = 9
                    #self.r2 = 22
                    #self.mA[self.r2] = 7
                with Else:
                    self.ar = 7
                self.exit()

        e = Program(ProgType.XDP, "GPL")
        e.load(log_level=1)
        e.test_run(1000, 1000, 100, 100, 1)
        self.assertEqual(e.ar, 7)
        e.ht1[8] = 3
        self.assertEqual(e.ht1[8], 3)
        with self.assertRaises(KeyError):
            e.ht1[7]
        e.ar = 5
        e.ht1[55] = 11
        e.test_run(1000, 1000, 100, 100, 1)
        self.assertEqual(set(e.ht1), {5, 55, 8, 0})
        self.assertEqual(e.ar, 14)
        self.assertEqual(e.ht1[55], 9)
        with self.assertRaises(IndexError):
            e.ht1[2] = 100
        e.ar = 100
        e.test_run(1000, 1000, 100, 100, 1)
        self.assertEqual(e.ar, -7)

        del e.ht1[5]
        with self.assertRaises(KeyError):
            e.ht1[5]
        self.assertEqual(e.ht1.pop(5, 8), 8)
        self.assertEqual(e.ht1.pop(55), 9)


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


class ProcessEBPFProgram(ProcessEBPF):
    map = ArrayMap()
    a = map.globalVar()

    async def subprocess_loop(self):
        from asyncio import sleep

        while self.running:
            self.a += 1
            await sleep(0.01)


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

    def test_process_ebpf(self):
        import asyncio

        p = ProcessEBPFProgram()
        async def run():
            task = p.start()
            for i in range(10):
                await asyncio.sleep(0.1)
                if p.a > 0:
                    break
            else:
                self.fail()
            task.cancel()
            await task
        with self.assertRaises(asyncio.CancelledError):
            asyncio.run(run())


class MinorTests(TestCase):
    def test_structure(self):
        class S(Structure):
            x = Member("i")
            y = Member("b")

        s = S()
        s.x = 3
        s.y = 5
        self.assertEqual(repr(s), 'S(x=3, y=5)')
        self.assertEqual(list(s), [3, 5])
        x, y = s
        self.assertEqual(x, 3)

        s = S(4, 5)
        self.assertEqual(s.y, 5)
        s = S(x=8, y=2)
        self.assertEqual(s.x, 8)
        self.assertEqual(s[1], 2)
        s[0] = 9
        self.assertEqual(s.x, 9)
        self.assertEqual(s, (9, 2))
        self.assertEqual(s.count(2), 1)

        self.assertEqual(s.pack((0x38373635, 0x34)), b'56784')
        self.assertEqual(s.unpack(b'12345'), (0x34333231, 0x35))


if __name__ == "__main__":
    main()
