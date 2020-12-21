from unittest import TestCase, main

from .ebpf import EBPF, Instruction
from .bpf import ProgType


class Tests(TestCase):
    def test_assemble(self):
        e = EBPF()
        e.append(0x24, 3, 4, 0x2c3d, 0x2d3e4f5e)
        self.assertEqual(e.assemble(), b"$C=,^O>-")

    def test_assign(self):
        e = EBPF()
        e.r5 = 7
        e.r6 = e.r3
        self.assertEqual(e.opcodes, 
            [Instruction(0xb7, 5, 0, 0, 7),
             Instruction(0xbf, 6, 3, 0, 0)])

    def test_short(self):
        e = EBPF()
        e.s3 = 7
        e.s4 = e.s1
        e.s2 += 3
        e.s5 += e.s6
        self.assertEqual(e.opcodes, 
            [Instruction(0xb4, 3, 0, 0, 7),
             Instruction(0xbc, 4, 1, 0, 0),
             Instruction(opcode=4, dst=2, src=0, off=0, imm=3),
             Instruction(opcode=0xc, dst=5, src=6, off=0, imm=0)])

    def test_augassign(self):
        e = EBPF()
        e.r5 += 7
        e.r3 += e.r6
        e.r4 -= 3
        e.r4 -= e.r7
        e.r4 *= 3
        e.r4 *= e.r7
        e.r4 /= 3
        e.r4 /= e.r7
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

        self.assertEqual(e.opcodes, 
            [Instruction(opcode=7, dst=5, src=0, off=0, imm=7),
             Instruction(opcode=15, dst=3, src=6, off=0, imm=0),
             Instruction(opcode=0x17, dst=4, src=0, off=0, imm=3),
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
             Instruction(opcode=0xaf, dst=4, src=7, off=0, imm=0)])


class KernelTests(TestCase):
    def test_minimal(self):
        e = EBPF(ProgType.XDP, "GPL")
        e.r0 = 0
        e.r1 = 5
        e.r0 += e.r1
        e.exit()
        self.assertEqual(e.load(log_level=1), "")


if __name__ == "__main__":
    main()
