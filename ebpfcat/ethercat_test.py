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

from asyncio import CancelledError, Future, get_event_loop, sleep, gather
from unittest import TestCase, main

from .devices import AnalogInput, AnalogOutput, Motor
from .terminals import EL4104, EL3164, EK1814
from .ethercat import ECCmd
from .ebpfcat import (
    FastSyncGroup, SyncGroup, TerminalVar, Device, EBPFTerminal, PacketDesc)
from .ebpf import Instruction, Opcode as O


class MockEtherCat:
    def __init__(self, test):
        self.test = test

    async def roundtrip(self, *args):
        self.test.assertEqual(args, self.expected.pop(0))
        return self.results.pop(0)

    def send_packet(self, data):
        self.test.assertEqual(data, self.expected.pop(0), data.hex())

    async def receive_index(self, index):
        self.test.assertEqual(index, self.expected.pop(0))
        if not self.expected:
            self.test.future.cancel()
            for i in range(10):
                await sleep(0)
        return self.results.pop(0)

    def register_sync_group(self, sg, packet):
        self.rsg = sg
        return 0x33


class Tests(TestCase):
    def test_input(self):
        ti = EL3164()
        ti.pdo_in_sz = 4
        ti.pdo_in_off = 0xABCD
        ti.position = 0x77
        ti.pdo_out_sz = 3
        ti.pdo_out_off = 0x4321
        ec = MockEtherCat(self)
        ti.ec = ec
        ai = AnalogInput(ti.channel1.value)
        SyncGroup.packet_index = 1000
        sg = SyncGroup(ec, [ai])
        self.task = sg.start()
        ec.expected = [
            (ECCmd.FPRD, 0x77, 304, "H2xH"),  # get state
            bytes.fromhex("2d10"  # EtherCAT Header, length & type
                          "0000e8030000008000000000"  # ID datagram
                          "04007700cdab04800000000000000000" # in datagram
                          "050077002143030000000000000000"), # out datagram
            1000, # == 0x3e8, see ID datagram
            bytes.fromhex("2d10"  # EtherCAT Header, length & type
                          "0000e8030000008000000000"  # ID datagram
                          "04007700cdab04800000123456780000" # in datagram
                          "050077002143030000000000000000"), # out datagram
            1000,
            ]
        ec.results = [
            (8, 0),  # return state 8, no error
            bytes.fromhex("2d10"  # EtherCAT Header, length & type
                          "0000e8030000008000000000"  # ID datagram
                          "04007700cdab04800000123456780000" # in datagram
                          "050077002143030000000000000000"), # out datagram
            ]
        self.future = Future()
        with self.assertRaises(CancelledError):
            get_event_loop().run_until_complete(
                    gather(self.future, self.task))
        self.assertEqual(ai.value, 0x7856)
        self.task.cancel()
        with self.assertRaises(CancelledError):
            get_event_loop().run_until_complete(self.task)

    def test_output(self):
        ti = EL4104()
        ti.pdo_in_sz = 4
        ti.pdo_in_off = 0xABCD
        ti.position = 0x77
        ti.pdo_out_sz = 3
        ti.pdo_out_off = 0x4321
        ec = MockEtherCat(self)
        ti.ec = ec
        ao = AnalogOutput(ti.ch1_value)
        SyncGroup.packet_index = 1000
        sg = SyncGroup(ec, [ao])
        self.task = sg.start()
        ec.expected = [
            (ECCmd.FPRD, 0x77, 304, "H2xH"),  # get state
            bytes.fromhex("2d10"  # EtherCAT Header, length & type
                          "0000e8030000008000000000"  # ID datagram
                          "04007700cdab04800000000000000000" # in datagram
                          "050077002143030000000000000000"), # out datagram
            1000, # == 0x3e8, see ID datagram
            ]
        ec.results = [
            (8, 0),  # return state 8, no error
            ]
        self.future = Future()
        ao.value = 0x9876
        with self.assertRaises(CancelledError):
            get_event_loop().run_until_complete(
                    gather(self.future, self.task))
        ec.expected = [
            bytes.fromhex("2d10"  # EtherCAT Header, length & type
                          "0000e8030000008000000000"  # ID datagram
                          "04007700cdab04800000123456780000" # in datagram
                          "050077002143030000007698000000"), # out datagram
            1000,
            ]
        ec.results = [
            bytes.fromhex("2d10"  # EtherCAT Header, length & type
                          "0000e8030000008000000000"  # ID datagram
                          "04007700cdab04800000123456780000" # in datagram
                          "050077002143030000007698000000"), # out datagram
            ]
        self.future = Future()
        with self.assertRaises(CancelledError):
            get_event_loop().run_until_complete(
                    gather(self.future, self.task))
        self.task.cancel()
        with self.assertRaises(CancelledError):
            get_event_loop().run_until_complete(self.task)

    def test_ebpf(self):
        ti = EL3164()
        ti.pdo_in_sz = 4
        ti.pdo_in_off = 0xABCD
        ti.position = 0x77
        ti.pdo_out_sz = None
        ti.pdo_out_off = None
        to = EL4104()
        to.pdo_in_sz = None
        to.pdo_in_off = None
        to.position = 0x55
        to.pdo_out_sz = 2
        to.pdo_out_off = 0x5678
        td = EK1814()
        td.pdo_in_sz = 1
        td.pdo_in_off = 0x7777
        td.position = 0x44
        td.pdo_out_sz = 1
        td.pdo_out_off = 0x8888

        class D(Device):
            ai = TerminalVar()
            ao = TerminalVar()
            di = TerminalVar()
            do = TerminalVar()

            def program(self):
                self.do = False
                self.do = True
                self.do = self.ai
                self.ao = self.di
                with self.di:
                    self.ao = self.ai

        d = D()
        d.ai = ti.channel1.value
        d.ao = to.ch1_value
        d.di = td.ch1
        d.do = td.ch5

        ec = MockEtherCat(self)
        sg = FastSyncGroup(ec, [d])
        ec.expected = [
            bytes.fromhex("4610"  # EtherCAT Header, length & type
                          "000033000000008000000000"  # ID datagram
                          "04004400777701800000000000"  # digi in
                          "05004400888801800000000000"  # digi out
                          "0500550078560280000000000000"  # ana out
                          "04007700cdab04000000000000000000")  # ana in
            ]
        task = sg.start()
        self.assertEqual(ec.rsg, sg)
        task.cancel()
        with self.assertRaises(CancelledError):
            get_event_loop().run_until_complete(task)
        sg.program()
        self.maxDiff = None
        self.assertEqual(sg.opcodes, [
            Instruction(opcode=O.W+O.LD, dst=9, src=1, off=0, imm=0),
            Instruction(opcode=O.W+O.LD, dst=0, src=1, off=4, imm=0),
            Instruction(opcode=O.W+O.LD, dst=2, src=1, off=0, imm=0),
            Instruction(opcode=O.ADD+O.LONG, dst=2, src=0, off=0, imm=83),
            Instruction(opcode=O.JLE+O.REG, dst=0, src=2, off=23, imm=0),
            Instruction(opcode=O.ST+O.B, dst=9, src=0, off=41, imm=5),
            Instruction(opcode=O.ST+O.B, dst=9, src=0, off=54, imm=5),

            Instruction(opcode=O.B+O.LD, dst=0, src=9, off=51, imm=0),
            Instruction(opcode=O.AND, dst=0, src=0, off=0, imm=-2),
            Instruction(opcode=O.STX+O.B, dst=9, src=0, off=51, imm=0),
            Instruction(opcode=O.B+O.LD, dst=0, src=9, off=51, imm=0),
            Instruction(opcode=O.OR, dst=0, src=0, off=0, imm=1),
            Instruction(opcode=O.STX+O.B, dst=9, src=0, off=51, imm=0),

            Instruction(opcode=O.LD+O.B, dst=0, src=9, off=51, imm=0),
            Instruction(opcode=O.REG+O.LD, dst=2, src=9, off=80, imm=0),
            Instruction(opcode=O.JEQ, dst=2, src=0, off=2, imm=0),
            Instruction(opcode=O.OR, dst=0, src=0, off=0, imm=1),
            Instruction(opcode=O.JMP, dst=0, src=0, off=1, imm=0),
            Instruction(opcode=O.AND, dst=0, src=0, off=0, imm=-2),
            Instruction(opcode=O.STX+O.B, dst=9, src=0, off=51, imm=0),

            Instruction(opcode=O.B+O.LD, dst=0, src=9, off=38, imm=0),
            Instruction(opcode=O.AND, dst=0, src=0, off=0, imm=1),
            Instruction(opcode=O.STX+O.REG, dst=9, src=0, off=64, imm=0),

            Instruction(opcode=O.LD+O.B, dst=0, src=9, off=38, imm=0),
            Instruction(opcode=O.JSET, dst=0, src=0, off=1, imm=1),
            Instruction(opcode=O.JMP, dst=0, src=0, off=2, imm=0),
            Instruction(opcode=O.LD+O.REG, dst=0, src=9, off=80, imm=0),
            Instruction(opcode=O.STX+O.REG, dst=9, src=0, off=64, imm=0),

            Instruction(opcode=O.MOV+O.LONG, dst=0, src=0, off=0, imm=3),
            Instruction(opcode=O.EXIT, dst=0, src=0, off=0, imm=0)])


    def tet_two(self):
        ti1 = EL3164()
        ti2 = EL3164()
        ti1.pdo_in_sz = ti2.pdo_in_sz = 4
        ti1.pdo_in_off = ti2.pdo_in_off = 0xABCD
        ti1.position = 0x77
        ti2.position = 0x99
        ti1.pdo_out_sz = ti2.pdo_out_sz = None
        ti1.pdo_out_off = ti2.pdo_out_off = None
        ec = MockEtherCat(self)
        ti1.ec = ti2.ec = ec
        ai1 = AnalogInput(ti1.ch1_value)
        ai2 = AnalogInput(ti2.ch1_value)
        ai3 = AnalogInput(ti1.ch1_attrs)
        SyncGroup.packet_index = 1000
        sg = SyncGroup(ec, [ai1, ai2, ai3])
        self.task = sg.start()
        ec.expected = [
            (ECCmd.FPRD, 0x99, 304, "H2xH"),  # get state
            (ECCmd.FPRD, 0x77, 304, "H2xH"),  # get state
            bytes.fromhex("2d10"  # EtherCAT Header, length & type
                          "0000e8030000008000000000"  # ID datagram
                          "04007700cdab04800000000000000000" # in datagram
                          "050077002143030000000000000000"), # out datagram
            1000, # == 0x3e8, see ID datagram
            bytes.fromhex("2d10"  # EtherCAT Header, length & type
                          "0000e8030000008000000000"  # ID datagram
                          "04007700cdab04800000123456780000" # in datagram
                          "050077002143030000000000000000"), # out datagram
            1000,
            ]
        ec.results = [
            (8, 0),  # return state 8, no error
            (8, 0),  # return state 8, no error
            bytes.fromhex("2d10"  # EtherCAT Header, length & type
                          "0000e8030000008000000000"  # ID datagram
                          "04007700cdab04800000123456780000" # in datagram
                          "050077002143030000000000000000"), # out datagram
            ]
        self.future = Future()
        with self.assertRaises(CancelledError):
            get_event_loop().run_until_complete(
                    gather(self.future, self.task))
        self.assertEqual(ai.value, 0x7856)
        self.task.cancel()
        with self.assertRaises(CancelledError):
            get_event_loop().run_until_complete(self.task)

    def test_motor(self):
        class T(EBPFTerminal):
            v = PacketDesc((0, 2), "H")
            e = PacketDesc((1, 0), "H")
            q = PacketDesc((0, 0), 0)
        t = T()
        t.pdo_in_sz = 2
        t.pdo_in_off = 0x1234
        t.pdo_out_sz = 4
        t.pdo_out_off = 0x5678
        t.position = 7
        m = Motor()
        m.velocity = t.v
        m.encoder = t.e
        m.low_switch = m.high_switch = t.q
        me = MockEtherCat(self)
        me.expected = [
            bytes.fromhex("2c10"
                          "000033000000008000000000"
                          "0400070034120280000000000000"
                          "05000700785604000000000000000000")]
        sg = FastSyncGroup(me, [m])
        sg.start()
        #sg.program()
        #sg.opcodes = sg.opcodes[:-1]
        print(sg.load(log_level=1)[1])
        self.maxDiff = None
        self.assertEqual(sg.opcodes, [])


if __name__ == "__main__":
    main()
