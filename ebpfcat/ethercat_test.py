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

from ast import literal_eval
from asyncio import as_completed, CancelledError, Event, Future, get_event_loop, sleep, gather
from contextlib import contextmanager
from functools import wraps
from itertools import count
from struct import pack
from unittest import TestCase, main, skip
from unittest.mock import Mock

from .devices import AnalogInput, AnalogOutput, Motor
from .terminals import EL4104, EL3164, EK1814, Skip
from .ethercat import ECCmd, MachineState, Terminal
from .ebpfcat import (
    FastSyncGroup, SyncGroup, TerminalVar, Device, EBPFTerminal, PacketDesc,
    SterilePacket, SimpleEtherCat, SyncManager)
from .ebpf import Instruction, Opcode as O


H = bytes.fromhex
ZERO = 0.01  # near-zero time to fool broken Python


class SimpleTests(TestCase):
    def test_device(self):
        ec = SimpleEtherCat('test network')
        ec.next_logical_addr = 7
        term = EL4104(ec)
        term.position = 3
        term.pdos = {(0x7000, 1): (SyncManager.OUT, 3, 'h')}
        term.pdo_in_sz = 0
        term.pdo_out_sz = 12
        device = AnalogOutput(term.ch1_value)
        sg = SyncGroup(ec, [device])
        sg.allocate()
        sg.current_data = bytearray(b'abcdefghijklmnopqrstuvwxyzABCDEFG')
        device.data = 0x3333
        self.assertEqual(sg.current_data, b'abcdefghijklmnopqrstuvwxyzABC33FG')


class MockEtherCatBase:
    def __init__(self, test):
        self.test = test
        with open(__file__.rsplit("/", 1)[0] + "/testdata.py", "r") as fin:
            self.test_data = literal_eval(fin.read())


class MockEtherCat(MockEtherCatBase):
    async def roundtrip(self, *args, data=None):
        if self.expected is None:
            return
        if data is not None:
            args += data,
        if not self.expected:
            self.test.fail(f"unexpected {args}")
        self.test.assertEqual(args, self.expected.pop(0))
        await sleep(ZERO)
        return self.results.pop(0)

    def send_packet(self, data):
        self.test.assertEqual(data, self.expected.pop(0), data.hex())

    async def receive_index(self, index):
        self.test.assertEqual(index, self.expected.pop(0))
        if not self.expected:
            self.test.data_needed.set()
        await sleep(ZERO)
        return self.results.pop(0)

    @contextmanager
    def register_sync_group(self, sg):
        self.rsg = sg
        yield 0x33
        return


class MockTerminal(Terminal):
    async def initialize(self, relative, absolute):
        self.position = absolute
        self.operational = 1
        data = self.ec.test_data[-relative]
        self.test_eeprom = data["eeprom"]
        self.test_sdo = data["sdo"]

        await self.apply_eeprom()

    async def to_operational(self, state=MachineState.OPERATIONAL):
        assert isinstance(state, MachineState)
        before = self.operational
        self.operational = state
        return state, 0, before

    async def sdo_read(self, index, subindex=None):
        assert self.operational.value >= 2
        if subindex is None:
            r = b''
            for i in count(1):
                a = self.test_sdo.get((index, i))
                if a is None:
                    break
                r += a
            return r
        elif subindex == 0 and (index, 0) not in self.test_sdo:
            for i in count(1):
                a = self.test_sdo.get((index, i))
                if a is None:
                    return pack("B", i - 1)
        return self.test_sdo[index, subindex]

    async def _eeprom_read_one(self, pos):
        if pos * 2 > len(self.test_eeprom):
            return b"\xff" * 8
        return self.test_eeprom[pos*2 : pos*2 + 8]


def mockAsync(f):
    @wraps(f)
    def wrapper(self):
        self.data_needed = Event()
        get_event_loop().run_until_complete(f(self))
        self.assertTrue(self.data_needed.is_set())
    return wrapper


def mockTerminal(ec, cls):
    class Mocked(MockTerminal, cls):
        pass
    return Mocked(ec)


class Tests(TestCase):
    async def new_data(self):
        for f in as_completed((self.data_needed.wait(), self.task)):
            await f
            return

    @mockAsync
    async def test_input(self):
        ec = MockEtherCat(self)
        ti = mockTerminal(ec, EL3164)
        ti.use_fmmu = False
        terms = [Skip(ec), ti]
        ec.expected = [ (ECCmd.FPWR, 2, 0x800, 0x80),
            (ECCmd.FPWR, 2, 0x800, H('00108000260001018010800022000102'
                                     '00110000040000038011100020000104')),
            (ECCmd.FPWR, 2, 2070, 'B', 0),  # disable sync manager
            (ECCmd.FPWR, 2, 2066, 'H', 0),  # set sync manager size
            (ECCmd.FPWR, 2, 2070, 'B', False),  # disable 0-length sync manager
            (ECCmd.FPWR, 2, 2078, 'B', 0),  # disable other sync manager
            (ECCmd.FPWR, 2, 2074, 'H', 16),  # set sync manager size
            (ECCmd.FPWR, 2, 2078, 'B', True),  # enable sync manager
        ]
        ec.results = [None, None, None, None, None, None, None, None]
        await gather(*[t.initialize(-i, i + 1)
                       for (i, t) in enumerate(terms)])
        ai = AnalogInput(ti.channel1.value)
        SyncGroup.packet_index = 0x66554433
        sg = SyncGroup(ec, [ai])
        self.task = sg.start()
        ec.expected = [
            H("2a10"  # EtherCAT Header, length & type
              "0000334455660280000000000000"  # ID datagram
              # in datagram
              "04000200801110000000000000000000000000000000000000000000"
              "3333"), # padding
            0x66554433, # index
            H("2a10"  # EtherCAT Header, length & type
              "0000334455660280000000000000"  # ID datagram
              # in datagram
              "04000400801110000000123456780000000000000000000000000000"
              "3333"),  # padding
            0x66554433, # index
            ]
        ec.results = [
            H("2a10"  # EtherCAT Header, length & type
              "0000334455660280000000000000"  # ID datagram
              # in datagram
              "04000400801110000000123456780000000000000000000000000100"
              "3333"), # padding
            ]
        with self.assertNoLogs():
            await self.new_data()
        self.assertFalse(ec.expected or ec.results)
        self.assertEqual(ai.value, 0x7856)
        self.task.cancel()
        with self.assertRaises(CancelledError):
            await self.task

    @mockAsync
    async def test_output(self):
        ec = MockEtherCat(self)
        ti = mockTerminal(ec, EL4104)
        ti.use_fmmu = False
        terms = [Skip(ec), Skip(ec), ti]
        ec.expected = [
            (ECCmd.FPWR, 3, 0x800, 0x80),
            (ECCmd.FPWR, 3, 0x800, H('0010800026000101801080002200010'
                                     '200110800240001038011000000000004')),
            (ECCmd.FPWR, 3, 2070, 'B', 0),  # disable sync manager
            (ECCmd.FPWR, 3, 2066, 'H', 8),  # set sync manager size
            (ECCmd.FPWR, 3, 2070, 'B', True),  # enable sync manager
            (ECCmd.FPWR, 3, 2078, 'B', 0),  # disable other sync manager
            (ECCmd.FPWR, 3, 2074, 'H', 0),  # set sync manager size
            (ECCmd.FPWR, 3, 2078, 'B', False),  # disable 0-length sync manager
        ]
        ec.results = [None, None, None, None, None, None, None, None]
        await gather(*[t.initialize(-i, i + 1)
                       for (i, t) in enumerate(terms)])
        ao = AnalogOutput(ti.ch1_value)
        SyncGroup.packet_index = 0x55443322
        sg = SyncGroup(ec, [ao])
        self.task = sg.start()
        self.assertFalse(ec.expected or ec.results)
        ec.expected = [
            H("2210"  # EtherCAT Header, length & type
              "0000223344550280000000000000"  # ID datagram
              "0500030000110800000000000000000000000000" # out datagram
              "33333333333333333333"), # padding
            0x55443322,  # index
            H("2210"  # EtherCAT Header, length & type
              "0000223344550280000000000000"  # ID datagram
              "0500030000110800000076980000000000000000" # out datagram
              "33333333333333333333"), # padding
            0x55443322,  # index
            H("2210"  # EtherCAT Header, length & type
              "0000223344550280000000000000"  # ID datagram
              "0500030000110800000076980000000000000000" # out datagram
              "33333333333333333333"), # padding
            0x55443322,  # index
            ]
        ec.results = [
            H("2210"  # EtherCAT Header, length & type
              "0000223344550280000000000000"  # ID datagram
              "0500030000110800000000000000000000000100" # out datagram
              "33333333333333333333"), # padding
            H("2210"  # EtherCAT Header, length & type
              "0000223344550280000000000000"  # ID datagram
              "0500030000110800000000000000000000000100" # out datagram
              "33333333333333333333"), # padding
            ]
        ao.value = 0x9876
        with self.assertNoLogs():
            await self.new_data()
        self.assertFalse(ec.expected or ec.results, f"{ec.expected} {ec.results}")
        self.task.cancel()
        with self.assertRaises(CancelledError):
            await self.task
        self.assertFalse(ec.expected or ec.results, f"{ec.expected} {ec.results}")

    @mockAsync
    async def test_ebpf(self):
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

        ec = MockEtherCat(self)
        ec.expected = None

        ti = mockTerminal(ec, EL3164)
        to = mockTerminal(ec, EL4104)
        td = mockTerminal(ec, EK1814)
        ti.use_fmmu = False
        to.use_fmmu = False
        td.use_fmmu = False

        terms = [td, ti, to]
        await gather(*[t.initialize(-i, i + 1)
                       for (i, t) in enumerate(terms)])
        d.ai = ti.channel1.value
        d.ao = to.ch1_value
        d.di = td.channel1
        d.do = td.channel5
        sg = FastSyncGroup(ec, [d])
        ec.expected = [
            bytes.fromhex("5810"  # EtherCAT Header, length & type
                          "0000330000000280000000000000"  # ID datagram
                          "04000100001001800000000000"  # digi in
                          "00000100010f01800000000000"  # digi out
                          "04000200801110800000000000000000000"
                              "000000000000000000000"  # ana in
                          "0000030000110800000000000000000000000000"  # ana out
                          )
            ] * 3 + [51]
        ec.results = [#ec.expected[0], ec.expected[0],
            ]
        self.task = sg.start()
        await self.new_data()
        self.assertFalse(ec.expected or ec.results)
        self.assertEqual(ec.rsg, sg)
        sg.program()
        self.maxDiff = None
        self.assertEqual(sg.opcodes, [
            Instruction(opcode=O.LD+O.W, dst=9, src=1, off=0, imm=0),
            Instruction(opcode=O.LD+O.W, dst=0, src=1, off=4, imm=0),
            Instruction(opcode=O.LD+O.W, dst=2, src=1, off=0, imm=0),
            Instruction(opcode=O.LONG+O.ADD, dst=2, src=0, off=0, imm=103),
            Instruction(opcode=O.REG+O.JLE, dst=0, src=2, off=24, imm=0),
            Instruction(opcode=O.ST+O.B, dst=9, src=0, off=43, imm=5),
            Instruction(opcode=O.ST+O.B, dst=9, src=0, off=84, imm=5),
            # self.do = False
            Instruction(opcode=O.LD+O.B, dst=0, src=9, off=53, imm=0),
            Instruction(opcode=O.AND, dst=0, src=0, off=0, imm=-2),
            Instruction(opcode=O.B+O.STX, dst=9, src=0, off=53, imm=0),
            # self.do = True
            Instruction(opcode=O.LD+O.B, dst=0, src=9, off=53, imm=0),
            Instruction(opcode=O.OR, dst=0, src=0, off=0, imm=1),
            Instruction(opcode=O.B+O.STX, dst=9, src=0, off=53, imm=0),
            # self.do = self.ai
            Instruction(opcode=O.LD+O.REG, dst=2, src=9, off=68, imm=0),
            Instruction(opcode=O.JEQ, dst=2, src=0, off=3, imm=0),
            Instruction(opcode=O.LD+O.B, dst=0, src=9, off=53, imm=0),
            Instruction(opcode=O.OR, dst=0, src=0, off=0, imm=1),
            Instruction(opcode=O.JMP, dst=0, src=0, off=2, imm=0),
            Instruction(opcode=O.LD+O.B, dst=0, src=9, off=53, imm=0),
            Instruction(opcode=O.AND, dst=0, src=0, off=0, imm=-2),
            Instruction(opcode=O.B+O.STX, dst=9, src=0, off=53, imm=0),
            # self.ao = self.di
            Instruction(opcode=O.LD+O.B, dst=0, src=9, off=40, imm=0),
            Instruction(opcode=O.LONG+O.AND, dst=0, src=0, off=0, imm=1),
            Instruction(opcode=O.REG+O.STX, dst=9, src=0, off=94, imm=0),
            # with self.di:
            Instruction(opcode=O.LD+O.B, dst=0, src=9, off=40, imm=0),
            Instruction(opcode=O.JSET, dst=0, src=0, off=1, imm=1),
            Instruction(opcode=O.JMP, dst=0, src=0, off=2, imm=0),
            # self.ao = self.ai
            Instruction(opcode=O.LD+O.REG, dst=0, src=9, off=68, imm=0),
            Instruction(opcode=O.REG+O.STX, dst=9, src=0, off=94, imm=0),

            Instruction(opcode=O.LONG+O.MOV, dst=0, src=0, off=0, imm=3),
            Instruction(opcode=O.EXIT, dst=0, src=0, off=0, imm=0)
            ])
        self.task.cancel()
        with self.assertRaises(CancelledError):
            await self.task

    @skip
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

    @skip
    def test_motor(self):
        class T(EBPFTerminal):
            v = PacketDesc(2, 2, "H")
            e = PacketDesc(3, 0, "H")
            q = PacketDesc(2, 0, 0)
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
        t.ec = me
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


class UnitTests(TestCase):
    def test_sterile(self):
        p = SterilePacket()
        p.append(ECCmd.LRD, b"asdf", 0x33, 0x654321)
        p.append_writer(ECCmd.FPRD, b"fdsa", 0x44, 0x55, 0x66)
        self.assertEqual(p.assemble(0x77),
                         H("2e10"
                           "0000770000000280000000000000"
                           "0a332143650004800000617364660000"
                           "04445500660004000000666473610000"))
        self.assertEqual(p.sterile(0x77),
                         H("2e10"
                           "0000770000000280000000000000"
                           "0a332143650004800000617364660000"
                           "00445500660004000000666473610000"))
        self.assertEqual(p.on_the_fly, [(32, ECCmd.FPRD)])

if __name__ == "__main__":
    main()
