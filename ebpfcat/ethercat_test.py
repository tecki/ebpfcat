from asyncio import CancelledError, Future, get_event_loop, sleep, gather
from unittest import TestCase, main

from .devices import AnalogInput, AnalogOutput
from .terminals import EL4104, EL3164
from .ethercat import ECCmd
from .ebpfcat import SyncGroup


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
        ai = AnalogInput(ti.ch1_value)
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


if __name__ == "__main__":
    main()
