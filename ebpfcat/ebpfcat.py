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

"""The high-level API for EtherCAT loops"""
from asyncio import (
    CancelledError, ensure_future, gather, sleep, wait_for, TimeoutError)
from collections import defaultdict
from contextlib import asynccontextmanager, AsyncExitStack, contextmanager
from enum import Enum
import logging
import os
from struct import pack, unpack, calcsize, pack_into, unpack_from
from time import time
from .arraymap import ArrayMap, ArrayGlobalVarDesc
from .ethercat import (
    ECCmd, EtherCat, MachineState, Packet, Terminal, EtherCatError,
    SyncManager)
from .ebpf import FuncId, MemoryDesc, SubProgram, prandom
from .xdp import XDP, XDPExitCode, PacketVar as XDPPacketVar
from .bpf import (
    ProgType, MapType, create_map, delete_elem, update_elem, prog_test_run,
    lookup_elem)


class PacketDesc:
    def __init__(self, sm, position, size):
        self.sm = sm
        self.position = position
        self.size = size

    def __get__(self, instance, owner):
        if instance is None:
            return self
        offset = instance.position_offset[self.sm]
        if isinstance(instance, Struct):
            terminal = instance.terminal
            device = instance.device
        else:
            terminal = instance
            device = None
        ret = PacketVar(terminal, self.sm, self.position + offset, self.size)
        if device is None:
            return ret
        else:
            return ret.get(device)


class ProcessDesc:
    """A process variable as described in the current mapping

    This describes a process variable as found in the current
    PDO mapping read from the terminal.

    :param index: the index of the process variable, usually found
        in the terminal's documentation
    :param subindex: the subindex, also found in the documentation
    :param size: usually the size is taken from the PDO mapping. A
        different size as in a :mod:`python:struct` definition may be
        given here, or the number of a bit for a bit field.
    """
    def __init__(self, index, subindex, size=None):
        self.index = index
        self.subindex = subindex
        self.size = size

    def __get__(self, instance, owner):
        if instance is None:
            return self
        index = self.index + instance.position_offset[SyncManager.IN]
        if isinstance(instance, Struct):
            terminal = instance.terminal
            device = instance.device
        else:
            terminal = instance
            device = None
        sm, offset, size = terminal.pdos[index, self.subindex]
        if self.size is not None:
            size = self.size
        ret = PacketVar(terminal, sm, offset, size)
        if device is None:
            return ret
        else:
            return ret.get(device)


class PacketVar(MemoryDesc):
    base_register = 9

    def fmt(self):
        if isinstance(self.size, int):
            return "B"
        else:
            return self.size

    def __init__(self, terminal, sm, position, size):
        self.terminal = terminal
        self.sm = sm
        self.position = position
        self.size = size

    def set(self, device, value):
        if device.sync_group.current_data is None:
            super().__set__(device, value)
        else:
            data = device.sync_group.current_data
            start = self._start(device)
            if isinstance(self.size, int):
                if value:
                    data[start] |= 1 << self.size
                else:
                    data[start] &= ~(1 << self.size)
            else:
                pack_into("<" + self.size, data, start, value)

    def get(self, device):
        if device.sync_group.current_data is None:
            return super().__get__(device, None)
        else:
            data = device.sync_group.current_data
            start = self._start(device)
            if isinstance(self.size, int):
                return bool(data[start] & (1 << self.size))
            else:
                return unpack_from("<" + self.size, data, start)[0]

    def _start(self, device):
        return device.sync_group.terminals[self.terminal][self.sm] \
               + self.position

    def fmt_addr(self, device):
        return ((self.size, 1) if isinstance(self.size, int) else self.size,
                self._start(device) + Packet.ETHERNET_HEADER)


class Struct:
    """Define repetitive structures in a PDO

    Some terminals, especially multi-channel terminals,
    have repetitive structures in their PDO. Inherit from this
    class to create a structure for them. Each instance
    will then define one channel. It takes one parameter, which
    is the offset in the CoE address space from the template
    structure to the one of the channel.
    """
    device = None

    def __new__(cls, *args):
        return StructDesc(cls, *args)


class StructDesc:
    def __init__(self, struct, sm3=0, sm2=None):
        self.struct = struct
        if sm2 is None:
            sm2 = sm3
        self.position_offset = {SyncManager.OUT: sm2, SyncManager.IN: sm3}

    def __get__(self, instance, owner):
        if instance is None:
            return self
        ret = object.__new__(self.struct)
        ret.position_offset = self.position_offset
        ret.terminal = instance
        return ret


class TerminalVar:
    def __set__(self, instance, value):
        if isinstance(value, PacketVar):
            instance.__dict__[self.name] = value
        elif isinstance(value, Struct):
            instance.__dict__[self.name] = value
            value.device = instance
        else:
            return instance.__dict__[self.name].set(instance, value)

    def __get__(self, instance, owner):
        if instance is None:
            return self
        var = instance.__dict__.get(self.name)
        if var is None:
            return None
        elif isinstance(var, Struct):
            return var
        else:
            return instance.__dict__[self.name].get(instance)

    def __set_name__(self, owner, name):
        self.name = name


class DeviceVar(ArrayGlobalVarDesc):
    def __init__(self, size="I", write=False):
        super().__init__(FastSyncGroup.properties, size)
        self.write = write

    def __get__(self, instance, owner):
        if instance is None:
            return self
        elif isinstance(instance.sync_group, FastSyncGroup):
            return super().__get__(instance, owner)
        else:
            return instance.__dict__.get(self.name, 0)

    def __set__(self, instance, value):
        if isinstance(instance.sync_group, FastSyncGroup):
            super().__set__(instance, value)
        else:
            instance.__dict__[self.name] = value


class Device(SubProgram):
    """A device is a functional unit in an EtherCAT loop

    A device aggregates data coming in and going to terminals
    to serve a common goal. A terminal may be used by several
    devices. """
    def get_terminals(self):
        """return the terminals used by this device

        return a dictionary of terminal vs. a boolean indicating
        whether access is read-write.
        """
        ret = defaultdict(lambda: False)
        for pv in self.__dict__.values():
            if isinstance(pv, (PacketVar, Struct)):
                ret[pv.terminal] |= pv.sm is SyncManager.OUT
        return ret

    def fast_update(self):
        pass


class EBPFTerminal(Terminal):
    """This is the base class for all supported terminal types

    inheriting classes should define a ``compatibility`` class variable
    which is a set of tuples, each of which is a pair of Ethercat vendor and
    product id of all supported terminal types.
    """
    compatibility = None
    position_offset = {SyncManager.OUT: 0, SyncManager.IN: 0}
    use_fmmu = True
    out_pdos = None
    in_pdos = None

    async def apply_eeprom(self):
        await super().apply_eeprom()
        if (self.compatibility is not None and
                (self.vendorId, self.productCode) not in self.compatibility):
            raise EtherCatError(
                f"Incompatible Terminal: {self.vendorId}:{self.productCode}")
        await self.to_operational(MachineState.PRE_OPERATIONAL)
        if self.out_pdos is not None:
            await self.write_pdos(0x1c12, self.out_pdos)
        if self.in_pdos is not None:
            await self.write_pdos(0x1c13, self.in_pdos)
        self.pdos = {}
        outbits, inbits = await self.parse_pdos()
        self.pdo_out_sz = int((outbits + 7) // 8)
        assert not self.pdo_out_sz or self.pdo_out_off
        self.pdo_in_sz = int((inbits + 7) // 8)
        assert not self.pdo_in_sz or self.pdo_in_off
        await self.write_pdo_sm()

    async def write_pdos(self, index, values):
        await self.sdo_write(pack('B', 0), index, 0)
        for i, v in enumerate(values, 1):
            await self.sdo_write(pack('<H', v), index, i)
        await self.sdo_write(pack('<H', 0), index, i + 1)
        await self.sdo_write(pack('B', len(values)), index, 0)

    def allocate(self, packet, readwrite):
        """allocate space in packet for the pdos of this terminal

        return a dict that contains the datagram number and
        starting offset therein for each sync manager.

        Negative datagram numbers are for the future FMMU
        datagrams."""
        bases = {}
        if self.use_fmmu:
            if self.pdo_in_sz:
                bases[SyncManager.IN] = (BaseType.FMMU_IN, packet.fmmu_in_size)
                packet.fmmu_in_size += self.pdo_in_sz
                packet.fmmu_in_count += 1
            if readwrite and self.pdo_out_sz:
                bases[SyncManager.OUT] = (BaseType.FMMU_OUT,
                                          packet.fmmu_out_size)
                packet.fmmu_out_size += self.pdo_out_sz
                packet.fmmu_out_count += 1
        else:
            if self.pdo_in_sz:
                bases[SyncManager.IN] = (BaseType.NO_FMMU, packet.size)
                packet.append(ECCmd.FPRD, b"\0" * self.pdo_in_sz, 0,
                              self.position, self.pdo_in_off)
            if readwrite and self.pdo_out_sz:
                bases[SyncManager.OUT] = (BaseType.NO_FMMU, packet.size)
                packet.append_writer(ECCmd.FPWR, b"\0" * self.pdo_out_sz, 0,
                                     self.position, self.pdo_out_off)
        return bases

    def update(self, data):
        pass


class EtherXDP(XDP):
    license = "GPL"
    minimumPacketSize = 30

    variables = ArrayMap()
    dropcounter = variables.globalVar("I")
    counters = variables.globalVar("64I")

    rate = 0

    DATA0 = 26

    ethertype = XDPPacketVar(12, "!H")
    addr0 = XDPPacketVar(18, "I")
    cmd0 = XDPPacketVar(16, "B")
    data0 = XDPPacketVar(DATA0, "H")

    def program(self):
        with prandom(self.ebpf) & 0xffff < self.rate:
            self.dropcounter += 1
            self.ebpf.exit(XDPExitCode.DROP)
        with self.ethertype == 0x88A4, self.cmd0 == 0:
            self.r3 = self.addr0  # use r3 for tail_call
            with self.counters.get_address(None, False, False) as (dst, _), \
                    self.r3 < FastEtherCat.MAX_PROGS:
                self.r[dst] += 4 * self.r3
                self.r4 = self.mH[self.r[dst]]
                # we lost a packet
                with self.data0 == self.r4 as Else:
                    self.mI[self.r[dst]] += 1 + (self.r4 & 1)
                # normal case: two packets on the wire
                with Else, ((self.data0 + 1 & 0xffff) == self.r4) \
                           | (self.data0 == 0) as Else:
                    self.mI[self.r[dst]] += 1
                    with self.r4 & 1:  # last one was active
                        self.data0 = self.mH[self.r[dst]]
                        self.exit(XDPExitCode.TX)
                with Else:
                    self.exit(XDPExitCode.PASS)
                self.data0 = self.mH[self.r[dst]]
                self.r2 = self.get_fd(self.programs)
                self.call(FuncId.tail_call)
        self.exit(XDPExitCode.PASS)


class SimpleEtherCat(EtherCat):
    pass


class FastEtherCat(SimpleEtherCat):
    MAX_PROGS = 64

    def __init__(self, network):
        super().__init__(network)
        self.programs = create_map(MapType.PROG_ARRAY, 4, 4, self.MAX_PROGS)
        self.sync_groups = {}

    @contextmanager
    def register_sync_group(self, sg):
        index = len(self.sync_groups)
        while index in self.sync_groups:
            index = (index + 1) % self.MAX_PROGS
        fd, _ = sg.load(log_level=1)
        update_elem(self.programs, pack("<I", index), pack("<I", fd), 0)
        os.close(fd)
        self.sync_groups[index] = sg
        try:
            yield index
        finally:
            delete_elem(self.programs, pack("<I", index))

    async def connect(self):
        await super().connect()
        self.ebpf = EtherXDP()
        self.ebpf.programs = self.programs
        self.fd = await self.ebpf.attach(self.addr[0])

    @asynccontextmanager
    async def run(self):
        await super().connect()
        self.ebpf = EtherXDP()
        self.ebpf.programs = self.programs
        async with self.ebpf.run(self.addr[0]):
            try:
                yield
            finally:
                for v in self.sync_groups.values():
                    v.cancel()


class SterilePacket(Packet):
    """a sterile packet has all its sets exchanged by NOPs"""
    next_logical_addr = 0  # global for all packets
    logical_addr_inc = 0x800

    def __init__(self):
        super().__init__()
        self.on_the_fly = []  # list of sterilized positions
        self.fmmu_out_size = self.fmmu_in_size = 0
        self.fmmu_out_count = self.fmmu_in_count = 0
        self.counters = {}

    def append_writer(self, cmd, *args, **kwargs):
        self.on_the_fly.append((self.size, cmd))
        self.append(cmd, *args, **kwargs)

    def append(self, cmd, *args, counter=1):
        super().append(cmd, *args)
        self.counters[self.size - 2] = counter

    def sterile(self, index):
        ret = bytearray(self.assemble(index))
        for pos, cmd in self.on_the_fly:
            ret[pos] = ECCmd.NOP.value
        return ret

    def append_fmmu(self):
        SterilePacket.next_logical_addr += 2 * self.logical_addr_inc
        fmmu_in_pos = self.size
        if self.fmmu_in_size:
            self.append(ECCmd.LRD, b"\0" * self.fmmu_in_size, 0,
                        self.next_logical_addr, counter=self.fmmu_in_count)
        fmmu_out_pos = self.size
        if self.fmmu_out_size:
            self.append_writer(ECCmd.LWR, b"\0" * self.fmmu_out_size, 0,
                               self.next_logical_addr + self.logical_addr_inc,
                               counter=self.fmmu_out_count)
        return (fmmu_in_pos, fmmu_out_pos, self.next_logical_addr,
                self.next_logical_addr + self.logical_addr_inc)

    def activate(self, ebpf):
        for pos, cmd in self.on_the_fly:
            ebpf.pB[pos + self.ETHERNET_HEADER] = cmd.value


class BaseType(Enum):
    NO_FMMU = 0
    FMMU_IN = 1
    FMMU_OUT = 2


class SyncGroupBase:
    missed_counter = 0

    current_data = None
    logical_in = logical_out = None

    def __init__(self, ec, devices, **kwargs):
        super().__init__(**kwargs)
        self.ec = ec
        self.devices = devices

        terminals = defaultdict(lambda: False)
        for dev in self.devices:
            for t, rw in dev.get_terminals().items():
                terminals[t] |= rw
            dev.sync_group = self
        # sorting is only necessary for test stability
        self.terminals = {t: rw for t, rw in
                          sorted(terminals.items(),
                                 key=lambda item: item[0].position)}

    async def to_operational(self):
        await gather(*[t.to_operational() for t in self.terminals])

    @asynccontextmanager
    async def map_fmmu(self):
        async with AsyncExitStack() as stack:
            for terminal, bases in self.fmmu_maps.items():
                base = bases.get(SyncManager.OUT)
                if base is not None:
                    await stack.enter_async_context(
                            terminal.map_fmmu(base, True))
                base = bases.get(SyncManager.IN)
                if base is not None:
                    await stack.enter_async_context(
                            terminal.map_fmmu(base, False))
            yield

    async def run(self):
        data = self.asm_packet
        async with self.map_fmmu():
            task = ensure_future(self.to_operational())
            try:
                while True:
                    self.ec.send_packet(data)
                    try:
                        data = await wait_for(
                                self.ec.receive_index(self.packet_index),
                                timeout=0.1)
                    except TimeoutError:
                        self.missed_counter += 1
                        logging.warning(
                            "did not receive Ethercat response in time %i",
                            self.missed_counter)
                        continue
                    data = self.update_devices(data)
            finally:
                task.cancel()
                try:
                    await task  # should be done quickly, just here to not forget
                except CancelledError:
                    pass

    def allocate(self):
        self.packet = SterilePacket()
        terminals = {t: t.allocate(self.packet, rw)
                     for t, rw in self.terminals.items()}
        in_pos, out_pos, logical_in, logical_out = self.packet.append_fmmu()
        offsets = {BaseType.NO_FMMU: 0,
                   BaseType.FMMU_IN: in_pos, BaseType.FMMU_OUT: out_pos}
        self.terminals = {t: {sm: offsets[base] + off + Packet.DATAGRAM_HEADER
                              for sm, (base, off) in d.items()}
                          for t, d in terminals.items()}
        offsets = {BaseType.FMMU_IN: logical_in,
                   BaseType.FMMU_OUT: logical_out}
        self.fmmu_maps = {t: {sm: offsets[base] + off
                              for sm, (base, off) in d.items()
                              if base is not BaseType.NO_FMMU}
                          for t, d in terminals.items()}


class SyncGroup(SyncGroupBase):
    """A group of devices communicating at the same time"""

    packet_index = 1000

    def update_devices(self, data):
        self.current_data = bytearray(data)
        for pos, count in self.packet.counters.items():
            if data[pos] != count:
                logging.warning(
                    'EtherCAT datagram was processe %i times, should be %i',
                    data[pos], count)
            self.current_data[pos] = 0
        for dev in self.devices:
            dev.update()
        return self.current_data

    async def to_operational(self):
        try:
            await gather(*[t.to_operational() for t in self.terminals])

            while True:
                r = await gather(*[t.to_operational() for t in self.terminals])
                for t, (state, error, status) in zip(self.terminals, r):
                    if state is not MachineState.OPERATIONAL:
                        logging.warning(
                            "terminal %s was not operational, status was %i",
                            t, status)
                await sleep(1)
        except CancelledError:
            raise
        except Exception:
            logging.exception('to_operational failed')
            raise

    def start(self):
        self.allocate()
        self.packet_index = SyncGroup.packet_index
        SyncGroup.packet_index += 1
        self.asm_packet = self.packet.assemble(self.packet_index)
        self.task = ensure_future(self.run())
        return self.task


class FastSyncGroup(SyncGroupBase, XDP):
    license = "GPL"

    properties = ArrayMap()

    def __init__(self, ec, devices, **kwargs):
        super().__init__(ec, devices, subprograms=devices, **kwargs)

    def program(self):
        with self.packetSize >= self.packet.size + Packet.ETHERNET_HEADER as p:
            self.packet.activate(p)
            for dev in self.devices:
                dev.program()
        self.exit(XDPExitCode.TX)

    async def run(self):
        with self.ec.register_sync_group(self) as self.packet_index:
            self.asm_packet = self.packet.sterile(self.packet_index)
            # prime the pump: two packets to get things going
            self.ec.send_packet(self.asm_packet)
            self.ec.send_packet(self.asm_packet)
            await super().run()

    def update_devices(self, data):
        if data[EtherXDP.DATA0 - Packet.ETHERNET_HEADER] & 1:
            self.current_data = data
        elif self.current_data is None:
            return self.asm_packet
        for dev in self.devices:
            dev.fast_update()
        return self.asm_packet

    def start(self):
        self.allocate()
        self.task = ensure_future(self.run())
        return self.task

    def cancel(self):
        self.task.cancel()
