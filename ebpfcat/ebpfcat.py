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
from asyncio import ensure_future, gather, sleep
from struct import pack, unpack, calcsize, pack_into, unpack_from
from time import time
from .arraymap import ArrayMap, ArrayGlobalVarDesc
from .ethercat import ECCmd, EtherCat, Packet, Terminal
from .ebpf import FuncId, MemoryDesc, SubProgram, ktime
from .xdp import XDP, XDPExitCode
from .bpf import (
    ProgType, MapType, create_map, update_elem, prog_test_run, lookup_elem)


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
    def __init__(self, index, subindex, size=None):
        self.index = index
        self.subindex = subindex
        self.size = size

    def __get__(self, instance, owner):
        if instance is None:
            return self
        index = self.index + instance.position_offset[3]
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
            if isinstance(self.size, int):
                try:
                    bool(value)
                except RuntimeError:
                    e = device.sync_group
                    with e.wtmp:
                        e.wtmp = super().__get__(device, None)
                        with value as cond:
                            e.wtmp |= 1 << self.size
                        with cond.Else():
                            e.wtmp &= ~(1 << self.size)
                        super().__set__(device, e.wtmp)
                    return
                else:
                    old = super().__get__(device, None)
                    if value:
                        value = old | (1 << self.size)
                    else:
                        value = old & ~(1 << self.size)
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
            if isinstance(self.size, int):
                return super().__get__(device, None) & (1 << self.size)
            else:
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
        return ("B" if isinstance(self.size, int) else self.size,
                self._start(device) + Packet.ETHERNET_HEADER)


class Struct:
    device = None

    def __new__(cls, *args):
        return StructDesc(cls, *args)


class StructDesc:
    def __init__(self, struct, sm3=0, sm2=0):
        self.struct = struct
        self.position_offset = {2: sm2, 3: sm3}

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
        elif instance.sync_group.current_data is None:
            return super().__get__(instance, owner)
        else:
            return instance.__dict__.get(self.name, 0)

    def __set__(self, instance, value):
        if instance.sync_group.current_data is None:
            super().__set__(instance, value)
        else:
            instance.__dict__[self.name] = value


class Device(SubProgram):
    """A device is a functional unit in an EtherCAT loop

    A device aggregates data coming in and going to terminals
    to serve a common goal. A terminal may be used by several
    devices. """
    def get_terminals(self):
        ret = set()
        for pv in self.__dict__.values():
            if isinstance(pv, (PacketVar, Struct)):
                ret.add(pv.terminal)
        return ret


class EBPFTerminal(Terminal):
    compatibility = None
    position_offset = {2: 0, 3: 0}

    async def initialize(self, relative, absolute):
        await super().initialize(relative, absolute)
        if (self.compatibility is not None and
                (self.vendorId, self.productCode) not in self.compatibility):
            raise RuntimeError(
                f"Incompatible Terminal: {self.vendorId}:{self.productCode} "
                f"({relative}, {absolute})")
        await self.to_operational()
        self.pdos = {}
        if self.has_mailbox():
            await self.parse_pdos()

    def allocate(self, packet, readonly):
        """allocate space in packet for the pdos of this terminal

        return a dict that contains the starting offset for each
        sync manager"""
        bases = {}
        if self.pdo_in_sz:
            bases[3] = packet.size + packet.DATAGRAM_HEADER
            packet.append(ECCmd.FPRD, b"\0" * self.pdo_in_sz, 0,
                          self.position, self.pdo_in_off)
        if self.pdo_out_sz:
            bases[2] = packet.size + packet.DATAGRAM_HEADER
            if readonly:
                packet.on_the_fly.append((packet.size, ECCmd.FPWR))
                packet.append(ECCmd.NOP, b"\0" * self.pdo_out_sz, 0,
                              self.position, self.pdo_out_off)
            else:
                packet.append(ECCmd.FPWR, b"\0" * self.pdo_out_sz, 0,
                              self.position, self.pdo_out_off)
        return bases

    def update(self, data):
        pass


class EtherXDP(XDP):
    license = "GPL"

    variables = ArrayMap()
    counters = variables.globalVar("64I")

    rate = 0

    def program(self):
        with self.tmp:
            self.ebpf.tmp = ktime(self.ebpf)
            self.ebpf.tmp = self.ebpf.tmp * 0xcf019d85 + 1
            with self.ebpf.tmp & 0xffff < self.rate:
                self.ebpf.exit(XDPExitCode.DROP)
        with self.packetSize > 24 as p, p.pH[12] == 0xA488, p.pB[16] == 0:
            self.r3 = p.pI[18]
            with self.counters.get_address(None, False, False) as (dst, _), \
                    self.r3 < FastEtherCat.MAX_PROGS:
                self.mH[self.r[dst] + 4 * self.r3] += 1
                p.pB[17] += 2
                with p.pB[17] & 1 as is_regular:
                    self.mB[self.r[dst] + 4 * self.r3 + 3] += 1
                    self.mB[self.r[dst] + 4 * self.r3 + 2] = 0
                with is_regular.Else():
                    self.mB[self.r[dst] + 4 * self.r3 + 2] += 1
                    self.mB[self.r[dst] + 4 * self.r3 + 3] = 0
                    with self.mB[self.r[dst] + 4 * self.r3 + 2] > 3 as exceed:
                        p.pB[17] += 1  # turn into regular package
                    with exceed.Else():
                        self.exit(XDPExitCode.TX)
            self.r2 = self.get_fd(self.programs)
            for i, o in enumerate(self.opcodes):
                print(i, o)
            self.call(FuncId.tail_call)

        self.exit(XDPExitCode.PASS)


class SimpleEtherCat(EtherCat):
    def __init__(self, network, terminals):
        super().__init__(network)
        self.terminals = terminals
        for t in terminals:
            t.ec = self

    async def scan_bus(self):
        await gather(*[t.initialize(-i, i + 1)
                     for (i, t) in enumerate(self.terminals)])

class FastEtherCat(SimpleEtherCat):
    MAX_PROGS = 64

    def __init__(self, network, terminals):
        super().__init__(network, terminals)
        self.programs = create_map(MapType.PROG_ARRAY, 4, 4, self.MAX_PROGS)
        self.sync_groups = {}

    def register_sync_group(self, sg, packet):
        index = len(self.sync_groups)
        while index in self.sync_groups:
            index = (index + 1) % self.MAX_PROGS
        fd, _ = sg.load(log_level=1)
        update_elem(self.programs, pack("<I", index), pack("<I", fd), 0)
        self.sync_groups[index] = sg
        sg.assembled = packet.assemble(index)
        return index

    async def watchdog(self):
        lastcounts = [0] * 64
        while True:
            t0 = time()
            counts = self.ebpf.counters
            for i, sg in self.sync_groups.items():
                if ((counts[i] ^ lastcounts[i]) & 0xffff == 0
                        or (counts[i] >> 24) > 3):
                    self.send_packet(sg.assembled)
                    print("sent", i)
                lastcounts[i] = counts[i]
            await sleep(0.001)

    async def connect(self):
        await super().connect()
        self.ebpf = EtherXDP()
        self.ebpf.programs = self.programs
        self.fd = await self.ebpf.attach(self.addr[0])
        ensure_future(self.watchdog())


class SyncGroupBase:
    def __init__(self, ec, devices, **kwargs):
        super().__init__(**kwargs)
        self.ec = ec
        self.devices = devices

        terminals = set()
        for dev in self.devices:
            terminals.update(dev.get_terminals())
            dev.sync_group = self
        # sorting is only necessary for test stability
        self.terminals = {t: None for t in
                          sorted(terminals, key=lambda t: t.position)}


class SyncGroup(SyncGroupBase):
    """A group of devices communicating at the same time"""

    packet_index = 1000

    current_data = False  # None is used to indicate FastSyncGroup

    async def run(self):
        self.current_data = self.asm_packet
        while True:
            self.ec.send_packet(self.current_data)
            data = await self.ec.receive_index(self.packet_index)
            self.current_data = bytearray(data)
            for dev in self.devices:
                dev.update()
            await sleep(0)

    def start(self):
        self.allocate()
        self.packet_index = SyncGroup.packet_index
        SyncGroup.packet_index += 1
        self.asm_packet = self.packet.assemble(self.packet_index)
        return ensure_future(self.run())

    def allocate(self):
        self.packet = Packet()
        self.terminals = {t: t.allocate(self.packet, False)
                          for t in self.terminals}


class FastSyncGroup(SyncGroupBase, XDP):
    license = "GPL"

    current_data = None

    properties = ArrayMap()

    def __init__(self, ec, devices, **kwargs):
        super().__init__(ec, devices, subprograms=devices, **kwargs)

    def program(self):
        with self.packetSize >= self.packet.size + Packet.ETHERNET_HEADER as p:
            for pos, cmd in self.packet.on_the_fly:
                p.pB[pos + Packet.ETHERNET_HEADER] = cmd.value
            for dev in self.devices:
                dev.program()
        for o in self.opcodes:
            if o is not None:
                print(o, hex(o.opcode.value))
            else:
                print("JMP")
        self.exit(XDPExitCode.TX)

    def start(self):
        self.allocate()
        self.ec.register_sync_group(self, self.packet)

    def allocate(self):
        self.packet = Packet()
        self.packet.on_the_fly = []
        self.terminals = {t: t.allocate(self.packet, True)
                          for t in self.terminals}
