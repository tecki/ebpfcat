"""The high-level API for EtherCAT loops"""
from asyncio import ensure_future, gather, sleep
from struct import pack, unpack, calcsize, pack_into, unpack_from
from time import time
from .arraymap import ArrayMap, ArrayGlobalVarDesc
from .ethercat import ECCmd, EtherCat, Packet, Terminal
from .ebpf import FuncId, MemoryDesc, SubProgram
from .xdp import XDP, XDPExitCode
from .hashmap import HashMap
from .bpf import (
    ProgType, MapType, create_map, update_elem, prog_test_run, lookup_elem)


class PacketDesc:
    def __init__(self, position, size):
        self.position = position
        self.size = size

    def __get__(self, instance, owner):
        if instance is None:
            return self
        offset = instance.position_offset[self.position[0]]
        if isinstance(instance, Struct):
            terminal = instance.terminal
            device = instance.device
        else:
            terminal = instance
            device = None
        ret = PacketVar(terminal, (self.position[0],
                                   self.position[1] + offset), self.size)
        if device is None:
            return ret
        else:
            return ret.get(device)

    def __set__(self, instance, value):
        offset = instance.position_offset[self.position[0]]
        ret = PacketVar(instance.terminal,
                        (self.position[0], self.position[1] + offset),
                        self.size)
        return ret.set(instance.device, value)


class PacketVar(MemoryDesc):
    base_register = 9

    def fmt(self):
        if isinstance(self.size, int):
            return "B"
        else:
            return self.size

    def __init__(self, terminal, position, size):
        self.terminal = terminal
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
        base, offset = self.position
        return device.sync_group.terminals[self.terminal][base] + offset

    def fmt_addr(self, device):
        return ("B" if isinstance(self.size, int) else self.size,
                self._start(device) + Packet.ETHERNET_HEADER)


class Struct:
    device = None

    def __new__(cls, *args):
        return StructDesc(cls, *args)


class StructDesc:
    def __init__(self, struct, *position_offset):
        self.struct = struct
        self.position_offset = position_offset

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
    def __init__(self, size="I"):
        super().__init__(FastSyncGroup.properties, size)

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
    position_offset = 0, 0

    def __init_subclass__(cls):
        cls.pdo = {}
        for c in cls.__mro__[::-1]:
            for k, v in c.__dict__.items():
                if isinstance(v, PacketDesc):
                    cls.pdo[k] = v

    async def initialize(self, relative, absolute):
        await super().initialize(relative, absolute)
        if (self.compatibility is not None and
                (self.vendorId, self.productCode) not in self.compatibility):
            raise RuntimeError("Incompatible Terminal")

    def allocate(self, packet):
        if self.pdo_in_sz:
            bases = [packet.size + packet.DATAGRAM_HEADER]
            packet.append(ECCmd.FPRD, b"\0" * self.pdo_in_sz, 0,
                          self.position, self.pdo_in_off)
        else:
            bases = [None]
        if self.pdo_out_sz:
            bases.append(packet.size + packet.DATAGRAM_HEADER)
            packet.append(ECCmd.FPWR, b"\0" * self.pdo_out_sz, 0,
                          self.position, self.pdo_out_off)
        return bases

    def update(self, data):
        pass


class EBPFCat(XDP):
    vars = HashMap()

    count = vars.globalVar()
    ptype = vars.globalVar()

    def program(self):
        #with self.If(self.packet16[12] != 0xA488):
        #    self.exit(2)
        self.count += 1
        #self.ptype = self.packet32[18]
        self.exit(2)


class EtherXDP(XDP):
    license = "GPL"

    variables = HashMap()
    count = variables.globalVar()
    allcount = variables.globalVar()

    def program(self):
        e = self
        with e.packetSize > 24 as p, p.pH[12] == 0xA488, p.pB[16] == 0:
            e.count += 1
            e.r2 = e.get_fd(self.programs)
            e.r3 = p.pI[18]
            e.call(FuncId.tail_call)
        e.allcount += 1
        e.exit(XDPExitCode.PASS)


class FastEtherCat(EtherCat):
    MAX_PROGS = 64

    def __init__(self, network, terminals):
        super().__init__(network)
        self.terminals = terminals
        for t in terminals:
            t.ec = self
        self.programs = create_map(MapType.PROG_ARRAY, 4, 4, self.MAX_PROGS)
        self.sync_groups = {}

    def register_sync_group(self, sg):
        index = len(self.sync_groups)
        while index in self.sync_groups:
            index = (index + 1) % self.MAX_PROGS
        fd, _ = sg.load(log_level=1)
        update_elem(self.programs, pack("<I", index), pack("<I", fd), 0)
        self.sync_groups[index] = sg
        return index

    async def scan_bus(self):
        await gather(*[t.initialize(-i, i + 1)
                     for (i, t) in enumerate(self.terminals)])

    async def connect(self):
        await super().connect()
        self.ebpf = EtherXDP()
        self.ebpf.programs = self.programs
        self.fd = await self.ebpf.attach(self.addr[0])

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

    def allocate(self):
        self.packet = Packet()
        self.terminals = {t: t.allocate(self.packet) for t in self.terminals}


class SyncGroup(SyncGroupBase):
    """A group of devices communicating at the same time"""

    packet_index = 1000

    current_data = False  # None is used to indicate FastSyncGroup

    async def run(self):
        await gather(*[t.to_operational() for t in self.terminals])
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


class FastSyncGroup(SyncGroupBase, XDP):
    license = "GPL"

    current_data = None

    properties = ArrayMap()

    def __init__(self, ec, devices, **kwargs):
        super().__init__(ec, devices, subprograms=devices, **kwargs)

    def program(self):
        with self.packetSize >= self.packet.size + Packet.ETHERNET_HEADER as p:
            for dev in self.devices:
                dev.program()
        self.exit(XDPExitCode.TX)

    def start(self):
        self.allocate()
        index = self.ec.register_sync_group(self)
        self.ec.send_packet(self.packet.assemble(index))
        self.monitor = ensure_future(gather(*[t.to_operational()
                                              for t in self.terminals]))
        return self.monitor
