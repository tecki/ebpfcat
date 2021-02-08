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
        return PacketVar(instance, self)


class PacketVar:
    def __init__(self, terminal, desc):
        self.terminal = terminal
        self.desc = desc


class TerminalVar(MemoryDesc):
    base_register = 9

    def __init__(self):
        super().__init__(fmt="H")

    def __set__(self, instance, value):
        if isinstance(value, PacketVar):
            self.terminal = value.terminal
            self.position = value.desc.position
            instance.__dict__[self.name] = value
        elif instance.sync_group.current_data is None:
            super().__set__(instance.sync_group, value)
        else:
            pv = instance.__dict__.get(self.name)
            data = instance.sync_group.current_data
            start = self.terminal.bases[self.position[0]] + self.position[1]
            fmt = "<" + pv.desc.size
            pack_into(fmt, data, start, value)

    def __get__(self, instance, owner):
        if instance is None:
            return self
        pv = instance.__dict__.get(self.name)
        if pv is None:
            return None
        elif instance.sync_group.current_data is None:
            return super().__get__(instance.sync_group, owner)
        else:
            data = instance.sync_group.current_data
            start = self.terminal.bases[self.position[0]] + self.position[1]
            fmt = "<" + pv.desc.size
            return unpack_from(fmt, data, start)[0]

    def __set_name__(self, name, owner):
        self.name = name

    def addr(self, instance):
        # 14 is Ethernet header
        return self.terminal.bases[self.position[0]] + self.position[1] + 14


class DeviceVar(ArrayGlobalVarDesc):
    def __init__(self, size=4, signed=False):
        super().__init__(FastSyncGroup.properties, size, signed)

    def __get__(self, instance, owner):
        if instance is None:
            return self
        elif instance.sync_group.current_data is None:
            return super().__get__(instance, owner)
        else:
            return instance.__dict__[self.name]

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
            if isinstance(pv, PacketVar):
                ret.add(pv.terminal)
        return ret


class EBPFTerminal(Terminal):
    compatibility = None

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
            self.bases = [packet.size + packet.DATAGRAM_HEADER]
            packet.append(ECCmd.FPRD, b"\0" * self.pdo_in_sz, 0,
                          self.position, self.pdo_in_off)
        else:
            self.bases = [None]
        if self.pdo_out_sz:
            self.bases.append(packet.size + packet.DATAGRAM_HEADER)
            packet.append(ECCmd.FPWR, b"\0" * self.pdo_out_sz, 0,
                          self.position, self.pdo_out_off)

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
        with e.packetSize > 24 as p, e.If(p.pH[12] == 0xA488), \
                e.If(p.pB[16] == 0):
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


class SyncGroup:
    """A group of devices communicating at the same time"""

    packet_index = 1000

    current_data = False  # None is used to indicate FastSyncGroup

    def __init__(self, ec, devices, **kwargs):
        self.ec = ec
        self.devices = devices

        self.terminals = set()
        for dev in self.devices:
            self.terminals.update(dev.get_terminals())
            dev.sync_group = self

    async def run(self):
        await gather(*[t.to_operational() for t in self.terminals])
        self.current_data = self.asm_packet
        while True:
            self.ec.send_packet(self.current_data)
            data = await self.ec.receive_index(self.packet_index)
            self.current_data = bytearray(data)
            for dev in self.devices:
                dev.update()

    def start(self):
        self.packet = Packet()
        for term in self.terminals:
            term.allocate(self.packet)
        print(self.packet)
        self.packet_index = SyncGroup.packet_index
        SyncGroup.packet_index += 1
        self.asm_packet = self.packet.assemble(self.packet_index)
        ensure_future(self.run())


class FastSyncGroup(XDP):
    license = "GPL"

    current_data = None

    properties = ArrayMap()

    def __init__(self, ec, devices, **kwargs):
        super().__init__(subprograms=devices, **kwargs)
        self.ec = ec
        self.devices = devices

        self.terminals = set()
        for dev in self.devices:
            self.terminals.update(dev.get_terminals())
            dev.sync_group = self

    def program(self):
        with self.packetSize >= self.packet.size + 14 as p:
            for dev in self.devices:
                dev.program()
        self.exit(XDPExitCode.TX)

    def start(self):
        self.packet = Packet()
        for term in self.terminals:
            term.allocate(self.packet)
        index = self.ec.register_sync_group(self)
        self.ec.send_packet(self.packet.assemble(index))
        self.monitor = ensure_future(gather(*[t.to_operational()
                                              for t in self.terminals]))
