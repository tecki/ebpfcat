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
import asyncio
from asyncio import (
    CancelledError, TimeoutError, ensure_future, gather,
    get_event_loop, sleep, wait_for)
from collections import defaultdict
from contextlib import asynccontextmanager, AsyncExitStack, contextmanager
from enum import Enum
import gc
import logging
from multiprocessing import Array, Process, Value, get_context
import os
from random import randint
import shutil
from struct import pack, unpack, calcsize, pack_into, unpack_from
import struct
import tempfile
from time import monotonic
from .arraymap import ArrayMap, ArrayGlobalVarDesc
from .ethercat import (
    ECCmd, EtherCat, MachineState, Packet, Terminal, EtherCatError,
    Struct, SyncManager)
from .ebpf import (
    EBPFBase, FuncId, MemoryDesc, SimulatedEBPF, SubProgram, prandom)
from .lock import FMMULock, LockFile, ParallelMailboxLock
from .xdp import XDP, XDPExitCode, PacketVar as XDPPacketVar
from .bpf import (
    MapType, ProgType, create_map, delete_elem, lookup_elem, obj_pin, obj_get,
    prog_test_run, update_elem)


class PacketDesc:
    """A single value in a process data

    This describes some data in the process data coming from or sent to
    a terminal. This is the low-level version of :class:`ProcessDesc`, which
    can be used if the terminal's self-desciption is lacking.

    :param sm: the sync manager, either :attr:`SyncManager.IN` or
        :attr:`SyncManager.OUT`.
    :param position: the byte position in the process data
    :param size: either a :mod:`python:struct` definition of a data type,
        or an integer denoting the bit within a byte to be adressed.
    """
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
        index = self.index + instance.position_offset[None]
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
            start = self._start(device)
            if isinstance(self.size, int):
                mask = 1 << self.size
                def set(instance, value):
                    assert instance is device
                    data = device.sync_group.current_data
                    if value:
                        data[start] |= mask
                    else:
                        data[start] &= ~mask
            else:
                mystruct = struct.Struct('<' + self.size)
                def set(instance, value):
                    assert instance is device
                    data = device.sync_group.current_data
                    mystruct.pack_into(data, start, value)
            self.set = set
            set(device, value)

    def get(self, device):
        if device.sync_group.current_data is None:
            return super().__get__(device, None)
        else:
            start = self._start(device)
            if isinstance(self.size, int):
                mask = 1 << self.size
                def get(instance):
                    assert instance is device
                    data = instance.sync_group.current_data
                    return bool(data[start] & mask)
            else:
                mystruct = struct.Struct("<" + self.size)
                def get(instance):
                    assert instance is device
                    data = instance.sync_group.current_data
                    return mystruct.unpack_from(data, start)[0]
            self.get = get
            return get(device)

    def _start(self, device):
        return device.sync_group.terminals[self.terminal][self.sm] \
               + self.position

    def fmt_addr(self, device):
        return ((self.size, 1) if isinstance(self.size, int) else self.size,
                self._start(device) + Packet.ETHERNET_HEADER)


class TerminalVar:
    """a device variable to be linked to a process variable

    Whithin a :class:`Device`, one can refer to process variables that should
    later be linked to process variables of a terminal. Within the device, one
    can access the process variable generically. Upon instantiation one would
    then assign a :class:`ProcessDesc` (or :class:`PacketDesc`) to it to link
    the variable to an actual terminal.

    For example::

        class MyDevice(Device):
            the_output = TerminalVar()

            def program(self):
                self.the_output = 5  # write 5 to whatever variable linked

        terminal = MyTerminal()
        device = MyDevice()
        device.the_output = terminal.output5  # link the_output to output5
    """

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
    """A variable in a device for higher-level use

    define a variable within a device which the device's user can
    access. This is especially important for fast devices, this is the
    way data is communicated to and from the EBPF program.

    For non-fast devices, this acts like normal Python variables.

    :param size: the size of a variable in :mod:`python:struct` letters
    :param write: whether the variable will be written to by the user

    For example::

        class MyDevice(Device):
            my_data = DeviceVar()

            def program(self):
                self.my_data = 7

        device = MyDevice()
        print(self.my_data)  # should print 7 once the program is running
    """
    def __init__(self, size="I", write=False):
        super().__init__(FastSyncGroup.properties, size)
        self.write = write

    def __get__(self, instance, owner):
        if instance is None:
            return self
        elif isinstance(instance.sync_group, EBPFBase):
            return super().__get__(instance, owner)
        else:
            return instance.__dict__.get(self.name, 0)

    def __set__(self, instance, value):
        if isinstance(instance.sync_group, EBPFBase):
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
    position_offset = {SyncManager.OUT: 0, SyncManager.IN: 0, None: 0}
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
    """The EtherCat packet dispatcher

    This class creates an EBPF program that receives EtherCAT packet
    from the network and dispatches them to the EBPF program of the fast
    sync group they belong to, or passes them on to user space if they
    do not belong to any fast sync group.

    The additional information needed is put into a first, internal
    datagram in the EtherCAT packet, marked as no-op. It also contains
    an ethertype that should be used once the packet is handed over to
    user space, so it can be dispatched to the correct listener.

    For each fast sync group, there are always two packets on the wire,
    one that only reads value from the terminals, the other one also
    writes.  Usually only the read-write packet is handed over to the
    sync group's program. If, however, that packet gets lost, the next
    read-only packet is handed over.

    User space is supposed to constantly feed in new packets, and the
    then-superfluous packets are sent back to user space. This way user
    space can constantly read data independent of the EBPF program. It
    cannot write, however, as this would cause priority issues.
    """
    license = "GPL"
    minimumPacketSize = 30

    variables = ArrayMap()
    dropcounter = variables.globalVar("I")
    counters = variables.globalVar("64I")

    rate = 0

    INDEX0 = 17

    ethertype = XDPPacketVar(12, "!H")
    addr0 = XDPPacketVar(18, "I")  # indicates the fast sync group number
    cmd0 = XDPPacketVar(16, "B")  # 0 is a noop, internal datagram
    index0 = XDPPacketVar(INDEX0, "B")  # the loop counter
    data0 = XDPPacketVar(26, "H")  # the ethertype to use

    def program(self):
        with prandom(self.ebpf) & 0xffff < self.rate:
            self.dropcounter += 1
            self.ebpf.exit(XDPExitCode.DROP)
        with self.ethertype == 0x88A4, self.cmd0 == 0:
            self.r3 = self.addr0  # use r3 for tail_call
            with self.counters.get_address(None, False, False) as (dst, _), \
                    self.r3 < FastEtherCat.MAX_PROGS:
                self.r[dst] += 4 * self.r3
                self.r4 = self.mB[self.r[dst]]
                # we lost a packet
                with self.index0 == self.r4 as Else:
                    self.mI[self.r[dst]] += 1 + (self.r4 & 1)
                # normal case: two packets on the wire
                with Else, ((self.index0 + 1 & 0xff) == self.r4) \
                           | (self.index0 == 0) as Else:
                    self.mI[self.r[dst]] += 1
                    with self.r4 & 1:  # last one was active
                        self.index0 = self.mB[self.r[dst]]
                        self.exit(XDPExitCode.TX)
                with Else:
                    self.ethertype = self.data0
                    self.exit(XDPExitCode.PASS)
                self.index0 = self.mB[self.r[dst]]
                self.r2 = self.get_fd(self.programs)
                self.call(FuncId.tail_call)
        self.ethertype = self.data0
        self.exit(XDPExitCode.PASS)


class SimpleEtherCat(EtherCat):
    pass


class FastEtherCat(SimpleEtherCat):
    """An EtherCAT driver class for fast and slow sync groups"""
    MAX_PROGS = 64

    def __init__(self, network):
        super().__init__(network)
        self.sync_groups = {}

    @contextmanager
    def register_sync_group(self, sg):
        index = len(self.sync_groups)
        while index in self.sync_groups:
            index = (index + 1) % self.MAX_PROGS
        sg.load()
        update_elem(self.programs, pack("<I", index),
                    pack("<I", sg.file_descriptor), 0)
        sg.close()
        self.sync_groups[index] = sg
        try:
            yield index
        finally:
            delete_elem(self.programs, pack("<I", index))

    async def connect(self):
        await super().connect()
        self.ebpf = EtherXDP()
        self.ebpf.programs = self.programs = \
            create_map(MapType.PROG_ARRAY, 4, 4, self.MAX_PROGS)
        await self.ebpf.attach(self.addr[0])

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


class ParallelEtherCat(FastEtherCat):
    """A multi-processing EtherCAT loop

    If several programs want to access an EtherCAT loop at the same time, they
    need to negotiate where the packets go. This class installs an XDP program
    that dispatches the packets to the right consumer. The dispatch is done by
    modifying the ethertype of the packet, as this is what we can bind to.

    The first program connecting to the loop installs the XDP program, the last
    one leaving uninstalls it. We put lock files into ``/run/lock`` to
    synchronize that, and put a map of XDP programs into ``/sys/fs/bpf``, where
    all participants can put their programs.
    """
    def get_ethertype(self, lockdir):
        while True:
            try:
                lockfile = f'{self.ethertype}.lock'
                with open(f'{lockdir}/{lockfile}', 'x') as lf:
                    lf.write(f'{os.getpid():10}\n')
                return lockfile
            except FileExistsError:
                self.ethertype = randint(0x3000, 0x6000)
                continue

    def get_mbx_lock(self, no):
        return ParallelMailboxLock(self.mbx_lock_file, no)

    def get_fmmu_addr(self):
        return self.fmmu_lock_file.get_next_addr()

    @asynccontextmanager
    async def run(self):
        lockdir = f'/run/lock/ebpf.{self.addr[0]}.lock'
        programs = f'/sys/fs/bpf/{self.addr[0]}'

        os.makedirs(programs, exist_ok=True)
        programs += '/programs'

        tmpdir = tempfile.mkdtemp(dir='/run/lock')
        lockfile = self.get_ethertype(tmpdir)
        try:
            os.rename(tmpdir, lockdir)
        except OSError:
            shutil.rmtree(tmpdir)
            lockfile = self.get_ethertype(lockdir)
            try:
                await super(FastEtherCat, self).connect()
                self.ebpf = EtherXDP()
                try:
                    self.ebpf.programs = self.programs = obj_get(programs)
                except FileNotFoundError:
                    await sleep(0.1)
                    self.ebpf.programs = self.programs = obj_get(programs)
            except Exception:
                os.remove(f'{lockdir}/{lockfile}')
                raise
        else:
            try:
                await super(FastEtherCat, self).connect()
                self.ebpf = EtherXDP()
                self.ebpf.programs = self.programs = \
                    create_map(MapType.PROG_ARRAY, 4, 4, self.MAX_PROGS)
                try:
                    os.remove(programs)
                except OSError:
                    pass
                else:
                    logging.error('an old programs file was still at %s',
                                  programs)
                obj_pin(programs, self.programs)
            except Exception:
                shutil.rmtree(lockdir)
                raise
        self.mbx_lock_file = LockFile(f'/run/ebpf/{self.addr[0]}',
                                      *self.terminal_addr_range)
        self.fmmu_lock_file = FMMULock(f'/run/ebpf/{self.addr[0]}.fmmu')
        try:
            await self.ebpf.attach(self.addr[0])
            self.ebpf.close()
            yield
        finally:
            for v in self.sync_groups.values():
                v.cancel()
            os.remove(f'{lockdir}/{lockfile}')
            try:
                os.rmdir(lockdir)
            except OSError:
                pass
            else:
                await self.ebpf.detach(self.addr[0])
                os.remove(programs)
                self.mbx_lock_file.remove()
                self.fmmu_lock_file.remove()

    def __getstate__(self):
        return self.addr[0]

    def __setstate__(self, network):
        self.__init__(network)


class SterilePacket(Packet):
    """a sterile packet has all its sets exchanged by NOPs"""
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
        self.counters[self.size - 2] = {counter}

    def sterile(self, index, ethertype=0x88A4):
        ret = bytearray(self.assemble(index, ethertype))
        for pos, cmd in self.on_the_fly:
            ret[pos] = ECCmd.NOP.value
        return ret

    def append_fmmu(self, logical_addr):
        self.next_logical_addr = logical_addr
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
    running = True
    cycletime = 0.01  # cycle time of the PLC loop
    task = None

    current_data = None
    logical_in = logical_out = None
    name = 'No Name'

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

        while True:
            try:
                ok = 0
                r = await gather(*[t.to_operational() for t in self.terminals])
                for t, (state, error, status) in zip(self.terminals, r):
                    if state is not MachineState.OPERATIONAL or status != 0:
                        logging.warning(
                            "terminal %s was not operational, status was %i",
                            t, status)
                    else:
                        ok += 1
                await sleep(1)
            except CancelledError:
                raise
            except Exception:
                logging.exception('to_operational of sync group %s failed',
                                  self.name)

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
            lasttime = monotonic()
            await gather(*[t.to_operational(MachineState.SAFE_OPERATIONAL)
                           for t in self.terminals])
            self.ec.send_packet(data)
            task = ensure_future(self.to_operational())
            try:
                while self.running:
                    try:
                        data = await wait_for(
                                self.ec.receive_index(self.packet_index),
                                timeout=0.02)
                    except TimeoutError:
                        self.missed_counter += 1
                        logging.warning(
                            "%s: did not receive Ethercat response in time %i",
                            self.name, self.missed_counter)
                        self.ec.send_packet(data)
                        continue
                    data = self.update_devices(data)
                    newtime = monotonic()
                    if newtime - lasttime > self.cycletime:
                        logging.warning('%s: response time exceeded (%.0f ms)',
                                        self.name, (newtime - lasttime) * 1000)
                    await sleep(self.cycletime - (newtime - lasttime))
                    newtime = monotonic()
                    if newtime - lasttime > 0.05:
                        logging.warning('%s: excessive cycle time (%.0f ms)',
                                        self.name, (newtime - lasttime) * 1000)
                    lasttime = newtime
                    assert not task.done()
                    self.ec.send_packet(data)
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
        in_pos, out_pos, logical_in, logical_out = \
            self.packet.append_fmmu(self.ec.get_fmmu_addr())
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
        self.current_data[:] = data
        for pos, counts in self.packet.counters.items():
            if data[pos] not in counts:
                logging.warning(
                    'EtherCAT datagram processed %i times, should be in %s',
                    data[pos], counts)
                counts.add(data[pos])
            self.current_data[pos] = 0
        for dev in self.devices:
            dev.update()
        return self.current_data

    def start(self):
        assert self.task is None or self.task.done()
        self.allocate()
        self.packet_index = SyncGroup.packet_index
        SyncGroup.packet_index += 1
        self.asm_packet = self.packet.assemble(self.packet_index,
                                               self.ec.ethertype)
        self.current_data = bytearray(self.asm_packet)
        self.task = ensure_future(self.run())
        return self.task


class ProcessSyncGroup(SyncGroup, SimulatedEBPF):
    """A :class:`SyncGroup` running in a separate process

    In order to lower latency, one may run a sync group in a different
    process. In this case communication is done via :class:`DeviceVar`s,
    or reading (but not writing) :class:`TerminalVar`s.
    """

    properties = ArrayMap()

    def __init__(self, ec, devices, **kwargs):
        self.ctx = get_context('spawn')
        super().__init__(ec, devices, subprograms=devices, **kwargs)

    def get_array(self, size):
        return self.ctx.Array('B', size).get_obj()

    @property
    def running(self):
        return self.runningValue.value

    def subprocess_run(self):
        gc.collect()
        gc.disable()
        param = os.sched_param(os.sched_get_priority_max(os.SCHED_RR))
        os.sched_setscheduler(0, os.SCHED_RR, param)
        if self.name != 'No Name':
            with open('/proc/self/comm', 'w') as fout:
                fout.write(self.name[-15:])
        asyncio.run(self.subprocess_loop())

    async def subprocess_loop(self):
        async with self.ec.run():
            self.asm_packet = self.packet.assemble(self.packet_index,
                                                   self.ec.ethertype)
            await self.run()

    async def wait_for_process(self):
        fd = os.pidfd_open(self.process.pid)
        loop = get_event_loop()
        error = None
        while True:
            future = loop.create_future()
            loop.add_reader(fd, future.set_result, None)
            try:
                await future
            except CancelledError as error:
                self.runningValue.value = False
            else:
                if error is None:
                    return
                else:
                    raise error
            finally:
                loop.remove_reader(fd)

    @property
    def current_data(self):
        return memoryview(self._current_data.get_obj()).cast('B')

    def start(self):
        assert isinstance(self.ec, ParallelEtherCat)
        self.runningValue = self.ctx.Value('B')
        self.runningValue.value = True
        self.allocate()
        self.packet_index = SyncGroup.packet_index
        SyncGroup.packet_index += 1
        self.task = None
        self._current_data = self.ctx.Array('B', max(46, self.packet.size))
        self.process = self.ctx.Process(target=self.subprocess_run)
        self.process.start()
        self.task = ensure_future(self.wait_for_process())
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
            self.asm_packet = self.packet.sterile(self.packet_index,
                                                  self.ec.ethertype)
            # prime the pump: two packets to get things going
            self.ec.send_packet(self.asm_packet)
            self.ec.send_packet(self.asm_packet)
            await super().run()

    def update_devices(self, data):
        if data[EtherXDP.INDEX0 - Packet.ETHERNET_HEADER] & 1:
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
