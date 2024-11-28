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
#
# This program may contain technology patented by Beckhoff GmbH.
# The author is not affiliated with this company, nor does he own a
# license. As a private enthusiast he also does not need one, other
# users may want to consult a lawyer before using this program.

"""\
Low-level access to EtherCAT
============================

this modules contains the code to actually talk to EtherCAT terminals.
"""
from asyncio import (
    CancelledError, ensure_future, Event, Future, gather, get_event_loop,
    Protocol, Queue, Lock)
from contextlib import asynccontextmanager
from enum import Enum, IntEnum
from itertools import count
import logging
import operator
from random import randint
from socket import AF_PACKET
from struct import pack, unpack, unpack_from, calcsize

from .lock import MailboxLock

class EtherCatError(Exception):
    pass


class ECCmd(Enum):
   NOP = 0  # No Operation
   APRD = 1  # Auto Increment Read
   APWR = 2  # Auto Increment Write
   APRW = 3  # Auto Increment Read Write
   FPRD = 4  # Configured Address Read
   FPWR = 5  # Configured Address Write
   FPRW = 6  # Configured Address Read Write
   BRD = 7  # Broadcast Read
   BWR = 8  # Broadcast Write
   BRW = 9 # Broadcast Read Write
   LRD = 10  # Logical Memory Read
   LWR = 11  # Logical Memory Write
   LRW = 12  # Logical Memory Read Write
   ARMW = 13  # Auto Increment Read Multiple Write
   FRMW = 14  # Configured Read Multiple Write


class ECDataType(Enum):
   def __new__(cls, value, fmt):
       obj = object.__new__(cls)
       obj._value_ = value
       obj.fmt = fmt
       return obj
   INVALID = 0, None
   BOOLEAN = 0x1, "?"
   INTEGER8 = 0x2, "b"
   INTEGER16 = 0x3, "h"
   INTEGER32 = 0x4, "i"
   UNSIGNED8 = 0x5, "B"
   UNSIGNED16 = 0x6, "H"
   UNSIGNED32 = 0x7, "I"
   REAL32 = 0x8, "f"
   VISIBLE_STRING = 0x9, None
   OCTET_STRING = 0xA, None
   UNICODE_STRING = 0xB, None
   TIME_OF_DAY = 0xC, "I"
   TIME_DIFFERENCE = 0xD, "i"
   DOMAIN = 0xF, "i"
   INTEGER24 = 0x10, "i"
   REAL64 = 0x11, "d"
   INTEGER64 = 0x15, "q"
   UNSIGNED24 = 0x16, "i"
   UNSIGNED64 = 0x1B, "Q"
   BIT1 = 0x30, "B"
   BIT2 = 0x31, "B"
   BIT3 = 0x32, "B"
   BIT4 = 0x33, "B"
   BIT5 = 0x34, "B"
   BIT6 = 0x35, "B"
   BIT7 = 0x36, "B"
   BIT8 = 0x37, "B"

class MBXType(Enum):
   ERR = 0  # Error
   AOE = 1  # ADS over EtherCAT
   EOE = 2  # Ethernet over EtherCAT
   COE = 3  # CANopen over EtherCAT
   FOE = 4  # File over EtherCAT
   SOE = 5  # Servo over EtherCAT
   VOE = 0xf  # Vendor over EtherCAT

class CoECmd(Enum):
   EMERGENCY = 1
   SDOREQ = 2
   SDORES = 3
   TXPDO = 4
   RXPDO = 5
   TXPDO_RR = 6
   RXPDO_RR = 7
   SDOINFO = 8

class ODCmd(Enum):
   LIST_REQ = 1
   LIST_RES = 2
   OD_REQ = 3
   OD_RES = 4
   OE_REQ = 5
   OE_RES = 6
   SDOINFO_ERROR = 7

   DOWN_INIT = 0x21
   DOWN_EXP = 0x23
   DOWN_INIT_CA = 0x31
   UP_REQ = 0x40
   UP_REQ_CA = 0x50
   SEG_UP_REQ = 0x60
   ABORT = 0x80

class EEPROM(IntEnum):
    VENDOR_ID = 8
    PRODUCT_CODE = 10
    REVISION = 12
    SERIAL_NO = 14

class MachineState(Enum):
    """The states of the EtherCAT state machine

    The states are in the order in which they should
    be taken, BOOTSTRAP is at the end as this is a
    state we usually do not go to.
    """
    INIT = 1
    PRE_OPERATIONAL = 2
    SAFE_OPERATIONAL = 4
    OPERATIONAL = 8
    BOOTSTRAP = 3

class SyncManager(Enum):
    OUT = 2
    IN = 3

class ObjectDescription:
    def __init__(self, terminal):
        self.terminal = terminal

    def __getitem__(self, idx):
        return self.entries[idx]

    def __repr__(self):
        return " ".join(f"[{k:X}: {v}]" for k, v in self.entries.items())


class ObjectEntry:
    name = None

    def __init__(self, terminal, index):
        self.terminal = terminal
        self.index = index

    async def read(self):
        ret = await self.terminal.sdo_read(self.index, self.valueInfo)
        if self.dataType in (ECDataType.VISIBLE_STRING,
                             ECDataType.UNICODE_STRING):
            return ret.decode("utf8")
        elif isinstance(self.dataType, int) or self.dataType.fmt is None:
            return ret
        else:
            return unpack("<" + self.dataType.fmt, ret)[0]

    async def write(self, data):
        if self.dataType in (ECDataType.VISIBLE_STRING,
                             ECDataType.UNICODE_STRING):
            d = data.encode("utf8")
        elif isinstance(self.dataType, int) or self.dataType.fmt is None:
            d = data
        else:
            d = pack("<" + self.dataType.fmt, data)

        return await self.terminal.sdo_write(d, self.index, self.valueInfo)

    def __repr__(self):
        if self.name is None:
            return "[unread ObjectEntry]"

        dt = self.dataType
        return f'{self.name} ' \
               f'{dt.name if isinstance(dt, ECDataType) else dt} ' \
               f'({self.bitLength} bit) flags {self.objectAccess:X}'


def datasize(args, data):
    out = calcsize("<" + "".join(arg for arg in args if isinstance(arg, str)))
    if isinstance(data, int):
        out += data
    elif data is not None:
        out += len(data)
    return out


class Packet:
    """An EtherCAT packet representation

    A packet contains one or more datagrams which are sent as EtherNet
    packets. We implicitly add a datagram in the front which later serves
    as an identifier for the packet.
    """
    MAXSIZE = 1500  # maximum size we use for an EtherCAT packet
    ETHERNET_HEADER = 14
    PACKET_HEADER = 16
    DATAGRAM_HEADER = 10
    DATAGRAM_TAIL = 2

    def __init__(self):
        self.data = []
        self.size = self.PACKET_HEADER

    def append(self, cmd, data, idx, *address):
        """Append a datagram to the packet

        :param cmd: EtherCAT command
        :type cmd: ECCmd
        :param data: the data in the datagram
        :param idx: the datagram index, unchanged by terminals

        Depending on the command, one or two more parameters represent the
        address, either terminal and offset for position or node addressing,
        or one value for logical addressing."""
        newsize = self.size + len(data) + self.DATAGRAM_HEADER \
                  + self.DATAGRAM_TAIL
        if newsize > self.MAXSIZE:
            raise OverflowError(f"ethercat packet size too big: {newsize}")
        elif len(self.data) > 14:
            raise OverflowError("Too many datagrams per packet")

        self.data.append((cmd, data, idx) + address)
        self.size = newsize

    def assemble(self, index, ethertype=0x88A4):
        """Assemble the datagrams into a packet

        :param index: an identifier for the packet

        An implicit empty datagram is added at the beginning of the packet
        that may be used as an identifier for the packet.
        """
        ret = [pack("<HBBiHHHH", (self.size-2) | 0x1000, 0, 0,
                    index, 0x8002, 0, ethertype, 0)]
        for i, (cmd, data, *dgram) in enumerate(self.data, start=1):
            ret.append(pack("<BBhHHH" if len(dgram) == 3 else "<BBiHH",
                            cmd.value, *dgram,
                            len(data) | ((i < len(self.data)) << 15), 0))
            ret.append(data)
            ret.append(b"\0\0")
        if self.size < 46:
            ret.append(b"3" * (46 - self.size))
        return b''.join(ret)

    def __str__(self):
        ret = "\n".join(f"{cmd} {data} {idx} {addr}"
                        for cmd, data, idx, *addr in self.data)
        return "Packet([" + ret + "]"

    def disassemble(self, data):
        pos = 14 + self.DATAGRAM_HEADER
        ret = []
        for cmd, bits, *dgram in self.data:
            ret.append(unpack("<Bxh6x", data[pos-self.DATAGRAM_HEADER:pos])
                       + (data[pos:pos+len(bits)],
                        unpack("<H", data[pos+len(bits):pos+len(bits)+2])[0]))
            pos += self.DATAGRAM_HEADER + self.DATAGRAM_TAIL
        return ''.join(f"{i}: {c} {a} {f} {d}\n" for i, (c, a, d, f) in enumerate(ret))

    def full(self):
        """Is the data limit reached?"""
        return self.size > self.MAXSIZE or len(self.data) > 14


class EtherCat(Protocol):
    """The EtherCAT connection

    An object of this class represents one connection to an EtherCAT loop.
    It keeps the socket, and eventually all data flows through it.

    This class supports both to send individual datagrams and wait for their
    response, but also to send and receive entire packets. """

    ethertype = 0x88A4  # this is the incoming protocol, not necessary EtherCAT
    terminal_addr_range = (1000, 30000)

    def __init__(self, network):
        """
        :param network: the name of the network adapter, like "eth0"
        """
        self.addr = (network, 0x88A4, 0, 0, b"\xff\xff\xff\xff\xff\xff")
        self.wait_futures = {}
        self.used_addresses = set()

    async def connect(self):
        """connect to the EtherCAT loop"""
        self.send_queue = Queue()
        await get_event_loop().create_datagram_endpoint(
            lambda: self, family=AF_PACKET, proto=0xA488)

    def get_mbx_lock(self, no):
        return MailboxLock()

    async def sendloop(self):
        """the eternal datagram sending loop

        This method runs while we are connected, takes the datagrams
        to be sent from a queue, packs them in a packet and ships them
        out. """
        try:
            dgrams = []
            packet = Packet()
            sent = True
            while True:
                if sent:
                   *dgram, future = await self.send_queue.get()
                try:
                   lastsize = packet.size
                   packet.append(*dgram)
                   dgrams.append((lastsize + 10, packet.size - 2, future))
                   sent = True
                   if not self.send_queue.empty():
                       continue
                except OverflowError:
                    sent = False
                ensure_future(self.process_packet(dgrams, packet))
                dgrams = []
                packet = Packet()
        except CancelledError:
            raise
        except Exception:
            logging.exception("sendloop failed")
            raise

    async def process_packet(self, dgrams, packet):
        try:
            data = await self.roundtrip_packet(packet)
            for start, stop, future in dgrams:
                wkc, = unpack("<H", data[stop:stop+2])
                if wkc == 0:
                    future.set_exception(
                        EtherCatError("datagram was not processed"))
                elif not future.done():
                    future.set_result(data[start:stop])
                else:
                    logging.info("future already done, dropped datagram")
        except CancelledError:
            raise
        except Exception as e:
            for _, _, future in dgrams:
                if not future.done():
                    future.set_exception(e)
            logging.exception("process_packet failed")
            raise

    async def roundtrip_packet(self, packet):
        """Send a packet and return the response

        Send the `packet` to the loop and wait that it comes back,
        and return that to the caller. """
        index = randint(2000, 1000000000)
        while index in self.wait_futures:
            index = randint(2000, 1000000000)
        self.send_packet(packet.assemble(index, self.ethertype))
        return await self.receive_index(index)

    async def receive_index(self, index):
        """Wait for packet identified by `index`"""
        future = Future()
        self.wait_futures[index] = future
        try:
            return await future
        finally:
            del self.wait_futures[index]

    def send_packet(self, packet):
        """simply send the `packet`, fire-and-forget"""
        self.transport.sendto(packet, self.addr)

    async def roundtrip(self, cmd, pos, offset, *args, data=None, idx=0):
        """Send a datagram and wait for its response

        :param cmd: the EtherCAT command
        :type cmd: ECCmd
        :param pos: the positional address of the terminal
        :param offset: the offset within the terminal
        :param idx: the EtherCAT datagram index
        :param data: the data to be sent, or and integer for the number of
            zeros to be sent as placeholder

        Any additional parameters will be interpreted as follows: every `str` is
        interpreted as a format for a `struct.pack`, everything else is the data
        for those format. Upon returning, the received data will be unpacked
        accoding to the format strings. """
        future = Future()
        fmt = "<" + "".join(arg for arg in args[:-1] if isinstance(arg, str))
        out = pack(fmt, *[arg for arg in args if not isinstance(arg, str)])
        if args and isinstance(args[-1], str):
            out += b"\0" * calcsize("<" + args[-1])
            fmt += args[-1]
        if isinstance(data, int):
            out += b"\0" * data
        elif data is not None:
            out += data
        self.send_queue.put_nowait((cmd, out, idx, operator.index(pos),
                                    operator.index(offset), future))
        ret = await future
        if data is None:
            return unpack(fmt, ret)
        elif args:
            if not isinstance(data, int):
                data = len(data)
            return unpack(fmt, ret[:-data]) + (ret[-data:],)
        else:
            return ret

    async def count(self):
        """Count the number of terminals on the bus"""
        p = Packet()
        p.append(ECCmd.APRD, b"\0\0", 0, 0, 0x10)
        ret = await self.roundtrip_packet(p)
        no, = unpack_from("<h", ret, 18)  # number of terminals
        return no

    async def find_free_address(self):
        """Find an absolute address not in use

        an address once returned by this method is assumed to be used in the
        future and will never be handed out again"""
        while True:
            i = randint(*self.terminal_addr_range)
            if i in self.used_addresses:
                continue
            self.used_addresses.add(i)
            try:
                await self.roundtrip(ECCmd.FPRD, i, 0x10, "H", 0)
            except EtherCatError:
                return i  # this address is not in use

    async def assigned_address(self, position):
        """return the set adress of terminal at position, if none set one"""
        ret, = await self.roundtrip(ECCmd.APRD, position, 0x10, "H", 0)
        if ret != 0:
            return ret
        ret = await self.find_free_address()
        await self.roundtrip(ECCmd.APWR, position, 0x10, "H", ret)
        return ret

    async def eeprom_read(self, position, start):
        """read 4 bytes from the eeprom of terminal `position` at `start`"""
        while (await self.roundtrip(ECCmd.APRD, position,
                                    0x502, "H"))[0] & 0x8000:
            pass
        await self.roundtrip(ECCmd.APWR, position, 0x502, "HI", 0x100, start)
        busy = 0x8000
        while busy & 0x8000:
            busy, data = await self.roundtrip(ECCmd.APRD, position,
                                              0x502, "H4xI")
        return data

    def connection_made(self, transport):
        """start the send loop once the connection is made"""
        transport._sock.bind((self.addr[0], self.ethertype))
        self.transport = transport
        ensure_future(self.sendloop())

    def datagram_received(self, data, addr):
        """distribute received packets to the recipients"""
        index, = unpack("<I", data[4:8])
        future = self.wait_futures.get(index)
        if future is not None and not future.done():
            future.set_result(data)


class ServiceDesc:
    def __init__(self, index, subidx):
        self.index = index
        self.subidx = subidx


class Struct:
    """Define repetitive structures in CoE objects

    Some terminals, especially multi-channel terminals,
    have repetitive structures in their CoE. Inherit from this
    class to create a structure for them. Each instance
    will then define one channel. It takes one parameter, which
    is the offset in the CoE address space from the template
    structure to the one of the channel.
    """
    device = None

    def __new__(cls, *args, **kwargs):
        return StructDesc(cls, *args, **kwargs)


class StructDesc:
    def __init__(self, struct, sm3=0, sm2=None, coe=None):
        self.struct = struct
        if sm2 is None:
            sm2 = sm3
        if coe is None:
            coe = sm3
        self.position_offset = {SyncManager.OUT: sm2, SyncManager.IN: sm3,
                                None: coe}

    def __get__(self, instance, owner):
        if instance is None:
            return self
        if (ret := instance.__dict__.get(self.name)) is not None:
            return ret
        ret = object.__new__(self.struct)
        ret.position_offset = self.position_offset
        ret.terminal = instance
        instance.__dict__[self.name] = ret
        return ret

    def __set_name__(self, owner, name):
        self.name = name


class Terminal:
    """Represent one terminal (*SubDevice* or *slave*) in the loop"""
    def __init__(self, ethercat):
        self.ec = ethercat

    name = 'No Name'

    def __repr__(self):
        return f'{self.__class__.__name__}.("{self.name}")'

    def __str__(self):
        return self.name

    async def initialize(self, relative=None, absolute=None):
        """Initialize the terminal

        this sets up the connection to the terminal we represent.

        :param relative: the position of the terminal in the loop,
            a negative number counted down from 0 for the first terminal
            If None, we assume the address is already initialized
        :param absolute: the number used to identify the terminal henceforth
            If None take a free one

        If only one parameter is given, it is taken to be an absolute
        position, the terminal address is supposed to be already initialized.

        This also reads the EEPROM and sets up the sync manager as defined
        therein. It still leaves the terminal in the init state.
        """
        assert relative is not None or absolute is not None
        if absolute is None:
            absolute = await self.ec.find_free_address()
        self.mbx_lock = self.ec.get_mbx_lock(absolute)
        if relative is not None:
            await self.ec.roundtrip(ECCmd.APWR, relative, 0x10, "H", absolute)
        self.position = absolute

        await self.to_operational(MachineState.INIT)

        fmmu_no, = await self.read(4, "B")
        self.fmmu_used = [None] * fmmu_no
        # switch off all fmmus
        for i in range(fmmu_no):
            await self.write(0x60c + 0x10 * i, "B", 0)

        await self.apply_eeprom()

    async def gentle_initialize(self, relative=None, absolute=None):
        """Initialize a terminal only if not already initialized

        Use this method instead of :meth:`initialize` if the terminal should
        be used in parallel with other users. This will bring the terminal
        to a state such that one can read and write SDO parameters. It is
        not possible to use PDOs, only one user can do that at a time.
        """
        assert (relative is None) != (absolute is None)
        if relative is not None:
            self.position, = await self.ec.roundtrip(ECCmd.APRD, relative,
                                                     0x10, "H")
            if self.position == 0:
                return await self.initialize(relative=relative)
        else:
            self.position = absolute
        self.mbx_lock = self.ec.get_mbx_lock(self.position)

        state, *_ = await self.get_state()
        if state is MachineState.INIT:
            return await self.initialize(relative=relative, absolute=absolute)

        await self.read_eeprom()
        sm = await self.read(0x800, data=0x80)
        self.parse_sync_managers(sm)

    async def set_watchdog(self, pdi, process):
        """set the watchdog time for the PDI and process data watchdog"""
        await self.write(0x410, 'H', pdi)
        await self.write(0x420, 'H', process)

    async def apply_eeprom(self):
        await self.read_eeprom()
        if 41 not in self.eeprom:
            # no sync managers defined in eeprom
            return
        await self.write(0x800, data=0x80)  # empty out sync manager
        await self.write(0x800, data=self.eeprom[41])
        self.mbx_out_off = self.mbx_out_sz = None
        self.mbx_in_off = self.mbx_in_sz = None
        self.pdo_out_off = self.pdo_out_sz = None
        self.pdo_in_off = self.pdo_in_sz = None
        self.pdo_in_addr = 0x818
        self.pdo_out_addr = 0x810
        self.parse_sync_managers(self.eeprom[41])

    def parse_sync_managers(self, data):
        for i in range(0, len(data), 8):
            offset, size, mode = unpack_from("<HHB", data, i)
            mode &= 0xf
            if mode == 0:
                self.pdo_in_off = offset
                self.pdo_in_sz = size
                self.pdo_in_addr = 0x800 + i
            elif mode == 2:
                self.mbx_in_off = offset
                self.mbx_in_sz = size
            elif mode == 4:
                self.pdo_out_off = offset
                self.pdo_out_sz = size
                self.pdo_out_addr = 0x800 + i
            elif mode == 6:
                self.mbx_out_off = offset
                self.mbx_out_sz = size
            else:
                logging.error("wrong mode parsing sync managers in EEPROM")

    async def write_pdo_sm(self):
        await self.write(self.pdo_out_addr + 6, "B", 0)
        await self.write(self.pdo_out_addr + 2, "H", self.pdo_out_sz)
        await self.write(self.pdo_out_addr + 6, "B", self.pdo_out_sz > 0)
        await self.write(self.pdo_in_addr + 6, "B", 0)
        await self.write(self.pdo_in_addr + 2, "H", self.pdo_in_sz)
        await self.write(self.pdo_in_addr + 6, "B", self.pdo_in_sz > 0)

    async def parse_pdos(self):
        """parse the PDOs from self description

        parse the PDO assignment from the SDO if available, or EEPROM
        if not. Return the number of bits for the output PDO and the
        input PDO. """
        async def parse_eeprom(s):
            i = 0
            bitpos = 0
            while i < len(s):
                # third parameter seems to indicate the sync manager, sometimes
                idx, e, sm, u1, u2, u3 = unpack_from("<HBbBBH", s, i)
                i += 8
                for er in range(e):
                    idx, subidx, k1, k2, bits, = unpack_from("<HBBBB2x", s, i)
                    yield idx, subidx, bits
                    i += 8

        async def parse_sdo(index):
            assignments, = unpack("B", await self.sdo_read(index, 0))
            bitpos = 0
            for i in range(1, assignments + 1):
                pdo, = unpack("<H", await self.sdo_read(index, i))
                if pdo == 0:
                    continue
                count, = unpack("B", await self.sdo_read(pdo, 0))
                for j in range(1, count + 1):
                    bits, subidx, idx = unpack("<BBH", await self.sdo_read(pdo, j))
                    yield idx, subidx, bits

        async def parse(func, sm):
            bitpos = 0
            async for idx, subidx, bits in func:
                if idx == 0:
                    pass
                elif bits < 8:
                    self.pdos[idx, subidx] = (sm, bitpos // 8, bitpos % 8)
                elif (bits % 8) or (bitpos % 8):
                    raise RuntimeError("PDOs must be byte-aligned")
                else:
                    self.pdos[idx, subidx] = \
                        (sm, bitpos // 8,
                         {8: "B", 16: "H", 32: "I", 64: "Q"}[bits])
                bitpos += bits
            return bitpos

        self.pdos = {}
        if self.has_mailbox():
            return (await parse(parse_sdo(0x1c12), SyncManager.OUT),
                    await parse(parse_sdo(0x1c13), SyncManager.IN))
        else:
            return (
                await parse(parse_eeprom(self.eeprom[51]), SyncManager.OUT)
                if 51 in self.eeprom else 0,
                await parse(parse_eeprom(self.eeprom[50]), SyncManager.IN)
                if 50 in self.eeprom else 0)

    async def parse_sdos(self):
        sdos = {}
        for cls in self.__class__.__mro__:
            for k, v in cls.__dict__.items():
                if isinstance(v, ServiceDesc):
                    setattr(self, k,
                            await self.read_object_entry(v.index, v.subidx))
                elif isinstance(v, StructDesc):
                    struct = getattr(self, k)
                    offset = struct.position_offset[None]
                    for ccls in struct.__class__.__mro__:
                        for kk, vv in ccls.__dict__.items():
                            if isinstance(vv, ServiceDesc):
                                setattr(struct, kk,
                                        await self.read_object_entry(
                                            vv.index + offset, vv.subidx))

    async def set_state(self, state):
        """try to set the state, and return the new state"""
        await self.ec.roundtrip(ECCmd.FPWR, self.position, 0x0120, "H", state)
        ret, = await self.ec.roundtrip(ECCmd.FPRD, self.position, 0x0130, "H")
        return ret

    async def get_state(self):
        """get the current state, error flag and status word"""
        state, status = await self.ec.roundtrip(ECCmd.FPRD, self.position,
                                                0x0130, "H2xH")
        return MachineState(state & 0xf), bool(state & 0x10), status

    async def to_operational(self, target=MachineState.OPERATIONAL):
        """try to bring the terminal to operational state

        this tries to push the terminal through its state machine to the
        target state. Note that even if it reaches there, the terminal
        will quickly return to pre-operational if no packets are sent to keep
        it operational.

        return the state, error flag and status before the operation."""
        order = list(MachineState)
        state, error, status = ret = await self.get_state()
        if error:
            await self.ec.roundtrip(ECCmd.FPWR, self.position,
                                    0x0120, "H", 0x11)
            state = MachineState.INIT
        for current in order[order.index(state) + 1:]:
            if state.value >= target.value:
                return ret
            await self.ec.roundtrip(ECCmd.FPWR, self.position,
                                    0x0120, "H", current.value)
            while current is not state:
                state, error, status = await self.get_state()
                if error:
                    raise EtherCatError(f"error status {status} in {self}")

    async def read(self, start, *args, **kwargs):
        """read data from the terminal at offset `start`

        see `EtherCat.roundtrip` for details on more parameters. """
        return (await self.ec.roundtrip(ECCmd.FPRD, self.position,
                                        start, *args, **kwargs))

    async def write(self, start, *args, **kwargs):
        """write data to the terminal at offset `start`

        see `EtherCat.roundtrip` for details on more parameters"""
        return (await self.ec.roundtrip(ECCmd.FPWR, self.position,
                                        start, *args, **kwargs))

    async def _eeprom_read_one(self, start):
        """read 8 bytes from the eeprom at `start`"""
        while (await self.read(0x502, "H"))[0] & 0x8000:
            pass
        await self.write(0x502, "HI", 0x100, start)
        busy = 0x8000
        while busy & 0x8000:
            busy, data = await self.read(0x502, "H4x8s")
        if busy & 0x40:  # otherwise we actually only read 4 bytes
            return data
        await self.write(0x502, "HI", 0x100, start + 2)
        busy = 0x8000
        while busy & 0x8000:
            busy, data2 = await self.read(0x502, "H4x4s")
        return data[:4] + data2

    async def eeprom_write_one(self, start, data):
        """write 2 bytes to the eeprom at `start`"""
        while (await self.read(0x502, "H"))[0] & 0x8000:
            pass
        busy = 0x1000
        while busy & 0xff00:
            await self.write(0x502, "HIH", 0x201, start, data)
            busy = 0x8000
            while busy & 0x8000:
                busy, = await self.read(0x502, "H")
            await self.write(0x502, "H", 0)

    async def read_eeprom(self):
        """read the entire eeprom"""
        async def get_data(size):
            nonlocal data, pos

            while len(data) < size:
                data += await self._eeprom_read_one(pos)
                pos += 4
            ret, data = data[:size], data[size:]
            return ret

        pos = 0x40
        data = b""
        self.eeprom = {}

        self.vendorId, self.productCode = \
                unpack('<II', await self._eeprom_read_one(EEPROM.VENDOR_ID))
        self.revisionNo, self.serialNo = \
                unpack('<II', await self._eeprom_read_one(EEPROM.REVISION))

        while True:
            hd, ws = unpack("<HH", await get_data(4))
            if hd == 0xffff:
                return
            self.eeprom[hd] = await get_data(ws * 2)

    def has_mailbox(self):
        return self.mbx_out_off is not None and self.mbx_in_off is not None

    async def mbx_send(self, type, *args, data=None, address=0, priority=0, channel=0):
        """send data to the mailbox"""
        status, = await self.read(0x805, "B")  # always using mailbox 0, OK?
        if status & 8:
            raise EtherCatError("mailbox full, read first")
        assert self.mbx_out_off is not None, "not send mailbox defined"
        await self.write(self.mbx_out_off, "HHBB",
                                datasize(args, data),
                                address, channel | priority << 6,
                                type.value | self.mbx_lock.next_counter() << 4,
                                *args, data=data)
        await self.write(self.mbx_out_off + self.mbx_out_sz - 1,
                                data=1)

    async def mbx_recv(self):
        """receive data from the mailbox"""
        status = 0
        while status & 8 == 0:
            # always using mailbox 1, OK?
            status, = await self.read(0x80D, "B")
        assert self.mbx_in_off is not None, "not receive mailbox defined"
        dlen, address, prio, type, data = await self.read(
                self.mbx_in_off, "HHBB", data=self.mbx_in_sz - 6)
        return MBXType(type & 0xf), data[:dlen]

    async def coe_request(self, coecmd, odcmd, *args, **kwargs):
        async with self.mbx_lock:
            await self.mbx_send(MBXType.COE, "HBxH", coecmd.value << 12,
                                odcmd.value, 0, *args, **kwargs)
            fragments = True
            ret = []
            offset = 8  # skip header in first packet

            while fragments:
                type = None
                while type is not MBXType.COE:
                    type, data = await self.mbx_recv()
                    if type is not MBXType.COE:
                        logging.warning(f"expected CoE package, got {type}")
                coecmd, rodcmd, fragments = unpack("<HBxH", data[:6])
                if rodcmd & 0x7f != odcmd.value + 1:
                    raise EtherCatError(f"expected {odcmd.value}, got {rodcmd}")
                ret.append(data[offset:])
                offset = 6
            return b"".join(ret)

    async def sdo_read(self, index, subindex=None):
        """read a single SDO entry

        given an adress for a CoE entry like 6020:12, you may read
        the value like ``await master.sdo_read(0x6020, 0x12)``.
        """
        async with self.mbx_lock:
            await self.mbx_send(
                    MBXType.COE, "HBHB4x", CoECmd.SDOREQ.value << 12,
                    ODCmd.UP_REQ_CA.value if subindex is None
                    else ODCmd.UP_REQ.value,
                    index, 1 if subindex is None else subindex)
            type = None
            while type is not MBXType.COE:
                type, data = await self.mbx_recv()
                if type is not MBXType.COE:
                    logging.warning(f"expected CoE package, got {type}")
            coecmd, sdocmd, idx, subidx, size = unpack("<HBHBI", data[:10])
            if coecmd >> 12 != CoECmd.SDORES.value:
                if subindex is None and coecmd >> 12 == CoECmd.SDOREQ.value:
                    return b""  # if there is no data, the terminal fails
                raise EtherCatError(
                    f"expected CoE SDORES (3), got {coecmd>>12:x} "
                    f"for {index:X}:{9 if subindex is None else subindex:02X}")
            if idx != index:
                raise EtherCatError(f"requested index {index}, got {idx}")
            if sdocmd & 2:
                return data[6 : 10 - ((sdocmd>>2) & 3)]
            ret = [data[10:]]
            retsize = len(ret[0])

            toggle = 0
            while retsize < size:
                await self.mbx_send(
                        MBXType.COE, "HBHB4x", CoECmd.SDOREQ.value << 12,
                        ODCmd.SEG_UP_REQ.value + toggle, index,
                        1 if subindex is None else subindex)
                type, data = await self.mbx_recv()
                if type is not MBXType.COE:
                    raise EtherCatError(f"expected CoE, got {type}")
                coecmd, sdocmd = unpack("<HB", data[:3])
                if coecmd >> 12 != CoECmd.SDORES.value:
                    raise EtherCatError(
                        f"expected CoE cmd SDORES, got {coecmd}")
                if sdocmd & 0xe0 != 0:
                    raise EtherCatError(f"requested index {index}, got {idx}")
                if sdocmd & 1 and len(data) == 7:
                    data = data[:3 + (sdocmd >> 1) & 7]
                ret += data[3:]
                retsize += len(data) - 3
                if sdocmd & 1:
                    break
                toggle ^= 0x10
            if retsize != size:
                raise EtherCatError(f"expected {size} bytes, got {retsize}")
            return b"".join(ret)

    async def sdo_write(self, data, index, subindex=None):
        """write a single SDO entry

        given a CoE address like 1200:2, one may write the value as
        in ``await master.sdo_write(b'abc', 0x1200, 0x2)``. Note that the
        data needs to already be a binary string matching the binary type of
        the parameter.
        """
        if len(data) <= 4 and subindex is not None:
            async with self.mbx_lock:
                await self.mbx_send(
                        MBXType.COE, "HBHB4s", CoECmd.SDOREQ.value << 12,
                        ODCmd.DOWN_EXP.value | (((4 - len(data)) << 2) & 0xc),
                        index, subindex, data)
                type, data = await self.mbx_recv()
            if type is not MBXType.COE:
                raise EtherCatError(f"expected CoE, got {type}, {data} "
                                    f"{odata} {index:x}:{subindex:x}")
            coecmd, sdocmd, idx, subidx = unpack("<HBHB", data[:6])
            if idx != index or subindex != subidx:
                raise EtherCatError(f"requested index {index:x}:{subindex:x}, "
                                    f"got {idx:x}:{subidx:x}")
            if coecmd >> 12 != CoECmd.SDORES.value:
                raise EtherCatError(f"expected CoE SDORES, got {coecmd>>12:x}")
        else:
            async with self.mbx_lock:
                stop = min(len(data), self.mbx_out_sz - 16)
                await self.mbx_send(
                        MBXType.COE, "HBHB4x", CoECmd.SDOREQ.value << 12,
                        ODCmd.DOWN_INIT_CA.value if subindex is None
                        else ODCmd.DOWN_INIT.value,
                        index, 1 if subindex is None else subindex,
                        data=data[:stop])
                type, data = await self.mbx_recv()
                if type is not MBXType.COE:
                    raise EtherCatError(f"expected CoE, got {type}")
                coecmd, sdocmd, idx, subidx = unpack("<HBHB", data[:6])
                if coecmd >> 12 != CoECmd.SDORES.value:
                    raise EtherCatError(f"expected CoE SDORES, got {coecmd>>12:x}")
                if idx != index or subindex != subidx:
                    raise EtherCatError(f"requested index {index}, got {idx}")
                toggle = 0
                while stop < len(data):
                    start = stop
                    stop = min(len(data), start + self.mbx_out_sz - 9)
                    if stop == len(data):
                        if stop - start < 7:
                            cmd = 1 + (7-stop+start << 1)
                            d = data[start:stop] + b"\0" * (7 - stop + start)
                        else:
                            cmd = 1
                            d = data[start:stop]
                        await self.mbx_send(
                                MBXType.COE, "HBHB4x", CoECmd.SDOREQ.value << 12,
                                cmd + toggle, index,
                                1 if subindex is None else subindex, data=d)
                        type, data = await self.mbx_recv()
                        if type is not MBXType.COE:
                            raise EtherCatError(f"expected CoE, got {type}")
                        coecmd, sdocmd, idx, subidx = unpack("<HBHB", data[:6])
                        if coecmd >> 12 != CoECmd.SDORES.value:
                            raise EtherCatError(f"expected CoE SDORES")
                        if idx != index or subindex != subidx:
                            raise EtherCatError(f"requested index {index}")
                    toggle ^= 0x10

    async def read_object_entry(self, index, subidx):
        """read a object entry from the CoE self description"""
        data = await self.coe_request(CoECmd.SDOINFO, ODCmd.OE_REQ,
                                      "HBB", index, subidx, 7)
        oe = ObjectEntry(self, index)
        oe.valueInfo, dataType, oe.bitLength, oe.objectAccess = \
            unpack_from("<BxHHH", data)
        assert subidx == oe.valueInfo
        oe.dataTypeOriginal = dataType
        if dataType < 2048:
            oe.dataType = ECDataType(dataType)
        elif oe.bitLength <= 8:
            oe.dataType = ECDataType.UNSIGNED8
        else:
            oe.dataType = dataType
        oe.name = data[8:].decode("utf8")
        return oe

    async def read_ODlist(self):
        idxes = await self.coe_request(CoECmd.SDOINFO, ODCmd.LIST_REQ, "H", 1)
        idxes = unpack("<" + "H" * int(len(idxes) // 2), idxes)

        ret = {}

        for index in idxes:
            data = await self.coe_request(CoECmd.SDOINFO, ODCmd.OD_REQ,
                                          "H", index)
            dtype, ms, oc = unpack("<HBB", data[:4])

            od = ObjectDescription(self)
            od.index = index
            od.dataType = dtype  # ECDataType(dtype)
            od.maxSub = ms
            od.name = data[4:].decode("utf8")
            ret[od.index] = od

        for od in ret.values():
            od.entries = {}
            for i in range(1 if od.maxSub > 0 else 0, od.maxSub + 1):
                try:
                    oe = await self.read_object_entry(od.index, i)
                except EtherCatError as e:
                    logging.info(f"problems reading SDO {od.index:x}:{i:x}:")
                    continue
                if oe.dataType is ECDataType.INVALID:
                    continue
                od.entries[i] = oe
        return ret

    @asynccontextmanager
    async def map_fmmu(self, logical, write):
        """map the pdo to `logical` address.

        :param write: a boolean indicating whether this is to be used
            for writing (instead of reading).
        """
        if write:
            offset = self.pdo_out_off
            size = self.pdo_out_sz
            start = 1
        else:
            offset = self.pdo_in_off
            size = self.pdo_in_sz
            start = len(self.fmmu_used)
        assert size is not None
        assert offset is not None

        index = start - self.fmmu_used[start::-1].index(None) - 1

        self.fmmu_used[index] = logical
        try:
            await self.write(0x600 + 0x10 * index, "IHBBHBBB3x", logical, size,
                             0, 7, offset, 0, 2 if write else 1, 1)
            yield index
            await self.write(0x60c + 0x10 * index, "B", 0)
        finally:
            self.fmmu_used[index] = None
