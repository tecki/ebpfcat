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
from asyncio import ensure_future, Event, Future, gather, get_event_loop, Protocol, Queue, Lock
from enum import Enum
from random import randint
from socket import socket, AF_PACKET, SOCK_DGRAM
from struct import pack, unpack, calcsize

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


class ObjectDescription:
    def __init__(self, terminal):
        self.terminal = terminal

    def __getitem__(self, idx):
        return self.entries[idx]


class ObjectEntry:
    def __init__(self, desc):
        self.desc = desc

    async def read(self):
        ret = await self.desc.terminal.sdo_read(self.desc.index, self.valueInfo)
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

        return await self.desc.terminal.sdo_write(d, self.desc.index,
                                                  self.valueInfo)


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
    MAXSIZE = 1000  # maximum size we use for an EtherCAT packet
    ETHERNET_HEADER = 14
    DATAGRAM_HEADER = 10
    DATAGRAM_TAIL = 2

    def __init__(self):
        self.data = []
        self.size = 14

    def append(self, cmd, data, idx, *address):
        """Append a datagram to the packet

        :param cmd: EtherCAT command
        :type cmd: ECCmd
        :param data: the data in the datagram
        :param idx: the datagram index, unchanged by terminals

        Depending on the command, one or two more parameters represent the
        address, either terminal and offset for position or node addressing,
        or one value for logical addressing."""
        self.data.append((cmd, data, idx) + address)
        self.size += len(data) + self.DATAGRAM_HEADER + self.DATAGRAM_TAIL

    def assemble(self, index):
        """Assemble the datagrams into a packet

        :param index: an identifier for the packet

        An implicit empty datagram is added at the beginning of the packet
        that may be used as an identifier for the packet.
        """
        ret = [pack("<HBBiHHH", self.size | 0x1000, 0, 0, index, 1 << 15, 0, 0)]
        for i, (cmd, data, *dgram) in enumerate(self.data, start=1):
            ret.append(pack("<BBhHHH" if len(dgram) == 3 else "<BBiHH",
                            cmd.value, *dgram,
                            len(data) | ((i < len(self.data)) << 15), 0))
            ret.append(data)
            ret.append(b"\0\0")
        return b''.join(ret)

    def __str__(self):
        ret = "\n".join(f"{cmd} {data} {idx} {addr}"
                        for cmd, data, idx, *addr in self.data)
        return "Packet([" + ret + "]"

    def disassemble(self, data):
        pos = 14 + self.DATAGRAM_HEADER
        ret = []
        for cmd, bits, *dgram in self.data:
            ret.append((data[pos-self.DATAGRAM_HEADER],
                        data[pos:pos+len(bits)],
                        unpack("<H", data[pos+len(bits):pos+len(bits)+2])[0]))
            pos += self.DATAGRAM_HEADER + self.DATAGRAM_TAIL
        return ''.join(f"{i}: {c} {f} {d}\n" for i, (c, d, f) in enumerate(ret))

    def full(self):
        """Is the data limit reached?"""
        return self.size > self.MAXSIZE or len(self.data) > 14


class EtherCat(Protocol):
    """The EtherCAT connection

    An object of this class represents one connection to an EtherCAT loop.
    It keeps the socket, and eventually all data flows through it.

    This class supports both to send individual datagrams and wait for their
    response, but also to send and receive entire packets. """
    def __init__(self, network):
        """
        :param network: the name of the network adapter, like "eth0"
        """
        self.addr = (network, 0x88A4, 0, 0, b"\xff\xff\xff\xff\xff\xff")
        self.send_queue = Queue()
        self.wait_futures = {}

    async def connect(self):
        """connect to the EtherCAT loop"""
        await get_event_loop().create_datagram_endpoint(
            lambda: self, family=AF_PACKET, proto=0xA488)

    async def sendloop(self):
        """the eternal datagram sending loop

        This method runs while we are connected, takes the datagrams
        to be sent from a queue, packs them in a packet and ships them
        out. """
        packet = Packet()
        dgrams = []
        while True:
            *dgram, future = await self.send_queue.get()
            lastsize = packet.size
            packet.append(*dgram)
            dgrams.append((lastsize + 10, packet.size - 2, future))
            if packet.full() or self.send_queue.empty():
                data = await self.roundtrip_packet(packet)
                for start, stop, future in dgrams:
                    future.set_result(data[start:stop])
                dgrams = []
                packet = Packet()

    async def roundtrip_packet(self, packet):
        """Send a packet and return the response

        Send the `packet` to the loop and wait that it comes back,
        and return that to the caller. """
        index = randint(2000, 1000000000)
        while index in self.wait_futures:
            index = randint(2000, 1000000000)
        self.send_packet(packet.assemble(index))
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
            out += b"\0" * calcsize(args[-1])
            fmt += args[-1]
        if isinstance(data, int):
            out += b"\0" * data
        elif data is not None:
            out += data
        self.send_queue.put_nowait((cmd, out, idx, pos, offset, future))
        ret = await future
        if data is None:
            return unpack(fmt, ret)
        elif args:
            if not isinstance(data, int):
                data = len(data)
            return unpack(fmt, ret[:-data]) + (ret[-data:],)
        else:
            return ret

    def connection_made(self, transport):
        """start the send loop once the connection is made"""
        transport.get_extra_info("socket").bind(self.addr)
        self.transport = transport
        ensure_future(self.sendloop())

    def datagram_received(self, data, addr):
        """distribute received packets to the recipients"""
        index, = unpack("<I", data[4:8])
        self.wait_futures[index].set_result(data)


class Terminal:
    """Represent one terminal ("slave") in the loop"""

    async def initialize(self, relative, absolute):
        """Initialize the terminal

        this sets up the connection to the terminal we represent.

        :param relative: the position of the terminal in the loop,
            a negative number counted down from 0 for the first terminal
        :param absolute: the number used to identify the terminal henceforth

        This also reads the EEPROM and sets up the sync manager as defined
        therein. It still leaves the terminal in the init state. """
        await self.ec.roundtrip(ECCmd.APWR, relative, 0x10, "H", absolute)
        self.position = absolute

        await self.set_state(0x11)
        await self.set_state(1)

        async def read_eeprom(no, fmt):
            return unpack(fmt, await self.eeprom_read_one(no))

        self.vendorId, self.productCode = await read_eeprom(8, "<II")
        self.revisionNo, self.serialNo = await read_eeprom(0xc, "<II")
        # this reads the mailbox configuration from the EEPROM header.
        # weirdly this does not match with the later EEPROM SM configuration
        # self.mbx_in_off, self.mbx_in_sz, self.mbx_out_off, self.mbx_out_sz = \
        #     await read_eeprom(0x18, "<HHHH")

        self.mbx_cnt = 1
        self.mbx_lock = Lock()

        self.eeprom = await self.read_eeprom()
        await self.write(0x800, data=0x80)  # empty out sync manager
        await self.write(0x800, data=self.eeprom[41])
        self.mbx_out_off = self.mbx_out_sz = None
        self.mbx_in_off = self.mbx_in_sz = None
        self.pdo_out_off = self.pdo_out_sz = None
        self.pdo_in_off = self.pdo_in_sz = None
        for i in range(0, len(self.eeprom[41]), 8):
            offset, size, mode = unpack("<HHB", self.eeprom[41][i:i+5])
            mode &= 0xf
            if mode == 0:
                self.pdo_in_off = offset
                self.pdo_in_sz = size
            elif mode == 2:
                self.mbx_in_off = offset
                self.mbx_in_sz = size
            elif mode == 4:
                self.pdo_out_off = offset
                self.pdo_out_sz = size
            elif mode == 6:
                self.mbx_out_off = offset
                self.mbx_out_sz = size
        s = await self.read(0x800, data=0x80)
        print(absolute, " ".join(f"{c:02x} {'|' if i % 8 == 7 else ''}" for i, c in enumerate(s)))

    def parse_pdos(self):
        def parse_pdo(s):
            i = 0
            while i < len(s):
                idx, e, sm, u1, u2, u3 = unpack("<HBBBBH", s[i:i+8])
                print(f"idx {idx:x} sm {sm} {u1:x} {u2:x} {u3:x}")
                i += 8
                for er in range(e):
                    bitsize, = unpack("<5xB2x", s[i:i+8])
                    print("  bs", bitsize, s[i:i+8])
                    i += 8

        if 50 in self.eeprom:
            parse_pdo(self.eeprom[50])
        if 51 in self.eeprom:
            parse_pdo(self.eeprom[51])

    async def set_state(self, state):
        """try to set the state, and return the new state"""
        await self.ec.roundtrip(ECCmd.FPWR, self.position, 0x0120, "H", state)
        ret, = await self.ec.roundtrip(ECCmd.FPRD, self.position, 0x0130, "H")
        return ret

    async def get_state(self):
        """get the current state"""
        ret, = await self.ec.roundtrip(ECCmd.FPRD, self.position, 0x0130, "H")
        return ret

    async def to_operational(self):
        """try to bring the terminal to operational state

        this tries to push the terminal through its state machine to the
        operational state. Note that even if it reaches there, the terminal
        will quickly return to pre-operational if no packets are sent to keep
        it operational. """
        order = [1, 2, 4, 8]
        ret, error = await self.ec.roundtrip(
                ECCmd.FPRD, self.position, 0x0130, "H2xH")
        if ret & 0x10:
            await self.ec.roundtrip(ECCmd.FPWR, self.position,
                                    0x0120, "H", 0x11)
            ret, error = await self.ec.roundtrip(ECCmd.FPRD, self.position,
                                                 0x0130, "H2xH")
        pos = order.index(ret)
        s = 0x11
        for state in order[pos+1:]:
            await self.ec.roundtrip(ECCmd.FPWR, self.position,
                                    0x0120, "H", state)
            while s != state:
                s, error = await self.ec.roundtrip(ECCmd.FPRD, self.position,
                                                   0x0130, "H2xH")
                if error != 0:
                    raise RuntimeError(f"AL register {error}")

    async def get_error(self):
        """read the error register"""
        return (await self.ec.roundtrip(ECCmd.FPRD, self.position,
                                        0x0134, "H"))[0]

    async def read(self, start, *args, **kwargs):
        """read data from the terminal at offset `start`

        see `EtherCat.roundtrip` for details on more parameters. """
        return (await self.ec.roundtrip(ECCmd.FPRD, self.position,
                                        start, *args, **kwargs))

    async def write(self, start, *args, **kwargs):
        """write data from the terminal at offset `start`

        see `EtherCat.roundtrip` for details on more parameters"""
        return (await self.ec.roundtrip(ECCmd.FPWR, self.position,
                                        start, *args, **kwargs))

    async def eeprom_read_one(self, start):
        """read 8 bytes from the eeprom at `start`"""
        while (await self.read(0x502, "H"))[0] & 0x8000:
            pass
        await self.write(0x502, "HI", 0x100, start)
        busy = 0x8000
        while busy & 0x8000:
            busy, data = await self.read(0x502, "H4x8s")
        return data

    async def read_eeprom(self):
        """read the entire eeprom"""
        async def get_data(size):
            nonlocal data, pos

            while len(data) < size:
                data += await self.eeprom_read_one(pos)
                pos += 4
            ret, data = data[:size], data[size:]
            return ret

        pos = 0x40
        data = b""
        eeprom = {}

        while True:
            hd, ws = unpack("<HH", await get_data(4))
            if hd == 0xffff:
                return eeprom
            eeprom[hd] = await get_data(ws * 2)

    async def mbx_send(self, type, *args, data=None, address=0, priority=0, channel=0):
        """send data to the mailbox"""
        status, = await self.read(0x805, "B")  # always using mailbox 0, OK?
        if status & 8:
            raise RuntimeError("mailbox full, read first")
        await self.write(self.mbx_out_off, "HHBB",
                                datasize(args, data),
                                address, channel | priority << 6,
                                type.value | self.mbx_cnt << 4,
                                *args, data=data)
        await self.write(self.mbx_out_off + self.mbx_out_sz - 1,
                                data=1)
        self.mbx_cnt = self.mbx_cnt % 7 + 1  # yes, we start at 1 not 0

    async def mbx_recv(self):
        """receive data from the mailbox"""
        status = 0
        while status & 8 == 0:
            # always using mailbox 1, OK?
            status, = await self.read(0x80D, "B")
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
                type, data = await self.mbx_recv()
                if type is not MBXType.COE:
                    raise RuntimeError(f"expected CoE package, got {type}")
                coecmd, rodcmd, fragments = unpack("<HBxH", data[:6])
                if rodcmd & 0x7f != odcmd.value + 1:
                    raise RuntimeError(f"expected {odcmd.value}, got {odcmd}")
                ret.append(data[offset:])
                offset = 6
            return b"".join(ret)

    async def sdo_read(self, index, subindex=None):
        async with self.mbx_lock:
            await self.mbx_send(
                    MBXType.COE, "HBHB4x", CoECmd.SDOREQ.value << 12,
                    ODCmd.UP_REQ_CA.value if subindex is None
                    else ODCmd.UP_REQ.value,
                    index, 1 if subindex is None else subindex)
            type, data = await self.mbx_recv()
            if type is not MBXType.COE:
                raise RuntimeError(f"expected CoE, got {type}")
            coecmd, sdocmd, idx, subidx, size = unpack("<HBHBI", data[:10])
            if coecmd >> 12 != CoECmd.SDORES.value:
                raise RuntimeError(f"expected CoE SDORES (3), got {coecmd>>12:x}")
            if idx != index:
                raise RuntimeError(f"requested index {index}, got {idx}")
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
                    raise RuntimeError(f"expected CoE, got {type}")
                coecmd, sdocmd = unpack("<HB", data[:3])
                if coecmd >> 12 != CoECmd.SDORES.value:
                    raise RuntimeError(f"expected CoE cmd SDORES, got {coecmd}")
                if sdocmd & 0xe0 != 0:
                    raise RuntimeError(f"requested index {index}, got {idx}")
                if sdocmd & 1 and len(data) == 7:
                    data = data[:3 + (sdocmd >> 1) & 7]
                ret += data[3:]
                retsize += len(data) - 3
                if sdocmd & 1:
                    break
                toggle ^= 0x10
            if retsize != size:
                raise RuntimeError(f"expected {size} bytes, got {retsize}")
            return b"".join(ret)

    async def sdo_write(self, data, index, subindex=None):
        if len(data) <= 4 and subindex is not None:
            async with self.mbx_lock:
                await self.mbx_send(
                        MBXType.COE, "HBHB4s", CoECmd.SDOREQ.value << 12,
                        ODCmd.DOWN_EXP.value | (((4 - len(data)) << 2) & 0xc),
                        index, subindex, data)
                type, data = await self.mbx_recv()
            if type is not MBXType.COE:
                raise RuntimeError(f"expected CoE, got {type}, {data} {odata} {index:x} {subindex}")
            coecmd, sdocmd, idx, subidx = unpack("<HBHB", data[:6])
            if idx != index or subindex != subidx:
                raise RuntimeError(f"requested index {index}, got {idx}")
            if coecmd >> 12 != CoECmd.SDORES.value:
                raise RuntimeError(f"expected CoE SDORES, got {coecmd>>12:x}")
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
                    raise RuntimeError(f"expected CoE, got {type}")
                coecmd, sdocmd, idx, subidx = unpack("<HBHB", data[:6])
                if coecmd >> 12 != CoECmd.SDORES.value:
                    raise RuntimeError(f"expected CoE SDORES, got {coecmd>>12:x}")
                if idx != index or subindex != subidx:
                    raise RuntimeError(f"requested index {index}, got {idx}")
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
                            raise RuntimeError(f"expected CoE, got {type}")
                        coecmd, sdocmd, idx, subidx = unpack("<HBHB", data[:6])
                        if coecmd >> 12 != CoECmd.SDORES.value:
                            raise RuntimeError(f"expected CoE SDORES")
                        if idx != index or subindex != subidx:
                            raise RuntimeError(f"requested index {index}")
                    toggle ^= 0x10

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
                data = await self.coe_request(CoECmd.SDOINFO, ODCmd.OE_REQ,
                                              "HBB", od.index, i, 7)
                oe = ObjectEntry(od)
                oe.valueInfo, dataType, oe.bitLength, oe.objectAccess = \
                        unpack("<HHHH", data[:8])
                if dataType == 0:
                    continue
                assert i == oe.valueInfo
                if dataType < 2048:
                    oe.dataType = ECDataType(dataType)
                else:
                    oe.dataType = dataType
                oe.name = data[8:].decode("utf8")
                od.entries[i] = oe
        return ret


async def main():
    from .bpf import lookup_elem

    ec = EtherCat("eth0")
    await ec.connect()
    #map_fd = await install_ebpf2()
    tin = Terminal()
    tin.ec = ec
    tout = Terminal()
    tout.ec = ec
    tdigi = Terminal()
    tdigi.ec = ec
    await gather(
        tin.initialize(-4, 19),
        tout.initialize(-2, 55),
        tdigi.initialize(0, 22),
        )
    print("tin")
    #await tin.to_operational()
    await tin.set_state(2)
    print("tout")
    await tout.to_operational()
    print("reading odlist")
    odlist2, odlist = await gather(tin.read_ODlist(), tout.read_ODlist())
    #oe = odlist[0x7001][1]
    #await oe.write(1)
    for o in odlist.values():
        print(hex(o.index), o.name, o.maxSub)
        for i, p in o.entries.items():
            print("   ", i, p.name, "|", p.dataType, p.bitLength, p.objectAccess)
            #sdo = await tin.sdo_read(o.index, i)
            try:
               sdo = await p.read()
               if isinstance(sdo, int):
                   t = hex(sdo)
               else:
                   t = ""
               print("   ", sdo, t)
            except RuntimeError as e:
               print("   E", e)
    print("set sdo")
    oe = odlist[0x8010][7]
    print("=", await oe.read())
    await oe.write(1)
    print("=", await oe.read())
    print(tdigi.eeprom[10])

if __name__ == "__main__":
    loop = get_event_loop()
    loop.run_until_complete(main())
