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

"""support for XDP programs"""
from asyncio import DatagramProtocol, Future, get_event_loop
from enum import Enum
from contextlib import contextmanager
from socket import AF_NETLINK, NETLINK_ROUTE, if_nametoindex
import socket
from struct import pack, unpack

from .ebpf import EBPF
from .bpf import ProgType


class XDPExitCode(Enum):
    ABORTED = 0
    DROP = 1
    PASS = 2
    TX = 3
    REDIRECT = 4


class XDRFD(DatagramProtocol):
    """just implement enough of the NETLINK protocol to attach programs"""

    def __init__(self, ifindex, fd, future):
        self.ifindex = ifindex
        self.fd = fd
        self.seq = None
        self.future = future

    def connection_made(self, transport):
        sock = transport.get_extra_info("socket")
        sock.setsockopt(270, 11, 1)
        sock.bind((0, 0))
        self.transport = transport
        p = pack("IHHIIBxHiIiHHHHiHHI",
                # NLmsghdr
                52,  # length of if struct
                19,  # RTM_SETLINK
                5,  # REQ | ACK
                1,  # sequence number
                0,  # pid
                # IFI
                0,  # AF_UNSPEC
                0,  # type
                self.ifindex,
                0,  #flags
                0,  #change
                # NLA
                20,  # length of field
                0x802B,  # NLA_F_NESTED | IFLA_XDP
                # NLA_XDP
                8,  # length of field
                1,  # IFLA_XDP_FD
                self.fd,
                8,
                3,  # IFLA_XDP_FLAGS,
                2)
        transport.sendto(p, (0, 0))

    def datagram_received(self, data, addr):
        pos = 0
        while (pos < len(data)):
            ln, type, flags, seq, pid = unpack("IHHII", data[pos : pos+16])
            if type == 3:  # DONE
                self.future.set_result(0)
            elif type == 2:  # ERROR
                errno, *args = unpack("iIHHII", data[pos+16 : pos+36])
                if errno != 0:
                    self.future.set_result(errno)
            if flags & 2 == 0:  # not a multipart message
                self.future.set_result(0)
            pos += ln


class PacketArray:
    """access a packet like a Python array"""
    def __init__(self, ebpf, no, memory):
        self.ebpf = ebpf
        self.no = no
        self.memory = memory

    def __getitem__(self, pos):
        return self.memory[self.ebpf.r[self.no] + pos]

    def __setitem__(self, pos, value):
        self.memory[self.ebpf.r[self.no] + pos] = value


class Packet:
    def __init__(self, ebpf, comp, no):
        self.ebpf = ebpf
        self.comp = comp
        self.no = no

        self.pB = PacketArray(self.ebpf, self.no, self.ebpf.mB)
        self.pH = PacketArray(self.ebpf, self.no, self.ebpf.mH)
        self.pI = PacketArray(self.ebpf, self.no, self.ebpf.mI)
        self.pQ = PacketArray(self.ebpf, self.no, self.ebpf.mQ)

    def Else(self):
        return self.comp.Else()


class PacketSize:
    def __init__(self, ebpf):
        self.ebpf = ebpf

    @contextmanager
    def __lt__(self, value):
        e = self.ebpf
        e.r9 = e.mA[e.r1]
        with e.mA[e.r1 + 4] < e.mA[e.r1] + value as comp:
            yield Packet(e, comp, 9)

    @contextmanager
    def __gt__(self, value):
        e = self.ebpf
        e.r9 = e.mA[e.r1]
        with e.mA[e.r1 + 4] > e.mA[e.r1] + value as comp:
            yield Packet(e, comp, 9)

    def __le__(self, value):
        return self < value + 1

    def __ge__(self, value):
        return self > value - 1


class XDP(EBPF):
    """the base class for XDP programs"""
    def __init__(self, **kwargs):
        super().__init__(prog_type=ProgType.XDP, **kwargs)

        self.packetSize = PacketSize(self)

    async def attach(self, network):
        """attach this program to a `network`"""
        ifindex = if_nametoindex(network)
        fd, _ = self.load(log_level=1)
        future = Future()
        transport, proto = await get_event_loop().create_datagram_endpoint(
                lambda: XDRFD(ifindex, fd, future),
                family=AF_NETLINK, proto=NETLINK_ROUTE)
        await future
        transport.get_extra_info("socket").close()
