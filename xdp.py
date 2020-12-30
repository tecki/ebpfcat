from asyncio import DatagramProtocol, Future, get_event_loop
from socket import AF_NETLINK, NETLINK_ROUTE, if_nametoindex
import socket
from struct import pack, unpack

from .ebpf import EBPF, Memory, MemoryDesc, Opcode
from .bpf import ProgType


class XDRFD(DatagramProtocol):
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

class Packet(Expression):
    def __init__(self, ebpf, bits, addr):
        self.ebpf = ebpf
        self.bits = bits
        self.address = addr
        self.signed = False

    @contextmanager
    def get_address(self, dst, long, signed, force=False):
        e = self.ebpf
        bits = Memory.bits_to_opcode[self.bits]
        with e.get_free_register(dst) as reg:
            e.r[reg] = e.m32[e.r1] + self.address
            with e.If(e.r[reg] + int(self.bits // 8) <= e.m32[e.r1 + 4]) as c:
                if force and dst != reg:
                    e.r[dst] = e.r[reg]
                    reg = dst
            with c.Else():
                e.exit(2)
        yield reg, bits

    def contains(self, no):
        return no == 1 or (not isinstance(self.address, int)
                           and self.address.contains(no))
                

class PacketDesc(MemoryDesc):
    def __setitem__(self, addr, value):
        super().__setitem__(self.ebpf.r9 + addr, value)

    def __getitem__(self, addr):
        return Memory(self.ebpf, self.bits, self.ebpf.r9 + addr)


class XDP(EBPF):
    def __init__(self, **kwargs):
        super().__init__(prog_type=ProgType.XDP, **kwargs)
        self.r9 = self.m32[self.r1]

        self.packet8 = MemoryDesc(self, Opcode.B)
        self.packet16 = MemoryDesc(self, Opcode.H)
        self.packet32 = MemoryDesc(self, Opcode.W)
        self.packet64 = MemoryDesc(self, Opcode.DW)

    async def attach(self, network):
        ifindex = if_nametoindex(network)
        fd = self.load()
        future = Future()
        transport, proto = await get_event_loop().create_datagram_endpoint(
                lambda: XDRFD(ifindex, fd, future),
                family=AF_NETLINK, proto=NETLINK_ROUTE)
        await future
        transport.get_extra_info("socket").close()
