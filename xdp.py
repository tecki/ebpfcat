from asyncio import DatagramProtocol, Future, get_event_loop
from socket import AF_NETLINK, NETLINK_ROUTE, if_nametoindex
from struct import pack, unpack

async def set_link_xdp_fd(network, fd):
    ifindex = if_nametoindex(network)
    future = Future()
    transport, proto = await get_event_loop().create_datagram_endpoint(
            lambda: XDRFD(ifindex, fd, future),
            family=AF_NETLINK, proto=NETLINK_ROUTE)

class XDRFD(DatagramProtocol):
    def __init__(self, ifindex, fd, future):
        self.ifindex = ifindex
        self.fd = fd
        self.seq = None
        self.future = future

    def connection_made(self, transport):
        transport.get_extra_info("socket").bind((0, 0))
        self.transport = transport
        p = pack("IHHIIBxHiIIHHHHi",
                16,  # length of if struct
                19,  # RTM_SETLINK
                5,  # REQ | ACK
                1,  # sequence number
                0,  # pid
                0,  # AF_UNSPEC
                0,  # type
                self.ifindex,
                0,  #flags
                0,  #change
                0x802B,  # NLA_F_NESTED | IFLA_XDP
                12,  # length of field
                1,  # IFLA_XDP_FD
                8,  # length of field
                self.fd)
        transport.sendto(p, (0, 0))

    def datagram_received(self, data, addr):
        pos = 0
        while (pos < len(data)):
            ln, type, flags, seq, pid = unpack("IHHII", data[pos : pos+16])
            if type == 3:  # DONE
                self.future.set_result(0)
            elif type == 2:  # ERROR
                self.future.set_result(-1)
            elif flags & 2 == 0:  # not a multipart message
                self.future.set_result(0)
            pos += ln
                
        
