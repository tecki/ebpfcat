from asyncio import DatagramProtocol, Future, get_event_loop
from socket import AF_NETLINK, NETLINK_ROUTE, if_nametoindex
import socket
from struct import pack, unpack

async def set_link_xdp_fd(network, fd):
    ifindex = if_nametoindex(network)
    future = Future()
    transport, proto = await get_event_loop().create_datagram_endpoint(
            lambda: XDRFD(ifindex, fd, future),
            family=AF_NETLINK, proto=NETLINK_ROUTE)
    await future
    transport.get_extra_info("socket").close()

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
        print("send", len(p), p)
        transport.sendto(p, (0, 0))

    def datagram_received(self, data, addr):
        pos = 0
        print("received", data)
        while (pos < len(data)):
            ln, type, flags, seq, pid = unpack("IHHII", data[pos : pos+16])
            print(f"  {ln} {type} {flags:x} {seq} {pid}")
            if type == 3:  # DONE
                self.future.set_result(0)
            elif type == 2:  # ERROR
                errno, *args = unpack("iIHHII", data[pos+16 : pos+36])
                print("ERROR", errno, args)
                if errno != 0:
                    self.future.set_result(errno)
            if flags & 2 == 0:  # not a multipart message
                print("not multipart")
                self.future.set_result(0)
            pos += ln
                
        
