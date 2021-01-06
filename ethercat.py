from asyncio import ensure_future, Event, Future, gather, get_event_loop, Protocol, Queue
from enum import Enum
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


class ECDatatype(Enum):
   BOOLEAN = 0x1
   INTEGER8 = 0x2
   INTEGER16 = 0x3
   INTEGER32 = 0x4
   UNSIGNED8 = 0x5
   UNSIGNED16 = 0x6
   UNSIGNED32 = 0x7
   REAL32 = 0x8
   VISIBLE_STRING = 0x9
   OCTET_STRING = 0xA
   UNICODE_STRING = 0xB
   TIME_OF_DAY = 0xC
   TIME_DIFFERENCE = 0xD
   DOMAIN = 0xF
   INTEGER24 = 0x10
   REAL64 = 0x11
   INTEGER64 = 0x15
   UNSIGNED24 = 0x16
   UNSIGNED64 = 0x1B
   BIT1 = 0x30
   BIT2 = 0x31
   BIT3 = 0x32
   BIT4 = 0x33
   BIT5 = 0x34
   BIT6 = 0x35
   BIT7 = 0x36
   BIT8 = 0x37

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

class SDOCmd(Enum):
   DOWN_INIT = 0x21
   DOWN_EXP = 0x23
   DOWN_INIT_CA = 0x31
   UP_REQ = 0x40
   UP_REQ_CA = 0x50
   SEG_UP_REQ = 0x60
   ABORT = 0x80

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
    pass


class ObjectEntry:
    pass


def datasize(args, data):
    out = calcsize("<" + "".join(arg for arg in args if isinstance(arg, str)))
    if isinstance(data, int):
        out += data
    elif data is not None:
        out += len(data)
    return out


class Packet:
    MAXSIZE = 1000  # maximum size we use for an EtherCAT packet

    def __init__(self):
        self.data = []
        self.size = 2

    def append(self, cmd, idx, pos, offset, data):
        self.data.append((cmd, idx, pos, offset, data))
        self.size += len(data) + 12

    def assemble(self):
        ret = [pack("<H", self.size | 0x1000)]
        for i, (cmd, *dgram, data) in enumerate(self.data, start=1):
            ret.append(pack("<BBhHHH", cmd.value, *dgram,
                            len(data) | ((i < len(self.data)) << 15), 0))
            ret.append(data)
            ret.append(b"\0\0")
        return b"".join(ret)

    def full(self):
        return self.size > self.MAXSIZE


class AsyncBase:
    async def __new__(cls, *args, **kwargs):
        ret = super().__new__(cls)
        await ret.__init__(*args, **kwargs)
        return ret


class EtherCat(Protocol, AsyncBase):
    async def __init__(self, network):
        self.addr = (network, 0x88A4, 0, 0, b"\xff\xff\xff\xff\xff\xff")
        self.send_queue = Queue()
        self.idle = Event()
        await get_event_loop().create_datagram_endpoint(
            lambda: self, family=AF_PACKET, proto=0xA488)

    async def sendloop(self):
        packet = Packet()
        while True:
            *dgram, future = await self.send_queue.get()
            lastsize = packet.size
            packet.append(*dgram)
            self.dgrams.append((lastsize + 10, packet.size - 2, future))
            if packet.full() or self.send_queue.empty():
                self.idle.clear()
                self.transport.sendto(packet.assemble(), self.addr)
                await self.idle.wait()
                assert len(self.dgrams) == 0
                packet = Packet()

    async def roundtrip(self, cmd, pos, offset, *args, data=None, idx=0):
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
        self.send_queue.put_nowait((cmd, idx, pos, offset, out, future))
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
        transport.get_extra_info("socket").bind(self.addr)
        self.transport = transport
        self.dgrams = []
        self.idle.set()
        ensure_future(self.sendloop())

    def datagram_received(self, data, addr):
        for start, stop, future in self.dgrams:
            future.set_result(data[start:stop])
        self.dgrams = []
        self.idle.set()


class Terminal:
    def __init__(self, ethercat):
        self.ec = ethercat

    async def initialize(self, relative, absolute):
        await self.ec.roundtrip(ECCmd.APWR, relative, 0x10, "H", absolute)
        self.position = absolute


        async def read_eeprom(no, fmt):
            return unpack(fmt, await self.eeprom_read_one(no))

        self.vendorId, self.productCode = await read_eeprom(8, "<II")
        self.revisionNo, self.serialNo = await read_eeprom(0xc, "<II")
        # this reads the mailbox configuration from the EEPROM header.
        # weirdly this does not match with the later EEPROM SM configuration
        # self.mbx_in_off, self.mbx_in_sz, self.mbx_out_off, self.mbx_out_sz = \
        #     await read_eeprom(0x18, "<HHHH")

        self.mbx_cnt = 1

        self.eeprom = await self.read_eeprom()
        await self.write(0x800, data=0x80)  # empty out sync manager
        await self.write(0x800, data=self.eeprom[41])
        self.mbx_out_off, self.mbx_out_sz, self.mbx_in_off, self.mbx_in_sz = \
            unpack("<HH4xHH", self.eeprom[41][:12])

    async def set_state(self, state):
        await self.ec.roundtrip(ECCmd.FPWR, self.position, 0x0120, "H", state)
        ret, = await self.ec.roundtrip(ECCmd.FPRD, self.position, 0x0130, "H")
        return ret

    async def to_operational(self):
        """try to bring the terminal to operational state"""
        order = [1, 2, 4]  #, 8]
        ret, error = await self.ec.roundtrip(
                ECCmd.FPRD, self.position, 0x0130, "H2xH")
        if ret & 0x10:
            await self.ec.roundtrip(ECCmd.FPWR, self.position,
                                    0x0120, "H", 0x11)
            ret, error = await self.ec.roundtrip(ECCmd.FPRD, self.position,
                                                 0x0130, "H2xH")
        pos = order.index(ret)
        s = 0x11 
        for state in order[pos:]:
            await self.ec.roundtrip(ECCmd.FPWR, self.position,
                                    0x0120, "H", state)
            while s != state:
                s, error = await self.ec.roundtrip(ECCmd.FPRD, self.position,
                                                   0x0130, "H2xH")
                if error != 0:
                    raise RuntimeError(f"AL register {error}")
    
    async def get_error(self):
        return (await self.ec.roundtrip(ECCmd.FPRD, self.position,
                                        0x0134, "H"))[0]

    async def read(self, start, *args, **kwargs):
        return (await self.ec.roundtrip(ECCmd.FPRD, self.position,
                                        start, *args, **kwargs))

    async def write(self, start, *args, **kwargs):
        return (await self.ec.roundtrip(ECCmd.FPWR, self.position,
                                        start, *args, **kwargs))

    async def eeprom_read_one(self, start):
        """read 8 bytes from the eeprom at start"""
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
        status, = await self.read(0x805, "B")  # always using mailbox 0, OK?
        if status & 8:
            raise RuntimeError("mailbox full, read first")
        await gather(self.write(self.mbx_out_off, "HHBB", datasize(args, data),
                                address, channel | priority << 6,
                                type.value | self.mbx_cnt << 4,
                                *args, data=data),
                     self.write(self.mbx_out_off + self.mbx_out_sz - 1, data=1)
                    )
        self.mbx_cnt = self.mbx_cnt % 7 + 1  # yes, we start at 1 not 0

    async def mbx_recv(self):
        status = 0
        while status & 8 == 0:
            status, = await self.read(0x80D, "B")  # always using mailbox 1, OK?
        dlen, address, prio, type, data = await self.read(
                self.mbx_in_off, "HHBB", data=self.mbx_in_sz - 6)
        return MBXType(type & 0xf), data[:dlen]

    async def coe_request(self, coecmd, odcmd, *args, **kwargs):
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

    async def read_ODlist(self):
        idxes = await self.coe_request(CoECmd.SDOINFO, ODCmd.LIST_REQ, "H", 1)
        idxes = unpack("<" + "H" * int(len(idxes) // 2), idxes)

        ret = []

        for index in idxes:
            data = await self.coe_request(CoECmd.SDOINFO, ODCmd.OD_REQ,
                                          "H", index)
            dtype, oc, ms = unpack("<HBB", data[:4])

            od = ObjectDescription()
            od.index = index
            od.dataType = dtype  # ECDataType(dtype)
            od.maxSub = ms
            od.name = data[4:].decode("utf8")
            ret.append(od)

        for od in ret:
            od.entries = {}
            for i in range(od.maxSub):
                try:
                    data = await self.coe_request(CoECmd.SDOINFO, ODCmd.OE_REQ,
                                                  "HBB", od.index, i, 7)
                except RuntimeError:
                    # many OEs just do not have more description
                    continue
                oe = ObjectEntry()
                oe.valueInfo, oe.dataType, oe.bitLength, oe.objectAccess = \
                        unpack("<HHHH", data[:8])
                oe.name = data[8:].decode("utf8")
                od.entries[i] = oe
        return ret


async def main():
    from .ebpfcat import install_ebpf
    from .bpf import lookup_elem

    ec = await EtherCat("eth0")
    map_fd = await install_ebpf("eth0")
    tin = Terminal(ec)
    tout = Terminal(ec)
    tdigi = Terminal(ec)
    await gather(
        tin.initialize(-1, 5),
        tout.initialize(-2, 6),
        tdigi.initialize(0, 22),
        )
    print("tin")
    await tin.to_operational(),
    print("tout")
    await tout.to_operational(),
    odlist = await tin.read_ODlist()
    for o in odlist:
        print(o.index, o.name)
        for i, p in o.entries.items():
            print("   ", i, p.name, p.valueInfo, p.dataType, p.bitLength, p.objectAccess)
            try:
                sdo = await tin.sdo_read(o.index, i)
                print("   ", sdo)
            except RuntimeError as e:
                print("   ", e)
    print("tdigi")
    print("bla", lookup_elem(map_fd, b"AAAA", 4))
    await tdigi.to_operational(),

    print(tout.eeprom[10])
    print(await tout.write(0x1100, "HHHH", 10000, 20000, 30000, 40000))
    print(await tin.read(0x1180, "HHHHHHHH"))

if __name__ == "__main__":
    loop = get_event_loop()
    loop.run_until_complete(main())
