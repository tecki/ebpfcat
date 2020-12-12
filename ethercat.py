from asyncio import ensure_future, Event, Future, gather, get_event_loop, Protocol, Queue
from enum import Enum
from socket import socket, AF_PACKET, SOCK_DGRAM
from struct import pack, unpack, calcsize

MAXSIZE = 1000  # maximum size we use for an EtherCAT packet

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


class ObjectDescription:
    pass


class ObjectEntry:
    pass


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
        ret = [None]
        size = 2
        while True:
            *dgram, data, future = await self.send_queue.get()
            done = size > MAXSIZE or self.send_queue.empty()
            ret.append(pack("<BBhHHH", *dgram,
                            len(data) | ((not done) << 15), 0))
            ret.append(data)
            ret.append(b"\0\0")
            self.dgrams.append((size + 10, size + len(data) + 10, future))
            size += len(data) + 12
            if done:
                ret[0] = pack("<H", size | 0x1000)
                self.idle.clear()
                self.transport.sendto(b"".join(ret), self.addr)
                await self.idle.wait()
                assert len(self.dgrams) == 0

                ret = [None]
                size = 2

    async def roundtrip(self, cmd, pos, offset, *args, data=None, idx=0):
        future = Future()
        fmt = "<"
        out = None
        for i, arg in enumerate(args):
            if not isinstance(arg, str):
                break
            fmt += arg
        else:
            out = b"\0" * calcsize(fmt)
        if out is None:
            out = pack(fmt, *args[i:])
        if isinstance(data, int):
            out += b"\0" * data
        elif data is not None:
            out += data
        self.send_queue.put_nowait(
            (cmd.value, idx, pos, offset, data, future))
        ret = await future
        if data is None:
            return unpack("<" + fmt, ret)
        elif args:
            return unpack("<" + fmt, ret[:-len(data)]) + (ret[-len(data):],)
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
        await self.write(0x800, 0x80)  # empty out sync manager
        await self.write(0x800, self.eeprom[41])
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
        print(ret, error)
        if ret & 0x10:
            await self.ec.roundtrip(ECCmd.FPWR, self.position,
                                    0x0120, "H", 0x11)
            ret, error = await self.ec.roundtrip(ECCmd.FPRD, self.position,
                                                 0x0130, "H2xH")
            print("B", ret, error)
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

    async def read(self, start, fmt, *args, **kwargs):
        return (await self.ec.roundtrip(ECCmd.FPRD, self.position,
                                        start, fmt, *args, **kwargs))

    async def write(self, start, fmt, *args, **kwargs):
        return (await self.ec.roundtrip(ECCmd.FPWR, self.position,
                                        start, fmt, *args, **kwargs))

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

    async def mbx_send(self, type, data, address=0, priority=0, channel=0):
        status, = await self.read(0x805, "B")  # always using mailbox 0, OK?
        if status & 8:
            raise RuntimeError("mailbox full, read first")
        await gather(self.write(self.mbx_out_off, "HHBB", len(data), address,
                                channel | priority << 6,
                                type.value | self.mbx_cnt << 4, data=data)
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

    async def read_ODlist(self):
        cmd = pack("<HBxHH", CoECmd.SDOINFO.value << 12,
                   ODCmd.LIST_REQ.value, 0, 1)
        await self.mbx_send(MBXType.COE, cmd)

        fragments = True
        offset = 8  # skip header in first packet
        indexes = []

        while fragments:
            type, data = await self.mbx_recv()
            if type is not MBXType.COE:
                raise RuntimeError(f"expected CoE package, got {type}")
            coecmd, odcmd, fragments = unpack("<HBxH", data[:6])
            coecmd = CoECmd(coecmd >> 12)
            odcmd = ODCmd(odcmd & 0x7f)
            if odcmd is not ODCmd.LIST_RES:
                raise RuntimeError(f"expected LIST_RES, got {odcmd}")

            indexes.extend(unpack("<" + "H" * int((len(data) - offset) // 2),
                                  data[offset:]))
            offset = 6

        ret = []

        for index in indexes:
            cmd = pack("<HBxHH", CoECmd.SDOINFO.value << 12,
                       ODCmd.OD_REQ.value, 0, index)
            await self.mbx_send(MBXType.COE, cmd)

            type, data = await self.mbx_recv()
            if type is not MBXType.COE:
                raise RuntimeError(f"expected CoE package, got {type}")
            coecmd, odcmd, fragments, dtype, oc, ms = unpack("<HBxH2xHBB", data[:12])
            coecmd = CoECmd(coecmd >> 12)
            odcmd = ODCmd(odcmd & 0x7f)
            if odcmd is not ODCmd.OD_RES:
                raise RuntimeError(f"expected OD_RES, got {odcmd}")

            od = ObjectDescription()
            od.index = index
            od.dataType = dtype  # ECDataType(dtype)
            od.maxSub = ms
            od.name = data[12:].decode("utf8")
            ret.append(od)

        for od in ret:
            od.entries = []
            for i in range(od.maxSub):
                cmd = pack("<HBxHHBB", CoECmd.SDOINFO.value << 12,
                           ODCmd.OE_REQ.value, 0, od.index, i, 7)
                await self.mbx_send(MBXType.COE, cmd)

                type, data = await self.mbx_recv()
                if type is not MBXType.COE:
                    raise RuntimeError(f"expected CoE package, got {type}")
                coecmd, odcmd, fragments, vi, dtype, bl, oa = unpack("<HBxHIHHH", (data + b"\0" * 16)[:16])
                coecmd = CoECmd(coecmd >> 12)
                odcmd = ODCmd(odcmd & 0x7f)
                if odcmd is ODCmd.OE_RES:
                    oe = ObjectEntry()
                    oe.valueInfo = vi
                    oe.dataType = dtype
                    oe.bitLength = bl
                    oe.objectAccess = oa
                    oe.name = data[16:].decode("utf8")
                    od.entries.append(oe)
        return ret


async def main():
    ec = await EtherCat("eth0")
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
    odlist = await tout.read_ODlist()
    for o in odlist:
        print(o.name)
        for p in o.entries:
            print("   ", p.name)
    print("tdigi")
    await tdigi.to_operational(),

    print(tout.eeprom[10])
    print(await tout.write(0x1100, "HHHH", 10000, 20000, 30000, 40000))
    print(await tin.read(0x1180, "HHHHHHHH"))

if __name__ == "__main__":
    loop = get_event_loop()
    loop.run_until_complete(main())
