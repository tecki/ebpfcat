from asyncio import ensure_future, Event, Future, gather, get_event_loop, Protocol, Queue
from socket import socket, AF_PACKET, SOCK_DGRAM
from struct import pack, unpack, calcsize

def create_frame(datagrams):
    ret = [None]

    for i, (cmd, idx, pos, offset, data) in enumerate(datagrams):
        if isinstance(data, int):
            data = b"\0" * data
        ret.append(pack("<BBhHHH", cmd, idx, pos, offset,
                        len(data) | ((i != len(datagrams) - 1) << 15), 0))
        ret.append(data)
        ret.append(b"\0\0")
    size = sum(len(r) for r in ret[1:])
    ret[0] = pack("<H", size | 0x1000)
    return b"".join(ret)

def print_frame(frame):
    i = 2
    while True:
        cmd, idx, pos, offset, size, irq = unpack("<BBhHHH", frame[i : i+10])
        i += 10
        print(f"cmd {cmd} idx {idx} {pos:04x}:{offset:04x} irq {irq}")
        nxt = size & 0x8000 != 0
        size &= 0x7ff
        print("data", size, frame[i : i+size], " ".join(f"{f:02x}" for f in frame[i : i+size]),
              " ".join(f"{f:08b}" for f in frame[i : i+size]))
        i += size
        wkc, = unpack("<H", frame[i : i+2])
        i += 2
        print("wkc", wkc)
        if not nxt:
            break

class Frame:
    def __init__(self, datagrams):
        ret = [None]
        self.blocks = []
        self.formats = []

        j = 12

        for i, (cmd, idx, pos, offset, data) in enumerate(datagrams):
            data = "<" + data
            size = calcsize(data)
            ret.append(pack("<BBhHHH", cmd, idx, pos, offset,
                            size | ((i != len(datagrams) - 1) << 15), 0))
            ret.append(b"\0" * size)
            self.blocks.append(j)
            self.formats.append(data)
            ret.append(b"\0\0")
            j += size + 12
        size = sum(len(r) for r in ret[1:])
        ret[0] = pack("<H", size | 0x1000)
        self.data = bytearray(b"".join(ret))

    def roundtrip(self, sock, addr):
        sock.sendto(self.data, addr)
        ret = sock.recv_into(self.data)
        if ret < len(self.data):
            raise RuntimeError("not enough data")

    def __getitem__(self, no):
        pos = self.blocks[no]
        d = self.data[pos : pos + calcsize(self.formats[no])]
        return unpack(self.formats[no], d)

    def __setitem__(self, no, data):
        if not isinstance(data, tuple):
            data = data,
        pos = self.blocks[no]
        self.data[pos : pos + calcsize(self.formats[no])
                  ] = pack(self.formats[no], *data)

    def __str__(self):
        return "".join(self._str())

    def _str(self):
        i = 2
        while True:
            cmd, idx, pos, offset, size, irq = unpack("<BBhHHH",
                                                      self.data[i : i+10])
            i += 10
            yield f"[{cmd} {idx} {pos:04x}:{offset:04x} {irq} ("
            nxt = size & 0x8000 != 0
            size &= 0x7ff
            yield " ".join(f"{f:02x}" for f in self.data[i : i+size])
            yield "   "
            yield " ".join(f"{f:08b}" for f in self.data[i : i+size])
            i += size
            wkc, = unpack("<H", self.data[i : i+2])
            i += 2
            yield f") {wkc}]"
            if nxt:
                yield "\n"
            else:
                return

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
            done = size > 1000 or self.send_queue.empty()
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

    async def roundtrip(self, cmd, pos, offset, fmt, *args, index=0):
        future = Future()
        if args:
            data = pack("<" + fmt, *args)
        elif isinstance(fmt, str):
            data = b"\0" * calcsize(fmt)
        else:
            data = fmt
        self.send_queue.put_nowait((cmd, index, pos, offset, data, future))
        ret = await future
        if args or isinstance(fmt, str):
            return unpack("<" + fmt, ret)
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

    async def eeprom_read_one(self, position, start):
        while (await self.roundtrip(4, position, 0x502, "H"))[0] & 0x8000:
            pass
        await self.roundtrip(5, position, 0x502, "HI", 0x100, start)
        busy = 0x8000
        while busy & 0x8000:
            busy, data = await self.roundtrip(4, position, 0x502, "H4x8s")
        return data

    async def read_eeprom(self, position):
        async def get_data(size):
            nonlocal data, pos

            while len(data) < size:
                data += await self.eeprom_read_one(position, pos)
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

async def main():
    ec = await EtherCat("eth0")
    await gather(
        ec.roundtrip(2, 0, 0x10, "H", 8),
        ec.roundtrip(2, -1, 0x10, "H", 3),
        ec.roundtrip(2, -2, 0x10, "H", 21),
        )

    print(await gather(ec.read_eeprom(21), ec.read_eeprom(3), ec.read_eeprom(8)))

if __name__ == "__main__":
    loop = get_event_loop()
    loop.run_until_complete(main())
