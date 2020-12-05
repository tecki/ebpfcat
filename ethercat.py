from asyncio import ensure_future, Event, Future, gather, get_event_loop, Protocol, Queue
from socket import socket, AF_PACKET, SOCK_DGRAM
from struct import pack, unpack, calcsize


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
        elif isinstance(fmt, int):
            data = b"\0" * fmt
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


class Terminal:
    def __init__(self, ethercat):
        self.ec = ethercat

    async def initialize(self, relative, absolute):
        await self.ec.roundtrip(2, relative, 0x10, "H", absolute)
        self.position = absolute
        self.eeprom = await self.ec.read_eeprom(absolute)
        await self.ec.roundtrip(5, absolute, 0x800, 0x80)
        await self.ec.roundtrip(5, absolute, 0x800, self.eeprom[41])

    async def set_state(self, state):
        await self.ec.roundtrip(5, self.position, 0x0120, "H", state)
        ret, = await self.ec.roundtrip(4, self.position, 0x0130, "H")
        return ret

    async def to_operational(self):
        """try to bring the terminal to operational state"""
        order = [1, 2, 4, 8]
        ret, error = await self.ec.roundtrip(4, self.position,
                                                   0x0130, "H2xH")
        print(ret, error)
        if ret & 0x10:
            await self.ec.roundtrip(5, self.position, 0x0120, "H", 0x11)
            ret, error = await self.ec.roundtrip(4, self.position,
                                                   0x0130, "H2xH")
            print("B", ret, error)
        pos = order.index(ret)
        s = 0x11 
        for state in order[pos:]:
            await self.ec.roundtrip(5, self.position, 0x0120, "H", state)
            while s != state:
                s, error = await self.ec.roundtrip(4, self.position,
                                                   0x0130, "H2xH")
                if error != 0:
                    raise RuntimeError(f"AL register {error}")
    
    async def get_error(self):
        return (await self.ec.roundtrip(4, self.position, 0x0134, "H"))[0]

    async def read(self, start, fmt):
        return (await self.ec.roundtrip(4, self.position, start, fmt))

    async def write(self, start, fmt, *args):
        return (await self.ec.roundtrip(5, self.position, start, fmt, *args))


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
    print("tdigi")
    await tdigi.to_operational(),

    print(tout.eeprom[10])
    print(await tout.write(0x1100, "HHHH", 10000, 20000, 30000, 40000))
    print(await tin.read(0x1180, "HHHHHHHH"))

if __name__ == "__main__":
    loop = get_event_loop()
    loop.run_until_complete(main())
