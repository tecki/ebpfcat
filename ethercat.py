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

def scanbus(maxno):
    data = create_frame([
        (1, 0, -i, 0, b"\0\0\0\0")
        for i in range(maxno)])
    sock.sendto(data, addr)
    ret = sock.recv(1024)
    print_frame(ret)

def eeprom_wait(position):
    f = Frame([(1, 0, position, 0x502, "H")])
    while True:
        f.roundtrip(sock, addr)
        if not f[0][0] & 0x8000:
            return

def eeprom_read_one(position, start):
    f = Frame([(4, 0, position, 0x502, "H")])
    f[0] = 0x8000
    while f[0][0] & 0x8000:
        f.roundtrip(sock, addr)
    f = Frame([(5, 0, position, 0x502, "H"),
               (5, 0, position, 0x504, "I")])
    f[0] = 0x100  # read
    f[1] = start
    f.roundtrip(sock, addr)
    f = Frame([(4, 0, position, 0x502, "H"),
               (4, 0, position, 0x508, "8s"),
               (4, 0, position, 0x504, "I")])
    f[0] = 0x8000
    while f[0][0] & 0x8000:
        f.roundtrip(sock, addr)
    return f[1][0]

sock = socket(AF_PACKET, SOCK_DGRAM, 0xA488)
addr = ("eth0", 0x88A4, 0, 0, b"\xff\xff\xff\xff\xff\xff")
sock.bind(addr)
data = create_frame([
    (1, 9, 0, 0x110, b"\0\0"),
    (1, 10, 0, 0x130, b"\0\0"),
    (7, 4, 0, 0, b"\0\0\0\0"),
    (1, 4, 0, 0x502, b"\0\0"),
    ])
print_frame(data)

# set adresses
f = Frame([
    (2, 9, 0, 0x10, "H"),
    (2, 9, -1, 0x10, "H"),
    (2, 9, -2, 0x10, "H"),
    ])
f[0] = 7
f[1] = 5
f[2] = 22
f.roundtrip(sock, addr)

# configure mailbox
print("configure mailbox")
f = Frame([
    (5, 2, 22, 0x800, "HHBBBB"),
    (5, 2, 22, 0x808, "HHBBBB"),
    ])
f[0] = 0x1000, 0x80, 2, 0, 1, 0
f[1] = 0x1080, 0x80, 6, 0, 1, 0
f.roundtrip(sock, addr)
print(f)

# request state
f = Frame([
    (5, 2, 7, 0x120, "H"),
    (5, 2, 5, 0x120, "H"),
    (5, 2, 22, 0x120, "H"),
    (4, 2, 7, 0x130, "HHH"),
    (4, 2, 5, 0x130, "HHH"),
    (4, 2, 22, 0x130, "HHH"),
    (4, 2, 22, 0x800, "HHBBBB"),
    (4, 2, 22, 0x808, "HHBBBB"),
    (4, 2, 22, 0x810, "HHBBBB"),
    (4, 2, 22, 0x818, "HHBBBB"),
    ])
f[0] = 1
f[1] = 1
f[2] = 1
f.roundtrip(sock, addr)
print(f)
f.roundtrip(sock, addr)
print(f)


pos = 0x40
for i in range(16):
    data = eeprom_read_one(22, pos)
    hd, ws = unpack("<HH4x", data)
    #print(hd, ws, data)
    if hd == 0xffff:
        break
    pos += 2
    cont = b""
    for j in range(int((ws + 3) // 4)):
        cont += eeprom_read_one(22, pos + j * 4)
    cont = cont[:ws * 2]
    print(hd, ":", " ".join(f"{c:02x}" for c in cont))
    pos += ws


