from argparse import ArgumentParser
import asyncio
from functools import wraps
from hashlib import sha1
from pprint import PrettyPrinter
from struct import unpack
import sys

from .ebpfcat import ParallelEtherCat
from .ethercat import EtherCat, MachineState, Terminal, ECCmd, EtherCatError

def entrypoint(func):
    @wraps(func)
    def wrapper():
        asyncio.run(func())
    return wrapper


@entrypoint
async def scanbus():
    ec = ParallelEtherCat(sys.argv[1])
    async with ec.run():
        no = await ec.count()
        print('counted', no)
        for i in range(no):
            r, = await ec.roundtrip(ECCmd.APRD, -i, 0x10, "H", 44)
            print(i, r, await ec.eeprom_read(-i, 0xa))

@entrypoint
async def info():
    parser = ArgumentParser(
        prog = "ec-info",
        description = "Retrieve information from an EtherCat bus")

    parser.add_argument("interface")
    parser.add_argument("-t", "--terminal", type=int)
    parser.add_argument("-i", "--ids", action="store_true")
    parser.add_argument("-n", "--names", action="store_true")
    parser.add_argument("-s", "--sdo", action="store_true")
    parser.add_argument("-v", "--values", action="store_true")
    parser.add_argument("-p", "--pdo", action="store_true")
    parser.add_argument("-e", "--eeprom", action="store_true")
    args = parser.parse_args()

    ec = ParallelEtherCat(args.interface)
    async with ec.run():
        if args.terminal is None:
            terminals = range(await ec.count())
            terms = [Terminal(ec) for t in terminals]
            for t in terms:
                t.ec = ec
            await asyncio.gather(*(t.gentle_initialize(-i)
                                   for i, t in zip(terminals, terms)))
        else:
            term = Terminal(ec)
            await term.gentle_initialize(-args.terminal)
            terms = [term]

        for i, t in enumerate(terms, args.terminal if args.terminal else 0):
            print(f"terminal no {i}")
            if args.ids:
                print(f"{t.vendorId:X}:{t.productCode:X} "
                      f"revision {t.revisionNo:X} serial {t.serialNo}")
            if args.names:
                infos = t.eeprom[10]
                i = 1
                while i < len(infos):
                    print(infos[i+1 : i+infos[i]+1].decode("latin1"))
                    i += infos[i] + 1

            if args.eeprom:
                for k, v in t.eeprom.items():
                    print(f"{k:2}: {v}\n    {v.hex()}")

            if args.sdo:
                await t.to_operational(MachineState.PRE_OPERATIONAL)
                ret = await t.read_ODlist()
                for k, v in ret.items():
                    print(f"{k:X}:")
                    for kk, vv in v.entries.items():
                        print(f"    {kk:X}: {vv}")
                        if args.values:
                            try:
                                r = await vv.read()
                            except EtherCatError as e:
                                print(f"        Error {e.args[0]}")
                            else:
                                if isinstance(r, int):
                                    print(f"        {r:10} {r:8X}")
                                else:
                                    print(f"        {r}")
                                    print(f"        {r!r}")
            if args.pdo:
                await t.to_operational(MachineState.PRE_OPERATIONAL)
                await t.parse_pdos()
                for (idx, subidx), (sm, pos, fmt) in t.pdos.items():
                    print(f"{idx:4X}:{subidx:02X} {sm.name} {pos} {fmt}")


def encode(name):
    r = int.from_bytes(sha1(name.encode("ascii")).digest(), "little")
    return r % 0xffffffff + 1

@entrypoint
async def eeprom():
    parser = ArgumentParser(
        prog = "ec-eeprom",
        description = "Read and write the eeprom")

    parser.add_argument("interface")
    parser.add_argument("-t", "--terminal", type=int)
    parser.add_argument("-r", "--read", action="store_true")
    parser.add_argument("-w", "--write", type=int)
    parser.add_argument("-n", "--name", type=str)
    parser.add_argument("-c", "--check", type=str)
    args = parser.parse_args()

    ec = EtherCat(args.interface)
    await ec.connect()

    if args.terminal is None:
        return

    t = Terminal(ec)
    await t.gentle_initialize(-args.terminal)

    if args.read or args.check is not None:
        r, = unpack("<4xI", await t._eeprom_read_one(0xc))
        if args.check is not None:
            c = encode(args.check)
            print(f"{r:8X} {c:8X} {r == c}")
        else:
            print(f"{r:8X} {r}")

    w = None
    if args.write is not None:
        w = args.write
    elif args.name is not None:
        w = encode(args.name)
        print(f"{w:8X} {w}")
    if w is not None:
        await t.eeprom_write_one(0xe, w & 0xffff)
        await t.eeprom_write_one(0xf, w >> 16)


@entrypoint
async def create_test():
    ec = EtherCat(sys.argv[1])
    await ec.connect()
    no = await ec.count()

    terminals = []

    for i in range(no):
        t = Terminal()
        t.ec = ec
        await t.initialize(-i)
        sdo = {}
        if t.has_mailbox():
            await t.to_operational(MachineState.PRE_OPERATIONAL)
            odlist = await t.read_ODlist()

            for k, v in odlist.items():
                for kk, vv in v.entries.items():
                    try:
                        ret = await t.sdo_read(v.index, vv.valueInfo)
                    except EtherCatError:
                        pass
                    sdo[v.index, vv.valueInfo] = ret

        ret = []
        for i in range(0, 0x400, 4):
            ret.append(await t._eeprom_read_one(i))
        eeprom = b"".join(ret).rstrip(b"\xff")
        terminals.append(dict(eeprom=eeprom, sdo=sdo))
    pp = PrettyPrinter(indent=4)
    pp.pprint(terminals)
