from argparse import ArgumentParser
import asyncio
from functools import wraps
from struct import unpack
import sys

from .ethercat import EtherCat, Terminal, ECCmd

def entrypoint(func):
    @wraps(func)
    def wrapper():
        asyncio.run(func())
    return wrapper


@entrypoint
async def scanbus():
    ec = EtherCat(sys.argv[1])
    await ec.connect()
    no = await ec.count()
    for i in range(no):
        r, = await ec.roundtrip(ECCmd.APRD, -i, 0x10, "H", 44)
        print(i, r)

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
    args = parser.parse_args()

    ec = EtherCat(args.interface)
    await ec.connect()

    if args.terminal is None:
        terminals = range(await ec.count())
    else:
#        print(await ec.roundtrip(ECCmd.FPRW, 7, 0x10, "H", 0))
        terminals = [args.terminal]

    terms = [Terminal() for t in terminals]
    for t in terms:
        t.ec = ec
    await asyncio.gather(*(t.initialize(-i, i + 7)
                           for i, t in zip(terminals, terms)))

    for i, t in enumerate(terms):
        print(f"terminal no {i}")
        if args.ids:
            print(f"{t.vendorId:X}:{t.productCode:X} "
                  f"revision {t.revisionNo:X} serial {t.serialNo}")
        if args.names:
            infos = t.eeprom[10]
            i = 1
            while i < len(infos):
                print(infos[i+1 : i+infos[i]+1].decode("ascii"))
                i += infos[i] + 1

        if args.sdo:
            await t.to_operational()
            ret = await t.read_ODlist()
            for k, v in ret.items():
                print(f"{k:X}:")
                for kk, vv in v.entries.items():
                     print(f"    {kk:X}: {vv}")
                     if args.values:
                         r = await vv.read()
                         if isinstance(r, int):
                             print(f"        {r:10} {r:8X}")
                         else:
                             print(f"        {r}")
