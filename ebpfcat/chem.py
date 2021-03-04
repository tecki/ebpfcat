# ebpfcat, A Python-based EBPF generator and EtherCAT master
# Copyright (C) 2021 Martin Teichmann <martin.teichmann@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

from asyncio import gather, sleep, ensure_future
from struct import unpack, pack
from .terminals import EL7041, EL5042, Skip
from .devices import Motor, Counter, AnalogInput
from .ebpfcat import FastEtherCat, FastSyncGroup, SyncGroup

con = Skip()
tm1 = EL7041()
te12 = EL5042()
tm2 = EL7041()

ec = FastEtherCat("enp0s31f6", [con, tm1, te12, tm2])


async def monitor(ec):
    while True:
        print("M", ec.ebpf.count, ec.ebpf.allcount, await tin.get_state())
        await sleep(0.1)


async def main():
    await ec.connect()
    await ec.scan_bus()
    #ensure_future(monitor(ec))

    print("S", await te12.set_state(2))
    for i in [1, 2, 3] + list(range(0x11, 0x19)):
        print(f"P{i:x}", await te12.sdo_read(0x8018, i))
    await te12.sdo_write(b"\0", 0x8018, 0x2)  # statusbits
    await te12.sdo_write(b"\0", 0x8018, 0x15)  # multi
    #await te12.sdo_write(b"\x1a", 0x8018, 0x16)  # singleturn
    await te12.sdo_write(b" ", 0x8018, 0x16)  # singleturn

    await tm2.set_state(2)
    await tm2.sdo_write(pack("<H", 2500), 0x8010, 0x1)  # current
    await tm2.sdo_write(pack("<H", 24000), 0x8010, 0x3)  # voltage

    for i in [1, 2, 3]:
        print(f"S{i:x}", await te12.sdo_read(0xB018, i))
    print(f"Pos", await te12.sdo_read(0x6010, 0x11))
    print(f"V", await te12.sdo_read(0xA018, 0x5))
    print(f"M", await te12.sdo_read(0x10F3, 0x6))
    print("State", await te12.get_state())

    print("S", await tm2.set_state(2))
    for i in [1,2,3,4,5,6,7,9,0x10,0x11]:
        print(f"M{i:x}", unpack("H", await tm2.sdo_read(0x8010, i))[0])


    m1 = Motor()
    m1.velocity = tm2.velocity
    m1.encoder = te12.channel2.position
    m1.enable = tm2.enable

    aie = AnalogInput(te12.channel2.status)
    aim = AnalogInput(tm2.status)

    fsg = SyncGroup(ec, [m1, aie, aim])

    m1.max_velocity = 10000
    m1.proportional = 23
    m1.target = 185525000

    print("do start")
    fsg.start()
    print("did start")

    print(f"P0", unpack("I", await tm2.sdo_read(0x6010, 0x14))[0])
    await sleep(0.1)
    m1.set_enable = True
    for i in range(20):
        print(f"M {m1.current_position:12} {m1.velocity:5} {aie.value:4x} {aim.value:4x}")
        await sleep(0.2)
    m1.set_enable = False
    m1.max_velocity = 0
    for i in range(20):
        print(f"S {m1.current_position:12} {aie.value:4x} {aim.value:4x}")
        await sleep(0.02)
    print(f"P1", unpack("I", await tm2.sdo_read(0x6010, 0x14))[0])

if __name__ == "__main__":
    from asyncio import get_event_loop
    loop = get_event_loop()
    loop.run_until_complete(main())
