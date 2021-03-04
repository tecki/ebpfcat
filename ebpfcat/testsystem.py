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
from .terminals import EL3164, EL4104, EK1814
from .devices import AnalogInput, AnalogOutput, DigitalInput, DigitalOutput
from .ebpfcat import FastEtherCat, FastSyncGroup, SyncGroup

tdigi = EK1814()
tout = EL4104()
tin = EL3164()

ec = FastEtherCat("eth0", [tdigi, tin, tout])


async def monitor(ec):
    while True:
        print("M", ec.ebpf.count, ec.ebpf.allcount, await tin.get_state())
        await sleep(0.1)


async def main():
    await ec.connect()
    await ec.scan_bus()
    #ensure_future(monitor(ec))

    ai = AnalogInput(tin.ch1_value)
    ao = AnalogOutput(tout.ch1_value)
    di = DigitalInput(tdigi.ch1)
    do = DigitalOutput(tdigi.ch8)
    #fsg = FastSyncGroup(ec, [ai, ao])
    fsg = SyncGroup(ec, [ai, ao, do, di])

    fsg.start()
    ao.value = 0
    do.value = False

    for i in range(100):
        await sleep(0.1)
        #fsg.properties.read()
        ao.value = 300 * i
        do.value = (i % 7) in (0, 1, 2, 5)
        #fsg.properties.write()
        print(i, ai.value, ao.value, di.value, await tout.get_state())

if __name__ == "__main__":
    from asyncio import get_event_loop
    loop = get_event_loop()
    loop.run_until_complete(main())
