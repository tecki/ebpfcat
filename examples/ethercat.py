"""A simple example of an EtherCat control

this is only an illustrative example to be read. It will not work unless
you happen to have an EtherCat setup where a Beckhoff EL4101 terminal is
the second terminal in the line.
"""
import asyncio
from ebpfcat.ebpfcat import FastEtherCat, SyncGroup
from ebpfcat.devices import AnalogOutput
from ebpfcat.terminals import EL4104


async def main():
    master = FastEtherCat("eth0")
    await master.connect()
    print("Number of terminals:", await master.count())
    out = EL4104(master)
    await out.initialize(-2, 20)
    ao = AnalogOutput(out.ch2_value)  # use channel 1 of terminal "out"
    sg = SyncGroup(master, [ao])  # this sync group only contains one terminal
    task = sg.start()  # start operating the terminals
    for i in range(10):
        # we would measure an increasing value on the terminal output
        ao.value = i
        await asyncio.sleep(0.1)

    task.cancel()  # stop the sync group

asyncio.run(main())
