"""\
:mod:`!ebpfcat.examples.epics_aio` --- A simple analog input/output example
===========================================================================

This shows how to write an EPICS IOC that can read from an analog input and
write to an analog output. Note that this is just an example file, it needs
to be adopted to your hardware configuration.
"""
import asyncio

from ebpfcat.ebpfcat import ParallelEtherCat, SyncGroup
from ebpfcat.devices import AnalogInput, AnalogOutput
from ebpfcat.terminals import EL4104, EL3164
from softioc import builder

from .epics import setter, start_ethercat_ioc


async def main(start_ioc):
    # tell which ethernet port to use
    master = ParallelEtherCat("eth0")
    async with master.run():
        # define the hardware layout, we declare two terminals
        tout = EL4104(master)
        await tout.initialize(-58)  # -58 is the negative position on the bus
        tin = EL3164(master)
        await tin.initialize(-57)

        builder.SetDeviceName("MY-ETHERCAT-DEVICE")

        dao = AnalogOutput(tout.ch4_value)  # use channel 4 on the output
        # connect the output to an EPICS PV
        ao = builder.aOut('AO', initial_value=12.45, always_update=True,
                          on_update=setter(dao.value))
        dai = AnalogInput(tin.channel4.value)  # use channel 4 on the input
        ai = builder.aIn('AI', initial_value=5)

        # combine input and output into one sync group
        sg = SyncGroup(master, [dai, dao])
        task = sg.start()

        # at this point, all EPICS PVs are defined, we can start the IOC
        start_ioc()

        # in an endless loop, copy over the inputs to EPICS
        while True:
            ai.set(dai.value)
            await asyncio.sleep(0.1)


if __name__ == '__main__':
    start_ethercat_ioc(main)
