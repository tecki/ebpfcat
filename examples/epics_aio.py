import asyncio

from ebpfcat.ebpfcat import ParallelEtherCat, SyncGroup
from ebpfcat.devices import AnalogInput, AnalogOutput
from ebpfcat.terminals import EL4104, EL3164
from softioc import builder

from .epics import setter, start_ethercat_ioc


async def main(start_ioc):
    master = ParallelEtherCat("eth0")
    async with master.run():
        tout = EL4104(master)
        await tout.initialize(-58)
        tin = EL3164(master)
        await tin.initialize(-57)

        builder.SetDeviceName("MY-ETHERCAT-DEVICE")

        dao = AnalogOutput(tout.ch4_value)
        ao = builder.aOut('AO', initial_value=12.45, always_update=True,
                          on_update=setter(dao.value))
        dai = AnalogInput(tin.channel4.value)
        ai = builder.aIn('AI', initial_value=5)

        sg = SyncGroup(master, [dai, dao])
        task = sg.start()

        start_ioc()

        while True:
            ai.set(dai.value)
            await asyncio.sleep(0.1)


if __name__ == '__main__':
    start_ethercat_ioc(main)
