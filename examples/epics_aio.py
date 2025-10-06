import asyncio

from ebpfcat.ebpfcat import ParallelEtherCat, SyncGroup
from ebpfcat.devices import AnalogInput, AnalogOutput
from ebpfcat.terminals import EL4104, EL3164
from softioc import softioc, builder, asyncio_dispatcher

# Create an asyncio dispatcher, the event loop is now running
dispatcher = asyncio_dispatcher.AsyncioDispatcher()

# Set the record prefix
builder.SetDeviceName("MY-ETHERCAT-DEVICE")

dao = None

def updater(value):
    if dao is not None:
        dao.value = int(value)

# Create some records
ai = builder.aIn('AI', initial_value=5)
ao = builder.aOut('AO', initial_value=12.45, always_update=True,
                  on_update=updater)

# Boilerplate get the IOC started
builder.LoadDatabase()
softioc.iocInit(dispatcher)

async def main():
    master = ParallelEtherCat("eth0")
    async with master.run():
        tout = EL4104(master)
        await tout.initialize(-58)
        tin = EL3164(master)
        await tin.initialize(-57)
        global dao
        dao = AnalogOutput(tout.ch4_value)
        dai = AnalogInput(tin.channel4.value)
        sg = SyncGroup(master, [dai, dao])
        task = sg.start()
        print('DONE')
        while True:
            ai.set(dai.value)
            await asyncio.sleep(0.1)

dispatcher(main)

softioc.non_interactive_ioc()
