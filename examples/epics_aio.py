import asyncio
import threading

from ebpfcat.ebpfcat import ParallelEtherCat, SyncGroup
from ebpfcat.devices import AnalogInput, AnalogOutput
from ebpfcat.terminals import EL4104, EL3164
from softioc import softioc, builder, asyncio_dispatcher

# Create an asyncio dispatcher, the event loop is now running
dispatcher = asyncio_dispatcher.AsyncioDispatcher()

# Set the record prefix
builder.SetDeviceName("MY-ETHERCAT-DEVICE")

def setter(param):
    def inner(value):
        setattr(*param, int(value))
    return inner

async def main():
    master = ParallelEtherCat("eth0")
    async with master.run():
        tout = EL4104(master)
        await tout.initialize(-58)
        tin = EL3164(master)
        await tin.initialize(-57)
        dao = AnalogOutput(tout.ch4_value)
        ao = builder.aOut('AO', initial_value=12.45, always_update=True,
                          on_update=setter(dao.value))
        dai = AnalogInput(tin.channel4.value)
        ai = builder.aIn('AI', initial_value=5)
        sg = SyncGroup(master, [dai, dao])
        task = sg.start()

        lock.release()  # this starts the IOC

        while True:
            ai.set(dai.value)
            await asyncio.sleep(0.1)

# run the main
lock = threading.Lock()
lock.acquire()
dispatcher(main)
lock.acquire()

# Boilerplate get the IOC started
builder.LoadDatabase()
softioc.iocInit(dispatcher)
softioc.non_interactive_ioc()
