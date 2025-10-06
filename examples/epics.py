import asyncio
import threading

from ebpfcat.ebpfcat import ParallelEtherCat, SyncGroup
from ebpfcat.devices import AnalogInput, AnalogOutput
from ebpfcat.terminals import EL4104, EL3164
from softioc import softioc, builder, asyncio_dispatcher

def setter(param):
    def inner(value):
        setattr(*param, int(value))
    return inner

def start_ethercat_ioc(main):
    # Create an asyncio dispatcher, the event loop is now running
    dispatcher = asyncio_dispatcher.AsyncioDispatcher()

    # run the main
    lock = threading.Lock()
    lock.acquire()
    dispatcher(main, (lock.release,))
    lock.acquire()

    # Boilerplate get the IOC started
    builder.LoadDatabase()
    softioc.iocInit(dispatcher)
    softioc.non_interactive_ioc()
