"""run an EtherCAT EPICS IOC

this is a minimal library to create an EPICS IOC for EtherCAT loops.
"""
import threading

from softioc import softioc, builder, asyncio_dispatcher


def setter(param):
    """a generic setter to be used with OUT records

    in order to connect an OUT record to an EtherCAT device paramter,
    one can write::

        builder.aOut('OUT', on_update=setter(device.value))

    where `device` is an EtherCAT device.
    """
    def inner(value):
        setattr(*param, int(value))
    return inner

def start_ethercat_ioc(main):
    """execute the main coroutine for the EtherCAT IOC

    This is supposed to be called from the main module, in the
    canonical way::

        if __name__ == '__main__':
            start_ethercat_ioc(main)

    the `async` function `main` is then called with one paramter,
    usually called `start_ioc`, which should be called by `main` once
    it is done setting up the IOC, and would like to start the
    actually control loop.
    """
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
