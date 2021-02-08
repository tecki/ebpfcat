from asyncio import gather, sleep, ensure_future
from .terminals import EL3164, EL4104, Generic
from .devices import AnalogInput, AnalogOutput
from .ebpfcat import FastEtherCat, FastSyncGroup, SyncGroup

tdigi = Generic()
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
    #fsg = FastSyncGroup(ec, [ai])
    fsg = SyncGroup(ec, [ai, ao])

    ao.value = 0

    fsg.start()

    for i in range(10):
        await sleep(0.1)
        #fsg.properties.read()
        ao.value = 3000 * i
        print(i, ai.value, ao.data, await tout.get_state())

if __name__ == "__main__":
    from asyncio import get_event_loop
    loop = get_event_loop()
    loop.run_until_complete(main())
