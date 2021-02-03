from asyncio import gather, sleep, ensure_future
from .terminals import EL3164, Generic
from .devices import AnalogInput
from .ebpfcat import FastEtherCat, FastSyncGroup, SyncGroup

tdigi = Generic()
tout = Generic()
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
    fsg = FastSyncGroup(ec, [ai])
    #fsg = SyncGroup(ec, [ai])

    fsg.start()

    for i in range(10):
        await sleep(0.1)
        fsg.properties.read()
        print(i, ai.value, ec.ebpf.count, ec.ebpf.allcount)

if __name__ == "__main__":
    from asyncio import get_event_loop
    loop = get_event_loop()
    loop.run_until_complete(main())
