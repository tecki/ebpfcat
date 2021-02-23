from asyncio import gather, sleep, Event
from karabo.middlelayer import (
    Device, getDevice, String, AccessMode, VectorString, Slot, State,
    waitUntil, Float, background)

from ebpfcat.ebpfcat import SimpleEtherCat, SyncGroup, FastSyncGroup, FastEtherCat
from ebpfcat import terminals, devices


class EtherCATMasterBase(Device):
    instances = {}

    interface = String(accessMode=AccessMode.INITONLY)
    terminals = VectorString(accessMode=AccessMode.INITONLY)


    async def onInitialization(self):
        self.instances[self.deviceId] = self
        terms = [getattr(terminals, t, terminals.Generic)
                 for t in self.terminals]
        self.terminals = [t.__name__ for t in terms]
        self.the_terminals = [t() for t in terms]
        self.ethercat = self.EtherCat(self.interface, self.the_terminals)
        await self.ethercat.connect()
        self.state = State.INIT
        await self.ethercat.scan_bus()
        self.state = State.ON


class EtherCATMaster(EtherCATMasterBase):
    EtherCat = SimpleEtherCat


class FastEtherCATMaster(EtherCATMasterBase):
    EtherCat = FastEtherCat


class EtherCATSyncGroupBase(Device):
    master = String(accessMode=AccessMode.INITONLY)
    devices = VectorString(accessMode=AccessMode.INITONLY)

    async def onInitialization(self):
        self.status = "waiting for master"
        master = await getDevice(self.master)
        self.ethercat = EtherCATMaster.instances[self.master]
        self.status = "waiting for devices"
        devs = await gather(*[getDevice(d) for d in self.devices])
        with master:
            await waitUntil(lambda: master.state == State.ON)
        self.devs = [EtherCATDevice.instances[d] for d in self.devices]
        for d in self.devs:
            d.syncGroup = self
            d.ethercat = self.ethercat
        self.status = "waiting for devices to join"
        await gather(*[d.join() for d in devs])
        self.status = "ready"

    @Slot(allowedStates={State.OFF})
    async def start(self):
        self.syncGroup.start()
        self.state = State.RUNNING


class EtherCATSyncGroup(EtherCATSyncGroupBase):
    async def onInitialization(self):
        await super().onInitialization()
        self.syncGroup = SyncGroup(self.ethercat.ethercat,
                                   [d.device for d in self.devs])
        self.state = State.OFF


class FastEtherCATSyncGroup(EtherCATSyncGroupBase):
    interval = Float(defaultValue=0.05)

    async def onInitialization(self):
        await super().onInitialization()
        devices = [EtherCATDevice.instances[d] for d in self.devices]
        self.syncGroup = FastSyncGroup(self.ethercat.ethercat,
                                       [d.device for d in self.devs])
        self.state = State.OFF

    @Slot(allowedStates={State.OFF})
    async def start(self):
        self.syncGroup.start()
        self.state = State.ON
        background(self.run())

    async def run(self):
        try:
            self.state = State.RUNNING

            while True:
                self.syncGroup.properties.read()
                await sleep(self.interval)
                for d in self.devs:
                    d.update_properties()
                self.syncGroup.properties.write()
        finally:
            self.state = State.ERROR


class EtherCATDevice(Device):
    instances = {}

    def __init__(self, configuration):
        super().__init__(configuration)
        self.instances[self.deviceId] = self

    def find_channel(self, name):
        terminal, *channel = name.split(".")
        ret = self.ethercat.the_terminals[int(terminal)]
        for c in channel:
            ret = getattr(ret, c)
        return ret

    def update_properties(self):
        pass
