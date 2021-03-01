from asyncio import gather, sleep, Event
from struct import pack, unpack

from karabo.middlelayer import (
    Device, getDevice, String, AccessMode, VectorString, Slot, State,
    waitUntil, Float, background, Simple, isSet)

from ebpfcat.ebpfcat import SimpleEtherCat, SyncGroup, FastSyncGroup, FastEtherCat, Struct
from ebpfcat import terminals, devices


class EtherCATMasterBase(Device):
    instances = {}

    interface = String(accessMode=AccessMode.INITONLY)
    terminals = VectorString(accessMode=AccessMode.INITONLY)
    names = VectorString(accessMode=AccessMode.INITONLY)


    async def onInitialization(self):
        self.instances[self.deviceId] = self
        terms = [getattr(terminals, t, terminals.Generic)
                 for t in self.terminals]
        self.terminals = [t.__name__ for t in terms]
        self.the_terminals = [t() for t in terms]
        for t, n in zip(self.the_terminals, self.names):
            t.name = n
        self.term_by_name = {k: v for k, v in
                             zip(self.names, self.the_terminals)}
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
                self.syncGroup.properties.readwrite()
                for d in self.devs:
                    d.update_properties()
                await sleep(self.interval)
        finally:
            self.state = State.ERROR


class EtherCATDevice(Device):
    instances = {}
    terminals = None

    def __init__(self, configuration):
        super().__init__(configuration)
        self.instances[self.deviceId] = self

    @classmethod
    def sdo_setter(cls, attr):
        term, idx, subidx = attr.alias.split(':')
        attr.idx = int(idx, 16)
        attr.subidx = int(subidx, 16)
        attr.terminal = term

        async def setter(self, value):
            if self.terminals is None:
                setattr(self, attr.key, value)
            else:
                term = self.terminals[attr.terminal]
                if isinstance(term, Struct):
                    idx = attr.idx + term.position_offset[2]
                    term = term.terminal
                else:
                    idx = attr.idx
                state = await term.get_state()
                if state < 2:
                    await term.set_state(2)
                await term.sdo_write(pack(attr.format, value),
                                     idx, attr.subidx)
                ret = await term.sdo_read(idx, attr.subidx)
                setattr(self, attr.key, *unpack(attr.format, ret))
        return setter

    async def sdo_set(self):
        for attr in self._sdo_attrs:
            val = getattr(self, attr.key)
            if isSet(val):
                await attr.setter(self, val)
            else:
                term = self.terminals[attr.terminal]
                if isinstance(term, Struct):
                    idx = attr.idx + term.position_offset[2]
                    term = term.terminal
                else:
                    idx = attr.idx
                print("get state")
                state = await term.get_state()
                if state < 2:
                    await term.set_state(2)
                print("set state")
                ret = await term.sdo_read(idx, attr.subidx)
                setattr(self, attr.key, *unpack(attr.format, ret))

    @classmethod
    def register(cls, name, dct):
        super(EtherCATDevice, cls).register(name, dct)
        cls._sdo_attrs = []
        for name in cls._allattrs:
            attr = getattr(cls, name)
            if isinstance(attr, Simple) and attr.alias is not None:
                attr(cls.sdo_setter(attr))
                cls._sdo_attrs.append(attr)

    def find_channel(self, name):
        terminal, *channel = name.split(".")
        ret = self.ethercat.term_by_name[terminal]
        for c in channel:
            ret = getattr(ret, c)
        return ret

    def update_properties(self):
        pass
