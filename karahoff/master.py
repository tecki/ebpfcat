from asyncio import gather, sleep, Event, get_event_loop
from itertools import chain
from struct import pack, unpack

from karabo.middlelayer import (
    Device, getDevice, String, AccessMode, VectorString, Slot, State,
    waitUntil, Float, background, Simple, isSet, VectorHash, Assignment)
from karabo import middlelayer as ml

from ebpfcat.ethercat import EEPROM, EtherCatError
from ebpfcat.ebpfcat import SimpleEtherCat, SyncGroup, FastSyncGroup, FastEtherCat, Struct
from ebpfcat import terminals, devices


formats = {
    ml.UInt8: 'B',
    ml.Int8: 'b',
    ml.UInt16: 'H',
    ml.Int16: 'h',
    ml.UInt32: 'I',
    ml.Int32: 'i',
    ml.UInt64: 'Q',
    ml.Int64: 'q',
    ml.Float: 'f',
    ml.Double: 'd',
}


class TerminalTable(ml.Configurable):
    name = ml.String()
    classId = ml.String()
    serialNo = ml.Int64()
    vendorId = ml.Int32(displayType='hex')
    productCode = ml.Int32(displayType='hex')


class EtherCATMasterBase(Device):
    instances = {}

    interface = String(accessMode=AccessMode.INITONLY,
                       assignment=Assignment.MANDATORY)
    terminals = VectorHash(accessMode=AccessMode.INITONLY, rows=TerminalTable)


    async def onInitialization(self):
        #loop = get_event_loop()
        #loop.set_debug(True)
        #loop.slow_callback_duration = 0.01
        self.instances[self.deviceId] = self

        term_by_serial = {row['serialNo'].value: row for row in self.terminals}
        self.ethercat = self.EtherCat(self.interface)
        await self.ethercat.connect()
        self.state = State.INIT
        count = await self.ethercat.count()
        self.status = f"counted {count} terminals"
        terms = []
        self.term_by_name = {}
        for i in range(count):
            serialNo = await self.ethercat.eeprom_read(-i, EEPROM.SERIAL_NO)
            if serialNo == 0:
                serialNo = -i
            term = term_by_serial.get(serialNo)
            vendor = await self.ethercat.eeprom_read(-i, EEPROM.VENDOR_ID)
            code = await self.ethercat.eeprom_read(-i, EEPROM.PRODUCT_CODE)
            if term is None:
                terms.append(("", "", serialNo, vendor, code))
            else:
                t = getattr(terminals, term['classId'], terminals.Generic)(self.ethercat)
                position = await self.ethercat.find_free_address()
                try:
                    await t.initialize(-i, position)
                except EtherCatError:
                    terms.append(
                        (term['name'], "Error", term['serialNo'],
                         vendor, code))
                else:
                    terms.append(
                        (term['name'], t.__class__.__name__, term['serialNo'],
                         vendor, code))
                    self.term_by_name[term['name']] = t
        self.terminals = terms
        self.state = State.ON


class EtherCATMaster(EtherCATMasterBase):
    EtherCat = SimpleEtherCat


class FastEtherCATMaster(EtherCATMasterBase):
    EtherCat = FastEtherCat


class EtherCATSyncGroupBase(Device):
    master = String(accessMode=AccessMode.INITONLY)
    devices = VectorString(accessMode=AccessMode.INITONLY)
    interval = Float(defaultValue=0.05)


    async def onInitialization(self):
        self.status = "waiting for master"
        master = await getDevice(self.master)
        self.ethercat = EtherCATMaster.instances[self.master]
        self.status = "waiting for devices"
        devs = await gather(*[getDevice(d) for d in self.devices])
        self.status = "waiting for master to go to ON state"
        with master:
            await waitUntil(lambda: master.state == State.ON)
        self.devs = [EtherCATDevice.instances[d] for d in self.devices]
        self.status = "waiting for devices to join"
        await gather(*[d.join(self) for d in self.devs])
        self.status = "ready"
        self.syncGroup = self.SyncGroup(
            self.ethercat.ethercat,
            list(chain.from_iterable(d.get_devices() for d in self.devs)))
        self.state = State.OFF
        self.syncGroup.start()
        self.state = State.ON
        background(self.run())

    async def run(self):
        try:
            self.state = State.RUNNING

            while not self.syncGroup.task.done():
                if self.syncGroup.current_data is not None:
                    for d in self.devs:
                        d.update_properties()
                        await sleep(0)
                await sleep(self.interval.value)
            self.syncGroup.task.result()  # raises error if problem
        except Exception as e:
            self.status = str(e)
            raise
        finally:
            self.state = State.ERROR


class EtherCATSyncGroup(EtherCATSyncGroupBase):
    SyncGroup = SyncGroup


class FastEtherCATSyncGroup(EtherCATSyncGroupBase):
    SyncGroup = FastSyncGroup


class EtherCATDevice(Device):
    instances = {}
    terminals = None

    def __init__(self, configuration):
        super().__init__(configuration)
        self.instances[self.deviceId] = self
        self.state_change = Event()

    def get_devices(self):
        return (self.device,)

    def set_state(self, state):
        if state != self.state:
            self.state = state
        self.state_change.set()
        self.state_change.clear()

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
                state, error = await term.get_state()
                if state < 2:
                    await term.set_state(2)
                await term.sdo_write(pack(formats[type(attr)], value),
                                     idx, attr.subidx)
                ret = await term.sdo_read(idx, attr.subidx)
                setattr(self, attr.key, *unpack(formats[type(attr)], ret))
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
                state, error = await term.get_state()
                if state < 2:
                    await term.set_state(2)
                ret = await term.sdo_read(idx, attr.subidx)
                setattr(self, attr.key, *unpack(formats[type(attr)], ret))

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

    async def join(self, syncGroup):
        """Let this device join a sync group"""
        self.syncGroup = syncGroup
        self.ethercat = syncGroup.ethercat
