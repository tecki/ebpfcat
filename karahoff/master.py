from asyncio import gather, sleep, Event, get_event_loop
from itertools import chain
from struct import pack, unpack

from karabo.middlelayer import (
    Device, getDevice, String, AccessMode, VectorString, Slot, State,
    waitUntil, Float, background, Simple, isSet, VectorHash, Assignment)
from karabo import middlelayer as ml

from ebpfcat.ethercat import EEPROM, EtherCatError, SyncManager
from ebpfcat.ebpfcat import (
    SimpleEtherCat, SyncGroup, FastSyncGroup, FastEtherCat, Struct)
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
    ml.Bool: '?',
}


class TerminalUnknownError(KeyError):
    pass


class TerminalTable(ml.Configurable):
    name = ml.String()
    classId = ml.String()
    serialNo = ml.Int64()
    vendorId = ml.Int32(displayType='hex')
    productCode = ml.Int32(displayType='hex')


class CoETable(ml.Configurable):
    index = ml.UInt16(displayType='hex')
    subIndex = ml.UInt8(displayType='hex')
    format = ml.String()
    value = ml.Int64()


class EtherCATMasterBase(Device):
    instances = {}
    terminalsInitializingCount = 0

    interface = String(accessMode=AccessMode.INITONLY,
                       assignment=Assignment.MANDATORY)

    async def onInitialization(self):
        #loop = get_event_loop()
        #loop.set_debug(True)
        #loop.slow_callback_duration = 0.01
        self.terminalsInitialized = Event()
        self.instances[self.deviceId] = self
        self.addr_by_serial = {}
        self.term_by_name = {}

        self.ethercat = self.EtherCat(self.interface)
        await self.ethercat.connect()
        self.state = State.INIT
        await self.scanBus()
        self.state = State.ON

    async def init_one_terminal(self, i):
        address = await self.ethercat.assigned_address(i)
        serialNo = await self.ethercat.eeprom_read(i, EEPROM.SERIAL_NO)
        old = self.addr_by_serial.get(serialNo)
        if old is not None and old != address:
            self.status = 'double serial number found'
            self.state = State.ERROR
        if serialNo > 0:
            self.addr_by_serial[serialNo] = address
        else:
            self.addr_by_serial[i] = address

    @Slot()
    async def scanBus(self):
        count = await self.ethercat.count()
        self.status = f"counted {count} terminals"
        await gather(*(self.init_one_terminal(-i) for i in range(count)))


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
        self.status = 'master is ON'
        self.devs = [EtherCATDevice.instances[d] for d in self.devices]
        self.status = "waiting for devices to join"
        if self.ethercat.terminalsInitializingCount != 0:
            await self.ethercat.terminalsInitialized.wait()
        while True:
            try:
                await gather(*[d.join(self) for d in self.devs])
                break
            except TerminalUnknownError as e:
                self.status = f"Terminal {e.args[0]} missing"
            await self.ethercat.terminalsInitialized.wait()
        self.status = "ready"
        self.syncGroup = self.SyncGroup(
            self.ethercat.ethercat,
            list(chain.from_iterable(d.get_devices() for d in self.devs)))
        for d in self.devs:
            d.initialize()
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

    def set_state(self, state, status=None):
        if state != self.state or (status is not None
                                   and status != self.status):
            self.state = state
            self.status = status
        self.state_change.set()
        self.state_change.clear()

    def find_channel(self, name):
        terminal, *channel = name.split(".")
        ret = self.ethercat.term_by_name.get(terminal)
        if ret is None:
            raise TerminalUnknownError(name)
        for c in channel:
            ret = getattr(ret, c)
        return ret

    def update_properties(self):
        pass

    async def join(self, syncGroup):
        """Let this device join a sync group"""
        self.syncGroup = syncGroup
        self.ethercat = syncGroup.ethercat

    def initialize(self):
        """called once everything is set up"""
        return


class EtherCATTerminal(Device):
    """Base class for Karabo devices representing a single terminal"""
    master = String(accessMode=AccessMode.INITONLY,
                    assignment=Assignment.MANDATORY)
    vendorId = ml.Int32(accessMode=AccessMode.READONLY)
    productCode = ml.Int32(accessMode=AccessMode.READONLY)
    revisionNo = ml.Int32(accessMode=AccessMode.READONLY)
    serialNumber = ml.Int32(accessMode=AccessMode.INITONLY,
                            assignment=Assignment.MANDATORY)
    coe = VectorHash(accessMode=AccessMode.INITONLY, rows=CoETable,
                     defaultValue=[])
    terminal = None

    async def onInitialization(self):
        self.status = "waiting for master"
        master = await getDevice(self.master)
        self.ethercat = EtherCATMaster.instances[self.master]
        self.ethercat.terminalsInitializingCount += 1
        self.terminal = self.Base(self.ethercat.ethercat)

        await self.terminal.initialize(
            absolute=self.ethercat.addr_by_serial[self.serialNumber.value])
        self.vendorId = self.terminal.vendorId
        self.productCode = self.terminal.productCode
        self.revisionNo = self.terminal.revisionNo
        self.state = State.INIT
        await self.terminal.parse_sdos()

        for k in self._sdo_attrs:
            v = getattr(self, k)
            if isSet(v):
                setattr(self, k, v)
            else:
                entry = self.terminal
                for kk in getattr(self.__class__, k).alias.split('.'):
                    entry = getattr(entry, kk)
                setattr(self, k, await entry.read())

        new_coes = []
        for coe in self.coe:
            await self.terminal.sdo_write(
                pack(coe['format'], coe['value']),
                coe['index'], coe['subIndex'])
            ret = await self.terminal.sdo_read(coe['index'], coe['subIndex'])
            new_coes.append((coe['index'], coe['subIndex'], coe['format'],
                             unpack(coe['format'], ret)[0]))
        self.coe = new_coes

        self.ethercat.term_by_name[self.deviceId.split('/')[-1]] = self.terminal
        self.ethercat.terminalsInitializingCount -= 1
        if self.ethercat.terminalsInitializingCount == 0:
            self.ethercat.terminalsInitialized.set()
        self.state = State.ON
        self.status = 'ready'

    @classmethod
    def sdo_setter(cls, attr):
        keys = attr.alias.split('.')

        async def setter(self, value):
            if self.terminal is None:
                return
            entry = self.terminal
            for k in keys:
                entry = getattr(entry, k)
            await entry.write(value)
            setattr(self, attr.key, await entry.read())

        return setter

    @classmethod
    def register(cls, name, dct):
        super(EtherCATTerminal, cls).register(name, dct)
        cls._sdo_attrs = []
        for name in cls._allattrs:
            attr = getattr(cls, name)
            if isinstance(attr, (Simple, ml.Bool)) and attr.alias is not None:
                attr(cls.sdo_setter(attr))
                cls._sdo_attrs.append(name)
