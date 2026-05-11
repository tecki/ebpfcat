"""
The core of KaraHoff
--------------------

These are the core devices that need to run an EtherCAT loop:

.. autoclass:: EtherCATMaster()
    :members:

.. autoclass:: FastEtherCATSyncGroup()
    :members:

.. autoclass:: ProcessEtherCATSyncGroup()
    :members:

Base clases
-----------

If you want to extend KaraHoff by writing your own devices or
terminals, these are the base classes to inherit from:

.. autoclass:: EtherCATDevice()
    :members:

"""
import logging
from asyncio import CancelledError, Event, gather, get_event_loop, sleep
from contextlib import AsyncExitStack
from itertools import chain
from struct import pack, unpack

from ebpfcat import devices, terminals
from ebpfcat.ebpfcat import (
    FastSyncGroup, ParallelEtherCat, ProcessSyncGroup, Struct,
    SyncGroup, Terminal)
from ebpfcat.ethercat import EEPROM, EtherCatError, MachineState, SyncManager
from karabo import middlelayer as ml
from karabo.middlelayer import (
    AccessMode, Assignment, Bool, Configurable, Device, Double, Float, Int64,
    MetricPrefix, Simple, Slot, State, String, Unit, VectorHash, VectorInt64,
    VectorString, background, getDevice, isSet, unit, waitUntil)

logger = logging.getLogger('ebpfcat')
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
logger.addHandler(handler)

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
    comment = ml.String()
    format = ml.String()
    value = ml.Int64()


class EtherCATMaster(Device):
    """A device to keep up the connection to the bus

    This device holds the connection to the EtherCAT bus. This means
    only housekeeping tasks, the actual heavy lifting is done in the
    sync groups. There should only be one master per device server.
    There may be more than one master and device server per EtherCAT
    loop, as long as they do not use the same terminals both.

    Upon instantiation, the master will read out all the serial numbers
    from the terminals, which we usually set to the QR code number
    unless they already have another one. For terminals which do not
    have a serial number yet, one may be written with
    :meth:`writeSerial`.
    """
    instances = {}
    terminalsInitializingCount = 0

    interface = String(accessMode=AccessMode.INITONLY,
                       assignment=Assignment.MANDATORY)
    serialNumbers = VectorInt64(
        accessMode=AccessMode.READONLY, displayedName='Serial Numbers',
        description="""The serial numbers of the termials in the order
        they have been found on the bus. Negative numbers indicate that
        no serial number has been set for this terminal.""")

    targetTerminal = Int64(
        displayedName='Target Terminal',
        description="""The serial number of the terminal to be used for
        other commands, or a negative number for the number on the bus""")
    targetSerial = ml.UInt32(displayedName='Target Serial Number',
                             description='The serial number to write')
    information = String(accessMode=AccessMode.READONLY,
                         description='The information read from the terminal')

    def __init__(self, configuration):
        super().__init__(configuration)
        self.terminalsInitialized = Event()
        self.addr_by_serial = {}
        self.term_by_name = {}
        self.term_by_addr = {}

    async def onInitialization(self):
        self.instances[self.deviceId] = self

        self.ethercat = ParallelEtherCat(self.interface.value)
        async with AsyncExitStack() as exitStack:
            await exitStack.enter_async_context(self.ethercat.run())
            self.state = State.INIT
            self.status = "trying to scan the bus..."
            await self.scanBus()
            self.state = State.ON
            self.status = "bus scanned"
            self.exitStack = exitStack.pop_all()

    async def onDestruction(self):
        async with self.exitStack:
            pass

    async def init_one_terminal(self, i):
        address = await self.ethercat.assigned_address(i)
        serialNo = await self.ethercat.eeprom_read(i, EEPROM.SERIAL_NO)
        if serialNo > 0:
            old = self.addr_by_serial.get(serialNo)
            if old is not None and old != address:
                status = f'double serial number found: {serialNo} at {i}'
                self.status = status
                self.logger.error(status)
                self.state = State.ERROR
            else:
                self.addr_by_serial[serialNo] = address
                return serialNo
        self.addr_by_serial[i] = address
        return i

    @Slot(displayedName='Scan Bus')
    async def scanBus(self):
        """Scan the bus and read the terminal serial numbers"""
        count = await self.ethercat.count()
        self.status = f"counted {count} terminals"
        self.serialNumbers = \
            await gather(*(self.init_one_terminal(-i) for i in range(count)))

    async def getTerminal(self):
        address = self.addr_by_serial[self.targetTerminal.value]
        term = self.term_by_addr.get(address)
        if term is None:
            term = Terminal(self.ethercat)
            await term.initialize(absolute=address)
        return term

    @Slot(displayedName='Get Information')
    async def getInfo(self):
        """get information about the targetTerminal"""
        term = await self.getTerminal()
        infos = term.eeprom[10]
        i = 1
        ret = []
        while i < len(infos):
            ret.append(infos[i+1 : i+infos[i]+1].decode("latin1"))
            i += infos[i] + 1
        self.information = '\n'.join(ret)

    @Slot(displayedName='Write Serial Number')
    async def writeSerial(self):
        """write the serial number to the EEPROM of the terminal"""
        term = await self.getTerminal()
        await term.eeprom_write_one(0xe, self.targetSerial.value & 0xffff)
        await term.eeprom_write_one(0xf, self.targetSerial.value >> 16)


class EtherCATSyncGroupBase(Device):
    master = String(accessMode=AccessMode.INITONLY)
    devices = VectorString(accessMode=AccessMode.INITONLY)
    interval = Double(defaultValue=0.05)
    cycletime = Double(accessMode=AccessMode.INITONLY, defaultValue=10,
                       unitSymbol=Unit.SECOND,
                       metricPrefixSymbol=MetricPrefix.MILLI)
    debug = Bool(accessMode=AccessMode.INITONLY, defaultValue=False)
    max_wkc_errors = ml.UInt32(
        displayedName='Working Counter Error Limit',
        description='Stop the sync group in case of that many WKC errors',
        defaultValue=5)
    task = None

    async def onInitialization(self):
        self.status = "waiting for master"
        master = await getDevice(self.master)
        assert master.serverId == self.serverId, f'server {master.serverId}'
        self.ethercat = self.getLocalDevice(self.master)
        assert isinstance(self.ethercat, EtherCATMaster)
        self.status = "waiting for devices"
        devs = await gather(*[getDevice(d) for d in self.devices])
        for d in devs:
            assert d.serverId == self.serverId, f'{d.deviceId} on {d.serverId}'
        self.status = "waiting for master to go to ON state"
        with master:
            await waitUntil(lambda: master.state == State.ON)
        self.status = 'master is ON'
        self.devs = [self.getLocalDevice(d) for d in self.devices]
        self.status = "waiting for devices to join"
        if self.ethercat.terminalsInitializingCount != 0:
            await self.ethercat.terminalsInitialized.wait()
        for d in self.devs:
            d.status = f'joining {self.deviceId}'
        while True:
            try:
                for d in self.devs:
                    try:
                        d.join(self)
                    except Exception as e:
                        e.add_note(f'while {d.deviceId} is joining')
                        raise
                break
            except TerminalUnknownError as e:
                self.status = f"Terminal {e.args[0]} missing"
            await self.ethercat.terminalsInitialized.wait()
        self.status = "ready"
        self.syncGroup = self.SyncGroup(
            self.ethercat.ethercat,
            list(chain.from_iterable(d.get_devices() for d in self.devs)))
        self.syncGroup.name = self.deviceId.value
        self.syncGroup.cycletime = float(self.cycletime / unit.second)
        self.syncGroup.debug = self.debug.value
        self.state = State.OFF
        self.syncGroupTask = self.syncGroup.start()
        self.state = State.ON
        self.task = background(self.run())

    async def run(self):
        try:
            last_wkc_errors = self.syncGroup.wkc_errors

            while not self.syncGroupTask.done():
                if last_wkc_errors < self.syncGroup.wkc_errors:
                    self.state = State.ERROR
                    self.status = 'working counter mismatches: ' \
                            f'{self.syncGroup.wkc_errors}'
                    last_wkc_errors = self.syncGroup.wkc_errors
                    if last_wkc_errors - last_good_wkc > self.max_wkc_errors:
                        return
                else:
                    last_wkc_errors = last_good_wkc = self.syncGroup.wkc_errors
                    if self.state != State.RUNNING:
                        self.state = State.RUNNING
                        self.status = ''
                if self.syncGroup.current_data is not None:
                    for d in self.devs:
                        if (newstate := d.update_properties()) is not None:
                            if isinstance(newstate, State):
                                d.set_state(newstate)
                            else:
                                d.set_state(*newstate)
                        await sleep(self.interval.value / len(self.devs))
                else:
                    await sleep(self.interval.value)
            self.syncGroupTask.result()  # raises error if problem
        except CancelledError:
            pass
        except Exception as e:
            self.status = str(e)
            self.logger.exception('Sync group %s failed', self.deviceId)
            raise
        finally:
            if not self.syncGroupTask.done():
                self.syncGroupTask.cancel()
            self.state = State.ERROR
            for d in self.devs:
                d.state = State.UNKNOWN
                d.status = f'Sync Group {self.deviceId} Stopped'


class EtherCATSyncGroup(EtherCATSyncGroupBase):
    SyncGroup = SyncGroup


class FastEtherCATSyncGroup(EtherCATSyncGroupBase):
    """A fast sync group where the code runs as EBPF

    Use this sync group for fast control loops, as needed for motors."""
    SyncGroup = FastSyncGroup


class ProcessEtherCATSyncGroup(EtherCATSyncGroupBase):
    """A sync group that runs in a different process

    This is a general purpose sync group for all slow needs, like
    vacuum.
    """
    SyncGroup = ProcessSyncGroup


class EtherCATDevice(Device):
    """The base class for all EtherCAT-Karabo devices

    .. attribute:: device

        This contains the :class:`~ebpfcat.ebpfcat.Device` we are using in the
        background. If there is more than one, overwrite :meth:`get_devices`
        instead.

    .. attribute:: state_change

        This :class:`~asyncio.Event` is set every time the state is set - no
        matter whether it changed or not.

    """

    instances = {}
    terminals = None

    def __init__(self, configuration):
        super().__init__(configuration)
        self.instances[self.deviceId] = self
        self.state_change = Event()

    def get_devices(self):
        """return the :class:`~ebpfcat.ebpfcat.Device`\ s used by this device

        return a tuple of the :class:`~ebpfcat.ebpfcat.Device`\ s used by us. By
        default just return the single :attr:`device`.
        """
        return (self.device,)

    def set_state(self, state, status=None):
        """Set a new state and status message

        Use this method to set a the state or status message.

        This is an important part of the Karabo protocol: Karabo
        :class:`~karabo.middlelayer.Slot`\ s are supposed to first set their new
        state before they return (if applicable). As the business logic is done
        asynchronously in :meth:`update_properties`, it is most easy to just
        wait until the state changes at the end of a slot. To this end, a
        :class:`~karabo.middlelayer.Slot` usually ends with ``await
        self.state_change.wait()``, and this :attr:`state_change` is evoked
        here.
        """

        if state != self.state or (status is not None and status !=
                                   self.status):
            self.state = state
            self.status = status
        self.state_change.set()
        self.state_change.clear()

    def find_channel(self, name):
        terminal, *channel = name.split(".")
        device = self.getLocalDevice(terminal)
        if device is None:
            ret = self.ethercat.term_by_name.get(terminal)
        else:
            ret = device.terminal
        if ret is None:
            self.status = f'missing terminal {name}'
            raise TerminalUnknownError(name)
        for c in channel:
            ret = getattr(ret, c)
        return ret

    def update_properties(self):
        """The business logic

        This is the core functionality of the device, on the Karabo side. This
        method gets called cyclically and should do the communication between
        the EBPFCat device and Karabo.

        The method may return the state this device is in after the call, or a
        pair of new state and status message. Returning ``None`` indicates the
        state should not change (but feel free to change the state elsewhere).
        This is useful to be used in a ``super()``-chain: mixins may return an
        error that they have detected, and the class using the mixin may or may
        not propagate this.
        """

    syncGroupDevice = String(
        displayedName='Sync Group',
        description='The Sync Group this device is member of',
        accessMode=AccessMode.READONLY)

    def join(self, syncGroup):
        """Let this device join a sync group

        This is where the :class:`~ebpfcat.ebpfcat.Device`\ s are created and
        linked to their :class:`~ebpfcat.ebpfcat.Terminal`\ s or channels
        thereof. Note that this might happen more than once, the device needs
        to be able to deal with that. Also don't forget to call ``super()``.
        """
        self.syncGroup = syncGroup
        self.syncGroupDevice = syncGroup.deviceId
        self.ethercat = syncGroup.ethercat

    def initialize(self):
        """called once everything is set up"""


class Channel(Configurable):
    _channel = None

    @classmethod
    def __init_subclass__(cls, **kwargs):
        super(Channel, cls).__init_subclass__(**kwargs)
        cls._sdo_attrs = []
        for name in cls._allattrs:
            attr = getattr(cls, name)
            if attr.alias is None:
                continue
            if isinstance(attr, (Simple, ml.Bool)):
                attr(cls.sdo_setter(attr))
                cls._sdo_attrs.append(name)

    @classmethod
    def sdo_setter(cls, attr):
        async def setter(self, value):
            if self._channel is None:
                setattr(self, attr.key, value)
                return
            entry = getattr(self._channel, attr.alias)
            try:
                await entry.write(value.value)
            except EtherCatError as e:
                self.get_root().logger.warning('could not write %s', attr.key)
            r = await entry.read()
            setattr(self, attr.key, r)

        return setter

    async def _initialize(self, channel):
        self._channel = channel
        for k in self._sdo_attrs:
            v = getattr(self, k)
            desc = getattr(self.__class__, k)
            if isSet(v):
                await desc.setter(self, v)
            else:
                entry = getattr(channel, desc.alias)
                setattr(self, k, await entry.read())


class EtherCATTerminal(Device):
    """Base class for Karabo devices representing a single terminal

    .. attribute:: Base

        The subclass of :class:`~ebpfcat.ebpfcat.Terminal` that this device
        represents. Usually set as a class variable.

    .. attribute:: terminal

        The instance of the :class:`~ebpfcat.ebpfcat.Terminal`.
    """

    master = String(accessMode=AccessMode.INITONLY,
                    assignment=Assignment.MANDATORY)
    vendorId = ml.Int32(displayedName='Vendor ID',
                        accessMode=AccessMode.READONLY)
    productCode = ml.Int32(displayedName='Product Code',
                           accessMode=AccessMode.READONLY)
    revisionNo = ml.Int32(displayedName='Revision Number',
                          accessMode=AccessMode.READONLY)
    serialNumber = ml.Int32(
        displayedName='Serial Number', accessMode=AccessMode.INITONLY,
        description="""The serial number of the terminal this device should
        control. Use negative numbers to indicate the position on the bus if
        no serial number is known (or set). At XFEL, this serial number is
        usually the QR code.""", assignment=Assignment.MANDATORY)
    coe = VectorHash(
        displayedName='CoE parameters',
        description="Additional CoE paramters to be set upon intialization",
        accessMode=AccessMode.INITONLY, rows=CoETable, defaultValue=[])
    currentCoE = VectorHash(displayedName='Current CoE Parameters',
                            accessMode=AccessMode.READONLY, rows=CoETable)
    watchdog = ml.Float(accessMode=AccessMode.INITONLY,
                        unitSymbol=Unit.SECOND,
                        metricPrefixSymbol=MetricPrefix.MILLI)
    terminal = None

    async def onInitialization(self):
        self.status = "waiting for master"
        dev = await getDevice(self.master)
        assert dev.serverId == self.serverId, f'wrong server {dev.serverId}'
        self.ethercat = self.getLocalDevice(self.master)
        await waitUntil(lambda: self.ethercat.state == State.ON)
        try:
            addr = self.ethercat.addr_by_serial[self.serialNumber.value]
        except KeyError:
            self.logger.exception('no terminal with serial number %i',
                                  self.serialNumber.value)
            raise
        self.terminal = self.Base(self.ethercat.ethercat)
        self.terminal.name = self.deviceId.value
        self.ethercat.term_by_addr[addr] = self.terminal
        self.status = "Initializing"
        self.ethercat.terminalsInitializingCount += 1
        try:
            await self.terminal.initialize(absolute=addr)
            if isSet(self.watchdog):
                wd = int(self.watchdog / (100 * unit.microsecond))
                await self.terminal.set_watchdog(wd, wd)

            self.status = 'parsing SDOs'
            self.vendorId = self.terminal.vendorId
            self.productCode = self.terminal.productCode
            self.revisionNo = self.terminal.revisionNo
            self.state = State.INIT
            await self.terminal.parse_sdos()

            for k in self._sdo_attrs:
                v = getattr(self, k)
                desc = getattr(self.__class__, k)
                if isSet(v):
                    await desc.setter(self, v)
                else:
                    entry = getattr(self.terminal, desc.alias)
                    setattr(self, k, await entry.read())

            for k in self._sdo_channels:
                await getattr(self, k)._initialize(
                    getattr(self.terminal, getattr(self.__class__, k).alias))

            self.status = 'setting custom CoE parameters'
            new_coes = []
            for coe in self.coe:
                await self.terminal.sdo_write(
                    pack(coe['format'], coe['value']),
                    coe['index'], coe['subIndex'])
                ret = await self.terminal.sdo_read(coe['index'],
                                                   coe['subIndex'])
                new_coes.append((coe['index'], coe['subIndex'],
                                 coe['comment'], coe['format'],
                                 unpack(coe['format'], ret)[0]))
            self.coe = new_coes
            self.ethercat.term_by_name[self.deviceId.split('/')[-1]] = \
                self.terminal
        finally:
            self.ethercat.terminalsInitializingCount -= 1
            if self.ethercat.terminalsInitializingCount == 0:
                self.ethercat.terminalsInitialized.set()
                self.ethercat.terminalsInitialized.clear()
        self.status = 'ready'
        background(self.monitor())

    async def monitor(self):
        laststate = None
        while True:
            try:
                state, error, status = await self.terminal.get_state()
            except EtherCatError as e:
                error = True
                status = e
            if error:
                self.state = State.ERROR
                self.status = f'error no {status}'
                laststate = None
            elif laststate is not state:
                self.state = {
                        MachineState.INIT: State.DISABLED,
                        MachineState.PRE_OPERATIONAL: State.STARTING,
                        MachineState.SAFE_OPERATIONAL: State.OFF,
                        MachineState.OPERATIONAL: State.ON}[state]
                self.status = ''
                laststate = state
            await sleep(1)

    async def onDestruction(self):
        del self.ethercat.term_by_name[self.deviceId.split('/')[-1]]

    @classmethod
    def sdo_setter(cls, attr):
        async def setter(self, value):
            if self.terminal is None:
                setattr(self, attr.key, value)
                return
            entry = getattr(self.terminal, attr.alias)
            await entry.write(value.value)
            setattr(self, attr.key, await entry.read())

        return setter

    @Slot(displayedName="Read CoE parameters")
    async def readCoE(self):
        """read the CoE parameters from the terminal"""
        await self.terminal.to_operational(MachineState.PRE_OPERATIONAL)
        odlist = await self.terminal.read_ODlist()
        coe = []
        for k, v in odlist.items():
            for kk, vv in v.entries.items():
                try:
                    value = await vv.read()
                except EtherCatError as e:
                    coe.append((k, kk, str(vv), f"Error {e.args[0]}", 0))
                else:
                    if isinstance(value, int):
                        coe.append((k, kk, str(vv), '', value))
                    else:
                        coe.append((k, kk, str(vv), repr(value), 0))
        self.currentCoE = coe

    @classmethod
    def __init_subclass__(cls, **kwargs):
        super(EtherCATTerminal, cls).__init_subclass__(**kwargs)
        cls._sdo_attrs = []
        cls._sdo_channels = []
        for name in cls._allattrs:
            attr = getattr(cls, name)
            if attr.alias is None:
                continue
            if isinstance(attr, (Simple, ml.Bool)):
                attr(cls.sdo_setter(attr))
                cls._sdo_attrs.append(name)
            elif isinstance(attr, ml.Node):
                cls._sdo_channels.append(name)
