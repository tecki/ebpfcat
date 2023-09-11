from struct import pack, unpack
from time import time, monotonic

from karabo.middlelayer import (
    AccessMode, String, Int16, Slot, isSet, background, State, Float, Int32,
    Int16, UInt16, UInt32, UInt64, UInt8, Double, Unit, MetricPrefix, Bool)
from .master import EtherCATDevice
from ebpfcat.ebpfcat import Device, TerminalVar, DeviceVar


class AnalogInputDevice(Device):
    value = TerminalVar()

    current_value = DeviceVar()

    def update(self):
        self.i += 1
        if self.i == 100:
            self.i = 0
            self.owner.value = self.value

    def program(self):
        self.current_value = self.value


class AnalogInput(EtherCATDevice):
    channel = String(accessMode=AccessMode.INITONLY)

    value = Int32(accessMode=AccessMode.READONLY)

    def update_properties(self):
        self.value = self.device.current_value

    @Slot()
    async def join(self):
        self.device = AnalogInputDevice()
        self.device.owner = self
        self.device.value = self.find_channel(self.channel)
        self.state = State.ON


class AnalogOutputDevice(Device):
    value = TerminalVar()
    set_value = DeviceVar(write=True)

    def update(self):
        if not isSet(self.owner.value):
            return
        self.value = int(self.owner.value)

    def program(self):
        print("programmed")
        self.value = self.set_value


class AnalogOutput(EtherCATDevice):
    channel = String(accessMode=AccessMode.INITONLY)

    @Int16()
    def value(self, value):
        if not isSet(value):
            return
        self.device.set_value = int(value)
        self.value = value

    @Slot()
    async def join(self):
        self.device = AnalogOutputDevice()
        self.device.owner = self
        self.device.value = self.find_channel(self.channel)
        self.state = State.ON


class CounterDevice(Device):
    counter = DeviceVar()

    def program(self):
        self.counter += 1


class Counter(EtherCATDevice):
    counter = Int32(accessMode=AccessMode.READONLY, defaultValue=0)
    frequency = Float(accessMode=AccessMode.READONLY)

    def update_properties(self):
        self.value = self.device.current_value

    @Slot()
    async def join(self):
        self.state = State.ON
        self.device = CounterDevice()
        self.lasttime = time()

    def update_properties(self):
        lc = self.counter
        self.counter = self.device.counter
        t1 = time()
        self.frequency = (self.counter - lc) / (t1 - self.lasttime)
        self.lasttime = t1


class MotorDevice(Device):
    velocity = TerminalVar()
    encoder = TerminalVar()
    low_switch = TerminalVar()
    high_switch = TerminalVar()
    enable = TerminalVar()

    tstatus = TerminalVar()

    current_position = DeviceVar('q')
    set_enable = DeviceVar('B', write=True)
    max_velocity = DeviceVar('i', write=True)
    max_acceleration = DeviceVar('i', write=True)
    target = DeviceVar('q', write=True)
    proportional = DeviceVar('q', write=True)
    current_velocity = DeviceVar('q')
    qstatus = DeviceVar('H')

    def program(self):
        self.enable = self.set_enable
        self.current_position = self.encoder
        self.qstatus = self.tstatus
        with self.ebpf.stmp:
            self.ebpf.stmp = (self.proportional * (self.target - self.encoder)) >> 16
            #with self.ebpf.tmp > self.velocity + self.max_acceleration:
            #    self.ebpf.tmp = self.velocity + self.max_acceleration
            #with self.ebpf.tmp + self.max_acceleration < self.velocity:
            #    self.ebpf.tmp = self.velocity - self.max_acceleration
            with self.ebpf.stmp > self.max_velocity:
                self.ebpf.stmp = self.max_velocity
            with self.ebpf.stmp + self.max_velocity < 0:
                self.ebpf.stmp = -self.max_velocity
            with (self.low_switch == 0) | (self.ebpf.stmp < 0) as Else:
                pass
            with Else:
                self.ebpf.stmp = 0
            with (self.high_switch == 0) | (self.ebpf.stmp > 0) as Else:
                pass
            with Else:
                self.ebpf.stmp = 0
            self.velocity = self.ebpf.stmp

    def whatever(self):
        with self.low_switch, self.velocity < 0:
            self.velocity = 0
        with self.high_switch, self.velocity > 0:
            self.velocity = 0


class Motor(EtherCATDevice):
    motor = String(accessMode=AccessMode.INITONLY)
    encoder = String(accessMode=AccessMode.INITONLY)
    proportional = Float(accessMode=AccessMode.INITONLY)
    max_velocity = Int16()
    stepSize = Double(
        accessMode=AccessMode.INITONLY,
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)

    current_position = Double(
        accessMode=AccessMode.READONLY,
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)
    current_velocity = Int32(accessMode=AccessMode.READONLY)

    motor_term = encoder_term = None

    statusbits = UInt8(alias="E:8008:2", defaultValue=0)
    crc_invert = UInt8(alias="E:8008:3", defaultValue=1)
    multiturn = UInt8(alias="E:8008:15", defaultValue=0)
    singleturn = UInt8(alias="E:8008:16", defaultValue=26)
    frequency = UInt8(alias="E:8008:13", defaultValue=0)
    polynomial = UInt32(alias="E:8008:11", defaultValue=67)

    high_switch = Bool(accessMode=AccessMode.READONLY)
    low_switch = Bool(accessMode=AccessMode.READONLY)

    max_current = UInt16(alias="M:8010:1")
    max_voltage = UInt16(alias="M:8010:3")

    qstatus = UInt16(accessMode=AccessMode.READONLY)

    target = Double(unitSymbol=Unit.METER,
                    metricPrefixSymbol=MetricPrefix.MILLI)

    @Slot()
    async def join(self):
        self.device = MotorDevice()
        self.motor_term = self.find_channel(self.motor)
        self.encoder_term = self.find_channel(self.encoder)
        self.device.velocity = self.motor_term.velocity
        self.device.low_switch = self.motor_term.low_switch
        self.device.high_switch = self.motor_term.high_switch
        self.device.tstatus = self.motor_term.status
        self.device.encoder = self.encoder_term.position
        self.device.enable = self.motor_term.enable
        self.terminals = dict(M=self.motor_term, E=self.encoder_term)
        await self.sdo_set()

    @Slot()
    async def on(self):
        if isSet(self.target):
            self.state = State.ON

    @Slot()
    async def off(self):
        self.state = State.OFF

    def update_properties(self):
        self.current_position = self.device.current_position * self.stepSize.value
        self.current_velocity = self.device.velocity
        self.qstatus = self.device.qstatus
        self.low_switch = self.device.low_switch
        self.high_switch = self.device.high_switch

        self.device.set_enable = bool(self.state == State.ON)
        if self.state != State.ON:
            return
        self.device.max_velocity = self.max_velocity
        self.device.proportional = int(self.proportional * (1 << 16))
        self.device.target = int(self.target // self.stepSize)


class TurboVacDevice(Device):
    pump_on = TerminalVar()
    reset = TerminalVar()
    error_status = TerminalVar()
    pump_is_on = TerminalVar()
    speed = TerminalVar()
    current = TerminalVar()
    set_pump_on = False

    def update(self):
        self.pump_on = self.set_pump_on


class TurboVac(EtherCATDevice):
    pump = String(accessMode=AccessMode.INITONLY)
    speed = UInt16(accessMode=AccessMode.READONLY)
    current = UInt16(accessMode=AccessMode.READONLY)

    @Slot()
    async def start(self):
        self.device.set_pump_on = True

    @Slot()
    async def stop(self):
        self.device.set_pump_on = False

    def update_properties(self):
        if self.device.pump_is_on:
            self.state = State.ON
        else:
            self.state = State.OFF
        self.current = self.device.current
        self.speed = self.device.speed

    @Slot()
    async def join(self):
        self.device = TurboVacDevice()
        self.pump_term = self.find_channel(self.pump)
        self.device.pump_on = self.pump_term.pump_on
        self.device.error_status = self.pump_term.error_status
        self.device.pump_is_on = self.pump_term.pump_is_on
        self.device.speed = self.pump_term.speed
        self.device.current = self.pump_term.current


class InficonDevice(Device):
    value = TerminalVar()

    def update(self):
        pass

class Inficon(EtherCATDevice):
    gauge = String(accessMode=AccessMode.INITONLY)
    value = Float(accessMode=AccessMode.READONLY)

    @Slot()
    async def join(self):
        self.device = InficonDevice()
        self.gauge_term = self.find_channel(self.gauge)
        self.device.value = self.gauge_term.value

    def update_properties(self):
        self.value = self.device.value


class ValveDevice(Device):
    coil = TerminalVar()
    openSwitch = TerminalVar()
    closeSwitch = TerminalVar()

    def update(self):
        if (self.openSwitch != self.closeSwitch) \
                and (self.openSwitch if self.coil else self.closeSwitch):
            self.lastGood = monotonic()
            self.coil = self.target
        elif time() - self.lastGood < self.movingTime:
            self.coil = self.target
        else:
            self.coil = self.target = self.safeState

    def reset(self):
        self.lastGood = monotonic()


class Valve(EtherCATDevice):
    coil = String(accessMode=AccessMode.INITONLY)
    openSwitch = String(accessMode=AccessMode.INITONLY)
    closeSwitch = String(accessMode=AccessMode.INITONLY)
    safeState = Bool(accessMode=AccessMode.INITONLY)
    movingTime = Float(accessMode=AccessMode.INITONLY, unitSymbol=Unit.SECOND)

    @Slot()
    async def join(self):
        self.device = ValveDevice()
        self.device.reset()
        self.device.coil = self.find_channel(self.coil)
        self.device.openSwitch = self.find_channel(self.openSwitch)
        self.device.closeSwitch = self.find_channel(self.closeSwitch)
        self.device.movingTime = self.movingTime.value
        self.device.target = self.device.safeState = self.safeState.value

    @Slot()
    async def open(self):
        self.device.target = True

    @Slot()
    async def close(self):
        self.device.target = False

    @Slot()
    async def reset(self):
        self.device.reset()

    def update_properties(self):
        if self.device.openSwitch:
            self.state = State.OPENED
        elif self.device.closeSwitch:
            self.state = State.CLOSED
        elif self.device.coil:
            self.state = State.OPENING
        else:
            self.state = State.CLOSING
