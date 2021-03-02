from struct import pack, unpack
from time import time

from karabo.middlelayer import (
    AccessMode, String, Int16, Slot, isSet, background, State, Float, Int32,
    Int16, UInt64, UInt8, Double, Unit, MetricPrefix)
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

    current_position = DeviceVar('q')
    set_enable = DeviceVar('B', write=True)
    max_velocity = DeviceVar('i', write=True)
    max_acceleration = DeviceVar('i', write=True)
    target = DeviceVar('q', write=True)
    proportional = DeviceVar('i', write=True)
    current_velocity = DeviceVar('i')

    def program(self):
        self.enable = self.set_enable
        self.current_position = self.encoder
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
            self.velocity = self.ebpf.stmp
            self.current_velocity = self.ebpf.stmp

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

    max_current = Int16(alias="M:8010:1")
    max_voltage = Int16(alias="M:8010:3")

    target = Double(unitSymbol=Unit.METER,
                    metricPrefixSymbol=MetricPrefix.MILLI)

    @Slot()
    async def join(self):
        self.device = MotorDevice()
        self.motor_term = self.find_channel(self.motor)
        self.encoder_term = self.find_channel(self.encoder)
        self.device.velocity = self.motor_term.velocity
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
        self.current_velocity = self.device.current_velocity

        self.device.set_enable = bool(self.state == State.ON)
        if self.state != State.ON:
            return
        self.device.max_velocity = self.max_velocity
        self.device.proportional = int(self.proportional * (1 << 16))
        self.device.target = int(self.target // self.stepSize)
