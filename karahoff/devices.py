from struct import pack, unpack
from time import time

from karabo.middlelayer import (
    AccessMode, String, Int16, Slot, isSet, background, State, Float, Int32, Int16, UInt64)
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

    value = Int16(accessMode=AccessMode.READONLY)

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
    set_value = DeviceVar()

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

    current_position = DeviceVar('Q')
    set_enable = DeviceVar('B')
    max_velocity = DeviceVar('i')
    max_acceleration = DeviceVar('i')
    target = DeviceVar('Q')
    proportional = DeviceVar('i')
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

    current_position = Int32(accessMode=AccessMode.READONLY)
    current_velocity = Int32(accessMode=AccessMode.READONLY)

    motor_term = encoder_term = None

    @Int16()
    async def max_current(self, value):
        if not isSet(value) or self.motor_term is None:
            return
        state = await self.motor_term.get_state()
        if state < 2:
            state = await self.motor_term.set_state(2)
        assert state >= 2
        await self.motor_term.sdo_write(pack("<H", value), 0x8010, 0x1)
        self.max_current, = unpack(
            "<H", await self.motor_term.sdo_read(0x8010, 0x1))

    @UInt64()
    async def target(self, value):
        if not isSet(value):
            return
        self.device.target = int(value)
        self.target = self.device.target

    @Slot()
    async def join(self):
        self.device = MotorDevice()
        self.motor_term = self.find_channel(self.motor)
        self.encoder_term = self.find_channel(self.encoder)
        self.device.velocity = self.motor_term.velocity
        self.device.encoder = self.encoder_term.position
        self.device.enable = self.motor_term.enable

    @Slot()
    async def on(self):
        self.device.proportional = int(self.proportional * (1 << 16))
        self.device.max_velocity = self.max_velocity
        self.device.set_enable = True

    @Slot()
    async def off(self):
        self.device.set_enable = False

    def update_properties(self):
        self.current_position = self.device.current_position
        self.current_velocity = self.device.current_velocity
