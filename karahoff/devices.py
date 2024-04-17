from asyncio import sleep
from struct import pack, unpack
from time import time, monotonic

from karabo.middlelayer import (
    AccessMode, Assignment, String, Int16, Slot, isSet, background, State,
    Float, Int32, Int16, UInt16, UInt32, UInt64, UInt8, Double, Unit, unit,
    MetricPrefix, Bool, Overwrite, QuantityValue, get_timestamp)
from .master import EtherCATDevice
from ebpfcat.ebpf import ktime
from ebpfcat.ebpfcat import Device, TerminalVar, DeviceVar, Struct
from ebpfcat.devices import (
    AnalogInput as AnalogInputDevice, DigitalOutput as DigitalOutputDevice)


def now():
    return QuantityValue(1, timestamp=get_timestamp())


class GenericInput(EtherCATDevice):
    channel = String(accessMode=AccessMode.INITONLY,
                     assignment=Assignment.MANDATORY)
    value = Double(accessMode=AccessMode.READONLY)

    def update_properties(self):
        self.value = self.device.value

    async def join(self, syncGroup):
        await super().join(syncGroup)
        self.the_channel = self.find_channel(self.channel)
        self.device = AnalogInputDevice(self.the_channel)
        self.state = State.ON


class AnalogInput(EtherCATDevice):
    channel = String(accessMode=AccessMode.INITONLY,
                     assignment=Assignment.MANDATORY)

    value = Double(accessMode=AccessMode.READONLY)

    def update_properties(self):
        self.value = self.device.value * self.the_channel.factor + self.the_channel.offset

    async def join(self, syncGroup):
        await super().join(syncGroup)
        self.the_channel = self.find_channel(self.channel)
        self.device = AnalogInputDevice(self.the_channel.value)
        self.state = State.ON


class FusedOutput(Device):
    data = TerminalVar()
    error = TerminalVar()
    value = DeviceVar('B')  # 0 regular off, 1 regular on, 2 error off

    def program(self):
        with (self.error != 0) | (self.value == 2) as Else:
            self.data = 0
            self.value = 2
        with Else:
            self.data = self.value

    def update(self):
        if self.error or self.value == 2:
            self.data = False
            self.value = 2
        else:
            self.data = self.value


def optionalFusedOutput(channel):
    if isinstance(channel, Struct):
        ret = FusedOutput()
        ret.data = channel.value
        ret.error = channel.overcurrent
        return ret
    else:
        return DigitalOutputDevice(channel)


class OptionalMixin(EtherCATDevice):
    switchChannel = String(accessMode=AccessMode.INITONLY)

    def get_devices(self):
        ret = super().get_devices()
        if self.switchChannel:
            return ret + (self.switchDevice,)
        else:
            return ret

    async def join(self, syncGroup):
        await super().join(syncGroup)
        if self.switchChannel:
            self.switchDevice = optionalFusedOutput(
                self.find_channel(self.switchChannel))
        else:
            self.switchDevice = None


class OptionalSwitchMixin(OptionalMixin):
    def update_properties(self):
        if self.switchDevice is None:
            return True
        if self.switchDevice.value == 2:
            self.set_state(State.ERROR)
            return False
        return True

    @Slot()
    async def on(self):
        self.switchDevice.value = 1
        await self.state_change.wait()

    @Slot()
    async def off(self):
        self.switchDevice.value = 0
        await self.state_change.wait()


class OptionalKeepOnMixin(OptionalMixin):
    def update_properties(self):
        if self.switchDevice is None:
            return True
        if self.switchDevice.value == 2:
            self.set_state(State.ERROR)
            return False
        self.switchDevice.value = 1
        return True

    @Slot()
    async def reset(self):
        self.switchDevice.value = 1
        await self.state_change.wait()


class DigitalOutput(OptionalSwitchMixin):
    switchChannel = Overwrite(assignment=Assignment.MANDATORY)
    startupValue = Bool(accessMode=AccessMode.INITONLY, defaultValue=False)

    def get_devices(self):
        return (self.switchDevice,)

    def update_properties(self):
        if super().update_properties():
            self.set_state(State.ON if self.switchDevice.data else State.OFF)

    def initialize(self):
        self.switchDevice.value = self.startupValue.value


class PressureGauge(OptionalSwitchMixin, EtherCATDevice):
    channel = String(accessMode=AccessMode.INITONLY,
                     assignment=Assignment.MANDATORY)

    value = Double(accessMode=AccessMode.READONLY, unitSymbol=Unit.BAR,
                   metricPrefixSymbol=MetricPrefix.MILLI,
                   relativeError=0.01, allowedStates={State.ON})
    factor = Double(accessMode=AccessMode.INITONLY,
                    assignment=Assignment.MANDATORY)
    offset = Double(accessMode=AccessMode.INITONLY,
                    assignment=Assignment.MANDATORY)
    minimum = Double(accessMode=AccessMode.INITONLY, defaultValue=1)
    maximum = Double(accessMode=AccessMode.INITONLY, defaultValue=8)

    def update_properties(self):
        if not super().update_properties():
            return
        semiRaw = self.device.value * self.the_channel.factor \
                + self.the_channel.offset
        if semiRaw < self.minimum.value:
            self.set_state(State.OFF)
        elif semiRaw > self.maximum.value:
            self.set_state(State.ERROR)
        else:
            self.set_state(State.ON)
            self.value = 10**(semiRaw * self.factor + self.offset) \
                    * unit.mbar * now()

    async def join(self, syncGroup):
        await super().join(syncGroup)
        self.the_channel = self.find_channel(self.channel)
        self.device = AnalogInputDevice(self.the_channel.value)
        self.state = State.ON


class AnalogOutputDevice(Device):
    value = TerminalVar()
    set_value = DeviceVar(write=True)

    def update(self):
        if not isSet(self.owner.value):
            return
        self.value = int(self.owner.value)

    def program(self):
        self.value = self.set_value


class AnalogOutput(EtherCATDevice):
    channel = String(accessMode=AccessMode.INITONLY,
                     assignment=Assignment.MANDATORY)

    @Int16()
    async def value(self, value):
        if not isSet(value):
            return
        self.device.set_value = int(value)
        self.value = value

    async def join(self, syncGroup):
        await super().join(syncGroup)
        self.device = AnalogOutputDevice()
        self.device.owner = self
        self.device.value = self.find_channel(self.channel)
        self.state = State.ON


class CounterDevice(Device):
    counter = DeviceVar()
    maxtime = DeviceVar(size='Q')
    lasttime = DeviceVar(size='Q')

    def program(self):
        self.counter += 1
        with self.ebpf.tmp:
            self.ebpf.tmp = ktime(self.ebpf)
            with self.ebpf.tmp - self.lasttime > self.maxtime:
                self.maxtime = self.ebpf.tmp - self.lasttime
            self.lasttime = self.ebpf.tmp

    def update(self):
        self.counter += 1
        tmp = monotonic()
        if tmp - self.lasttime > self.maxtime:
            self.maxtime = (tmp - self.lasttime) * 1e6
        self.lasttime = tmp


class Counter(EtherCATDevice):
    counter = Int32(accessMode=AccessMode.READONLY, defaultValue=0)
    frequency = Float(accessMode=AccessMode.READONLY)
    maxtime = Int32(accessMode=AccessMode.READONLY)

    def update_properties(self):
        self.value = self.device.current_value

    async def join(self, syncGroup):
        await super().join(syncGroup)
        self.state = State.ON
        self.device = CounterDevice()
        self.lasttime = monotonic()

    def update_properties(self):
        lc = self.counter
        t1 = monotonic()
        if t1 - self.lasttime < 0.1:
            return
        self.counter = self.device.counter
        self.frequency = (self.counter - lc) / (t1 - self.lasttime)
        self.lasttime = t1

        if self.device.maxtime < 1000000000:
            self.maxtime = self.device.maxtime
        self.device.maxtime = 0


class MotorDevice(Device):
    velocity = TerminalVar()
    encoder = TerminalVar()
    low_switch = TerminalVar()
    high_switch = TerminalVar()
    enable = TerminalVar()
    reset = TerminalVar()
    error = TerminalVar()
    reduced_current = TerminalVar()

    tstatus = TerminalVar()
    encoder_error = TerminalVar()

    set_enable = DeviceVar('B')
    deadband_exceeded = DeviceVar('b')
    max_velocity = DeviceVar('q')
    max_acceleration = DeviceVar('i')
    deadband = DeviceVar('q')
    target = DeviceVar('q')
    proportional = DeviceVar('q')

    def program(self):
        self.reset = self.set_enable > 1
        self.enable = self.set_enable > 0
        with abs(self.target - self.encoder) < self.deadband as Else:
            self.reduced_current = True
        with Else:
            self.reduced_current = False
            self.deadband_exceeded = 1
        with self.ebpf.stmp:
            self.ebpf.stmp = (self.proportional
                              * (self.target - self.encoder)) >> 16
            with self.ebpf.stmp > self.max_velocity:
                self.ebpf.stmp = self.max_velocity
            with self.ebpf.stmp + self.max_velocity < 0:
                self.ebpf.stmp = -self.max_velocity
            with ((self.low_switch != 0) & (self.ebpf.stmp < 0)):
                self.ebpf.stmp = 0
            with ((self.high_switch != 0) & (self.ebpf.stmp > 0)):
                self.ebpf.stmp = 0
            self.velocity = self.ebpf.stmp


class Motor(OptionalKeepOnMixin, EtherCATDevice):
    motor = String(accessMode=AccessMode.INITONLY,
                   assignment=Assignment.MANDATORY)
    encoder = String(accessMode=AccessMode.INITONLY,
                     assignment=Assignment.MANDATORY)
    proportional = Float(defaultValue=1, accessMode=AccessMode.INITONLY)
    encodeStep = Float(
        accessMode=AccessMode.INITONLY, defaultValue=5e-5,
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)
    offset = Float(
        accessMode=AccessMode.INITONLY, defaultValue=0,
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)
    deadband = Float(
        defaultValue=1e-3,
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)

    actualPosition = Float(
        accessMode=AccessMode.READONLY,
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)
    actualVelocity = Int32(accessMode=AccessMode.READONLY)

    motor_term = encoder_term = None

    isCWLimit = Bool(accessMode=AccessMode.READONLY)
    isCCWLimit = Bool(accessMode=AccessMode.READONLY)

    qstatus = UInt16(accessMode=AccessMode.READONLY)

    targetVelocity = Int32(defaultValue=1000)
    targetPosition = Float(unitSymbol=Unit.METER,
                           metricPrefixSymbol=MetricPrefix.MILLI)
    stepSize = Float(unitSymbol=Unit.METER,
                     metricPrefixSymbol=MetricPrefix.MILLI)

    async def join(self, syncGroup):
        await super().join(syncGroup)
        self.device = MotorDevice()
        self.motor_term = self.find_channel(self.motor)
        self.encoder_term = self.find_channel(self.encoder)
        self.device.velocity = self.motor_term.velocity
        self.device.low_switch = self.motor_term.low_switch
        self.device.high_switch = self.motor_term.high_switch
        self.device.tstatus = self.motor_term.status
        if isinstance(self.encoder_term, Struct):
            self.device.encoder = self.encoder_term.position
            self.device.encoder_error = self.encoder_term.error
            self.terminals = dict(M=self.motor_term, E=self.encoder_term)
        else:
            self.device.encoder = self.encoder_term
            self.terminals = dict(M=self.motor_term, E=None)
        self.device.enable = self.motor_term.enable
        self.device.error = self.motor_term.error
        self.device.reset = self.motor_term.reset
        self.device.reduced_current = self.motor_term.reduced_current

    @Slot(displayedName='Move')
    async def move(self):
        self.device.target = int((self.targetPosition - self.offset)
                                 // self.encodeStep)
        self.device.set_enable = True

    @Slot(displayedName='Stop')
    async def stop(self):
        self.device.target = self.device.encoder

    @Slot(displayedName='Off')
    async def off(self):
        self.device.set_enable = False

    @Slot(displayedName='Step Up')
    async def stepUp(self):
        self.targetPosition = self.actualPosition + self.stepSize
        await self.move()

    @Slot(displayedName='Step Down')
    async def stepDown(self):
        self.targetPosition = self.actualPosition - self.stepSize
        await self.move()

    @Slot()
    async def reset(self):
        self.device.set_enable = 2
        await sleep(0.2)
        self.device.set_enable = 0

    def update_properties(self):
        self.actualPosition = (self.device.encoder * self.encodeStep
                               + self.offset) * now()
        self.actualVelocity = self.device.velocity
        self.qstatus = self.device.tstatus
        self.isCCWLimit = self.device.low_switch
        self.isCWLimit = self.device.high_switch

        if super().update_properties():
            if self.terminals["E"] is not None and self.device.encoder_error:
                self.set_state(State.ERROR, f'encoder reported error')
            elif self.device.error:
                self.set_state(State.ERROR, 'motor reported error')
            elif not self.device.enable:
                self.set_state(State.OFF)
            elif self.device.velocity != 0 and self.device.deadband_exceeded:
                self.set_state(State.MOVING)
            else:
                self.set_state(State.ON)
        self.device.deadband_exceeded = 0

        self.device.max_velocity = self.targetVelocity
        self.device.proportional = int(self.proportional * (1 << 16))
        self.device.deadband = int(self.deadband // self.encodeStep)


class BronkhorstDevice(Device):
    setpoint = TerminalVar()
    current_value = TerminalVar()
    controller_output = TerminalVar()
    control_byte = TerminalVar()
    status_word = TerminalVar()
    set_setpoint = 0

    def update(self):
        self.setpoint = self.set_setpoint
        self.control_byte = 1


class Bronkhorst(EtherCATDevice):
    terminal = String(accessMode=AccessMode.INITONLY,
                      assignment=Assignment.MANDATORY)
    setpoint = UInt16()
    current_value = UInt16(accessMode=AccessMode.READONLY)
    controller_output = Int16(accessMode=AccessMode.READONLY)

    @Int16()
    async def setpoint(self, value):
        if not isSet(value):
            return
        self.device.set_setpoint = int(value)
        self.setpoint = value

    def update_properties(self):
        self.current_value = self.device.current_value
        self.controller_output = self.device.controller_output

    async def join(self, syncGroup):
        await super().join(syncGroup)
        self.the_terminal = self.find_channel(self.terminal)
        self.device = BronkhorstDevice()
        self.device.owner = self
        self.device.setpoint = self.the_terminal.setpoint
        self.device.current_value = self.the_terminal.current_value
        self.device.controller_output = self.the_terminal.controller_output
        self.device.control_byte = self.the_terminal.control_byte
        self.device.status_word = self.the_terminal.status_word
        await self.set_mode(None)

    async def set_mode(self, mode):
        if mode is not None:
            await self.the_terminal.sdo_write(pack('B', mode), 0x6423, 1)
        mode, = unpack('B', await self.the_terminal.sdo_read(0x6423, 1))
        self.state = {
                0x80: State.RUNNING,
                0x83: State.CLOSED,
                0x84: State.OFF,
                0x88: State.OPENED
                }.get(mode, State.UNKNOWN)

    @Slot()
    async def start(self):
        await self.set_mode(0x80)

    @Slot()
    async def stop(self):
        await self.set_mode(0x84)

    @Slot()
    async def open(self):
        await self.set_mode(0x88)

    @Slot()
    async def close(self):
        await self.set_mode(0x83)


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
    pump = String(accessMode=AccessMode.INITONLY,
                  assignment=Assignment.MANDATORY)
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

    async def join(self, syncGroup):
        await super().join(syncGroup)
        self.device = TurboVacDevice()
        self.pump_term = self.find_channel(self.pump)
        self.device.pump_on = self.pump_term.pump_on
        self.device.error_status = self.pump_term.error_status
        self.device.pump_is_on = self.pump_term.pump_is_on
        self.device.speed = self.pump_term.speed
        self.device.current = self.pump_term.current


class InficonDevice(Device):
    value = TerminalVar()
    valid = TerminalVar()

    def update(self):
        pass


class Inficon(EtherCATDevice):
    gauge = String(accessMode=AccessMode.INITONLY,
                   assignment=Assignment.MANDATORY)
    value = Float(accessMode=AccessMode.READONLY)

    async def join(self, syncGroup):
        await super().join(syncGroup)
        self.device = InficonDevice()
        self.gauge_term = self.find_channel(self.gauge)
        self.device.value = self.gauge_term.value
        self.device.valid = self.gauge_term.valid

    def update_properties(self):
        if self.device.valid:
            self.set_state(State.ON)
            self.value = self.device.value
        else:
            self.set_state(State.OFF)


class ValveDevice(Device):
    coil = TerminalVar()
    openSwitch = TerminalVar()
    closeSwitch = TerminalVar()
    error = False

    def update(self):
        if (self.openSwitch != self.closeSwitch) \
                and (self.closeSwitch if (self.coil == self.safeState)
                     else self.openSwitch):
            self.lastGood = monotonic()
            self.coil = self.target
        elif monotonic() - self.lastGood < self.movingTime:
            self.coil = self.target
        else:
            self.error = True
            self.coil = self.target = False

    def reset(self):
        self.error = False
        self.lastGood = monotonic()


class Valve(OptionalKeepOnMixin, EtherCATDevice):
    coil = String(accessMode=AccessMode.INITONLY,
                  assignment=Assignment.MANDATORY)
    openSwitch = String(accessMode=AccessMode.INITONLY,
                        assignment=Assignment.MANDATORY)
    closeSwitch = String(accessMode=AccessMode.INITONLY,
                         assignment=Assignment.MANDATORY)
    safeState = Bool(accessMode=AccessMode.INITONLY, defaultValue=False)
    movingTime = Float(accessMode=AccessMode.INITONLY, unitSymbol=Unit.SECOND,
                       defaultValue=3)

    isOpened = Bool(accessMode=AccessMode.READONLY)
    isClosed = Bool(accessMode=AccessMode.READONLY)

    async def join(self, syncGroup):
        await super().join(syncGroup)
        self.device = ValveDevice()
        self.device.reset()
        self.device.coil = self.find_channel(self.coil)
        self.device.openSwitch = self.find_channel(self.openSwitch)
        self.device.closeSwitch = self.find_channel(self.closeSwitch)
        self.device.movingTime = self.movingTime.value
        self.device.target = self.device.safeState = self.safeState.value

    @Slot(allowedStates={State.CLOSED, State.CLOSING})
    async def open(self):
        self.device.target = not self.safeState

    @Slot(allowedStates={State.OPENED, State.OPENING})
    async def close(self):
        self.device.target = self.safeState

    @Slot(allowedStates={State.ERROR})
    async def reset(self):
        await super().reset()
        self.device.reset()

    def update_properties(self):
        if self.device.openSwitch != self.isOpened:
            self.isOpened = self.device.openSwitch
        if self.device.closeSwitch != self.isClosed:
            self.isClosed = self.device.closeSwitch
        if not super().update_properties():
            return
        if self.device.error:
            self.set_state(State.ERROR)
        elif self.device.openSwitch:
            self.set_state(State.OPENED)
        elif self.device.closeSwitch:
            self.set_state(State.CLOSED)
        elif self.device.coil == self.safeState:
            self.set_state(State.CLOSING)
        else:
            self.set_state(State.OPENING)


class ShutterDevice(Device):
    velocity = TerminalVar()
    enable = TerminalVar()
    openSwitch = TerminalVar()
    closeSwitch = TerminalVar()
    opening = TerminalVar()
    closing = TerminalVar()

    def update(self):
        if (self.openSwitch != self.closeSwitch) \
                and (self.openSwitch if self.target else self.closeSwitch):
            self.lastGood = monotonic()
            self.enable = False
        elif monotonic() - self.lastGood < self.movingTime:
            self.velocity = -(-1) ** self.target * self.speed
            self.enable = True
        else:
            self.error = True
            self.enable = False

    def reset(self):
        self.error = False
        self.lastGood = monotonic()


class Shutter(EtherCATDevice):
    velocity = String(accessMode=AccessMode.INITONLY,
                  assignment=Assignment.MANDATORY)
    enable = String(accessMode=AccessMode.INITONLY,
                  assignment=Assignment.MANDATORY)
    openSwitch = String(accessMode=AccessMode.INITONLY,
                        assignment=Assignment.MANDATORY)
    closeSwitch = String(accessMode=AccessMode.INITONLY,
                         assignment=Assignment.MANDATORY)
    opening = String(accessMode=AccessMode.INITONLY,
                     assignment=Assignment.MANDATORY)
    closing = String(accessMode=AccessMode.INITONLY,
                     assignment=Assignment.MANDATORY)
    movingTime = Float(accessMode=AccessMode.INITONLY, unitSymbol=Unit.SECOND,
                       defaultValue=3)
    speed = Int16(accessMode=AccessMode.INITONLY, defaultValue=3, minInc=0)

    async def join(self, syncGroup):
        await super().join(syncGroup)
        self.device = ShutterDevice()
        self.device.reset()
        self.device.velocity = self.find_channel(self.velocity)
        self.device.openSwitch = self.find_channel(self.openSwitch)
        self.device.closeSwitch = self.find_channel(self.closeSwitch)
        self.device.opening = self.find_channel(self.opening)
        self.device.closing = self.find_channel(self.closing)
        self.device.enable = self.find_channel(self.enable)
        self.device.movingTime = self.movingTime.value
        self.device.speed = self.speed.value
        self.device.target = False

    @Slot(allowedStates={State.CLOSED, State.CLOSING})
    async def open(self):
        self.device.target = True

    @Slot(allowedStates={State.OPENED, State.OPENING})
    async def close(self):
        self.device.target = False

    @Slot(allowedStates={State.ERROR})
    async def reset(self):
        self.device.reset()

    def update_properties(self):
        if self.device.error:
            self.set_state(State.ERROR)
        elif self.device.openSwitch:
            self.set_state(State.OPENED)
        elif self.device.closeSwitch:
            self.set_state(State.CLOSED)
        elif self.device.opening:
            self.set_state(State.OPENING)
        elif self.device.closing:
            self.set_state(State.CLOSING)
        else:
            self.set_state(State.ERROR)
