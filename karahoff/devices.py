from asyncio import Event, Lock, sleep
from math import sqrt
from struct import pack, unpack
from time import time, monotonic

from karabo.middlelayer import (
    AccessMode, Assignment, String, Int16, Slot, isSet, background, State,
    Float, Int32, Int16, UInt16, UInt32, UInt64, UInt8, Double, Unit, unit,
    MetricPrefix, Bool, Overwrite, QuantityValue, get_timestamp, Timestamp)
from .master import EtherCATDevice
from ebpfcat.ebpf import ktime
from ebpfcat.ebpfcat import Device, TerminalVar, DeviceVar, Struct
from ebpfcat.devices import (
    AnalogInput as AnalogInputDevice, DigitalOutput as DigitalOutputDevice)
from ebpfcat.serial import Serial


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


class AnalogStatisticsDevice(Device):
    value = TerminalVar()

    maxValue = DeviceVar('i')
    minValue = DeviceVar('i')
    currentValue = DeviceVar('i')
    sumValue = DeviceVar('q')
    sumSquared = DeviceVar('q')
    counter = DeviceVar('i')
    trigger = DeviceVar('i')
    lastSum = DeviceVar('q')
    lastSquared = DeviceVar('q')
    lastCounter = DeviceVar('i')

    def program(self):
        self.currentValue = self.value
        with self.value > self.maxValue:
            self.maxValue = self.value
        with self.value < self.minValue:
            self.minValue = self.value
        with self.trigger != 0:
            self.lastSum = self.sumValue
            self.lastSquared = self.sumSquared
            self.lastCounter = self.counter
            self.sumValue = 0
            self.sumSquared = 0
            self.counter = 0
            self.trigger = 0
        self.sumValue += self.value
        self.sumSquared += self.value * self.value
        self.counter += 1


class AnalogStatistics(EtherCATDevice):
    channel = String(accessMode=AccessMode.INITONLY,
                     assignment=Assignment.MANDATORY)
    factor = Double(accessMode=AccessMode.INITONLY, defaultValue=1)
    offset = Double(accessMode=AccessMode.INITONLY, defaultValue=0)

    mean = Double(accessMode=AccessMode.READONLY)
    minimum = Double(accessMode=AccessMode.READONLY)
    maximum = Double(accessMode=AccessMode.READONLY)
    deviation = Double(accessMode=AccessMode.READONLY)

    def update_properties(self):
        if self.device.lastCounter == 0:
            self.device.trigger = 1
            return

        factor = self.the_channel.factor * self.factor * now()
        offset = self.the_channel.offset * self.factor + self.offset

        self.mean = (self.device.lastSum
                     / self.device.lastCounter) * factor + offset
        self.minimum = self.device.minValue * factor + offset
        self.maximum = self.device.maxValue * factor + offset
        self.device.minValue = self.device.currentValue
        self.device.maxValue = self.device.currentValue
        variance = self.device.lastSquared / self.device.lastCounter \
                 - (self.device.lastSum / self.device.lastCounter) ** 2
        if variance > 0:
            self.deviation = sqrt(variance) * factor
        self.device.trigger = 1


    async def join(self, syncGroup):
        await super().join(syncGroup)
        self.the_channel = self.find_channel(self.channel)
        self.device = AnalogStatisticsDevice()
        self.device.value = self.the_channel.value
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
        if self.switchDevice is not None and self.switchDevice.value == 2:
            return State.ERROR

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
            return
        if self.switchDevice.value == 2:
            return State.ERROR
        self.switchDevice.value = 1

    @Slot()
    async def reset(self):
        if self.switchDevice is not None:
            self.switchDevice.value = 1
            await self.state_change.wait()


class DigitalOutput(OptionalSwitchMixin):
    switchChannel = Overwrite(assignment=Assignment.MANDATORY)
    startupValue = Bool(accessMode=AccessMode.INITONLY, defaultValue=False)

    def get_devices(self):
        return (self.switchDevice,)

    def update_properties(self):
        if super().update_properties() is None:
            return State.ON if self.switchDevice.data else State.OFF

    def initialize(self):
        self.switchDevice.value = self.startupValue.value

    on = Overwrite(allowedStates={State.OFF})
    off = Overwrite(allowedStates={State.ON})


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

    old_value = -1
    old_time = monotonic()

    def update_properties(self):
        if (ret := super().update_properties()) is not None:
            return ret
        semiRaw = self.device.value * self.the_channel.factor \
                + self.the_channel.offset
        if semiRaw < self.minimum.value:
            self.set_state(State.OFF)
        elif semiRaw > self.maximum.value:
            self.set_state(State.ERROR)
        else:
            self.set_state(State.ON)
            newtime = monotonic()
            if abs(self.old_value - self.device.value) \
                    > 10 / (newtime - self.old_time):
                self.value = 10 ** (semiRaw * self.factor + self.offset) \
                    * unit.mbar * now()
                self.old_value = self.device.value
                self.old_time = newtime

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


class MonitoredOutputDevice(Device):
    outputTerm = TerminalVar()
    inputTerm = TerminalVar()

    ramping = DeviceVar('i')
    value = DeviceVar('q')
    lastTime = monotonic() * unit.second

    def update(self):
        target = int(self.owner.target / (self.owner.outputFactor
                                          * self.owner.outputCalibration))
        now = monotonic() * unit.second
        diff = int(
            self.owner.rampSpeed * (now - self.lastTime)
            / (self.owner.outputFactor * self.owner.outputCalibration))
        if self.owner.rampSpeed == 0 or abs(target - self.lastValue) < diff:
            self.lastValue = self.outputTerm = target
            self.lastTime = now
            self.ramping = 0
        else:
            self.ramping = target - self.outputTerm
            self.lastValue = self.outputTerm = \
                    self.lastValue + diff if target > self.outputTerm \
                    else self.lastValue - diff
            if diff > 0:
                self.lastTime = now
        self.value = self.inputTerm


class MonitoredOutput(EtherCATDevice):
    inputChannel = String(accessMode=AccessMode.INITONLY,
                          assignment=Assignment.MANDATORY)
    outputChannel = String(accessMode=AccessMode.INITONLY,
                           assignment=Assignment.MANDATORY)

    inputCalibration = Float(defaultValue=1, accessMode=AccessMode.INITONLY)
    outputCalibration = Float(defaultValue=1, accessMode=AccessMode.INITONLY)

    target = Float(unitSymbol=Unit.VOLT, defaultValue=0)
    value = Float(unitSymbol=Unit.VOLT, accessMode=AccessMode.READONLY)
    lastValue = 0
    rampSpeed = Float(unitSymbol=Unit.VOLT_PER_SECOND, defaultValue=0)

    async def join(self, syncGroup):
        await super().join(syncGroup)
        self.device = MonitoredOutputDevice()
        self.device.owner = self
        inputChannel = self.find_channel(self.inputChannel)
        self.device.inputTerm = inputChannel.value
        self.inputFactor = inputChannel.factor * unit.volt
        outputChannel = self.find_channel(self.outputChannel)
        self.device.outputTerm = outputChannel.value
        self.outputFactor = outputChannel.factor * unit.volt

    def update_properties(self):
        if self.lastValue != self.device.value:
            self.lastValue = self.device.value
            self.value = self.device.value * self.inputFactor \
                         * self.inputCalibration * now()
        if self.device.ramping == 0:
            return State.ON
        elif self.device.ramping > 0:
            return State.RAMPING_UP
        else:
            return State.RAMPING_DOWN


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
            self.maxtime = int((tmp - self.lasttime) * 1e6)
        self.lasttime = int(tmp)


class Counter(EtherCATDevice):
    counter = UInt64(accessMode=AccessMode.READONLY, defaultValue=0)
    frequency = Float(accessMode=AccessMode.READONLY)
    maxtime = Int32(accessMode=AccessMode.READONLY)
    errorSleep = Float(defaultValue=0, unitSymbol=Unit.SECOND,
                       metricPrefixSymbol=MetricPrefix.MILLI)

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
        self.counter = self.device.counter
        self.frequency = (self.counter - lc) / (t1 - self.lasttime)
        self.lasttime = t1

        if self.device.maxtime < 1000000000:
            self.maxtime = self.device.maxtime
        self.device.maxtime = 0

    @Slot()
    async def error(self):
        import time
        time.sleep(self.errorSleep.value / 1000)


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
    proportional = Float(
        displayedName='Proportionality Constant',
        defaultValue=1, accessMode=AccessMode.INITONLY)
    encodeStep = Float(
        displayedName='Encoder Stepsize',
        accessMode=AccessMode.INITONLY, defaultValue=5e-5,
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)
    offset = Float(
        accessMode=AccessMode.INITONLY, defaultValue=0,
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)
    deadband = Float(
        defaultValue=1e-3,
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)

    actualPosition = Float(
        displayedName='Actual Position',
        accessMode=AccessMode.READONLY,
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)
    actualVelocity = Int32(
        displayedName='Actual Velocity',
        accessMode=AccessMode.READONLY)

    motor_term = encoder_term = None

    isCWLimit = Bool(
        displayedName='At Positive Limit?',
        accessMode=AccessMode.READONLY)
    isCCWLimit = Bool(
        displayedName='At Negative Limit?',
        accessMode=AccessMode.READONLY)

    qstatus = UInt16(accessMode=AccessMode.READONLY)

    targetVelocity = Int32(displayedName='Target Velocity', defaultValue=1000)
    targetPosition = Float(
        displayedName='Target Position',
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)
    stepSize = Float(
        displayedName='Step Size', defaultValue=1,
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)

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

    @Slot(displayedName='On')
    async def on(self):
        self.targetPosition = self.actualPosition
        await self.move()

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

        self.device.deadband_exceeded = 0
        self.device.max_velocity = self.targetVelocity
        self.device.proportional = int(self.proportional * (1 << 16))
        self.device.deadband = int(self.deadband // self.encodeStep)

        if (ret := super().update_properties()) is not None:
            return ret
        elif self.terminals["E"] is not None and self.device.encoder_error:
            return State.ERROR, f'encoder reported error'
        elif self.device.error:
            return State.ERROR, 'motor reported error'
        elif not self.device.enable:
            return State.OFF
        elif self.device.velocity != 0 and self.device.deadband_exceeded:
            return State.MOVING
        else:
            return State.ON


class BronkhorstDevice(Device):
    setpoint = TerminalVar()
    current_value = TerminalVar()
    controller_output = TerminalVar()
    control_byte = TerminalVar()
    status_word = TerminalVar()

    set_setpoint = DeviceVar('H')

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

    set_pump_on = DeviceVar('?')

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
        self.current = self.device.current
        self.speed = self.device.speed
        return State.ON if self.device.pump_is_on else State.OFF

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
            return State.ON
            self.value = self.device.value
        else:
            return State.OFF


class ValveDevice(Device):
    coil = TerminalVar()
    openSwitch = TerminalVar()
    closeSwitch = TerminalVar()

    error = DeviceVar('?')
    target = DeviceVar('?')
    modulo = DeviceVar('I')
    divisor = DeviceVar('I')
    delay = DeviceVar('f')

    lastGood = 0

    def update(self):
        if self.divisor > 0:
            ts = get_timestamp(Timestamp(time() - self.delay))
            self.target = ts.tid % self.divisor == self.modulo
        inPosition = self.openSwitch != self.closeSwitch
        isCorrect = ((self.closeSwitch or not self.openSwitch)
                     if (self.coil == self.safeState)
                     else (self.openSwitch or not self.closeSwitch))
        if inPosition and isCorrect:
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
    openSwitch = String(accessMode=AccessMode.INITONLY)
    closeSwitch = String(accessMode=AccessMode.INITONLY)
    safeState = Bool(accessMode=AccessMode.INITONLY, defaultValue=False)
    movingTime = Float(accessMode=AccessMode.INITONLY, unitSymbol=Unit.SECOND,
                       defaultValue=3)

    isOpened = Bool(accessMode=AccessMode.READONLY)
    isClosed = Bool(accessMode=AccessMode.READONLY)

    divisor = Int32(defaultValue=1, minExc=0)
    modulo = Int32(defaultValue=0)
    delay = Float(defaultValue=0, unitSymbol=Unit.SECOND,
                  metricPrefixSymbol=MetricPrefix.MILLI)

    async def join(self, syncGroup):
        await super().join(syncGroup)
        self.device = ValveDevice()
        self.device.coil = self.find_channel(self.coil)
        if self.openSwitch:
            self.device.openSwitch = self.find_channel(self.openSwitch)
        if self.closeSwitch:
            self.device.closeSwitch = self.find_channel(self.closeSwitch)
        self.device.movingTime = self.movingTime.value
        self.device.safeState = self.safeState.value

    @Slot(allowedStates={State.CLOSED, State.CLOSING, State.MOVING})
    async def open(self):
        self.device.divisor = 0
        self.device.target = not self.safeState
        await self.state_change.wait()

    @Slot(allowedStates={State.OPENED, State.OPENING, State.MOVING})
    async def close(self):
        self.device.divisor = 0
        self.device.target = self.safeState
        await self.state_change.wait()

    @Slot(allowedStates={State.OPENED, State.MOVING, State.CLOSED})
    async def rock(self):
        self.device.divisor = self.divisor.value
        self.device.modulo = self.modulo.value
        self.device.delay = (self.delay / unit.second).value
        await self.state_change.wait()

    @Slot(allowedStates={State.ERROR})
    async def reset(self):
        await super().reset()
        self.device.reset()

    def update_properties(self):
        if self.openSwitch and self.device.openSwitch != self.isOpened:
            self.isOpened = self.device.openSwitch
        if self.closeSwitch and self.device.closeSwitch != self.isClosed:
            self.isClosed = self.device.closeSwitch
        if (ret := super().update_properties()) is not None:
            return ret
        if self.device.error:
            self.set_state(State.ERROR)
        elif self.device.divisor > 0:
            self.set_state(State.MOVING)
        elif self.device.coil == self.safeState:
            if (self.closeSwitch and not self.device.closeSwitch
                    or self.openSwitch and self.device.openSwitch):
                return State.CLOSING
            else:
                return State.CLOSED
        else:
            if (self.openSwitch and not self.device.openSwitch
                    or self.closeSwitch and self.device.closeSwitch):
                return State.OPENING
            else:
                return State.OPENED


class SlowRoughingValve(Valve):
    slowCoil = String(accessMode=AccessMode.INITONLY,
                      assignment=Assignment.MANDATORY)

    def get_devices(self):
        ret = super().get_devices()
        return ret + (self.slowDevice,)

    async def join(self, syncGroup):
        await super().join(syncGroup)
        self.slowDevice = optionalFusedOutput(
            self.find_channel(self.slowCoil))

    @Slot(allowedStates=
          {State.CLOSED, State.CLOSING, State.MOVING, State.EMPTYING})
    async def open(self):
        self.slowDevice.value = False
        await super().open()

    @Slot(allowedStates=
          {State.OPENED, State.OPENING, State.MOVING, State.EMPTYING})
    async def close(self):
        self.slowDevice.value = False
        await super().close()

    @Slot(allowedStates=
          {State.CLOSED, State.CLOSING, State.MOVING, State.EMPTYING})
    async def slow(self):
        self.slowDevice.value = True
        await self.state_change.wait()

    @Slot(allowedStates={State.ERROR})
    async def reset(self):
        await super().reset()
        self.slowDevice.value = False
        self.device.reset()

    def update_properties(self):
        if (ret := super().update_properties()) == State.ERROR:
            return ret
        if self.slowDevice.value == 1:
            return State.EMPTYING
        elif self.slowDevice.value == 2:
            return State.ERROR
        else:
            return ret


class ShutterDevice(Device):
    velocity = TerminalVar()
    enable = TerminalVar()
    openSwitch = TerminalVar()
    closeSwitch = TerminalVar()
    opening = TerminalVar()
    closing = TerminalVar()

    error = DeviceVar('?')
    target = DeviceVar('?')
    speed = DeviceVar('h')

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
            return State.ERROR
        elif self.device.openSwitch:
            return State.OPENED
        elif self.device.closeSwitch:
            return State.CLOSED
        elif self.device.opening:
            return State.OPENING
        elif self.device.closing:
            return State.CLOSING
        else:
            return State.ERROR


class EtherCATSCPIMaster(EtherCATDevice):
    terminal = String(accessMode=AccessMode.INITONLY,
                      assignment=Assignment.MANDATORY)

    def __init__(self, configuration):
        from scpiDevices.scpi import GenericSCPIMaster

        super().__init__(configuration)
        self.connectEvent = GenericSCPIMaster.instances.setdefault(
            self.deviceId.value, Event())

    async def join(self, syncGroup):
        await super().join(syncGroup)
        self.channel = self.find_channel(self.terminal)
        self.device = Serial(self.channel)

    initialized = False

    def update_properties(self):
        async def initialize():
            self.reader, self.writer = await self.device.connect()
            self.lock = Lock()
            self.connectEvent.set()
            self.state = State.ON

        if not self.initialized:
            self.state = State.INIT
            background(initialize())
            self.initialized = True


class Automation1Device(Device):
    actualPosition = TerminalVar()
    actualVelocity = TerminalVar()
    error = TerminalVar()
    status = TerminalVar()
    enabled = TerminalVar()
    homed = TerminalVar()

    targetPosition_term = TerminalVar()
    targetVelocity_term = TerminalVar()
    command_term = TerminalVar()

    targetPosition = DeviceVar('d')
    targetVelocity = DeviceVar('d')
    command = DeviceVar('i')


    def update(self):
        self.targetPosition_term = self.targetPosition
        self.targetVelocity_term = self.targetVelocity
        self.command_term = self.command

class Automation1(EtherCATDevice):
    motor = String(accessMode=AccessMode.INITONLY,
                   assignment=Assignment.MANDATORY)
    actualPosition = Float(
        displayedName='Actual Position',
        accessMode=AccessMode.READONLY,
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)
    homed = Int32(
        displayedName='Homed',
        accessMode=AccessMode.READONLY,
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)
    enabled = Int32(
        displayedName='Enabled',
        accessMode=AccessMode.READONLY,
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)
    error = Int32(
        displayedName='Error Code',
        accessMode=AccessMode.READONLY,
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)
    status = Int32(
        displayedName='Status',
        accessMode=AccessMode.READONLY,
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)
    targetPosition = Float(
        displayedName='Target Position',
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)
    targetVelocity = Float(
        displayedName='Target Velocity',
        unitSymbol=Unit.METER_PER_SECOND, metricPrefixSymbol=MetricPrefix.MILLI)

    async def join(self, syncGroup):
        await super().join(syncGroup)
        self.device = Automation1Device()
        self.motor_term = self.find_channel(self.motor)
        self.device.actualPosition = self.motor_term.actualPosition
        self.device.actualVelocity = self.motor_term.actualVelocity
        self.device.targetPosition_term = self.motor_term.targetPosition
        self.device.targetVelocity_term = self.motor_term.targetVelocity
        self.device.command_term = self.motor_term.command
        self.device.error = self.motor_term.error
        self.device.status = self.motor_term.status
        self.device.enabled = self.motor_term.enabled
        self.device.homed = self.motor_term.homed

    @Slot()
    async def on(self):
        self.device.command = 4

    @Slot()
    async def off(self):
        self.device.command = 5

    @Slot()
    async def reset(self):
        self.device.command = 2

    @Slot()
    async def home(self):
        self.device.command = 3

    @Slot()
    async def move(self):
        self.device.targetPosition = self.targetPosition.value
        self.device.targetVelocity = self.targetVelocity.value
        self.device.command = 1

    @Slot()
    async def update(self):
        self.device.targetPosition = self.targetPosition.value
        self.device.targetVelocity = self.targetVelocity.value
        self.device.command = 2

    def update_properties(self):
        self.actualPosition = self.device.actualPosition
        self.actualVelocity = self.device.actualVelocity
        self.enabled = self.device.enabled
        self.homed = self.device.homed
        self.status = self.device.status
        self.error = self.device.error

        if self.device.error != 0:
            self.state = State.ERROR
        else:
            if self.device.enabled == 1:
                self.state = State.ON
            else:
                self.state = State.OFF
