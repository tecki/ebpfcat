"""
A collection of simple devices
------------------------------

.. autoclass:: PressureGauge()
    :members:

.. autoclass:: Valve()
    :members:

.. autoclass:: MonitoredOutput()
    :members:

.. autoclass:: Motor()
    :members:

.. autoclass:: RotoationMotor()
    :members:

.. autoclass:: Shutter()
    :members:
"""
from asyncio import Event, Lock, sleep
from math import sqrt
from struct import pack, unpack
from time import monotonic, time

from ebpfcat.devices import AnalogInput as AnalogInputDevice
from ebpfcat.devices import DigitalOutput as DigitalOutputDevice
from ebpfcat.ebpf import ktime
from ebpfcat.ebpfcat import Device, DeviceVar, Struct, TerminalVar
from ebpfcat.serial import Serial
from karabo.middlelayer import (
    AccessMode, Assignment, Bool, Double, Float, Int16, Int32, MetricPrefix,
    Overwrite, QuantityValue, Slot, State, String, Timestamp, UInt8, UInt16,
    UInt32, UInt64, Unit, background, get_timestamp, isSet, unit)
from numpy import polyfit

from .interlock import SingleInterlock
from .master import EtherCATDevice


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
    lastvalue = None

    def update_properties(self):
        if self.device.value != self.lastvalue:
            self.value = self.device.value * self.the_channel.factor \
                    + self.the_channel.offset
            self.lastvalue = self.device.value

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
        return ret + tuple(self.switchDevices)

    async def join(self, syncGroup):
        await super().join(syncGroup)
        if self.switchChannel:
            self.switchDevices = tuple(
                optionalFusedOutput(self.find_channel(c))
                for c in self.switchChannel.split(','))
        else:
            self.switchDevices = ()


class OptionalSwitchMixin(OptionalMixin):
    startupValue = Bool(
        displayedName="Start Powered?",
        description="Should the power be automatically switched on?",
        accessMode=AccessMode.INITONLY, defaultValue=False)

    def update_properties(self):
        for d in self.switchDevices:
            if d.value == 2:
                return State.ERROR, 'fuse reported error'

    def initialize(self):
        super().initialize()
        for d in self.switchDevices:
            d.value = self.startupValue.value

    @Slot()
    async def on(self):
        for d in self.switchDevices:
            d.value = 1
        await self.state_change.wait()

    @Slot()
    async def off(self):
        for d in self.switchDevices:
            d.value = 0
        await self.state_change.wait()


class OptionalKeepOnMixin(OptionalMixin):
    def update_properties(self):
        ret = super().update_properties()
        for d in self.switchDevices:
            if d.value == 2:
                return State.ERROR
            d.value = 1
        return ret

    @Slot()
    async def reset(self):
        for d in self.switchDevices:
            d.value = 1
        await self.state_change.wait()


class DigitalOutput(OptionalSwitchMixin):
    switchChannel = Overwrite(assignment=Assignment.MANDATORY)

    def get_devices(self):
        return self.switchDevices

    def update_properties(self):
        ret = super().update_properties()
        if ret is not None:
            return ret
        if all(d.data for d in self.switchDevices):
            return State.ON
        if any(d.data for d in self.switchDevices):
            return State.CHANGING
        return State.OFF

    on = Overwrite(allowedStates={State.OFF})
    off = Overwrite(allowedStates={State.ON})


class PressureGauge(OptionalSwitchMixin, EtherCATDevice):
    """An analog input that converts to a pressure

    This device takes an analog input and converts it into a pressure reading
    according to the formula

    .. math::

        P = 10^{\\textbf{factor} U / \\textrm V + \\textbf{offset}}
        \\textrm{mbar}

    where *P* is the pressure and *U* the voltage, **factor** and **offset**
    are user-defined parameters.
    """
    channel = String(accessMode=AccessMode.INITONLY,
                     assignment=Assignment.MANDATORY)

    value = Double(accessMode=AccessMode.READONLY, unitSymbol=Unit.BAR,
                   metricPrefixSymbol=MetricPrefix.MILLI,
                   relativeError=0.01, allowedStates={State.ON})
    factor = Double(
        accessMode=AccessMode.INITONLY, assignment=Assignment.MANDATORY,
        description="the raw voltage is multiplied by this factor")
    offset = Double(
        accessMode=AccessMode.INITONLY, assignment=Assignment.MANDATORY,
        description="the offset added to the raw value times factor")
    minimum = Double(
        accessMode=AccessMode.INITONLY, defaultValue=1, unitSymbol=Unit.VOLT,
        description="Below this voltage, the gauge is considered to be off")
    maximum = Double(
        accessMode=AccessMode.INITONLY, defaultValue=8, unitSymbol=Unit.VOLT,
        description="Above this voltage, "
        "the gauge is considered to have an error")

    old_value = -1
    old_time = monotonic()

    def update_properties(self):
        if (ret := super().update_properties()) is not None:
            return ret
        semiRaw = self.device.value * self.the_channel.factor \
                + self.the_channel.offset
        if semiRaw < self.minimum.value:
            return State.OFF
        elif semiRaw > self.maximum.value:
            return State.ERROR, 'gauge reported error'
        else:
            newtime = monotonic()
            if abs(self.old_value - self.device.value) \
                    > 10 / (newtime - self.old_time):
                self.value = 10 ** (semiRaw * self.factor + self.offset) \
                    * unit.mbar * now()
                self.old_value = self.device.value
                self.old_time = newtime
            return State.ON

    async def join(self, syncGroup):
        await super().join(syncGroup)
        self.the_channel = self.find_channel(self.channel)
        self.device = AnalogInputDevice(self.the_channel.value)


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
    """A combination of an analog output and input

    This device writes to an analog output and reads from another
    one. One may ramp the voltage slowly.
    """
    inputChannel = String(accessMode=AccessMode.INITONLY,
                          assignment=Assignment.MANDATORY)
    outputChannel = String(accessMode=AccessMode.INITONLY,
                           assignment=Assignment.MANDATORY)

    inputCalibration = Float(
        defaultValue=1, accessMode=AccessMode.INITONLY,
        description="multiply the input by this factor")
    outputCalibration = Float(
        defaultValue=1, accessMode=AccessMode.INITONLY,
        description="divide the output value by this factor")

    target = Float(
        unitSymbol=Unit.VOLT, defaultValue=0,
        description="the target voltage to go to")
    value = Float(
        unitSymbol=Unit.VOLT, accessMode=AccessMode.READONLY,
        description="the voltage read back from the input")
    lastValue = 0
    rampSpeed = Float(
        unitSymbol=Unit.VOLT_PER_SECOND, defaultValue=0,
        description="ramp the output voltage by this speed. "
        "Put 0 for immediate setting")

    async def join(self, syncGroup):
        await super().join(syncGroup)
        self.device = MonitoredOutputDevice()
        self.device.lastTime = monotonic() * unit.second
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
    error = DeviceVar()

    def program(self):
        self.counter += 1
        with self.ebpf.tmp:
            self.ebpf.tmp = ktime(self.ebpf)
            with self.ebpf.tmp - self.lasttime > self.maxtime:
                self.maxtime = self.ebpf.tmp - self.lasttime
            self.lasttime = self.ebpf.tmp

    def update(self):
        self.counter += 1
        tmp = int(monotonic() * 1e6)
        if tmp - self.lasttime > self.maxtime:
            self.maxtime = tmp - self.lasttime
        self.lasttime = tmp

        import time
        if self.error:
            time.sleep(self.error / 1000)
            self.error = 0


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
        self.device.error = int(self.errorSleep.value)


class MotorDevice(Device):
    velocity = TerminalVar()
    encoder = TerminalVar()
    low_switch = TerminalVar()
    high_switch = TerminalVar()
    enable = TerminalVar()
    reset = TerminalVar()
    error = TerminalVar()
    reduced_current = TerminalVar()
    stepcounter = TerminalVar()

    tstatus = TerminalVar()
    encoder_error = TerminalVar()

    set_enable = DeviceVar('B')
    deadband_exceeded = DeviceVar('b')
    max_velocity = DeviceVar('q')
    max_acceleration = DeviceVar('i')
    deadband = DeviceVar('q')
    target = DeviceVar('q')
    proportional = DeviceVar('q')
    modulo = None

    def program(self, leader=None):
        self.reset = (self.set_enable & 2) != 0
        self.enable = (self.set_enable & 1) != 0
        with abs(self.target - self.encoder) < self.deadband as Else:
            self.reduced_current = True
        with Else:
            self.reduced_current = False
            self.deadband_exceeded = 1
        with self.ebpf.stmp:
            self.ebpf.stmp = self.target - self.encoder
            if self.modulo:
                self.ebpf.stmp = (self.ebpf.stmp + self.modulo) \
                                 % (2 * self.modulo) - self.modulo
            self.ebpf.stmp = (self.proportional * self.ebpf.stmp) >> 16
            if leader is not None:
                with (self.set_enable & 4) != 0:
                    self.ebpf.stmp += \
                        (int(self.motors_factor * self.follow_factor
                             * (1 << 16)) * leader.velocity) >> 16
            with self.ebpf.stmp > self.max_velocity:
                self.ebpf.stmp = self.max_velocity
            with self.ebpf.stmp + self.max_velocity < 0:
                self.ebpf.stmp = -self.max_velocity
            if not self.isLimitless:
                with ((self.low_switch != 0) & (self.ebpf.stmp < 0)):
                    self.ebpf.stmp = 0
                with ((self.high_switch != 0) & (self.ebpf.stmp > 0)):
                    self.ebpf.stmp = 0
            if self.encoder_error is not None:
                with self.encoder_error:
                    self.ebpf.stmp = 0
            self.velocity = self.ebpf.stmp


class Motor(OptionalKeepOnMixin, EtherCATDevice):
    """A stepper motor with encoder device
    """

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
    motorStep = Float(
        displayedName='Motor Stepsize',
        accessMode=AccessMode.INITONLY, defaultValue=5e-5,
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)
    motorStepMeasured = Float(
        displayedName='Motor Stepsize as Measured',
        accessMode=AccessMode.READONLY,
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
    actualVelocity = Float(
        displayedName='Actual Velocity',
        unitSymbol=Unit.METER_PER_SECOND,
        metricPrefixSymbol=MetricPrefix.MILLI,
        accessMode=AccessMode.READONLY)

    motor_term = encoder_term = None

    isLimitless = Bool(
        displayedName='Is Limitless?', description='Ignore the limit switches',
        defaultValue=False, accessMode=AccessMode.INITONLY)
    isCWLimit = Bool(
        displayedName='At Positive Limit?',
        accessMode=AccessMode.READONLY)
    isCCWLimit = Bool(
        displayedName='At Negative Limit?',
        accessMode=AccessMode.READONLY)

    targetVelocity = Float(
        displayedName='Target Velocity', defaultValue=1,
        unitSymbol=Unit.METER_PER_SECOND,
        metricPrefixSymbol=MetricPrefix.MILLI)
    targetPosition = Float(
        displayedName='Target Position',
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)
    stepSize = Float(
        displayedName='Step Size', defaultValue=1,
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)

    @Float()
    async def stepLength(self, value):
        """Legacy version of stepSize"""
        if isSet(value):
            self.stepLength = self.stepSize = value.value

    Device = MotorDevice

    async def join(self, syncGroup):
        await super().join(syncGroup)
        self.device = self.Device()
        self.motor_term = self.find_channel(self.motor)
        self.encoder_term = self.find_channel(self.encoder)
        self.device.velocity = self.motor_term.velocity
        self.device.isLimitless = self.isLimitless.value
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
        if hasattr(self.motor_term, 'stepcounter'):
            self.device.stepcounter = self.motor_term.stepcounter
        self.device.enable = self.motor_term.enable
        self.device.error = self.motor_term.error
        self.device.reset = self.motor_term.reset
        self.device.reduced_current = self.motor_term.reduced_current
        self.counts = []
        self.encoders = []

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
        await super().reset()
        self.device.set_enable = 2
        await sleep(0.2)
        self.device.set_enable = 0

    lastvelocity = lastposition = 0

    def update_properties(self):
        baseFrequency = 128000 / 0x7fff * unit.Hz  # base frequency of EL7041

        if abs(self.device.encoder - self.lastposition) > 3:
            self.actualPosition = (self.device.encoder * self.encodeStep
                                   + self.offset) * now()
            self.lastposition = self.device.encoder
        if abs(self.device.velocity - self.lastvelocity) > 3:
            self.actualVelocity = self.device.velocity * self.motorStep \
                    * baseFrequency * now()
            self.lastvelocity = self.device.velocity
        if self.device.low_switch != self.isCCWLimit:
            self.isCCWLimit = self.device.low_switch
        if self.device.high_switch != self.isCWLimit:
            self.isCWLimit = self.device.high_switch

        self.device.deadband_exceeded = 0
        self.device.max_velocity = \
            min(0x7fff, int(self.targetVelocity / self.motorStep
                            / baseFrequency))
        self.device.proportional = int(self.proportional * self.encodeStep
                                       / self.motorStep * (1 << 16))
        self.device.deadband = int(self.deadband // self.encodeStep)

        if self.state == State.MOVING:
            self.counts.append(self.device.stepcounter)
            self.encoders.append(self.device.encoder)
            if len(self.counts) >= 100:
                slope, _ = polyfit(self.counts, self.encoders, 1)
                self.motorStepMeasured = slope * self.encodeStep * now()
                self.counts = []
                self.encoders = []

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


class RotationMotor(Motor):
    """A stepper motor with degrees as unit"""
    encodeStep = Overwrite(unitSymbol=Unit.DEGREE,
                           metricPrefixSymbol=MetricPrefix.NONE)
    motorStep = Overwrite(unitSymbol=Unit.DEGREE,
                          metricPrefixSymbol=MetricPrefix.NONE)
    motorStepMeasured = Overwrite(unitSymbol=Unit.DEGREE,
                                  metricPrefixSymbol=MetricPrefix.NONE)
    offset = Overwrite(unitSymbol=Unit.DEGREE,
                       metricPrefixSymbol=MetricPrefix.NONE)
    deadband = Overwrite(unitSymbol=Unit.DEGREE,
                         metricPrefixSymbol=MetricPrefix.NONE)
    actualPosition = Overwrite(unitSymbol=Unit.DEGREE,
                               metricPrefixSymbol=MetricPrefix.NONE)
    actualVelocity = Overwrite(unitSymbol=Unit.HERTZ,
                               metricPrefixSymbol=MetricPrefix.NONE)
    targetVelocity = Overwrite(unitSymbol=Unit.HERTZ,
                               metricPrefixSymbol=MetricPrefix.NONE)
    targetPosition = Overwrite(unitSymbol=Unit.DEGREE,
                               metricPrefixSymbol=MetricPrefix.NONE)
    stepSize = Overwrite(unitSymbol=Unit.DEGREE,
                         metricPrefixSymbol=MetricPrefix.NONE)
    modulo = Float(
        description="""Restart counting at this position.
        Set to 0 if motor cannot go around.""",
        unitSymbol=Unit.DEGREE, defaultValue=360,
        accessMode=AccessMode.INITONLY)

    async def join(self, syncGroup):
        await super().join(syncGroup)
        self.device.modulo = int(self.modulo // (2 * self.encodeStep))


class FollowerDevice(MotorDevice):
    follow_offset = DeviceVar('q')

    def program(self):
        with (self.set_enable & 4) != 0:
            self.target = ((self.leader.encoder
                           * int(self.follow_factor * (1 << 16))) >> 16) \
                        + self.follow_offset
            with abs(self.target - self.encoder) > self.follow_lag:
                self.set_enable = 0
                self.leader.set_enable = 0
        super().program(self.leader)

class MotorFollower(Motor):
    """A stepper motor that may follow another motor"""
    Device = FollowerDevice

    leader = String(assignment=Assignment.MANDATORY)
    factor = Float(accessMode=AccessMode.INITONLY, defaultValue=1)
    maxLag = Float(
        displayedName='Maximum Lag',
        accessMode=AccessMode.INITONLY, unitSymbol=Unit.METER,
        metricPrefixSymbol=MetricPrefix.MILLI, defaultValue=0.1)

    async def join(self, syncGroup):
        await super().join(syncGroup)
        leader = self.getLocalDevice(self.leader)
        self.device.leader = leader.device
        self.device.follow_factor = self.factor.value
        self.device.motors_factor = (leader.motorStep / self.motorStep).value
        self.device.follow_lag = int(self.maxLag // self.encodeStep)

    @Slot(allowedStates={State.ON})
    async def couple(self):
        """start following the leader at this positon"""
        self.device.follow_offset = \
            int(self.device.encoder - self.device.leader.encoder * self.factor)
        self.device.set_enable = 5
        await self.state_change.wait()

    def update_properties(self):
        ret = super().update_properties()
        if ret in (State.MOVING, State.ON) and self.device.set_enable & 4:
            return State.INTERLOCKED
        return ret


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
    onSpeed = UInt16(accessMode=AccessMode.INITONLY, defaultValue=990)

    @Slot()
    async def start(self):
        self.device.set_pump_on = True

    @Slot()
    async def stop(self):
        self.device.set_pump_on = False

    def update_properties(self):
        if self.current != self.device.current:
            self.current = self.device.current
        if self.speed != self.device.speed:
            self.speed = self.device.speed
        if self.device.pump_is_on:
            if self.device.speed >= self.onSpeed:
                return State.ON
            else:
                return State.STARTING
        else:
            if self.device.speed > 1:
                return State.STOPPING
            else:
                return State.OFF

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
        self.value = self.device.value
        if self.device.valid:
            return State.ON
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


class Valve(OptionalKeepOnMixin, SingleInterlock, EtherCATDevice):
    """A standard valve, one coil and two limit switches"""
    coil = String(accessMode=AccessMode.INITONLY,
                  assignment=Assignment.MANDATORY)
    openSwitch = String(accessMode=AccessMode.INITONLY)
    closeSwitch = String(accessMode=AccessMode.INITONLY)
    safeState = Bool(
        displayedName='Safe State',
        description="""The 'normal' state to go to when off,
        True for normally open, False for normally closed""",
        accessMode=AccessMode.INITONLY, defaultValue=False)
    movingTime = Float(
        displayedName='moving time limit',
        description="""the maximum time the valve may not be at its limit
        before it is considered an error""",
        accessMode=AccessMode.INITONLY, unitSymbol=Unit.SECOND,
        defaultValue=3)

    isOpened = Bool(displayedName='Is Open?', accessMode=AccessMode.READONLY)
    isClosed = Bool(displayedName='Is Closed?', accessMode=AccessMode.READONLY)

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
        self.device.lastGood = monotonic()

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
        """open and close the valve regularly"""
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
        ret = super().update_properties()
        if isinstance(ret, tuple) and ret[0] == State.INTERLOCKED:
            self.device.target = False
            self.device.divisor = 0
            if self.device.error:
                return State.ERROR
            else:
                return ret
        elif ret is not None:
            return ret
        if self.device.error:
            return State.ERROR
        elif self.device.divisor > 0:
            return State.MOVING
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
    """A valve with a second coil for slow pumping"""
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
    """A shutter that is operated by a motor

    this device sets a positive or negative speed to a motor in order to open
    or close a shutter, respectively.
    """
    velocity = String(accessMode=AccessMode.INITONLY,
                  assignment=Assignment.MANDATORY)
    enable = String(accessMode=AccessMode.INITONLY,
                  assignment=Assignment.MANDATORY)
    openSwitch = String(accessMode=AccessMode.INITONLY,
                        assignment=Assignment.MANDATORY)
    closeSwitch = String(accessMode=AccessMode.INITONLY,
                         assignment=Assignment.MANDATORY)
    movingTime = Float(
        accessMode=AccessMode.INITONLY, unitSymbol=Unit.SECOND, defaultValue=3,
        description="The maximum time it takes to reach a limit switch")
    speed = Int16(
        accessMode=AccessMode.INITONLY, defaultValue=3, minInc=0,
        description="The speed to set the motor to for opening and closing")

    async def join(self, syncGroup):
        await super().join(syncGroup)
        self.device = ShutterDevice()
        self.device.reset()
        self.device.velocity = self.find_channel(self.velocity)
        self.device.openSwitch = self.find_channel(self.openSwitch)
        self.device.closeSwitch = self.find_channel(self.closeSwitch)
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
        elif self.device.velocity > 0:
            return State.OPENING
        elif self.device.velocity < 0:
            return State.CLOSING
        else:
            return State.ERROR


class EtherCATSCPIMaster(EtherCATDevice):
    terminal = String(accessMode=AccessMode.INITONLY,
                      assignment=Assignment.MANDATORY)

    allowLF = False  # duck-typing an SCPI Master

    def __init__(self, configuration):
        from scpiDevices.scpi import GenericSCPIMaster

        super().__init__(configuration)
        self.connectEvent = GenericSCPIMaster.instances.setdefault(
            self.deviceId.value, Event())

    async def join(self, syncGroup):
        await super().join(syncGroup)
        self.channel = self.find_channel(self.terminal)
        self.device = Serial(self.channel)

        async def initialize():
            self.reader, self.writer = await self.device.connect()
            self.lock = Lock()
            self.connectEvent.set()
            self.state = State.ON

        self.state = State.INIT
        background(initialize())


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
        displayedName='Actual Position', accessMode=AccessMode.READONLY,
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)
    actualVelocity = Float(
        displayedName='Actual Velocity', accessMode=AccessMode.READONLY,
        unitSymbol=Unit.METER_PER_SECOND,
        metricPrefixSymbol=MetricPrefix.MILLI)
    homed = Bool(
        displayedName='Homed', accessMode=AccessMode.READONLY)
    error = Int32(
        displayedName='Error Code',
        accessMode=AccessMode.READONLY)
    targetPosition = Float(
        displayedName='Target Position',
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)
    targetVelocity = Float(
        displayedName='Target Velocity', defaultValue=1, minExc=0,
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

    @Slot(allowedStates={State.OFF})
    async def on(self):
        self.device.command = 4

    @Slot(allowedStates={State.ON})
    async def off(self):
        self.device.command = 5

    @Slot(allowedStates={State.ERROR})
    async def reset(self):
        self.device.command = 2

    @Slot(allowedStates={State.ON})
    async def home(self):
        self.device.command = 3

    @Slot(allowedStates={State.ON, State.MOVING})
    async def move(self):
        self.device.targetPosition = self.targetPosition.value
        self.device.targetVelocity = self.targetVelocity.value
        self.device.command = 1

    @Slot(allowedStates={State.MOVING})
    async def stop(self):
        self.device.command = 6

    stepSize = Float(
        displayedName='Step Size', minExc=0, defaultValue=1,
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)

    @Slot(allowedStates={State.ON})
    async def stepUp(self):
        self.targetPosition = self.actualPosition + self.stepSize
        await self.move()

    @Slot(allowedStates={State.ON})
    async def stepDown(self):
        self.targetPosition = self.actualPosition - self.stepSize
        await self.move()

    def update_properties(self):
        self.actualPosition = self.device.actualPosition
        self.actualVelocity = self.device.actualVelocity
        self.homed = self.device.homed

        self.state = (State.OFF, State.ON, State.MOVING, State.ERROR) \
            [self.device.status]

        if self.error != self.device.error:
            self.error = self.device.error
            self.status = (
                "All OK",
                "Lower Limit",
                "Upper Limit",
                "Too slow",
                "Too fast",
                "Not homed",
            )[self.device.error]
