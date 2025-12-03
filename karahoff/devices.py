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

.. autoclass:: RotationMotor()
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
from ebpfcat.devices import DigitalInput
from ebpfcat.ebpf import LocalVar, ktime
from ebpfcat.ebpfcat import Device, DeviceVar, Struct, TerminalVar
from ebpfcat.serial import Serial
from karabo.middlelayer import (
    AccessMode, Assignment, Bool, Double, Float, Int16, Int32, Int64, MetricPrefix,
    Overwrite, QuantityValue, Slot, State, String, TimeMixin, Timestamp,
    UInt16, UInt64, Unit, background, get_timestamp, isSet, unit)
from numpy import polyfit
from numpy.linalg import LinAlgError

from .interlock import Interlock, InterlockSlot
from .master import EtherCATDevice


def now():
    return QuantityValue(1, timestamp=get_timestamp())


class GenericInput(EtherCATDevice):
    channel = String(accessMode=AccessMode.INITONLY,
                     assignment=Assignment.MANDATORY)
    value = Double(accessMode=AccessMode.READONLY)

    def update_properties(self):
        self.value = self.device.value

    def join(self, syncGroup):
        super().join(syncGroup)
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

    def join(self, syncGroup):
        super().join(syncGroup)
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


    def join(self, syncGroup):
        super().join(syncGroup)
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
    switchChannel = String(
        accessMode=AccessMode.INITONLY,
        description="""List here the digital output channels (comma separated)
        that need to be on for this device to function. Leave empty if there
        are none""")

    def get_devices(self):
        ret = super().get_devices()
        return ret + tuple(self.switchDevices)

    def join(self, syncGroup):
        super().join(syncGroup)
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
                return State.ERROR, "fuse failed"
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

    def join(self, syncGroup):
        super().join(syncGroup)
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

    def join(self, syncGroup):
        super().join(syncGroup)
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

    def join(self, syncGroup):
        super().join(syncGroup)
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

    def join(self, syncGroup):
        super().join(syncGroup)
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
    enabled = TerminalVar()
    control_word = TerminalVar()
    reduced_current = TerminalVar()
    stepcounter = TerminalVar()

    encoder_error = TerminalVar()

    set_control_word = DeviceVar('H')
    deadband_exceeded = DeviceVar('b')
    max_velocity = DeviceVar('q')
    last_velocity = DeviceVar('q')
    max_acceleration = DeviceVar('Q')
    deadband = DeviceVar('q')
    target = DeviceVar('q')
    proportional = DeviceVar('q')
    lasttime = DeviceVar('Q')
    velocity_diff = LocalVar('q')

    def calculate_speed(self):
        self.ebpf.stmp = (self.proportional * self.ebpf.stmp) >> 16

    def program(self):
        with self.ebpf.tmp:
            self.ebpf.tmp = ktime(self.ebpf)
            self.velocity_diff = (self.max_acceleration
                                  * (self.ebpf.tmp - self.lasttime)) >> 32
            with self.velocity_diff > 0 as Else:
                self.lasttime = self.ebpf.tmp

        self.control_word = self.set_control_word
        with abs(self.target - self.encoder) > self.deadband as Else:
            if self.reduced_current is not None:
                self.reduced_current = False
            self.deadband_exceeded = 1
        if self.reduced_current is not None:
            with Else:
                self.reduced_current = True
        with self.ebpf.stmp:
            self.ebpf.stmp = self.target - self.encoder
            self.calculate_speed()
            with self.ebpf.stmp > self.max_velocity:
                self.ebpf.stmp = self.max_velocity
            with self.ebpf.stmp + self.max_velocity < 0:
                self.ebpf.stmp = -self.max_velocity
            if not self.isLimitless:
                with (((self.low_switch != 0) & (self.ebpf.stmp < 0))
                      | ((self.high_switch != 0) & (self.ebpf.stmp > 0))):
                    self.ebpf.stmp = 0
                    self.target = self.encoder
            if self.encoder_error is not None:
                with self.encoder_error:
                    self.ebpf.stmp = 0
            self.velocity = self.ebpf.stmp
            with self.ebpf.stmp > self.last_velocity + self.velocity_diff as Else:
                self.velocity = self.last_velocity + self.velocity_diff
            with Else, self.last_velocity > self.ebpf.stmp + self.velocity_diff:
                self.velocity = self.last_velocity - self.velocity_diff
            with self.enabled as Else:
                self.last_velocity = self.velocity
            with Else:
                self.last_velocity = 0


class Motor(OptionalKeepOnMixin, Interlock, EtherCATDevice):
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
    rawPosition = Int64(accessMode=AccessMode.READONLY)
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
    maxAcceleration = Float(defaultValue=10)

    targetVelocity = Float(
        displayedName='Target Velocity', defaultValue=1,
        unitSymbol=Unit.METER_PER_SECOND,
        metricPrefixSymbol=MetricPrefix.MILLI)
    targetPosition = Float(
        displayedName='Target Position',
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)
    stepSize = Float(
        displayedName='Step Size', defaultValue=1, minExc=0,
        unitSymbol=Unit.METER, metricPrefixSymbol=MetricPrefix.MILLI)

    @Float()
    async def stepLength(self, value):
        """Legacy version of stepSize"""
        if isSet(value):
            self.stepLength = self.stepSize = value.value

    Device = MotorDevice

    def join(self, syncGroup):
        super().join(syncGroup)
        self.device = self.Device()
        self.motor_term = self.find_channel(self.motor)
        from ebpfcat.terminals import EL7062
        if isinstance(self.motor_term, EL7062.Channel):
            self.isServo = True
            self.FAULT_RESET = 0x80
            self.SHUTDOWN = 6
            self.SWITCH_OFF = 7
            self.ENABLE = 0xf
        else:
            self.isServo = False
            self.FAULT_RESET = 2
            self.ENABLE = 1
            self.SWITCH_OFF = self.SHUTDOWN = 0
        self.encoder_term = self.find_channel(self.encoder)
        self.device.velocity = self.motor_term.velocity
        self.device.isLimitless = self.isLimitless.value
        self.device.low_switch = self.motor_term.low_switch
        self.device.high_switch = self.motor_term.high_switch
        if isinstance(self.encoder_term, Struct):
            self.device.encoder = self.encoder_term.position
            self.device.encoder_error = self.encoder_term.error
            self.terminals = dict(M=self.motor_term, E=self.encoder_term)
        else:
            self.device.encoder = self.encoder_term
            self.terminals = dict(M=self.motor_term, E=None)
        if hasattr(self.motor_term, 'stepcounter'):
            self.device.stepcounter = self.motor_term.stepcounter
        self.device.control_word = self.motor_term.control
        self.device.enabled = self.motor_term.enabled
        if hasattr(self.motor_term, 'reduced_current'):
            self.device.reduced_current = self.motor_term.reduced_current

        self.counts = []
        self.encoders = []

    @Slot(displayedName='Move',
          allowedStates={State.OFF, State.ON, State.MOVING,
                         State.MOVING_FORWARD, State.MOVING_BACK})
    async def move(self):
        self._move()
        # just in case await twice, to guarantee the device goes to the right
        # state. Not sure whether that's actually necessay, didn't test
        await self.state_change.wait()
        await self.state_change.wait()

    def _move(self):
        self.device.target = int((self.targetPosition - self.offset)
                                 // self.encodeStep)
        self.device.set_control_word = self.ENABLE

    @Slot(displayedName='Stop',
          allowedStates={State.ON, State.MOVING,
                         State.MOVING_FORWARD, State.MOVING_BACK})
    async def stop(self):
        self.device.target = self.device.encoder

    @Slot(displayedName='On',
          allowedStates={State.OFF, State.ON, State.MOVING, State.ENGAGED,
                         State.MOVING_FORWARD, State.MOVING_BACK})
    async def on(self):
        self.targetPosition = self.actualPosition
        await self.move()

    @InterlockSlot(displayedName='Off',
                   allowedStates={State.ON, State.MOVING, State.ENGAGED,
                                  State.MOVING_FORWARD, State.MOVING_BACK})
    def off(self):
        self.device.set_control_word = self.SWITCH_OFF

    @Slot(displayedName='Step Up',
          allowedStates={State.OFF, State.ON, State.MOVING,
                         State.MOVING_FORWARD})
    async def stepUp(self):
        self.targetPosition = self.actualPosition + self.stepSize
        await self.move()

    @Slot(displayedName='Step Down',
          allowedStates={State.OFF, State.ON, State.MOVING,
                         State.MOVING_BACK})
    async def stepDown(self):
        self.targetPosition = self.actualPosition - self.stepSize
        await self.move()

    @Slot()
    async def reset(self):
        await super().reset()
        self.device.set_control_word = self.FAULT_RESET
        await sleep(0.2)
        self.device.set_control_word = self.SHUTDOWN

    keepDisabled = False

    @Slot()
    async def disable(self):
        self.device.set_control_word = 0
        self.keepDisabled = True

    lastvelocity = lastposition = 100j  # always far away from the real value
    baseFrequency = 128000 / 0x7fff * unit.Hz  # base frequency of EL7041

    def update_properties(self):
        self.device.max_acceleration = \
            int((self.maxAcceleration/ self.motorStep / 1e9 * 2**32).value)
        if abs(self.device.encoder - self.lastposition) > 3:
            self.actualPosition = (self.device.encoder * self.encodeStep
                                   + self.offset) * now()
            self.rawPosition = self.device.encoder
            if not isSet(self.targetPosition):
                self.targetPosition = self.actualPosition
            self.lastposition = self.device.encoder
        if abs(self.device.velocity - self.lastvelocity) > 3:
            self.actualVelocity = self.device.velocity * self.motorStep \
                    * self.baseFrequency * now()
            self.lastvelocity = self.device.velocity
        if self.device.low_switch != self.isCCWLimit:
            self.isCCWLimit = self.device.low_switch
        if self.device.high_switch != self.isCWLimit:
            self.isCWLimit = self.device.high_switch

        self.device.deadband_exceeded = 0
        self.device.max_velocity = \
            min(0x7fff, int(self.targetVelocity / self.motorStep
                            / self.baseFrequency))
        self.device.proportional = int(self.proportional * self.encodeStep
                                       / self.motorStep * (1 << 16))
        self.device.deadband = int(self.deadband // self.encodeStep)

        if self.state == State.MOVING:
            self.counts.append(self.device.stepcounter)
            self.encoders.append(self.device.encoder)
            if len(self.counts) >= 100:
                try:
                    slope, _ = polyfit(self.counts, self.encoders, 1)
                except LinAlgError:
                    pass
                else:
                    self.motorStepMeasured = slope * self.encodeStep * now()
                    self.counts = []
                    self.encoders = []

        if (ret := super().update_properties()) is not None:
            return ret
        elif self.terminals["E"] is not None and self.device.encoder_error:
            return State.ERROR, f'encoder reported error'
        elif self.motor_term.error.get(self.device):
            return State.ERROR, 'motor reported error'
        elif self.isServo \
                and not self.motor_term.ready_switch_on.get(self.device):
            if self.motor_term.switch_on_disabled.get(self.device):
                if not self.keepDisabled:
                    self.device.set_control_word = self.SHUTDOWN
                return State.DISABLED
            else:
                return State.STARTING
        elif not self.motor_term.enabled.get(self.device):
            if self.isServo \
                    and not self.motor_term.switched_on.get(self.device):
                self.device.set_control_word = self.SWITCH_OFF
                return State.SWITCHING_ON
            else:
                return State.OFF
        elif self.device.deadband_exceeded and self.device.velocity != 0:
            return State.MOVING
        elif not self.isLimitless:
            if self.device.low_switch:
                if self.device.proportional > 0:
                    return State.MOVING_FORWARD
                else:
                    return State.MOVING_BACK
            elif self.device.high_switch:
                if self.device.proportional > 0:
                    return State.MOVING_BACK
                else:
                    return State.MOVING_FORWARD
        return State.ON


class RotationDevice(MotorDevice):
    def calculate_speed(self):
        if self.modulo:
            # we need to add a huge number to avoid signed modulo
            self.ebpf.stmp = (
                self.ebpf.stmp
                + (self.modulo + 2 * (0x80000000 // self.modulo + 1)
                   * self.modulo)) % (2 * self.modulo) - self.modulo
        super().calculate_speed()


class RotationMotor(Motor):
    """A stepper motor with degrees as unit"""
    Device = RotationDevice

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
                               metricPrefixSymbol=MetricPrefix.MILLI)
    targetVelocity = Overwrite(unitSymbol=Unit.HERTZ,
                               metricPrefixSymbol=MetricPrefix.MILLI)
    targetPosition = Overwrite(unitSymbol=Unit.DEGREE,
                               metricPrefixSymbol=MetricPrefix.NONE)
    stepSize = Overwrite(unitSymbol=Unit.DEGREE,
                         metricPrefixSymbol=MetricPrefix.NONE)
    modulo = Float(
        description="""Restart counting at this position.
        Set to 0 if motor cannot go around.""",
        unitSymbol=Unit.DEGREE, defaultValue=360,
        accessMode=AccessMode.INITONLY)

    def join(self, syncGroup):
        super().join(syncGroup)
        self.device.modulo = int(self.modulo // (2 * self.encodeStep))


class FollowerDevice(MotorDevice):
    follow_offset = DeviceVar('q')
    doFollow = DeviceVar('B')

    def calculate_speed(self):
        super().calculate_speed()
        with (self.doFollow != 0) \
                & (self.leader.device.enabled != 0):
            self.ebpf.stmp += \
                (int(self.motors_factor * self.follow_factor * (1 << 16)) \
                * self.leader.device.velocity) >> 16

    def program(self):
        with self.doFollow != 0:
            self.target = ((self.leader.device.encoder
                           * int(self.encoders_factor * self.follow_factor
                                 * (1 << 16))) >> 16) + self.follow_offset
            with abs(self.target - self.encoder) > self.follow_lag:
                self.set_control_word = self.SWITCH_OFF
                self.doFollow = 0
                self.leader.device.set_control_word = self.leader.SWITCH_OFF
        super().program()


class MotorFollower(Motor):
    """A stepper motor that may follow another motor"""
    Device = FollowerDevice

    leader = String(assignment=Assignment.MANDATORY)
    factor = Float(accessMode=AccessMode.INITONLY, defaultValue=1)
    maxLag = Float(
        displayedName='Maximum Lag',
        accessMode=AccessMode.INITONLY, unitSymbol=Unit.METER,
        metricPrefixSymbol=MetricPrefix.MILLI, defaultValue=0.1)

    def join(self, syncGroup):
        super().join(syncGroup)
        leader = self.getLocalDevice(self.leader)
        self.device.leader = leader
        self.device.SWITCH_OFF = self.SWITCH_OFF
        self.device.follow_factor = self.factor.value
        self.device.motors_factor = (leader.motorStep / self.motorStep).value
        self.device.encoders_factor = (leader.encodeStep
                                       / self.encodeStep).value
        self.device.follow_lag = int(self.maxLag // self.encodeStep)

    @Slot(displayedName='Move',
          allowedStates={State.OFF, State.ON, State.MOVING, State.ENGAGED,
                         State.MOVING_FORWARD, State.MOVING_BACK})
    async def move(self):
        self.device.doFollow = 0
        await super().move()

    @Slot(displayedName='Engage', allowedStates={State.ON})
    async def couple(self):
        """start following the leader at this positon"""
        leader = self.getLocalDevice(self.leader)
        if leader.state != State.ON:
            self.status = 'cannot couple if leader is not ON'
            return
        self.device.follow_offset = int(
            self.device.encoder
            - self.device.leader.device.encoder * self.device.encoders_factor
            * self.factor)
        self.device.doFollow = 1
        self.device.set_control_word = self.ENABLE
        await self.state_change.wait()

    def update_properties(self):
        ret = super().update_properties()
        if ret in (State.MOVING, State.ON) and self.device.doFollow:
            return State.ENGAGED
        return ret


class RotationFollower(MotorFollower, RotationMotor):
    maxLag = Overwrite(unitSymbol=Unit.DEGREE,
                       metricPrefixSymbol=MetricPrefix.NONE)


class SynchronizeDevice(RotationDevice):
    trigtime = DeviceVar('Q')
    trigposition = DeviceVar('i')
    set_velocity = DeviceVar('h')
    lastswitch = DeviceVar('B')
    doSynchronize = DeviceVar('B')

    def calculate_speed(self):
        super().calculate_speed()
        with self.doSynchronize != 0:
            self.ebpf.stmp = self.set_velocity

    def program(self):
        with (self.high_switch == 0) & (self.lastswitch == 1) \
                & (self.last_velocity > 0):
            self.trigtime = ktime(self.ebpf)
            self.trigposition = self.encoder
        self.lastswitch = self.high_switch
        super().program()


class SynchronizedMotor(RotationMotor):
    Device = SynchronizeDevice

    targetPhase = Float(defaultValue=0)
    lasttrigtime = 0
    timediff = int((monotonic() - time()) * 1e9)

    offset = Double(defaultValue=0, unitSymbol=Unit.DEGREE)

    integral = Float(unitSymbol=Unit.HERTZ, accessMode=AccessMode.READONLY)
    triggerPosition = Float(accessMode=AccessMode.READONLY, unitSymbol=Unit.DEGREE)
    triggerPhase = Float(accessMode=AccessMode.READONLY)

    proportionalTerm = Float(defaultValue=0)
    integralTerm = Float(defaultValue=0)


    def update_properties(self):
        ret = super().update_properties()
        if self.lasttrigtime != self.device.trigtime:
            self.lasttrigtime = self.device.trigtime
            self.triggerPosition = (self.device.trigposition
                                    * self.motorStep) % (360 * unit.degree)
            trainId = ((self.device.trigtime - self.timediff
                        - TimeMixin._time_sec * 1e9
                        - TimeMixin._time_frac * 1e-9)
                       / (TimeMixin._period * 1e3)) + TimeMixin._tid
            error = ((trainId + self.targetPhase.value + 1) % 2 - 1)
            self.triggerPhase = error
            self.offset = -self.device.trigposition * self.encodeStep * now()
            if self.device.doSynchronize:
                self.integral += \
                    error * self.integralTerm.value * unit.Hz * now()
                self.device.set_velocity = \
                    int((self.proportionalTerm.value * error * unit.Hz
                         + self.integral) / self.baseFrequency)
        return ret

    @Slot(displayedName='Move',
          allowedStates={State.OFF, State.ON, State.MOVING,
                         State.MOVING_FORWARD, State.MOVING_BACK})
    async def move(self):
        self.device.doSynchronize = 0
        await super().move()

    @Slot()
    async def synchronize(self):
        self.device.doSynchronize = 1
        self.device.set_control_word = self.ENABLE
        self.integral = 45 * unit.degree \
                / (100 * unit.millisecond * self.motorStep)
        self.device.set_velocity = int(self.integral / self.baseFrequency)


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

    def join(self, syncGroup):
        super().join(syncGroup)
        self.the_terminal = self.find_channel(self.terminal)
        self.device = BronkhorstDevice()
        self.device.owner = self
        self.device.setpoint = self.the_terminal.setpoint
        self.device.current_value = self.the_terminal.current_value
        self.device.controller_output = self.the_terminal.controller_output
        self.device.control_byte = self.the_terminal.control_byte
        self.device.status_word = self.the_terminal.status_word
        #await self.set_mode(None)

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
    speed_status = TerminalVar()
    pump_is_on = TerminalVar()
    speed = TerminalVar()
    current = TerminalVar()

    set_pump_on = DeviceVar('?')

    def update(self):
        self.pump_on = self.set_pump_on


class TurboVac(EtherCATDevice):
    pump = String(accessMode=AccessMode.INITONLY,
                  assignment=Assignment.MANDATORY)
    speed = UInt16(accessMode=AccessMode.READONLY, unitSymbol=Unit.HERTZ)
    current = Float(accessMode=AccessMode.READONLY,
                    unitSymbol=Unit.AMPERE)
    statusbits = UInt16(accessMode=AccessMode.READONLY)

    @Slot()
    async def start(self):
        self.device.set_pump_on = True

    @Slot()
    async def stop(self):
        self.device.set_pump_on = False

    @Slot()
    async def reset(self):
        self.device.set_pump_on = False
        self.device.reset = True
        await sleep(0.3)
        self.device.reset = False

    lastcurrent = None
    laststatus = None

    def update_properties(self):
        if self.lastcurrent != self.device.current:
            self.lastcurrent = self.device.current
            self.current = self.device.current / 10
        if self.speed != self.device.speed:
            self.speed = self.device.speed
        if self.laststatus != self.device.speed_status:
            self.statusbits = self.laststatus = self.device.speed_status
        if self.device.error_status & 7:
            return State.ERROR, f'error status {self.device.error_status}'
        elif self.device.speed_status & 0x10:
            return State.OFF
        elif self.device.speed_status & 0x40:
            return State.STARTED
        elif self.device.speed_status & 0x20:
            return State.STARTING
        elif self.device.speed_status & 0x80:
            return State.STOPPING
        elif self.device.speed_status & 1:
            return State.ON
        else:
            return State.UNKNOWN, f'unknown state {self.device.speed_status:x}'

    def join(self, syncGroup):
        super().join(syncGroup)
        self.device = TurboVacDevice()
        self.pump_term = self.find_channel(self.pump)
        self.device.pump_on = self.pump_term.pump_on
        self.device.error_status = self.pump_term.error_status
        self.device.speed_status = self.pump_term.speed_status
        self.device.pump_is_on = self.pump_term.pump_is_on
        self.device.reset = self.pump_term.reset
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
    value = Float(accessMode=AccessMode.READONLY,
                  unitSymbol=Unit.BAR, metricPrefixSymbol=MetricPrefix.MILLI)

    def join(self, syncGroup):
        super().join(syncGroup)
        self.device = InficonDevice()
        self.gauge_term = self.find_channel(self.gauge)
        self.device.value = self.gauge_term.value
        self.device.valid = self.gauge_term.valid

    def update_properties(self):
        self.value = self.device.value * unit.Pa
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
    divisor = DeviceVar('d')
    opentime = DeviceVar('d')
    delay = DeviceVar('d')

    def update(self):
        if self.divisor > 0:
            self.target = (time() - self.delay) % self.divisor < self.opentime
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


class Valve(OptionalKeepOnMixin, Interlock, EtherCATDevice):
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

    def join(self, syncGroup):
        super().join(syncGroup)
        self.device = ValveDevice()
        self.device.coil = self.find_channel(self.coil)
        if self.openSwitch:
            self.device.openSwitch = self.find_channel(self.openSwitch)
        if self.closeSwitch:
            self.device.closeSwitch = self.find_channel(self.closeSwitch)
        self.device.movingTime = self.movingTime.value
        self.device.safeState = self.safeState.value
        self.device.lastGood = monotonic()
        self.chopping = False

    @InterlockSlot(allowedStates={State.CLOSED, State.CLOSING, State.MOVING})
    def open(self):
        self.chopping = False
        self.device.target = not self.safeState

    @InterlockSlot(allowedStates={State.OPENED, State.OPENING, State.MOVING})
    def close(self):
        self.chopping = False
        self.device.target = self.safeState

    @Slot(allowedStates={State.OPENED, State.MOVING, State.CLOSED})
    async def chopper(self):
        """open and close the valve regularly"""
        self.chopping = True
        await self.state_change.wait()

    @Slot(allowedStates={State.ERROR})
    async def reset(self):
        await super().reset()
        self.chopping = False
        self.device.reset()

    def update_properties(self):
        if self.chopping:
            self.device.divisor = self.divisor * TimeMixin._period * 1e-6
            self.device.delay = TimeMixin._time_sec + TimeMixin._time_frac * 1e-18 \
                    + self.delay / unit.s + self.modulo * TimeMixin._period * 1e-6
            self.device.opentime = TimeMixin._period * 1e-6
        else:
            self.device.divisor = 0
        if self.openSwitch and self.device.openSwitch != self.isOpened:
            self.isOpened = self.device.openSwitch
        if self.closeSwitch and self.device.closeSwitch != self.isClosed:
            self.isClosed = self.device.closeSwitch
        ret = super().update_properties()
        if isinstance(ret, tuple) and ret[0] == State.INTERLOCKED:
            self.device.divisor = 0
            if self.device.error:
                return State.ERROR
            else:
                return ret
        elif ret is not None:
            return ret
        if self.device.error:
            return State.ERROR
        elif self.chopping:
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

    def join(self, syncGroup):
        super().join(syncGroup)
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
    lastGood = monotonic()

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

    def join(self, syncGroup):
        super().join(syncGroup)
        self.device = ShutterDevice()
        self.device.velocity = self.find_channel(self.velocity)
        self.device.openSwitch = self.find_channel(self.openSwitch)
        self.device.closeSwitch = self.find_channel(self.closeSwitch)
        self.device.enable = self.find_channel(self.enable)
        self.device.movingTime = self.movingTime.value
        self.device.speed = self.speed.value

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

    def join(self, syncGroup):
        super().join(syncGroup)
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

    def join(self, syncGroup):
        super().join(syncGroup)
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


class TurboPump(EtherCATDevice):
    rpm80 = String(accessMode=AccessMode.INITONLY,
                   assignment=Assignment.MANDATORY)
    speedChannel = String(accessMode=AccessMode.INITONLY,
                          assignment=Assignment.MANDATORY)

    speed = Float(accessMode=AccessMode.READONLY, unitSymbol=Unit.PERCENT)

    oldvalue = -1

    def get_devices(self):
        return (self.speedDevice, self.rpm80Device)

    def join(self, syncGroup):
        super().join(syncGroup)
        self.the_speedChannel = self.find_channel(self.speedChannel)
        self.speedDevice = AnalogInputDevice(self.the_speedChannel.value)
        self.rpm80Device = DigitalInput(self.find_channel(self.rpm80))

    def update_properties(self):
        if self.speedDevice.value != self.oldvalue:
            self.oldvalue = self.speedDevice.value
            self.speed = (self.speedDevice.value * self.the_speedChannel.factor
                    + self.the_speedChannel.offset) * 10
        if self.rpm80Device.value:
            return State.ON
        else:
            return State.OFF
