from asyncio import gather

from karabo.middlelayer import (
    AccessMode, Bool, Double, Slot, State, String, Unit, unit, waitUntil)
from numpy import arcsin, arctan, pi, sin, sqrt, tan

from .master import EtherCATDevice
from .devices import Safety

SIN = sin(23.75 * unit.degree)
TAN = tan(23.75 * unit.degree)
OFFSET = 100 * unit.degree


class SCS_XRD_TRF(EtherCATDevice):
    trf1 = String(accessMode=AccessMode.INITONLY)
    trf2 = String(accessMode=AccessMode.INITONLY)
    trf3 = String(accessMode=AccessMode.INITONLY)

    targetPosition = Double(unitSymbol=Unit.DEGREE)
    actualPosition = Double(accessMode=AccessMode.READONLY,
                            unitSymbol=Unit.DEGREE)
    trf1error = Double(accessMode=AccessMode.READONLY,
                       unitSymbol=Unit.DEGREE)
    trf3error = Double(accessMode=AccessMode.READONLY,
                       unitSymbol=Unit.DEGREE)

    def get_devices(self):
        return ()

    def join(self, syncGroup):
        super().join(syncGroup)

        self.m1 = self.getLocalDevice(self.trf1)
        self.m2 = self.getLocalDevice(self.trf2)
        self.m3 = self.getLocalDevice(self.trf3)

        self.m1.lockedBy = self.deviceId
        self.m2.lockedBy = self.deviceId
        self.m3.lockedBy = self.deviceId

        self.m1.targetVelocity = 7.0
        self.m2.targetVelocity = 3.0
        self.m3.targetVelocity = 7.0

        self.state = State.OFF

    def update_properties(self):
        current = 2 * arcsin(sin(self.m2.actualPosition / 2) * SIN)
        self.actualPosition = current + OFFSET
        target = -arctan(tan(current / 2) / sqrt(TAN**2 - tan(current / 2)**2))
        self.trf1error = self.m1.actualPosition - target
        self.trf3error = self.m3.actualPosition - target
        if abs(self.trf1error.value) > 0.1 \
                or abs(self.trf3error.value) > 0.1:
            if self.state != State.ERROR:
                self.m1.do_off()
                self.m2.do_off()
                self.m3.do_off()
            state = State.ERROR
        elif self.m1.state != State.ENGAGED or self.m3.state != State.ENGAGED:
            state = State.OFF
        else:
            state = State.ON
        if self.state != state:
            self.state = state

        self.m1.targetPosition = self.m3.targetPosition = target

        self.m1.device.follow_offset = int(
            (target - self.m1.offset) // self.m1.encodeStep
            - self.m2.device.encoder * self.m1.device.encoders_factor * self.m1.factor)
        self.m3.device.follow_offset = int(
            (target - self.m3.offset) // self.m3.encodeStep
            - self.m2.device.encoder * self.m3.device.encoders_factor * self.m3.factor)

    @Slot(allowedStates={State.OFF})
    async def move(self):
        await self.m2.on()
        assert self.m2.state == State.ON
        await self.m1.couple()
        assert self.m1.state == State.ENGAGED
        await self.m3.couple()
        assert self.m3.state == State.ENGAGED
        self.m2.targetPosition = 2 * arcsin(sin((self.targetPosition - OFFSET) / 2) / SIN)
        await self.m2.move()
        self.state = State.ON

    @Slot(allowedStates={State.ERROR})
    async def moveToStart(self):
        current = 2 * arcsin(sin(self.m2.actualPosition / 2) * SIN)
        self.targetPosition = current + OFFSET
        target = -arctan(tan(current / 2) / sqrt(TAN**2 - tan(current / 2)**2))
        self.m1.targetPosition = self.m3.targetPosition = target
        self.m1.do_move()
        self.m3.do_move()

    @Slot()
    async def off(self):
        self.m1.do_off()
        self.m2.do_off()
        self.m3.do_off()
        self.state = State.OFF


class HRIXSSafety(Safety):
    running = Bool(alias='1', accessMode=AccessMode.READONLY)
    button_pressed = Bool(alias='0x100', accessMode=AccessMode.READONLY)
    manual_mode = Bool(alias='4', accessMode=AccessMode.READONLY)
    auto_mode = Bool(alias='2', accessMode=AccessMode.READONLY)
    hutch_searched = Bool(alias='0x10', accessMode=AccessMode.READONLY)
    dty = Bool(alias='0x20', accessMode=AccessMode.READONLY)
    dtz = Bool(alias='0x40', accessMode=AccessMode.READONLY)
    gtz = Bool(alias='0x10', accessMode=AccessMode.READONLY)
    rry = Bool(alias='0x80', accessMode=AccessMode.READONLY)

    RUN_BIT = 2
    ACKNOWLEDGE_BIT = 1

    def update_properties(self):
        state = super().update_properties()
        if state is State.ON and self.device.generic_input & 1:
            state = State.RUNNING
        return state


class FFTSafety(Safety):
    RUN_BIT = 1
    ACKNOWLEDGE_BIT = 2

    running = Bool(alias='0x10', accessMode=AccessMode.READONLY)
    switchedOn = Bool(alias='2', accessMode=AccessMode.READONLY)

    def update_properties(self):
        state = super().update_properties()
        if state is State.ON and self.device.generic_input & 2:
            state = State.RUNNING
        return state
