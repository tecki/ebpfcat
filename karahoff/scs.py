from karabo.middlelayer import (
    AccessMode, Double, Slot, State, String, Unit, unit)
from numpy import arcsin, arctan, pi, sin, sqrt, tan

from .master import EtherCATDevice

SIN = sin(23.75 * pi / 180)
TAN = tan(23.75 * pi / 180)


class SCS_XRD_TRF(EtherCATDevice):
    trf1 = String(accessMode=AccessMode.INITONLY)
    trf2 = String(accessMode=AccessMode.INITONLY)
    trf3 = String(accessMode=AccessMode.INITONLY)

    targetPosition = Double(unitSymbol=Unit.DEGREE)
    actualPosition = Double(unitSymbol=Unit.DEGREE)


    def get_devices(self):
        return ()

    def join(self, syncGroup):
        super().join(syncGroup)

        self.m1 = self.getLocalDevice(self.trf1)
        self.m2 = self.getLocalDevice(self.trf2)
        self.m3 = self.getLocalDevice(self.trf3)

        self.state = State.OFF

    def update_properties(self):
        current = 2 * arcsin(sin(self.m2.actualPosition / 2) * SIN)
        self.actualPosition = current
        if self.state != State.ON:
            return
        target = -arctan(tan(current / 2) / sqrt(TAN**2 - tan(current / 2)**2))
        self.m1.targetPosition = self.m3.targetPosition = target

        self.m1.device.follow_offset = ll = int(
            (target - self.m1.offset) // self.m1.encodeStep
            - self.m2.device.encoder * self.m1.device.encoders_factor * self.m1.factor)
        self.m3.device.follow_offset = uu = int(
            (target - self.m3.offset) // self.m3.encodeStep
            - self.m2.device.encoder * self.m3.device.encoders_factor * self.m3.factor)

    @Slot()
    async def move(self):
        self.m2.targetPosition = 2 * arcsin(sin(self.targetPosition / 2) / SIN)
        self.state = State.ON
        await self.m2.move()

    @Slot()
    async def off(self):
        self.state = State.OFF
