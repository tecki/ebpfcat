from karabo.middlelayer import (
    AccessMode, String, Int16, Slot, isSet, background, State)
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
