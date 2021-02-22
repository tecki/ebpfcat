from karabo.middlelayer import AccessMode, String, Int16, Slot, isSet
from .master import EtherCATDevice
from ebpfcat.ebpfcat import Device, TerminalVar


class AnalogInputDevice(Device):
    value = TerminalVar()
    i = 0

    def update(self):
        self.i += 1
        if self.i == 100:
            self.i = 0
            self.owner.value = self.value


class AnalogInput(EtherCATDevice):
    channel = String(accessMode=AccessMode.INITONLY)

    value = Int16(accessMode=AccessMode.READONLY)


    @Slot()
    async def join(self):
        self.device = AnalogInputDevice()
        self.device.owner = self
        self.device.value = self.find_channel(self.channel)


class AnalogOutputDevice(Device):
    value = TerminalVar()

    def update(self):
        if not isSet(self.owner.value):
            return
        self.value = int(self.owner.value)


class AnalogOutput(EtherCATDevice):
    channel = String(accessMode=AccessMode.INITONLY)

    value = Int16()


    @Slot()
    async def join(self):
        self.device = AnalogOutputDevice()
        self.device.owner = self
        self.device.value = self.find_channel(self.channel)
