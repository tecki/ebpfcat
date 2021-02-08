from .ebpfcat import Device, FastSyncGroup, TerminalVar, DeviceVar


class AnalogInput(Device):
    value = DeviceVar()
    data = TerminalVar()

    def __init__(self, data):
        self.data = data

    def program(self):
        self.value = self.data

    def update(self):
        self.value = self.data


class AnalogOutput(Device):
    value = DeviceVar()
    data = TerminalVar()

    def __init__(self, data):
        self.data = data

    def program(self):
        self.data = self.value

    def update(self):
        self.data = self.value
