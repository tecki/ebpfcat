"""\
A collection of devices
=======================

This modules contains a collection of devices which may be helpful
in many projects.
"""
from .ebpfcat import Device, FastSyncGroup, TerminalVar, DeviceVar


class AnalogInput(Device):
    """Generic analog input device

    This device can be linked to an analog input of a terminal.
    It will read from there and return the result in its
    parameter `value`.
    """
    value = DeviceVar()
    data = TerminalVar()

    def __init__(self, data):
        self.data = data

    def program(self):
        self.value = self.data

    def update(self):
        self.value = self.data


class AnalogOutput(Device):
    """Generic analog output device

    This device can be linked to an analog output of a terminal.
    It will write the `value` to that terminal.
    """
    value = DeviceVar()
    data = TerminalVar()

    def __init__(self, data):
        self.data = data

    def program(self):
        self.data = self.value

    def update(self):
        self.data = self.value


class DigitalInput(Device):
    """Generic digital input device

    This device can be linked to an analog input of a terminal.
    It will read from there and return the result in its
    parameter `value`.
    """
    value = DeviceVar()
    data = TerminalVar()

    def __init__(self, data):
        self.data = data

    def program(self):
        self.value = self.data

    def update(self):
        self.value = self.data


class DigitalOutput(Device):
    """Generic digital output device

    This device can be linked to an analog output of a terminal.
    It will write the `value` to that terminal.
    """
    value = DeviceVar()
    data = TerminalVar()

    def __init__(self, data):
        self.data = data

    def program(self):
        self.data = self.value

    def update(self):
        self.data = self.value
