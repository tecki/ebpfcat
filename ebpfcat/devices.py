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


class PWM(Device):
    """Generic digital output device

    This device can be linked to an analog output of a terminal.
    It will write the `value` to that terminal.
    """
    seed = DeviceVar("I")
    value = DeviceVar("I")
    data = TerminalVar()

    def __init__(self, data):
        self.data = data

    def program(self):
        self.seed = self.seed * 0xcf019d85 + 1
        self.data = self.value > self.seed

    def update(self):
        self.data = self.value


class Counter(Device):
    """A fake device counting the loops"""

    count = DeviceVar("I")

    def program(self):
        self.count += 1

    def update(self):
        self.count += 1


class Motor(Device):
    velocity = TerminalVar()
    encoder = TerminalVar()
    low_switch = TerminalVar()
    high_switch = TerminalVar()
    enable = TerminalVar()

    current_position = DeviceVar()
    set_velocity = DeviceVar()
    set_enable = DeviceVar()
    max_velocity = DeviceVar()
    max_acceleration = DeviceVar()
    target = DeviceVar()
    proportional = DeviceVar()

    def update(self):
        velocity = self.proportional * (self.target - self.encoder)
        if velocity > self.max_velocity:
            velocity = self.max_velocity
        elif velocity < -self.max_velocity:
            velocity = -self.max_velocity
        self.current_position = self.encoder
        self.velocity = velocity
        self.enable = self.set_enable

    def program(self):
        with self.ebpf.tmp:
            self.ebpf.tmp = self.proportional * (self.target - self.encoder)
            with self.ebpf.tmp > self.velocity + self.max_acceleration:
                self.ebpf.tmp = self.velocity + self.max_acceleration
            with self.ebpf.tmp + self.max_acceleration < self.velocity:
                self.ebpf.tmp = self.velocity - self.max_acceleration
            self.velocity = self.ebpf.tmp
        with self.velocity > self.max_velocity:
            self.velocity = self.max_velocity
        with self.velocity < -self.max_velocity:
            self.velocity = -self.max_velocity
        with self.low_switch, self.velocity < 0:
            self.velocity = 0
        with self.high_switch, self.velocity > 0:
            self.velocity = 0

class Dummy(Device):
    """A placeholder device assuring a terminal is initialized"""
    def __init__(self, terminals):
        self.terminals = terminals

    def get_terminals(self):
        return set(self.terminals)

    def program(self):
        pass
