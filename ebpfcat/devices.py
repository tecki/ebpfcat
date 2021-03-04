# ebpfcat, A Python-based EBPF generator and EtherCAT master
# Copyright (C) 2021 Martin Teichmann <martin.teichmann@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

"""\
A collection of devices
=======================

This modules contains a collection of devices which may be helpful
in many projects.
"""
from .ebpfcat import Device, FastSyncGroup, TerminalVar, DeviceVar
from .ebpf import ktime


class AnalogInput(Device):
    """Generic analog input device

    This device can be linked to an analog input of a terminal.
    It will read from there and return the result in its
    parameter `value`.
    """
    value = DeviceVar(write=False)
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
    value = DeviceVar(write=True)
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
    value = DeviceVar(write=False)
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
    value = DeviceVar(write=True)
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
    seed = DeviceVar("I", write=True)
    value = DeviceVar("I", write=True)
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
    lasttime = DeviceVar("Q")
    maxtime = DeviceVar("Q", write=True)
    squared = DeviceVar("Q", write=True)

    def program(self):
        self.count += 1

        with self.ebpf.tmp:
            self.ebpf.tmp = self.lasttime
            self.lasttime = ktime(self.ebpf)
            with self.ebpf.tmp != 0:
                self.ebpf.tmp = self.lasttime - self.ebpf.tmp
                with self.ebpf.tmp > self.maxtime:
                    self.maxtime = self.ebpf.tmp
                self.squared += self.ebpf.tmp * self.ebpf.tmp

    def update(self):
        self.count += 1


class Motor(Device):
    velocity = TerminalVar()
    encoder = TerminalVar()
    low_switch = TerminalVar()
    high_switch = TerminalVar()
    enable = TerminalVar()

    current_position = DeviceVar()
    set_velocity = DeviceVar(write=True)
    set_enable = DeviceVar(write=True)
    max_velocity = DeviceVar(write=True)
    max_acceleration = DeviceVar(write=True)
    target = DeviceVar(write=True)
    proportional = DeviceVar(write=True)

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


class RandomDropper(Device):
    rate = DeviceVar("I", write=True)

    def program(self):
        from .xdp import XDPExitCode
        with self.ebpf.tmp:
            self.ebpf.tmp = ktime(self.ebpf)
            self.ebpf.tmp = self.ebpf.tmp * 0xcf019d85 + 1
            with self.ebpf.tmp & 0xffff < self.rate:
                self.ebpf.exit(XDPExitCode.DROP)
