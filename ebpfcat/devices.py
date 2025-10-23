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
:mod:`!ebpfcat.devices` --- A collection of devices
===================================================

This modules contains a collection of devices which may be helpful
in many projects.
"""
from time import monotonic

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
        super().__init__()
        self.data = data

    def program(self):
        # it does not make much sense to copy data faster than
        # we can process
        return

    def update(self):
        self.value = self.data

    def fast_update(self):
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


class RandomOutput(Device):
    """Randomized digital output

    This device randomly switches its linked digital output
    on or off, with a probability given by :attr:`probability`.
    """
    seed = DeviceVar("I", write=True)
    value = DeviceVar("I", write=True)
    data = TerminalVar()

    def __init__(self, data):
        self.data = data

    def program(self):
        self.seed = self.seed * 0xcf019d85 + 1
        self.data = self.value > self.seed

    @property
    def probability(self):
        return self.value / 0xffffffff

    @probability.setter
    def probability(self, value):
        self.value = int(value * 0xffffffff)


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


class Valve(Device):
    """a digital output with two inputs for feedback

    .. attribute:: coil
        :type: TerminalVar

        link this to a digital output which will open the valve

    .. attribute:: openSwitch
        :type: TerminalVar
    .. attribute:: closedSwitch
        :type: TerminalVar

        link these to the switches which indicated that the valve
        is open or closed.

    .. attribute:: target
        :type: DeviceVar

        The position the valve is supposed to be in. ``True`` if it
        should be at the :attr:`openSwitch`, ``False`` if it should
        be at the :attr:`closedSwitch`.

    .. attribute:: error
        :type: DeviceVar

        indicate that the valve did not reach its target in time.

    .. attribute:: movingTime

        the time in seconds to reach the :attr:`target`. After this time has
        passed, the target is set to the :attr:`safeState`.

    .. attribute:: safeState

        this is what the :attr:`target` is set to if an error occurs.
    """

    coil = TerminalVar()
    openSwitch = TerminalVar()
    closedSwitch = TerminalVar()

    error = DeviceVar('?')
    target = DeviceVar('?')

    movingTime = 5  # time in seconds to reach target
    safeState = False  # the safe state is closed

    def update(self):
        inPosition = self.openSwitch != self.closedSwitch
        isCorrect = ((self.closedSwitch or not self.openSwitch)
                     if (self.coil == self.safeState)
                     else (self.openSwitch or not self.closedSwitch))
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


class Motor(Device):
    """A simple closed-loop motor

    This device implements a closed loop between an encoder and a
    velocity-control motor.

    .. attribute:: velocity
        :type: TerminalVar

        link this to the velocity output of a motor terminal

    .. attribute:: encoder
        :type: TerminalVar

        link this to the position input of an encoder

    .. attribute:: low_switch
        :type: TerminalVar

        link to a digital input for a low limit switch

    .. attribute:: high_switch
        :type: TerminalVar

        link to a digital input for a high limit switch

    .. attribute:: enable
        :type: TerminalVar

        link to the enable parameter of the motor terminal

    .. attribute:: current_position
        :type: TerminalVar

    .. attribute:: set_enable
        :type: DeviceVar

        set to whether the motor should be enabled, i.e. moving

    .. attribute:: target
        :type: DeviceVar

        the current target the motor should move to

    .. attribute:: max_velocity
        :type: DeviceVar

        the maximum allowed velocity for the motor. If the motor is far away
        from its target, this is the velocity the motor will go with.

    .. attribute:: proportional
        :type: DeviceVar

        the proportionality factor between the distance from target and the
        desired velocity.
    """
    velocity = TerminalVar()
    encoder = TerminalVar()
    low_switch = TerminalVar()
    high_switch = TerminalVar()
    enable = TerminalVar()

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
        self.velocity = velocity
        self.enable = self.set_enable

    def program(self):
        self.enable = self.set_enable
        with self.ebpf.stmp:
            self.ebpf.stmp = self.proportional * (self.target - self.encoder)
            with self.ebpf.stmp > self.velocity + self.max_acceleration:
                self.ebpf.stmp = self.velocity + self.max_acceleration
            with self.ebpf.stmp + self.max_acceleration < self.velocity:
                self.ebpf.stmp = self.velocity - self.max_acceleration
            self.velocity = self.ebpf.stmp
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
    """Randomly drop packets

    This fake device randomly drops EtherCat packets, to simulate bad
    connections.
    """
    rate = DeviceVar("I", write=True)

    def program(self):
        from .xdp import XDPExitCode
        with self.ebpf.tmp:
            self.ebpf.tmp = ktime(self.ebpf)
            self.ebpf.tmp = self.ebpf.tmp * 0xcf019d85 + 1
            with self.ebpf.tmp & 0xffff < self.rate:
                self.ebpf.exit(XDPExitCode.DROP)
