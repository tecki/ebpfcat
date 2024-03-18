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

from .ebpfcat import EBPFTerminal, PacketDesc, ProcessDesc, Struct


class Generic(EBPFTerminal):
    pass


class Skip(EBPFTerminal):
    async def initialize(self, relative, absolute):
        pass


class EL1808(EBPFTerminal):
    compatibility = {(2, 118501458)}

    channel1 = ProcessDesc(0x6000, 1)
    channel2 = ProcessDesc(0x6010, 1)
    channel3 = ProcessDesc(0x6020, 1)
    channel4 = ProcessDesc(0x6030, 1)
    channel5 = ProcessDesc(0x6040, 1)
    channel6 = ProcessDesc(0x6050, 1)
    channel7 = ProcessDesc(0x6060, 1)
    channel8 = ProcessDesc(0x6070, 1)


class EL2808(EBPFTerminal):
    compatibility = {(2, 184037458), (2, 0x7D83052)}

    channel1 = ProcessDesc(0x7000, 1)
    channel2 = ProcessDesc(0x7010, 1)
    channel3 = ProcessDesc(0x7020, 1)
    channel4 = ProcessDesc(0x7030, 1)
    channel5 = ProcessDesc(0x7040, 1)
    channel6 = ProcessDesc(0x7050, 1)
    channel7 = ProcessDesc(0x7060, 1)
    channel8 = ProcessDesc(0x7070, 1)


class EL2819(EBPFTerminal):
    compatibility = {(2, 0xB033052)}

    class Channel(Struct):
        value = ProcessDesc(0x7000, 1)
        overtemperature = ProcessDesc(0x6001, 1)
        open_load = ProcessDesc(0x6001, 2)
        overcurrent = ProcessDesc(0x6001, 3)
        short_circuit = ProcessDesc(0x6001, 4)

    channel1 = Channel(0)
    channel2 = Channel(0x10)
    channel3 = Channel(0x20)
    channel4 = Channel(0x30)
    channel5 = Channel(0x40)
    channel6 = Channel(0x50)
    channel7 = Channel(0x60)
    channel8 = Channel(0x70)
    channel9 = Channel(0x80)
    channel10 = Channel(0x90)
    channel11 = Channel(0xa0)
    channel12 = Channel(0xb0)
    channel13 = Channel(0xc0)
    channel14 = Channel(0xd0)
    channel15 = Channel(0xe0)
    channel16 = Channel(0xf0)


class EL2624(EBPFTerminal):
    compatibility = {(2, 171978834)}

    channel1 = ProcessDesc(0x7000, 1)
    channel2 = ProcessDesc(0x7010, 1)
    channel3 = ProcessDesc(0x7020, 1)
    channel4 = ProcessDesc(0x7030, 1)


class EL4104(EBPFTerminal):
    ch1_value = ProcessDesc(0x7000, 1)
    ch2_value = ProcessDesc(0x7010, 1)
    ch3_value = ProcessDesc(0x7020, 1)
    ch4_value = ProcessDesc(0x7030, 1)


class EL3164(EBPFTerminal):
    compatibility = {(2, 0x0c5c3052)}

    class Channel(Struct):
        attrs = ProcessDesc(0x6000, 1, 'H')
        value = ProcessDesc(0x6000, 0x11)
        factor = 10/32767
        offset = 0

    channel1 = Channel(0)
    channel2 = Channel(0x10)
    channel3 = Channel(0x20)
    channel4 = Channel(0x30)


class EK1101(EBPFTerminal):
    compatibility = {(2, 72166482)}


class EK1814(EBPFTerminal):
    channel1 = ProcessDesc(0x6000, 1)
    channel2 = ProcessDesc(0x6010, 1)
    channel3 = ProcessDesc(0x6020, 1)
    channel4 = ProcessDesc(0x6030, 1)
    channel5 = ProcessDesc(0x7080, 1)
    channel6 = ProcessDesc(0x7090, 1)
    channel7 = ProcessDesc(0x70A0, 1)
    channel8 = ProcessDesc(0x70B0, 1)


class EL5042(EBPFTerminal):
    compatibility = {(2, 330444882)}
    class Channel(Struct):
        position = ProcessDesc(0x6000, 0x11, 'q')
        warning = ProcessDesc(0x6000, 1)
        error = ProcessDesc(0x6000, 2)
        status = ProcessDesc(0x6000, 1, "H")

    channel1 = Channel(0)
    channel2 = Channel(0x10)


class EL6022(EBPFTerminal):
    class Channel(Struct):
        transmit_accept = PacketDesc(3, 0, 0)
        receive_request = PacketDesc(3, 0, 1)
        init_accept = PacketDesc(3, 0, 2)
        status = PacketDesc(3, 0, "H")
        in_string = PacketDesc(3, 1, "23p")

        transmit_request = PacketDesc(2, 0, 0)
        receive_accept = PacketDesc(2, 0, 1)
        init_request = PacketDesc(2, 0, 2)
        control = PacketDesc(2, 0, "H")
        out_string = PacketDesc(2, 1, "23p")

    channel1 = Channel(0, 0)
    channel2 = Channel(24, 24)


class EL7041(EBPFTerminal):
    compatibility = {(2, 461451346), (2, 461455442), (2, 460795986)}
    out_pdos = [0x1600, 0x1602, 0x1604]
    in_pdos = [0x1A00, 0x1A03, 0x1A07]
    velocity = ProcessDesc(0x7010, 0x21, "h")
    enable = ProcessDesc(0x7010, 1)
    reset = ProcessDesc(0x7010, 2)
    reduced_current = ProcessDesc(0x7010, 3)
    status = ProcessDesc(0x6010, 1, "H")
    error = ProcessDesc(0x6010, 4)
    low_switch = ProcessDesc(0x6010, 0xc)
    high_switch = ProcessDesc(0x6010, 0xd)
    stepcounter = ProcessDesc(0x6010, 0x14)


class EL7332(EBPFTerminal):
    compatibility = {(2, 0x1CA43052)}

    class Channel(Struct):
        moving_positive = ProcessDesc(0x6020, 5)
        moving_negative = ProcessDesc(0x6020, 6)
        low_switch = ProcessDesc(0x6020, 0xc)
        high_switch = ProcessDesc(0x6020, 0xd)
        enable = ProcessDesc(0x7020, 1)
        velocity = ProcessDesc(0x7020, 0x21, "h")

    channel1 = Channel(0)
    channel2 = Channel(0x10)


class TurboVac(EBPFTerminal):
    compatibility = {(0x723, 0xb5)}
    pump_on = ProcessDesc(0x20D3, 0, 0)
    stand_by = ProcessDesc(0x20D3, 0, 5)
    reset = ProcessDesc(0x20D3, 0, 7)
    error_status = ProcessDesc(0x20CA, 0)
    speed_status = ProcessDesc(0x20CB, 0)
    pump_is_on = ProcessDesc(0x20CC, 0, 0)
    pump_warning = ProcessDesc(0x20CC, 0, 2)
    pump_alarm = ProcessDesc(0x20CC, 0, 3)
    speed = ProcessDesc(0x20CD, 0, "H")
    current = ProcessDesc(0x20D1, 0, "H")


class Inficon(EBPFTerminal):
    compatibility = {(0x644, 0x21)}
    valid = ProcessDesc(0xF640, 1)
    overrange = ProcessDesc(0xF640, 2)
    underrange = ProcessDesc(0xF640, 3)
    value = ProcessDesc(0xF640, 0x11, "f")
    sensorNo = ProcessDesc(0xF640, 0x12, "f")


class Bronkhorst(EBPFTerminal):
    compatibility = {(0x56B, 7)}
    setpoint = ProcessDesc(0x7402, 1)
    current_value = ProcessDesc(0x7400, 1)
    controller_output = ProcessDesc(0x6410, 1)
    control_byte = ProcessDesc(0x6425, 1)
    status_word = ProcessDesc(0x6427, 1)
