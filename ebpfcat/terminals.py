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

    ch1 = PacketDesc(3, 0, 0)
    ch2 = PacketDesc(3, 0, 1)
    ch3 = PacketDesc(3, 0, 2)
    ch4 = PacketDesc(3, 0, 3)
    ch5 = PacketDesc(3, 0, 4)
    ch6 = PacketDesc(3, 0, 5)
    ch7 = PacketDesc(3, 0, 6)
    ch8 = PacketDesc(3, 0, 7)


class EL2808(EBPFTerminal):
    compatibility = {(2, 184037458)}

    ch1 = PacketDesc(2, 0, 0)
    ch2 = PacketDesc(2, 0, 1)
    ch3 = PacketDesc(2, 0, 2)
    ch4 = PacketDesc(2, 0, 3)
    ch5 = PacketDesc(2, 0, 4)
    ch6 = PacketDesc(2, 0, 5)
    ch7 = PacketDesc(2, 0, 6)
    ch8 = PacketDesc(2, 0, 7)


class EL4104(EBPFTerminal):
    ch1_value = ProcessDesc(0x7000, 1)
    ch2_value = ProcessDesc(0x7010, 1)
    ch3_value = ProcessDesc(0x7020, 1)
    ch4_value = ProcessDesc(0x7030, 1)


class EL3164(EBPFTerminal):
    class Channel(Struct):
        attrs = ProcessDesc(0x6000, 1, 'H')
        value = ProcessDesc(0x6000, 0x11)

    channel1 = Channel(0)
    channel2 = Channel(0x10)
    channel3 = Channel(0x20)
    channel4 = Channel(0x30)


class EK1101(EBPFTerminal):
    compatibility = {(2, 72166482)}


class EK1814(EBPFTerminal):
    ch1 = PacketDesc(3, 0, 0)
    ch2 = PacketDesc(3, 0, 1)
    ch3 = PacketDesc(3, 0, 2)
    ch4 = PacketDesc(3, 0, 3)
    ch5 = PacketDesc(2, 0, 0)
    ch6 = PacketDesc(2, 0, 1)
    ch7 = PacketDesc(2, 0, 2)
    ch8 = PacketDesc(2, 0, 3)


class EL5042(EBPFTerminal):
    compatibility = {(2, 330444882)}
    class Channel(Struct):
        position = PacketDesc(3, 2, "q")
        warning = PacketDesc(3, 0, 0)
        error = PacketDesc(3, 0, 1)
        status = PacketDesc(3, 0, "H")

    channel1 = Channel(0, 0)
    channel2 = Channel(10, 0x10)


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
    velocity = PacketDesc(2, 6, "h")
    enable = PacketDesc(2, 4, 0)
    status = PacketDesc(3, 6, "H")
    low_switch = PacketDesc(3, 1, 7)
    high_switch = PacketDesc(3, 1, 8)
