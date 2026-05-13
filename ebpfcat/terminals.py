# ebpfcat, A Python-based EBPF generator and EtherCAT master
# Copyright (C) 2021 Martin Teichmann <martin.teichmann@xfel.eu>
# Copyright (C) 2026 European XFEL GmbH
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
:mod:`!ebpfcat.terminal --- classes describing common EtherCAT terminals
========================================================================
"""

from .ebpfcat import (
    BaseType, EBPFTerminal, PacketDesc, ProcessDesc, ServiceDesc, Struct)
from .ethercat import ECCmd, SyncManager
from .safety import SafetyMain, SafetySub


class Generic(EBPFTerminal):
    pass


class Skip(EBPFTerminal):
    async def initialize(self, relative, absolute):
        pass


class EL1124(EBPFTerminal):
    compatibility = {(2, 0x4643052), }

    channel1 = ProcessDesc(0x6000, 1)
    channel2 = ProcessDesc(0x6010, 1)
    channel3 = ProcessDesc(0x6020, 1)
    channel4 = ProcessDesc(0x6030, 1)


class EL1808(EBPFTerminal):
    compatibility = {(2, 118501458), (2, 0x3F03052)}

    channel1 = ProcessDesc(0x6000, 1)
    channel2 = ProcessDesc(0x6010, 1)
    channel3 = ProcessDesc(0x6020, 1)
    channel4 = ProcessDesc(0x6030, 1)
    channel5 = ProcessDesc(0x6040, 1)
    channel6 = ProcessDesc(0x6050, 1)
    channel7 = ProcessDesc(0x6060, 1)
    channel8 = ProcessDesc(0x6070, 1)


class EL2212(EBPFTerminal):
    compatibility = {(2, 0x8A43052)}

    class Channel(Struct):
        value = ProcessDesc(0x7000, 2)

        boost_current = ServiceDesc(0x8000, 1)
        hold_current = ServiceDesc(0x8000, 2)
        supply_voltage = ServiceDesc(0x8000, 3)
        coil_resistance = ServiceDesc(0x8000, 5)
        booster_on_time = ServiceDesc(0x8000, 6)
        booster_off_time = ServiceDesc(0x8000, 7)
        switch_off_threshold = ServiceDesc(0x8000, 8)
        enable_booster_on = ServiceDesc(0x8002, 1)
        enable_booster_off = ServiceDesc(0x8002, 2)
        enable_off_threshold = ServiceDesc(0x8002, 3)

    channel1 = Channel(0)
    channel2 = Channel(0x10)


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
    # EL2624, EL2124, EL2794
    compatibility = {(2, 171978834), (2, 139210834), (2, 0xAEA3052)}

    channel1 = ProcessDesc(0x7000, 1)
    channel2 = ProcessDesc(0x7010, 1)
    channel3 = ProcessDesc(0x7020, 1)
    channel4 = ProcessDesc(0x7030, 1)


EL2124 = EL2624


class EL2911(SafetyMain):
    input1 = ProcessDesc(0x6011, 1)
    input2 = ProcessDesc(0x6011, 2)
    input3 = ProcessDesc(0x6011, 3)
    input4 = ProcessDesc(0x6011, 4)
    output1 = ProcessDesc(0x7001, 1)


class EL3154(EBPFTerminal):
    compatibility = {(2, 0xC523052)}

    class Channel(Struct):
        attrs = ProcessDesc(0x6000, 1, 'H')
        value = ProcessDesc(0x6000, 0x11, 'h')
        factor = 16/32767
        offset = 4

    channel1 = Channel(0)
    channel2 = Channel(0x10)
    channel3 = Channel(0x20)
    channel4 = Channel(0x30)


class EL3164(EBPFTerminal):
    compatibility = {(2, 0x0c5c3052), (2, 0xc203052)}

    class Channel(Struct):
        attrs = ProcessDesc(0x6000, 1, 'H')
        value = ProcessDesc(0x6000, 0x11, 'h')
        factor = 10/32767
        offset = 0

    channel1 = Channel(0)
    channel2 = Channel(0x10)
    channel3 = Channel(0x20)
    channel4 = Channel(0x30)


class EL4102(EBPFTerminal):
    compatibility = {(2, 268841042)}

    class Channel(Struct):
        value = ProcessDesc(0x3000, 1, 'h')
        factor = 10/32767
        offset = 0

    channel1 = Channel(1)
    channel2 = Channel(2)


class EL4122(EBPFTerminal):
    compatibility = {(2, 0x101A3052)}

    class Channel(Struct):
        value = ProcessDesc(0x3000, 1, 'h')
        factor = 16/32767
        offset = 4

    channel1 = Channel(1)
    channel2 = Channel(2)


class EL4134(EBPFTerminal):
    # used to be for EL4104, but had not compatibility set
    compatibility = {(2, 0x10263052)}

    class Channel(Struct):
        value = ProcessDesc(0x7000, 1, 'h')
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
        invalid = ProcessDesc(0x6000, 0xE)

        invert_position = ServiceDesc(0x8008, 1)
        statusbits = ServiceDesc(0x8008, 2)
        crc_invert = ServiceDesc(0x8008, 3)
        multiturn = ServiceDesc(0x8008, 0x15)
        singleturn = ServiceDesc(0x8008, 0x16)
        frequency = ServiceDesc(0x8008, 0x13)
        polynomial = ServiceDesc(0x8008, 0x11)

    channel1 = Channel(0)
    channel2 = Channel(0x10)


class EL6002(EBPFTerminal):
    compatibility = {(2, 393359442)}

    class Channel(Struct):
        transmit_accept = PacketDesc(SyncManager.IN, 0, 0)
        receive_request = PacketDesc(SyncManager.IN, 0, 1)
        init_accept = PacketDesc(SyncManager.IN, 0, 2)
        in_string = PacketDesc(SyncManager.IN, 1, "23p")

        transmit_request = PacketDesc(SyncManager.OUT, 0, 0)
        receive_accept = PacketDesc(SyncManager.OUT, 0, 1)
        init_request = PacketDesc(SyncManager.OUT, 0, 2)
        out_string = PacketDesc(SyncManager.OUT, 1, "23p")

        enableRtsCts = ServiceDesc(0x8000, 1)
        enableXonXoffSend = ServiceDesc(0x8000, 2)
        enableXonXoffReceive = ServiceDesc(0x8000, 3)
        enableFIFOcontinuous = ServiceDesc(0x8000, 4)
        enableTransferRateOptimization = ServiceDesc(0x8000, 5)
        enableHalfDuplex = ServiceDesc(0x8000, 6)
        enablePointToPoint = ServiceDesc(0x8000, 7)
        baudRate = ServiceDesc(0x8000, 0x11)
        dataFrame = ServiceDesc(0x8000, 0x15)

    channel1 = Channel(0, 0, 0)
    channel2 = Channel(24, 24, 0x10)



class EL6022(EBPFTerminal):
    compatibility = {(2, 0x17863052)}

    class Channel(EL6002.Channel):
        enableHalfDuplex = ServiceDesc(0x8000, 6)
        enablePointToPoint = ServiceDesc(0x8000, 7)

    channel1 = Channel(0, 0, 0)
    channel2 = Channel(24, 24, 0x10)


class EL7041(EBPFTerminal):
    compatibility = {(2, 461451346), (2, 461455442), (2, 460795986)}
    out_pdos = [0x1601, 0x1602, 0x1604]
    in_pdos = [0x1A01, 0x1A03]
    velocity = ProcessDesc(0x7010, 0x21, "h")
    control = ProcessDesc(0x7010, 1, 'H')
    enable = ProcessDesc(0x7010, 1)
    reset = ProcessDesc(0x7010, 2)
    reduced_current = ProcessDesc(0x7010, 3)
    status = ProcessDesc(0x6010, 1, "H")
    enabled = ProcessDesc(0x6010, 2)
    error = ProcessDesc(0x6010, 4)
    high_switch = ProcessDesc(0x6010, 0xc)
    low_switch = ProcessDesc(0x6010, 0xd)
    stepcounter = ProcessDesc(0x6000, 0x11, 'i')

    max_current = ServiceDesc(0x8010, 1)
    max_voltage = ServiceDesc(0x8010, 3)
    coil_resistance = ServiceDesc(0x8010, 4)
    motor_emf = ServiceDesc(0x8010, 5)
    invLogicLim1 = ServiceDesc(0x8012, 0x30)
    invLogicLim2 = ServiceDesc(0x8012, 0x31)


class EL7062(EBPFTerminal):
    compatibility = {(2, 0x1B963052)}

    out_pdos = [0x1600, 0x1601, 0x1680, 0x1681]
    in_pdos = [0x1A00, 0x1A01, 0x1A10, 0x1A80, 0x1A81, 0x1A90]

    class Channel(Struct):
        velocity = ProcessDesc(0x7010, 6, 'i')
        enable = ProcessDesc(0x7010, 1, 1)
        reset = ProcessDesc(0x7010, 1, 7)
        control = ProcessDesc(0x7010, 1)

        status = ProcessDesc(0x6010, 1)
        ready_switch_on = ProcessDesc(0x6010, 1, 0)
        switched_on = ProcessDesc(0x6010, 1, 1)
        enabled = ProcessDesc(0x6010, 1, 2)
        error = ProcessDesc(0x6010, 1, 3)
        switch_on_disabled = ProcessDesc(0x6010, 1, 6)

        low_switch = ProcessDesc(0x6020, 1)
        high_switch = ProcessDesc(0x6020, 2)
        stepcounter = ProcessDesc(0x6000, 0x11, 'i')

        max_current = ServiceDesc(0x8011, 0x34)
        operation_mode = ServiceDesc(0x7010, 3)

    channel1 = Channel(0)
    channel2 = Channel(0x100)


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


class EPP2308(EBPFTerminal):
    compatibilty = {(2, 0x64765649)}

    input1 = ProcessDesc(0x6000, 1)
    input2 = ProcessDesc(0x6010, 1)
    input3 = ProcessDesc(0x6020, 1)
    input4 = ProcessDesc(0x6030, 1)
    output1 = ProcessDesc(0x7040, 1)
    output2 = ProcessDesc(0x7050, 1)
    output3 = ProcessDesc(0x7060, 1)
    output4 = ProcessDesc(0x7070, 1)


class EPP3184(EBPFTerminal):
    compatibility = {(2, 0x64768d09)}

    class Channel(Struct):
        value = ProcessDesc(0x6000, 0x11)

        factor = 10 / 32767  # see manual version 1.4, section 5.2.2
        offset = 0

    channel1 = Channel(0)
    channel2 = Channel(0x10)
    channel3 = Channel(0x20)
    channel4 = Channel(0x30)


class EPP3204(EBPFTerminal):
    compatibility = {(2, 0x64768e49), (2, 0x64769529)}

    class Channel(Struct):
        value = ProcessDesc(0x6000, 0x11)

        factor = 0.01
        offset = 0

    channel1 = Channel(0)
    channel2 = Channel(0x10)
    channel3 = Channel(0x20)
    channel4 = Channel(0x30)


EPP3314 = EPP3204  # lazy coding


class EL3102(EBPFTerminal):
    compatibility = {(2, 203305042)}

    class Input(Struct):
        status = ProcessDesc(0x3100, 1)
        value = ProcessDesc(0x3100, 2, 'h')
        offset = 0
        factor = 10/32767

    channel1 = Input(1)
    channel2 = Input(2)


class EL3202(EBPFTerminal):
    compatibility = {(2, 0xC823052)}

    class Input(Struct):
        underrange = ProcessDesc(0x6010, 1)
        overrange = ProcessDesc(0x6010, 2)
        value = ProcessDesc(0x6010, 0x11)

    channel1 = Input(0)
    channel2 = Input(0x10)


class EPP4304(EBPFTerminal):
    compatibility = {(2, 0x6476D309)}

    class Input(Struct):
        underrange = ProcessDesc(0x6010, 1)
        overrange = ProcessDesc(0x6010, 2)
        value = ProcessDesc(0x6010, 0x11, 'h')

        factor = 327.68e-6  # see manual version 1.3, Section 3.2.4.1
        offset = 0

    input1 = Input(0)
    input2 = Input(0x10)

    class Output(Struct):
        impedanceError = ProcessDesc(0x6030, 1)
        error = ProcessDesc(0x6030, 7)
        value = ProcessDesc(0x7030, 1, 'h')

        factor = 305.19e-6  # see manual version 1.3, Section 3.2.5.1
        offset = 0

    output1 = Output(0)
    output2 = Output(0x10)

    digitalInput1 = ProcessDesc(0x6000, 1)
    digitalInput2 = ProcessDesc(0x6000, 2)


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


class ELMO(EBPFTerminal):
    compatibility = {(0x9a, 0x30924)}
    out_pdos = [0x1601]
    in_pdos = [0x1A00, 0x1A0D]

    velocity = ProcessDesc(0x60ff, 0, 'i')
    enable = ProcessDesc(0x6040, 0, 1)
    reset = ProcessDesc(0x6040, 0, 7)
    control = ProcessDesc(0x6040, 0)

    status = ProcessDesc(0x6041, 0)
    ready_switch_on = ProcessDesc(0x6041, 0, 0)
    switched_on = ProcessDesc(0x6041, 0, 1)
    enabled = ProcessDesc(0x6041, 0, 2)
    error = ProcessDesc(0x6041, 0, 3)
    switch_on_disabled = ProcessDesc(0x6041, 0, 6)
    encoder = ProcessDesc(0x6064, 0)

    low_switch = ProcessDesc(0x60fd, 0, 0)
    high_switch = ProcessDesc(0x60fd, 0, 1)
    stepcounter = ProcessDesc(0x6063, 0, 'i')

    max_current = ServiceDesc(0x6073, 0)
    operation_mode = ServiceDesc(0x6060, 0)


class AerotechBase(EBPFTerminal):
    """A base class for Aerotech devices

    Aerotech defines a huge PDO, so big it is hard to even put into one
    packet. So we define our own packet size.

    The PDO is not actually defined, the user can define it at will on
    the Aerotech controller side.
    Subclass this class, add :class:`PacketDesc`s to the child class
    to match what you defined in the controller. Then define the class
    variables ``in_size`` and ``out_size`` to define the packet sizes
    needed to transfer your data.
    """

    in_size = None
    out_size = None

    def allocate(self, packet, readwrite):
        bases = {}
        if self.pdo_in_sz:
            bases[SyncManager.IN] = (BaseType.FMMU_IN, packet.fmmu_in_size)
            packet.fmmu_in_size += self.in_size
            packet.fmmu_in_count += 1

            packet.append(ECCmd.FPRD, b"0", 0,
                          self.position, self.pdo_in_off + self.pdo_in_sz - 1)
        if readwrite and self.pdo_out_sz:
            bases[SyncManager.OUT] = (BaseType.NO_FMMU, packet.size)
            packet.append_writer(ECCmd.FPWR, b"\0" * self.out_size, 0,
                                 self.position, self.pdo_out_off)
            packet.append_writer(ECCmd.FPWR, b"3", 0, self.position,
                                 self.pdo_out_off + self.pdo_out_sz - 1)
        return bases
