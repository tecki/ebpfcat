from karabo.middlelayer import (
    AccessMode, Assignment, Bool, Node, UInt16, UInt32, UInt8, String)
from .master import Channel, EtherCATTerminal
from ebpfcat import terminals


class GenericTerminal(EtherCATTerminal):
    @String(accessMode=AccessMode.INITONLY, assignment=Assignment.MANDATORY)
    async def terminalType(self, value):
        self.Base = getattr(terminals, value)
        self.terminalType = value


class EL5042Terminal(EtherCATTerminal):
    Base = terminals.EL5042

    class OneChannel(Channel):
        statusbits = UInt8(alias='statusbits')
        crc_invert = Bool(alias='crc_invert')
        multiturn = UInt8(alias='multiturn')
        singleturn = UInt8(alias='singleturn')
        frequency = UInt8(alias='frequency')
        polynomial = UInt32(alias='polynomial')

    channel1 = Node(OneChannel, alias='channel1')
    channel2 = Node(OneChannel, alias='channel2')


class EL7041Terminal(EtherCATTerminal):
    Base = terminals.EL7041

    max_current = UInt16(alias='max_current')
    max_voltage = UInt16(alias='max_voltage')
    coil_resistance = UInt16(alias='coil_resistance')
    motor_emf = UInt16(alias='motor_emf')
    invLogicLim1 = Bool(alias='invLogicLim1')
    invLogicLim2 = Bool(alias='invLogicLim2')


class EL6022Terminal(EtherCATTerminal):
    Base = terminals.EL6022

    class OneChannel(Channel):
        enableFIFOcontinuous = Bool(alias='enableFIFOcontinuous')
        enableHalfDuplex = Bool(alias='enableHalfDuplex')
        enablePointToPoint = Bool(alias='enablePointToPoint')
        baudRate = UInt16(alias='baudRate')
        dataFrame = UInt16(alias='dataFrame')

    channel1 = Node(OneChannel, alias='channel1')
    channel2 = Node(OneChannel, alias='channel1')
