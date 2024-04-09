from karabo.middlelayer import (
    AccessMode, Assignment, Bool, UInt16, UInt32, UInt8, String)
from .master import EtherCATTerminal
from ebpfcat import terminals


class GenericTerminal(EtherCATTerminal):
    @String(accessMode=AccessMode.INITONLY, assignment=Assignment.MANDATORY)
    async def terminalType(self, value):
        self.Base = getattr(terminals, value)
        self.terminalType = value


class EL5042Terminal(EtherCATTerminal):
    Base = terminals.EL5042

    statusbits1 = UInt8(alias='channel1.statusbits')
    crc_invert1 = Bool(alias='channel1.crc_invert')
    multiturn1 = UInt8(alias='channel1.multiturn')
    singleturn1 = UInt8(alias='channel1.singleturn')
    frequency1 = UInt8(alias='channel1.frequency')
    polynomial1 = UInt32(alias='channel1.polynomial')
    statusbits2 = UInt8(alias='channel2.statusbits')
    crc_invert2 = Bool(alias='channel2.crc_invert')
    multiturn2 = UInt8(alias='channel2.multiturn')
    singleturn2 = UInt8(alias='channel2.singleturn')
    frequency2 = UInt8(alias='channel2.frequency')
    polynomial2 = UInt32(alias='channel2.polynomial')


class EL7041Terminal(EtherCATTerminal):
    Base = terminals.EL7041

    max_current = UInt16(alias='max_current')
    max_voltage = UInt16(alias='max_voltage')
    coil_resistance = UInt16(alias='coil_resistance')
    motor_emf = UInt16(alias='motor_emf')
    invLogicLim1 = Bool(alias='invLogicLim1')
    invLogicLim2 = Bool(alias='invLogicLim2')
