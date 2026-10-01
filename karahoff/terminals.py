"""
A collection of terminals
-------------------------

.. autoclass:: GenericTerminal()
    :members:
"""
from karabo.middlelayer import (
    AccessMode, Assignment, Bool, Node, Int16, MetricPrefix, UInt16, UInt32,
    UInt8, Unit, String)
from .master import Channel, EtherCATTerminal
from ebpfcat import terminals
from ebpfcat.ebpfcat import PacketDesc
from ebpfcat.ethercat import SyncManager


class GenericTerminal(EtherCATTerminal):
    """A Karabo device able to represent simple KaraHoff terminals"""

    @String(accessMode=AccessMode.INITONLY, assignment=Assignment.MANDATORY)
    async def terminalType(self, value):
        """Set this to the name of a terminal class from KaraHoff"""
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

    max_current = UInt16(displayedName='Nominal Current',
                         alias='max_current', unitSymbol=Unit.AMPERE,
                         metricPrefixSymbol=MetricPrefix.MILLI)
    max_voltage = UInt16(displayedName='Input Voltage',
                         alias='max_voltage', unitSymbol=Unit.VOLT,
                         metricPrefixSymbol=MetricPrefix.MILLI)
    coil_resistance = UInt16(displayedName='Coil Resistance',
                             alias='coil_resistance', unitSymbol=Unit.OHM,
                             metricPrefixSymbol=MetricPrefix.CENTI)
    motor_emf = UInt16(alias='motor_emf')
    invLogicLim1 = Bool(alias='invLogicLim1')
    invLogicLim2 = Bool(alias='invLogicLim2')


class EL7062Terminal(EtherCATTerminal):
    Base = terminals.EL7062

    class OneChannel(Channel):
        operation_mode = UInt8(alias='operation_mode', defaultValue=9)
        max_current = UInt16(alias='max_current')

    channel1 = Node(OneChannel, alias='channel1')
    channel2 = Node(OneChannel, alias='channel2')


class EL6002Terminal(EtherCATTerminal):
    Base = terminals.EL6002

    class OneChannel(Channel):
        enableFIFOcontinuous = Bool(alias='enableFIFOcontinuous')
        baudRate = UInt16(alias='baudRate')
        dataFrame = UInt16(alias='dataFrame')

    channel1 = Node(OneChannel, alias='channel1')
    channel2 = Node(OneChannel, alias='channel2')


class EL6022Terminal(EL6002Terminal):
    Base = terminals.EL6022

    class OneChannel(EL6002Terminal.OneChannel):
        enableHalfDuplex = Bool(alias='enableHalfDuplex')
        enablePointToPoint = Bool(alias='enablePointToPoint')

    channel1 = Node(OneChannel, alias='channel1')
    channel2 = Node(OneChannel, alias='channel2')


class EL2212Terminal(EtherCATTerminal):
    Base = terminals.EL2212

    class OneChannel(Channel):
        boostCurrent = UInt16(
            alias='boost_current',
            unitSymbol=Unit.AMPERE, metricPrefixSymbol=MetricPrefix.MILLI)
        holdCurrent = UInt16(
            alias='hold_current',
            unitSymbol=Unit.AMPERE, metricPrefixSymbol=MetricPrefix.MILLI)
        supplyVoltage = UInt16(
            alias='supply_voltage',
            unitSymbol=Unit.VOLT, metricPrefixSymbol=MetricPrefix.CENTI)
        coilResistance = UInt16(
            alias='coil_resistance',
            unitSymbol=Unit.OHM, metricPrefixSymbol=MetricPrefix.CENTI)
        boosterOnTime = UInt16(
            description='Time the booster is on (in 0.1 ms steps)',
            alias='booster_on_time')
        boosterOffTime = UInt16(
            description='Time the booster pulls back (in 0.1 ms steps)',
            alias='booster_off_time')
        switchOffThreshold = Int16(
            alias='switch_off_threshold',
            unitSymbol=Unit.AMPERE, metricPrefixSymbol=MetricPrefix.MILLI)
        enableBoosterOn = Bool(alias='enable_booster_on')
        enableBoosterOff = Bool(alias='enable_booster_off')
        enableOffThreshold = Bool(alias='enable_off_threshold')

    channel1 = Node(OneChannel, alias='channel1')
    channel2 = Node(OneChannel, alias='channel2')


class Aerotech(EtherCATTerminal):
    class Base(terminals.AerotechBase):
        compatibility = {(2608, 4096)}

        actualPosition = PacketDesc(SyncManager.IN, 8, "d")
        actualVelocity = PacketDesc(SyncManager.IN, 0, "d")
        positionLag = PacketDesc(SyncManager.IN, 36, "d")
        enabled = PacketDesc(SyncManager.IN, 28, "i")
        homed = PacketDesc(SyncManager.IN, 24, "i")
        error = PacketDesc(SyncManager.IN, 20, "i")
        inPosition = PacketDesc(SyncManager.IN, 32, "i")
        status = PacketDesc(SyncManager.IN, 16, "i")

        targetPosition = PacketDesc(SyncManager.OUT, 8, "d")
        targetVelocity = PacketDesc(SyncManager.OUT, 16, "d")
        command = PacketDesc(SyncManager.OUT, 0, "i")
        emergencyStop = PacketDesc(SyncManager.OUT, 4, "i")

        in_size = 44
        out_size = 24
