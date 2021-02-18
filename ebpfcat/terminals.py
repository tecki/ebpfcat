from .ebpfcat import EBPFTerminal, PacketDesc, Struct


class Generic(EBPFTerminal):
    pass


class EL4104(EBPFTerminal):
    ch1_value = PacketDesc((1, 0), 'H')
    ch2_value = PacketDesc((1, 2), 'H')
    ch3_value = PacketDesc((1, 4), 'H')
    ch4_value = PacketDesc((1, 6), 'H')


class EL3164(EBPFTerminal):
    class Channel(Struct):
        attrs = PacketDesc((0, 0), 'H')
        value = PacketDesc((0, 2), 'H')

    channel1 = Channel(0)
    channel2 = Channel(4)
    channel3 = Channel(8)
    channel4 = Channel(12)


class EK1814(EBPFTerminal):
    ch1 = PacketDesc((0, 0), 0)
    ch2 = PacketDesc((0, 0), 1)
    ch3 = PacketDesc((0, 0), 2)
    ch4 = PacketDesc((0, 0), 3)
    ch5 = PacketDesc((1, 0), 0)
    ch6 = PacketDesc((1, 0), 1)
    ch7 = PacketDesc((1, 0), 2)
    ch8 = PacketDesc((1, 0), 3)
