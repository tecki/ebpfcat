from .ebpfcat import EBPFTerminal, PacketDesc


class Generic(EBPFTerminal):
    pass


class EL3164(EBPFTerminal):
    ch1_attrs = PacketDesc((0, 0), 'H')
    ch2_attrs = PacketDesc((0, 4), 'H')
    ch3_attrs = PacketDesc((0, 8), 'H')
    ch4_attrs = PacketDesc((0, 12), 'H')
    ch1_value = PacketDesc((0, 2), 'H')
    ch2_value = PacketDesc((0, 6), 'H')
    ch3_value = PacketDesc((0, 10), 'H')
    ch4_value = PacketDesc((0, 14), 'H')
