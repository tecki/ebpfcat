# ebpfcat, A Python-based EBPF generator and EtherCAT master
# Copyright (C) 2026 Martin Teichmann <martin.teichmann@xfel.eu>
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
#
# This program may contain technology patented by Beckhoff GmbH.
# Users may want to consult a lawyer before using this program.

"""\
:mod:`!ebpfcat.safety` --- Support Safety-over-EtherCat communication
=====================================================================

Use this module to establish communication between Safety-over-EtherCat
devices. Note that EBPFCat does not support any safety logic itself, it
only supports the communication between safety devices which have been
programmed by different means. The communication is not part of the safety
considerations of Safety-over-Ethercat.
"""

from itertools import count

from .ethercat import ECCmd, EtherCatError, Packet, SyncManager
from .ebpfcat import Device, EBPFTerminal, ProcessDesc, TerminalVar, DeviceVar


class SafetyDevice(Device):
    """A device to establish safety communication

    This device asssures the communication between safety terminals. It takes
    the main terminal of the safety PLC as a parameter, and finds all other
    terminals in the PLC, so long as they have already been initialized.

    :param main_terminal: The terminal that controls the safety PLC
    """
    safe_logic_state = TerminalVar()
    my_output = TerminalVar()
    generic_input = TerminalVar()
    generic_output = DeviceVar()

    def __init__(self, main_terminal):
        super().__init__()
        self.main_terminal = main_terminal
        self.safe_logic_state = main_terminal.safe_logic_state
        try:
            self.my_output = main_terminal.generic_output
            self.has_output = True
        except KeyError:
            self.has_output = False

        try:
            self.generic_input = main_terminal.generic_input
        except KeyError:
            pass

    def program(self):
        main = self.main_terminal
        HDR = Packet.ETHERNET_HEADER
        ebpf = self.sync_group.packet_access
        if self.has_output:
            self.my_output = self.generic_output
        self.ddebug = ebpf.pB[main.in_cmd_pos + HDR]
        with ebpf.pB[main.in_cmd_pos + HDR] == ECCmd.LRD.value as Else:
            ebpf.pB[main.in_cmd_pos + HDR] = ECCmd.LWR.value
            ebpf.pI[main.in_cmd_pos + 2 + HDR] = main.sub_out_base
            ebpf.pB[main.out_cmd_pos + HDR] = ECCmd.LWR.value
            ebpf.pI[main.out_cmd_pos + 2 + HDR] = main.main_out_base
        with Else:
            ebpf.pB[main.in_cmd_pos + HDR] = ECCmd.LRD.value
            ebpf.pI[main.in_cmd_pos + 2 + HDR] = main.main_in_base
            ebpf.pB[main.out_cmd_pos + HDR] = ECCmd.LRD.value
            ebpf.pI[main.out_cmd_pos + 2 + HDR] = main.sub_in_base

    def get_terminals(self):
        terminals = self.main_terminal.ec.terminal_by_safe_address
        ret = {self.main_terminal: True}
        for _, addr in self.main_terminal.sub_addrs:
            ret[terminals[addr]] = True
        return ret


class SafetyMain(EBPFTerminal):
    """The main instance of a safety PLC"""

    compatibility = {(2, 0x1afe3052), (2, 190787666)}

    safe_logic_state = ProcessDesc(0xF100, 1)
    cycle_counter = ProcessDesc(0xF100, 2)
    generic_output = ProcessDesc(0xF788, 0)
    generic_input = ProcessDesc(0xF688, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, *kwargs)
        self.ec.terminal_by_safe_address = {}

    async def initialize(self, *args, **kwargs):
        await super().initialize(*args, **kwargs)

        self.sub_addrs = []
        for idx, subidx in self.pdos:
            if idx & 0xf00f == 0x6001 and subidx == 1:
                safe_addr, = await self.sdo_read_format('<H', idx + 0x3000, 2)
                self.sub_addrs.append((idx - 1, safe_addr))

    def allocate(self, packet, readwrite):
        self.main_in_base = self.ec.get_fmmu_addr()
        self.main_out_base = self.main_in_base + 1000
        self.sub_in_base = self.main_in_base + 2000
        self.sub_out_base = self.main_in_base + 3000

        for idx, safe_addr in self.sub_addrs:
            term = self.ec.terminal_by_safe_address[safe_addr]
            term.bases = {
                SyncManager.IN: (self.sub_in_base,
                                 self.pdos[idx + 0x1000, 1][1]),
                SyncManager.OUT: (self.sub_out_base,
                                  self.pdos[idx, 1][1]),
            }

        bases = {}
        bases[SyncManager.IN] = (self.main_in_base - packet.size, packet.size)
        self.in_cmd_pos = packet.size
        packet.append(ECCmd.LRD, bytes(self.pdo_in_sz), 0, self.main_in_base)
        bases[SyncManager.OUT] = (self.main_out_base - packet.size, packet.size)
        self.out_cmd_pos = packet.size
        packet.append(ECCmd.LRD, bytes(self.pdo_out_sz), 0, self.sub_in_base)
        return bases


class SafetySub(EBPFTerminal):
    """All sub instances of a safety PLC"""
    
    compatibility = {(2, 0x7703052), (2, 190328914)}

    async def initialize(self, *args, **kwargs):
        await super().initialize(*args, **kwargs)
        safe_address, = await self.sdo_read_format('<H', 0x9001, 2)
        self.ec.terminal_by_safe_address[safe_address] = self

    def allocate(self, packet, readwrite):
        return self.bases
