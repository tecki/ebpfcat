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

import asyncio
import os
from multiprocessing.context import get_spawning_popen
from .ebpfcat import Device, TerminalVar


class Serial(Device):
    transmit_accept = TerminalVar()
    receive_request = TerminalVar()
    init_accept = TerminalVar()
    in_string = TerminalVar()

    transmit_request = TerminalVar()
    receive_accept = TerminalVar()
    init_request = TerminalVar()
    out_string = TerminalVar()

    def __init__(self, channel):
        self.transmit_accept = channel.transmit_accept
        self.receive_request = channel.receive_request
        self.init_accept = channel.init_accept
        self.in_string = channel.in_string
        self.transmit_request = channel.transmit_request
        self.receive_accept = channel.receive_accept
        self.init_request = channel.init_request
        self.out_string = channel.out_string

        self.in_read, self.in_write = os.pipe2(os.O_NONBLOCK)
        self.out_read, self.out_write = os.pipe2(os.O_NONBLOCK)

    def __getstate__(self):
        get_spawning_popen().duplicate_for_child(self.in_write)
        get_spawning_popen().duplicate_for_child(self.out_read)
        return super().__getstate__()

    connected = False

    async def connect(self):
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        await loop.connect_read_pipe(
            lambda: asyncio.StreamReaderProtocol(reader),
            open(self.in_read, 'rb'))
        writer, _ = await loop.connect_write_pipe(asyncio.Protocol,
                                                  open(self.out_write, 'wb'))

        init = await reader.readexactly(1)
        os.close(self.in_write)
        os.close(self.out_read)
        assert init == b'A'
        return reader, writer

    last_transmit_request = False
    last_receive_accept = False
    current_transmit = None
    remainder = b''

    def update(self):
        self.init_request = False
        if not self.connected:
            if self.init_accept:
                self.connected = True
                os.write(self.in_write, b'A')
                self.last_transmit_accept = self.transmit_accept
                self.last_receive_request = self.receive_request
            else:
                self.init_request = True
            return

        if self.last_receive_request != self.receive_request:
            os.write(self.in_write, self.in_string)
            self.last_receive_accept = not self.last_receive_accept
            self.receive_accept = self.last_receive_accept
        self.last_receive_request = self.receive_request

        if self.last_transmit_accept != self.transmit_accept:
            self.current_transmit = None
            self.last_transmit_accept = self.transmit_accept

        if self.current_transmit is None:
            try:
                data = os.read(self.out_read, 22)
            except BlockingIOError:
                pass
            else:
                if data:
                    self.current_transmit = data
                    self.last_transmit_request = not self.last_transmit_request
        if self.current_transmit is not None:
            self.out_string = self.current_transmit
        self.transmit_request = self.last_transmit_request
