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

from asyncio import ensure_future, Event, Future, Queue, StreamReader, gather
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

        self.buffer = Queue()

    def write(self, data):
        if data:
            self.buffer.put_nowait(data)

    connected = None

    async def connect(self):
        self.connected = Future()
        self.reader = StreamReader()
        await self.connected
        return self.reader, self

    last_transmit_request = False
    last_receive_accept = False
    current_transmit = None
    remainder = b''

    def update(self):
        self.init_request = False
        if self.connected is None:
            return
        if not self.connected.done():
            if self.init_accept:
                self.connected.set_result(None)
                self.last_transmit_accept = self.transmit_accept
                self.last_receive_request = self.receive_request
            else:
                self.init_request = True
            return

        if self.last_receive_request != self.receive_request:
            self.reader.feed_data(self.in_string)
            self.last_receive_accept = not self.last_receive_accept
            self.receive_accept = self.last_receive_accept
        self.last_receive_request = self.receive_request

        if self.last_transmit_accept != self.transmit_accept:
            self.current_transmit = None
            self.last_transmit_accept = self.transmit_accept

        if self.current_transmit is None \
                and (self.remainder or not self.buffer.empty()):
            n = len(self.remainder)
            ret = [self.remainder]
            while not self.buffer.empty():
                nxt = self.buffer.get_nowait()
                n += len(nxt)
                if n > 22:
                    ret.append(nxt[:22-n])
                    self.remainder = nxt[22-n:]
                    break
                else:
                    ret.append(nxt)
            else:
                self.remainder = b''
            self.current_transmit = b''.join(ret)
            self.last_transmit_request = not self.last_transmit_request

        self.transmit_request = self.last_transmit_request
        if self.current_transmit is not None:
            self.out_string = self.current_transmit
