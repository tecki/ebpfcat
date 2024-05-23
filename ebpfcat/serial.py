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
        self.data_arrived = Event()

    def write(self, data):
        self.buffer.put_nowait(data)

    async def connect(self):
        connected = Future()
        self.task = ensure_future(self.run(connected))
        self.reader = StreamReader()
        await connected
        return self.reader, self

    async def run(self, connected):
        while not self.init_accept:
            self.init_request = True
            await self.data_arrived.wait()
        self.init_request = False
        while self.init_accept:
            await self.data_arrived.wait()

        connected.set_result(None)

        await gather(self.receive(), self.transmit())

    async def receive(self):
        ra = self.receive_accept
        while True:
            rr = self.receive_request
            while rr == self.receive_request:
                self.receive_accept = ra
                await self.data_arrived.wait()
            self.reader.feed_data(self.in_string)
            ra = not ra

    async def transmit(self):
        remainder = b""

        async def inner():
            nonlocal remainder
            s = remainder
            size = len(remainder)

            while True:
                remainder = s[22-size:]
                yield s[:22-size]
                size += len(s)
                if (self.buffer.empty() and size > 0) or size > 22:
                    return
                s = await self.buffer.get()

        while True:
            ta = self.transmit_accept
            tr = self.transmit_request
            chunk = b"".join([s async for s in inner()])
            while ta == self.transmit_accept:
                self.out_string = chunk
                self.transmit_request = not tr
                await self.data_arrived.wait()

    def update(self):
        self.data_arrived.set()
        self.data_arrived.clear()

    def get_chunk(self):
        def inner():
            size = 0
            while size < 22 and len(self.buffer):
                s = self.buffer.popleft()
                if size + len(s) > 22:
                    self.buffer.appendleft(s[22-size:])
                    yield s[:22-size]
                else:
                    yield
                l += len(s)
        return b"".join(inner())
