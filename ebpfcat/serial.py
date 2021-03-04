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

from asyncio import ensure_future, Event, Queue, StreamReader, gather
from .ebpfcat import Device, TerminalVar


class Serial(Device):
    channel = TerminalVar()

    def __init__(self, channel):
        self.buffer = Queue()
        self.channel = channel
        self.data_arrived = Event()

    def write(self, data):
        self.buffer.put_nowait(data)

    def connect(self):
        self.task = ensure_future(self.run())
        self.reader = StreamReader()
        return self.reader, self

    async def run(self):
        while not self.channel.init_accept:
            self.channel.init_request = True
            await self.data_arrived.wait()
        self.channel.init_request = False
        while self.channel.init_accept:
            await self.data_arrived.wait()

        await gather(self.receive(), self.transmit())

    async def receive(self):
        ra = self.channel.receive_accept
        while True:
            rr = self.channel.receive_request
            while rr == self.channel.receive_request:
                self.channel.receive_accept = ra
                await self.data_arrived.wait()
            self.reader.feed_data(self.channel.in_string)
            ra = not ra

    async def transmit(self):
        remainder = b""

        async def inner():
            nonlocal remainder
            s = remainder
            size = len(remainder)
            while not self.buffer.empty() or size == 0:
                if size + len(s) > 22:
                    remainder = s[22-size:]
                    yield s[:22-size]
                    return
                else:
                    yield s
                    size += len(s)
                    s = await self.buffer.get()

        while True:
            ta = self.channel.transmit_accept
            tr = self.channel.transmit_request
            chunk = b"".join([s async for s in inner()])
            while ta == self.channel.transmit_accept:
                self.channel.out_string = chunk
                self.channel.transmit_request = not tr
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
