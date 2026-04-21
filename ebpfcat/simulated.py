# ebpfcat, A Python-based EBPF generator and EtherCAT master
# Copyright (C) 2026 European XFEL GmbH
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

import gc
import os
from asyncio import CancelledError, ensure_future, get_event_loop, run
from multiprocessing import Array, Process, Value, get_context

from .ebpf import EBPFBase, Map


class SimulatedEBPF(EBPFBase):
    loaded = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        unique = set()
        for cls in self.__class__.__mro__:
            for k, v in cls.__dict__.items():
                if k not in unique and isinstance(v, Map):
                    size = v.collect(self)
                    setattr(self, k, self.get_array(size))
                    unique.add(k)


class ProcessEBPF(SimulatedEBPF):
    def __init__(self, **kwargs):
        self.ctx = get_context('spawn')
        super().__init__(**kwargs)

    def get_array(self, size):
        return self.ctx.Array('B', size).get_obj()

    @property
    def running(self):
        """is the subprocess supposted to run?"""
        return self.runningValue.value

    def subprocess_run(self):
        gc.collect()
        gc.disable()
        param = os.sched_param(os.sched_get_priority_max(os.SCHED_RR))
        os.sched_setscheduler(0, os.SCHED_RR, param)
        if self.name != 'No Name':
            with open('/proc/self/comm', 'w') as fout:
                fout.write(self.name[-15:])
        run(self.subprocess_loop())

    async def subprocess_loop(self):
        """The loop to be implemented by inheritance

        It should run while self.running is True, and return once it it not.
        """
        raise NotImplementedError

    async def wait_for_process(self):
        fd = os.pidfd_open(self.process.pid)
        loop = get_event_loop()
        lasterror = None
        while True:
            future = loop.create_future()
            loop.add_reader(fd, future.set_result, None)
            try:
                await future
            except CancelledError as error:
                self.runningValue.value = False
                lasterror = error
            else:
                if lasterror is None:
                    return
                else:
                    raise lasterror
            finally:
                loop.remove_reader(fd)

    def start(self):
        self.runningValue = self.ctx.Value('B')
        self.runningValue.value = True
        self.process = self.ctx.Process(target=self.subprocess_run)
        self.process.start()
        return ensure_future(self.wait_for_process())
