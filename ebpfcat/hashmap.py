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

from contextlib import contextmanager
from struct import pack, unpack, unpack

from .ebpf import AssembleError, Expression, Opcode, Map, FuncId, Memory
from .bpf import create_map, lookup_elem, MapType, update_elem


class HashGlobalVar(Expression):
    def __init__(self, ebpf, count, fmt):
        self.ebpf = ebpf
        self.count = count
        self.fmt = fmt
        self.signed = fmt.islower()

    @contextmanager
    def get_address(self, dst, long, signed, force=False):
        if signed != self.fmt.islower():
            raise AssembleError("HashMap variable has wrong signedness")
        with self.ebpf.save_registers([i for i in range(6) if i != dst]), \
                self.ebpf.get_stack(4) as stack:
            self.ebpf.append(Opcode.ST, 10, 0, stack, self.count)
            self.ebpf.r1 = self.ebpf.get_fd(self.fd)
            self.ebpf.r2 = self.ebpf.r10 + stack
            self.ebpf.call(FuncId.map_lookup_elem)
            with self.ebpf.r0 == 0:
                self.ebpf.exit()
            if dst != 0 and force:
                self.ebpf.append(Opcode.MOV + Opcode.LONG + Opcode.REG, dst,
                                 0, 0, 0)
            else:
                dst = 0
        yield dst, self.fmt


class HashGlobalVarDesc:
    def __init__(self, count, fmt, default=0):
        self.count = count
        self.fmt = fmt
        self.default = default

    def __get__(self, instance, owner):
        if instance is None:
            return self
        if instance.loaded:
            fd = instance.__dict__[self.name].fd
            ret = lookup_elem(fd, pack("B", self.count), 4)
            return unpack(self.fmt, ret)[0]
        ret = instance.__dict__.get(self.name, None)
        if ret is None:
            ret = HashGlobalVar(instance, self.count, self.fmt)
            instance.__dict__[self.name] = ret
        return ret

    def __set_name__(self, owner, name):
        self.name = name

    def __set__(self, ebpf, value):
        if ebpf.loaded:
            fd = ebpf.__dict__[self.name].fd
            update_elem(fd, pack("B", self.count),
                        pack("q" if self.fmt.islower() else "Q", value), 0)
            return
        with ebpf.save_registers([3]):
            with value.get_address(3, True, self.fmt.islower(), True):
                with ebpf.save_registers([0, 1, 2, 4, 5]), \
                        ebpf.get_stack(4) as stack:
                    ebpf.r1 = ebpf.get_fd(ebpf.__dict__[self.name].fd)
                    ebpf.append(Opcode.ST, 10, 0, stack, self.count)
                    ebpf.r2 = ebpf.r10 + stack
                    ebpf.r4 = 0
                    ebpf.call(FuncId.map_update_elem)


class HashMap(Map):
    count = 0

    def __init__(self):
        self.vars = []

    def globalVar(self, fmt="I", default=0):
        self.count += 1
        ret = HashGlobalVarDesc(self.count, fmt, default)
        self.vars.append(ret)
        return ret

    def init(self, ebpf):
        fd = create_map(MapType.HASH, 1, 8, self.count)
        for v in self.vars:
            getattr(ebpf, v.name).fd = fd

    def load(self, ebpf):
        for v in self.vars:
            setattr(ebpf, v.name, ebpf.__class__.__dict__[v.name].default)
