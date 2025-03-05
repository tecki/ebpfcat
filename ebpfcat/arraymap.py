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

"""The ``arraymap`` module defines array maps, usually used for global
variables in EBPF programs"""

__all__ = ["ArrayMap"]

from itertools import chain
from mmap import mmap
from struct import pack_into, unpack_from, calcsize

from .ebpf import Expression, FuncId, Map, MemoryDesc, Opcode, SubProgram
from .bpf import create_map, lookup_elem, MapType, MapFlags, update_elem


class ArrayGlobalVarDesc(MemoryDesc):
    base_register = 0

    def __init__(self, map, fmt):
        self.map = map
        self.fmt = fmt
        self.fixed = fmt == "x"

    def fmt_addr(self, ebpf):
        return self.fmt, ebpf.__dict__[self.name]

    def __set_name__(self, owner, name):
        self.name = name

    def __get__(self, instance, owner):
        if instance is None:
            return self
        if instance.ebpf.loaded:
            fmt, addr = self.fmt_addr(instance)
            data = instance.ebpf.__dict__[self.map.name]
            if fmt == "x":
                return unpack_from("q", data, addr)[0] / Expression.FIXED_BASE
            else:
                ret = unpack_from(fmt, data, addr)
            if len(ret) == 1:
                return ret[0]
            else:
                return ret
        else:
            return super().__get__(instance, owner)

    def __set__(self, instance, value):
        if instance.ebpf.loaded:
            fmt, addr = self.fmt_addr(instance)
            if fmt == "x":
                fmt = "q"
                value = int(value * Expression.FIXED_BASE)
            if not isinstance(value, tuple):
                value = value,
            pack_into(fmt, instance.ebpf.__dict__[self.map.name],
                      addr, *value)
        else:
            super().__set__(instance, value)


class ArrayMap(Map):
    """A descriptor for an array map"""

    def globalVar(self, fmt="I"):
        return ArrayGlobalVarDesc(self, fmt)

    def collect(self, ebpf):
        collection = []

        for prog in chain([ebpf], ebpf.subprograms):
            for cls in prog.__class__.__mro__:
                unique = set()
                for k, v in cls.__dict__.items():
                    if isinstance(v, ArrayGlobalVarDesc) and k not in unique:
                        collection.append((8 if v.fmt == "x"
                                           else calcsize(v.fmt), prog, k))
                        unique.add(k)
        collection.sort(key=lambda t: t[0], reverse=True)
        position = 0
        for size, prog, name in collection:
            prog.__dict__[name] = position
            position += size
        return position

    def __set_name__(self, owner, name):
        self.name = name

    def init(self, ebpf, fd):
        size = self.collect(ebpf)
        if not size:  # nobody is actually using the map
            return
        if fd is None:
            fd = create_map(MapType.ARRAY, 4, size, 1, MapFlags.MMAPABLE)
        setattr(ebpf, self.name, mmap(fd, size))
        with ebpf.save_registers(list(range(6))), ebpf.get_stack(4) as stack:
            ebpf.mI[ebpf.r10 + stack] = 0
            ebpf.r1 = ebpf.get_fd(fd)
            ebpf.r2 = ebpf.r10 + stack
            ebpf.call(FuncId.map_lookup_elem)
            with ebpf.r0 == 0:
                ebpf.exit()
        ebpf.owners.add(0)
