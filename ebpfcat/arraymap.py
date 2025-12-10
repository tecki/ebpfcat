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

__all__ = ["ArrayMap", "PerCPUArrayMap"]

from collections.abc import Sequence
from itertools import chain
from mmap import mmap
from os import cpu_count
from struct import pack, pack_into, unpack_from

from .bpf import MapFlags, MapType, create_map, lookup_elem, update_elem
from .ebpf import Expression, FuncId, Map, MemoryDesc, fmtsize


class ArrayGlobalVarDesc(MemoryDesc):
    def __init__(self, map, fmt):
        self.map = map
        self.fmt = fmt
        self.fixed = fmt == "x"
        self.base_register = map.base_register

    def fmt_addr(self, ebpf):
        return self.fmt, ebpf.__dict__[self.name]

    def __set_name__(self, owner, name):
        self.name = name

    def unpack(self, instance, data):
        fmt, addr = self.fmt_addr(instance)
        if fmt == "x":
            return unpack_from("q", data, addr)[0] / Expression.FIXED_BASE
        else:
            ret = unpack_from(fmt, data, addr)
        if len(ret) == 1:
            return ret[0]
        else:
            return ret

    def __get__(self, instance, owner):
        if instance is None:
            return self
        if instance.ebpf.loaded:
            return self.unpack(instance, instance.ebpf.__dict__[self.map.name])
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
            b = pack(fmt, *value)
            instance.ebpf.__dict__[self.map.name][addr:addr + len(b)] = b
        else:
            super().__set__(instance, value)


class PerCPUVarDesc(ArrayGlobalVarDesc):
    def __get__(self, instance, owner):
        if instance.ebpf.loaded:
            return PerCPUVar(self, instance)
        else:
            return super().__get__(instance, owner)


class PerCPUVar(Sequence):
    def __init__(self, descriptor, instance):
        self.descriptor = descriptor
        self.instance = instance

    def __len__(self):
        return self.descriptor.map.cpu_no

    def __getitem__(self, key):
        if 0 <= key < len(self):
            return self.descriptor.unpack(
                self.instance,
                getattr(self.instance.ebpf, self.descriptor.map.name)
                .data[key * self.descriptor.map.size:])
        else:
            raise IndexError(f"no such CPU #{key}")


class ArrayMap(Map):
    """A descriptor for an array map

    Array maps are the most convenient way to communicate between the
    eBPF and Python worlds. One can declare variables in such a map, which
    can then be accessed freely from both sides::

        class Example(EBPF):
            map = ArrayMap()
            counter = map.globalVar()  # declare a variable in the map
    """

    base_register = 7

    def globalVar(self, fmt="I"):
        return ArrayGlobalVarDesc(self, fmt)

    def collect(self, ebpf):
        collection = []

        for prog in chain([ebpf], ebpf.subprograms):
            for cls in prog.__class__.__mro__:
                unique = set()
                for k, v in cls.__dict__.items():
                    if isinstance(v, ArrayGlobalVarDesc) and v.map is self \
                            and k not in unique:
                        collection.append((fmtsize(v.fmt), prog, k))
                        unique.add(k)
        collection.sort(key=lambda t: t[0], reverse=True)
        position = 0
        for size, prog, name in collection:
            prog.__dict__[name] = position
            position += size
        position = ((position + 7) // 8) * 8
        return position

    def __set_name__(self, owner, name):
        self.name = name

    def create_map(self, ebpf, fd):
        if fd is None:
            fd = create_map(MapType.ARRAY, 4, self.size, 1, MapFlags.MMAPABLE)
        setattr(ebpf, self.name, mmap(fd, self.size))
        return fd

    def init(self, ebpf, fd):
        self.size = self.collect(ebpf)
        if not self.size:  # nobody is actually using the map
            return
        fd = self.create_map(ebpf, fd)
        with ebpf.save_registers(list(range(6))), ebpf.get_stack(4) as stack:
            ebpf.mI[ebpf.r10 + stack] = 0
            ebpf.r1 = ebpf.get_fd(fd)
            ebpf.r2 = ebpf.r10 + stack
            ebpf.call(FuncId.map_lookup_elem)
            with ebpf.r0 == 0:
                ebpf.exit()
        ebpf.owners.add(0)
        if self.base_register != 0:
            ebpf.r[self.base_register] = ebpf.r0
            ebpf.owners.remove(0)
        ebpf.owners.add(self.base_register)


class PerCPUReader:
    def __init__(self, map, fd):
        self.map = map
        self.fd = fd
        self.data = None

    def read(self):
        self.data = memoryview(lookup_elem(self.fd, bytes(4),
                               self.map.size * self.map.cpu_no))


class PerCPUArrayMap(ArrayMap):
    """a Per-CPU array map

    In high-performance applications parallel access to array maps via
    different CPUs may become a bottleneck. For this case, variables can
    be declared on a per-CPU map. From the eBPF side, they look like normal
    variables and can be accessed in any way, just that one sees only the
    changes done on the CPU the program is currently running on.

    From the Python side, the variables look like an array of values, one
    entry per CPU. The variables also can only be read from Python, and this
    reading needs to be done explicitly::

        class PerCPUExample(EBPF):
            perCPU = PerCPUArrayMap()
            counter = perCPU.globalVar()

            def program(self):
                ...
                self.counter += 1  # use like any variable
                ...

        ...  # later, from Python:

        ebpf = PerCPUExample()
        ... # run the program
        ebpf.perCPU.read()  # explicitly read the entire map
        count = sum(ebpf.counter)  # sum over all CPUs
        print(ebpf.counter[2])  # or access just one CPU
    """
    base_register = 6

    def globalVar(self, fmt="I"):
        return PerCPUVarDesc(self, fmt)

    def create_map(self, ebpf, fd):
        self.cpu_no = cpu_count()
        if fd is None:
            fd = create_map(MapType.PERCPU_ARRAY, 4, self.size, 1)
        setattr(ebpf, self.name, PerCPUReader(self, fd))
        return fd
