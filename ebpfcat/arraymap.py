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

from itertools import chain
from struct import pack_into, unpack_from, calcsize

from .ebpf import FuncId, Map, MemoryDesc
from .bpf import create_map, lookup_elem, MapType, update_elem


class ArrayGlobalVarDesc(MemoryDesc):
    base_register = 0

    def __init__(self, map, fmt, write=False):
        self.map = map
        self.fmt = fmt
        self.write = write

    def fmt_addr(self, ebpf):
        return self.fmt, ebpf.__dict__[self.name]

    def __set_name__(self, owner, name):
        self.name = name

    def __get__(self, instance, owner):
        if instance is None:
            return self
        if instance.ebpf.loaded:
            fmt, addr = self.fmt_addr(instance)
            data = instance.ebpf.__dict__[self.map.name].data
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
            if not isinstance(value, tuple):
                value = value,
            pack_into(fmt, instance.ebpf.__dict__[self.map.name].data,
                      addr, *value)
        else:
            super().__set__(instance, value)


class ArrayMapAccess:
    """This is the array map proper"""
    def __init__(self, fd, write_size, size):
        self.fd = fd
        self.write_size = write_size
        self.size = size
        self.data = bytearray(size)

    def read(self):
        """read all variables in the map from EBPF to user space"""
        self.data = lookup_elem(self.fd, b"\0\0\0\0", self.size)

    def write(self):
        """write all variables in the map from user space to EBPF

        *all* variables are written, even those not marked ``write=True``
        """
        update_elem(self.fd, b"\0\0\0\0", self.data, 0)

    def readwrite(self):
        """read variables from EBPF and write them out immediately

        This reads all variables, swaps in the user-modified values for
        the ``write=True`` variables, and writes the out again
        immediately.

        This means that even the read-only variables will be overwritten
        with the values we have just read. If the EBPF program changed
        the value in the meantime, that may be a problem.

        Note that after this method returns, all *write* variables
        will have the value from the EBPF program in user space, and
        vice-versa.
        """
        write = self.data[:self.write_size]
        data = lookup_elem(self.fd, b"\0\0\0\0", self.size)
        self.data[:] = data
        data[:self.write_size] = write
        update_elem(self.fd, b"\0\0\0\0", data, 0)


class ArrayMap(Map):
    """A descriptor for an array map"""
    def globalVar(self, fmt="I", write=False):
        return ArrayGlobalVarDesc(self, fmt, write)

    def collect(self, ebpf):
        collection = []

        for prog in chain([ebpf], ebpf.subprograms):
            for k, v in prog.__class__.__dict__.items():
                if isinstance(v, ArrayGlobalVarDesc):
                    collection.append((v.write, calcsize(v.fmt), prog, k))
        collection.sort(key=lambda t: t[:2], reverse=True)
        position = 0
        last_write = write = True
        for write, size, prog, name in collection:
            if last_write != write:
                position = (position + 7) & -8
                write_size = position
            prog.__dict__[name] = position
            position += size
            last_write = write
        if write:  # there are read variables
            return position, position
        else:
            return write_size, position

    def __set_name__(self, owner, name):
        self.name = name

    def init(self, ebpf):
        setattr(ebpf, self.name, 0)
        write_size, size = self.collect(ebpf)
        if not size:  # nobody is actually using the map
            return
        fd = create_map(MapType.ARRAY, 4, size, 1)
        setattr(ebpf, self.name, ArrayMapAccess(fd, write_size, size))
        with ebpf.save_registers(list(range(6))), ebpf.get_stack(4) as stack:
            ebpf.mI[ebpf.r10 + stack] = 0
            ebpf.r1 = ebpf.get_fd(fd)
            ebpf.r2 = ebpf.r10 + stack
            ebpf.call(FuncId.map_lookup_elem)
            with ebpf.r0 == 0:
                ebpf.exit()
        ebpf.owners.add(0)
