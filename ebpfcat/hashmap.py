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

from collections.abc import MutableMapping
from contextlib import contextmanager
from struct import pack, unpack, unpack

from .ebpf import AssembleError, Expression, Opcode, Map, FuncId
from .bpf import (
    MapType, UpdateFlags, create_map, delete_elem, get_next_key, lookup_elem,
    lookup_and_delete_elem, update_elem)


class HashGlobalVar(Expression):
    def __init__(self, ebpf, count, fmt):
        self.ebpf = ebpf
        self.count = count
        self.fmt = fmt
        self.signed = fmt.islower()
        self.fixed = fmt == "x"

    @contextmanager
    def get_address(self, dst, long, force=False):
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
            return lookup_elem(fd, pack("B", self.count), self.fmt)
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
                        pack("q" if self.fmt.islower() else "Q", value))
            return
        with ebpf.save_registers([3]):
            with value.get_address(3, True, True):
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

    def init(self, ebpf, fd):
        if fd is None:
            fd = create_map(MapType.HASH, 1, 8, self.count)
        for v in self.vars:
            getattr(ebpf, v.name).fd = fd

    def load(self, ebpf):
        for v in self.vars:
            setattr(ebpf, v.name, ebpf.__class__.__dict__[v.name].default)


class TheDict(MutableMapping):
    def __init__(self, ht, ebpf, fd):
        self.key = ht.Key()
        self.key.addr_offset = ht.key_offset
        self.key.data = None
        self.key.ebpf = ebpf
        self.value = ht.Value()
        self.value.addr_offset = ht.value_offset
        self.value.data = None
        self.value.ebpf = ebpf
        self.ebpf = ebpf
        self.fd = fd

    def __setitem__(self, key, value):
        assert isinstance(key, type(self.key))
        assert isinstance(value, type(self.value))
        update_elem(self.fd, key.data, value.data)

    def __getitem__(self, key):
        assert isinstance(key, type(self.key))
        ret = type(self.value)()
        ret.data = lookup_elem(self.fd, key.data, self.value.stack)
        return ret

    __marker = object()

    def pop(self, key, default=__marker):
        assert isinstance(key, type(self.key))
        ret = type(self.value)()
        try:
            ret.data = lookup_and_delete_elem(self.fd, key.data,
                                              self.value.stack)
        except KeyError:
            if default is self.__marker:
                raise
            return default
        return ret

    def __delitem__(self, key):
        assert isinstance(key, type(self.key))
        delete_elem(self.fd, key.data)

    def __len__(self):
        """there is no way to actually tell how many elements are in a
        hash map, but we need a __len__ method for MutableMapping. We just
        raise a TypeError, so that list(table) still works.
        """
        raise TypeError

    def __iter__(self):
        current = get_next_key(self.fd, self.key.stack)
        while True:
            ret = type(self.key)()
            ret.data = current
            yield ret
            try:
                current = get_next_key(self.fd, current)
            except StopIteration:
                return

    def update(self, flags=UpdateFlags.ANY):
        assert isinstance(flags, UpdateFlags)
        ebpf = self.ebpf
        with ebpf.save_registers([1, 2, 3, 4, 5]):
            ebpf.r1 = ebpf.get_fd(self.fd)
            ebpf.r2 = ebpf.r10 + self.key.addr_offset
            ebpf.r3 = ebpf.r10 + self.value.addr_offset
            ebpf.r4 = flags.value
            ebpf.call(FuncId.map_update_elem)

    @contextmanager
    def lookup(self):
        ebpf = self.ebpf
        with ebpf.save_registers([1, 2, 3, 4, 5]):
            ebpf.r1 = ebpf.get_fd(self.fd)
            ebpf.r2 = ebpf.r10 + self.key.addr_offset
            ebpf.call(FuncId.map_lookup_elem)
        with ebpf.r0 != 0 as Else:
            value = type(self.value)()
            value.addr_offset = 0
            value.base_register = 0
            value.data = None
            value.ebpf = ebpf
            yield value, Else



class Dict(Map):
    """A dictionary, implemented using a bpf hash map

    This is a lookup table similar to a Python :class:`dict`.
    Both key and value are subclasses of :class:`~ebpf.Structure`::

        class Key(Structure):
            some_key = Member('I')

        class Value(Structure):
            some_value = Member('q')

    A dictionary can then be declared in an EBPF program:

        class Program(EBPF):
            table = Dict(key=Key, value=Value)

    On the Python side, the usage is like a Python :class:`dict`::

        e = Program()
        e.load()
        k = Key()
        k.some_key = 3
        v = Value()
        v.some_value = 7

        # update a value
        e.table[k] = v

        # look up a value:
        v = e.table[k]

    On the EBPF side, things are a bit more complicated. We always keep a
    key on the local stack for lookups, as well as a value for updates.
    Possible errors are returned in register 0, which one may immediately
    after::

        def program(self):
            self.table.key.some_key = 3
            self.table.update()
            with self.r0 != 0:
                # do some error handling, if needed

    Lookups need to be enclosed in a ``with`` statement, during which the
    looked up value will be valid. One may modify the looked up value, which
    will indeed change the value in the dictionary.

    In case of an error (e.g., the looked up key does not exist), we skip
    over the entire ``with`` clause. The lookup function also returns an
    ``Else`` handler for later error handling::

        def program(self):
            self.table.key.some_key = 7
            with self.table.lookup() as value, Else:
                value.some_value = 3  # this changes the value in the Dict
            with Else:
                # do some error handling

    :param size: the maximum number of elements in the Dict
    """

    def __init__(self, key, value, size=31, lru=False):
        self.Key = key
        self.Value = value
        if lru:
            self.mapType = MapType.LRU_HASH
        else:
            self.mapType = MapType.HASH
        self.size = size

    def __set_name__(self, owner, name):
        owner.stack -= self.Key.stack
        owner.stack &= -8
        self.key_offset = owner.stack
        owner.stack -= self.Value.stack
        owner.stack &= -8
        self.value_offset = owner.stack
        self.name = name

    def init(self, ebpf, fd):
        if fd is None:
            fd = create_map(self.mapType, self.Key.stack,
                            self.Value.stack, self.size)
        setattr(ebpf, self.name, TheDict(self, ebpf, fd))
