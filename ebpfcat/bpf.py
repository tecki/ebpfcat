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

"""\
A module that wraps the `bpf` system call in Python, using `ctypes`.
"""
import string
from ctypes import (
    CDLL, addressof, c_char, c_char_p, c_int, c_void_p, cast,
    create_string_buffer, get_errno)
from enum import Enum, Flag
from os import strerror
from platform import machine
from struct import calcsize, pack, unpack

try:
    SYS_BPF = {
        "armv7l": 386,
        "x86_64": 321,
        "aarch64": 280,
        }[machine()]
except KeyError:
    print("Unknown platform:", machine())


class BPFError(OSError):
    pass


class MapType(Enum):
    UNSPEC = 0
    HASH = 1
    ARRAY = 2
    PROG_ARRAY = 3
    PERF_EVENT_ARRAY = 4
    PERCPU_HASH = 5
    PERCPU_ARRAY = 6
    STACK_TRACE = 7
    CGROUP_ARRAY = 8
    LRU_HASH = 9
    LRU_PERCPU_HASH = 10
    LPM_TRIE = 11
    ARRAY_OF_MAPS = 12
    HASH_OF_MAPS = 13
    DEVMAP = 14
    SOCKMAP = 15
    CPUMAP = 16
    XSKMAP = 17
    SOCKHASH = 18


class MapFlags(Flag):
    MMAPABLE = 1 << 10


class ProgType(Enum):
    UNSPEC = 0
    SOCKET_FILTER = 1
    KPROBE = 2
    SCHED_CLS = 3
    SCHED_ACT = 4
    TRACEPOINT = 5
    XDP = 6
    PERF_EVENT = 7
    CGROUP_SKB = 8
    CGROUP_SOCK = 9
    LWT_IN = 10
    LWT_OUT = 11
    LWT_XMIT = 12
    SOCK_OPS = 13
    SK_SKB = 14
    CGROUP_DEVICE = 15
    SK_MSG = 16
    RAW_TRACEPOINT = 17
    CGROUP_SOCK_ADDR = 18
    LWT_SEG6LOCAL = 19
    LIRC_MODE2 = 20


class UpdateFlags(Flag):
    ANY = 0
    NOEXIST = 1
    EXIST = 2
    F_LOCK = 4


libc = CDLL("libc.so.6", use_errno=True)

def addrof(ptr):
    return cast(ptr, c_void_p).value

def bpf(cmd, fmt, *args):
    attr = pack(fmt, *args)
    attr = create_string_buffer(attr, len(attr))
    ret = libc.syscall(SYS_BPF, c_int(cmd), attr, len(attr))
    if ret == -1:
        raise OSError(get_errno(), strerror(get_errno()))
    return ret, unpack(fmt, attr.raw)

def create_map(map_type, key_size, value_size, max_entries,
               attributes=MapFlags(0)):
    assert isinstance(map_type, MapType)
    assert isinstance(attributes, MapFlags)
    return bpf(0, "IIIII", map_type.value, key_size, value_size, max_entries,
               attributes.value)[0]

def lookup_elem(fd, key, fmt):
    value = bytearray(calcsize(fmt))
    addr = addressof(c_char.from_buffer(value))
    ret, _ = bpf(1, "IQQQ", fd, addrof(key), addr, 0)
    if ret == 0:
        return unpack(fmt, value)[0]
    else:
        return None

def update_elem(fd, key, value, flags=UpdateFlags.ANY):
    assert isinstance(flags, UpdateFlags)
    if isinstance(value, bytearray):
        addr = addressof(c_char.from_buffer(value))
    else:
        addr = addrof(value)
    return bpf(2, "IQQQ", fd, addrof(key), addr, flags.value)[0]

def delete_elem(fd, key):
    return bpf(3, "IQ", fd, addrof(key))[0]

allowed_chars = set(string.ascii_letters + string.digits + "-_")

def prog_load(prog_type, insns, license,
              log_level=0, log_size=4096, kern_version=0, flags=0,
              name="", ifindex=0, attach_type=0):
    if log_level == 0:
        log_buf = 0
        log_size = 0
    else:
        the_logbuf = create_string_buffer(log_size)
        log_buf = addrof(the_logbuf)
    license = license.encode("utf8")
    assert len(name) < 16 and set(name) <= allowed_chars, f'wrong name {name}'
    try:
        fd, _ = bpf(5, "IIQQIIQII16sII", prog_type.value, int(len(insns) // 8),
                    addrof(insns), addrof(license), log_level, log_size,
                    log_buf, kern_version, flags, name.encode("utf8"), ifindex,
                    attach_type)
    except OSError as e:
        if log_level != 0:
            raise BPFError(e.errno, the_logbuf.value.decode("utf8"))
        raise
    if log_level != 0:
        return fd, the_logbuf.value.decode("utf8")
    else:
        return fd, None

def obj_pin(pathname, fd):
    pn = pathname.encode("utf8")
    bpf(6, "QI", addrof(pn), fd)

def obj_get(pathname):
    pn = pathname.encode("utf8")
    fd, _ = bpf(7, "Q", addrof(pn))
    return fd

def prog_test_run(fd, data_in, data_out, ctx_in, ctx_out,
                  repeat=1):
    if isinstance(data_in, int):
        data_in = create_string_buffer(data_in)
    else:
        data_in = create_string_buffer(data_in, len(data_in))
    if isinstance(ctx_in, int):
        ctx_in = create_string_buffer(ctx_in)
    else:
        ctx_in = create_string_buffer(ctx_in, len(ctx_in))
    data_out = create_string_buffer(data_out)
    ctx_out = create_string_buffer(ctx_out)
    ret, (_, retval, _, _, _, _, _, duration) = bpf(
            10, "IIIIQQII20x", fd, 0, len(data_in), len(data_out),
            addrof(data_in), addrof(data_out), repeat, 0)
    return ret, retval, duration, data_out.value, ctx_out.value
