from ctypes import CDLL, c_int, get_errno, cast, c_void_p, create_string_buffer
from enum import Enum
from struct import pack

from os import strerror

class BPFError(OSError):
    pass

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

libc = CDLL("libc.so.6", use_errno=True)

def addrof(ptr):
    return cast(ptr, c_void_p).value

def bpf(cmd, fmt, *args):
    attr = pack(fmt, *args)
    ret = libc.syscall(386, c_int(cmd), attr, len(attr))
    if ret == -1:
        raise OSError(get_errno(), strerror(get_errno()))
    return ret

def create_map(map_type, key_size, value_size, max_entries):
    return bpf(0, "IIII", map_type, key_size, value_size, max_entries)

def lookup_elem(fd, key, size):
    value = create_string_buffer(size)
    bpf(1, "IQQQ", fd, addrof(key), addrof(value), 0)
    return value.value

def update_elem(fd, key, value, flags):
    return bpf(2, "IQQQ", fd, addrof(key), addrof(value), flags)

def prog_load(prog_type, insns, license,
              log_level=0, log_size=4096, kern_version=0):
    if log_level == 0:
        log_buf = 0
        log_size = 0
    else:
        the_logbuf = create_string_buffer(log_size)
        log_buf = addrof(the_logbuf)
    license = license.encode("utf8")
    try:
        bpf(5, "IIQQIIQI", prog_type.value, int(len(insns) // 8),
            addrof(insns), addrof(license), log_level, log_size, log_buf,
            kern_version)
    except OSError as e:
        if log_level != 0:
            raise BPFError(e.errno, the_logbuf.value.decode("utf8"))
        raise
    if log_level != 0:
        return the_logbuf.value.decode("utf8")

if __name__ == "__main__":
    fd = create_map(1, 4, 4, 10)
    update_elem(fd, b"asdf", b"ckde", 0)
    print(lookup_elem(fd, b"asdf", 4))
