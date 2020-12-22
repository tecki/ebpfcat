from ctypes import CDLL, c_int, get_errno, cast, c_void_p, create_string_buffer, c_char_p
from enum import Enum
from struct import pack, unpack

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
    attr = create_string_buffer(attr, len(attr))
    ret = libc.syscall(386, c_int(cmd), attr, len(attr))
    if ret == -1:
        raise OSError(get_errno(), strerror(get_errno()))
    return ret, unpack(fmt, attr.raw)

def create_map(map_type, key_size, value_size, max_entries):
    return bpf(0, "IIII", map_type, key_size, value_size, max_entries)[0]

def lookup_elem(fd, key, size):
    value = create_string_buffer(size)
    ret, _ = bpf(1, "IQQQ", fd, addrof(key), addrof(value), 0)
    if ret == 0:
        return value.raw
    else:
        return None

def update_elem(fd, key, value, flags):
    return bpf(2, "IQQQ", fd, addrof(key), addrof(value), flags)[0]

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
        fd, _ = bpf(5, "IIQQIIQI", prog_type.value, int(len(insns) // 8),
                    addrof(insns), addrof(license), log_level, log_size,
                    log_buf, kern_version)
    except OSError as e:
        if log_level != 0:
            raise BPFError(e.errno, the_logbuf.value.decode("utf8"))
        raise
    if log_level != 0:
        return fd, the_logbuf.value.decode("utf8")
    else:
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
    ret, (_, retval, _, _, _, _, _, duration, _, _, _, _) = bpf(
            10, "IIIIQQIIIIQQ20x", fd, 0, len(data_in), len(data_out),
            addrof(data_in), addrof(data_out), repeat, 0, 0, 0, 0, 0)
            #len(ctx_in), len(ctx_out), addrof(ctx_in), addrof(ctx_out))
    return ret, retval, duration, data_out.value, ctx_out.value

if __name__ == "__main__":
    fd = create_map(1, 4, 4, 10)
    update_elem(fd, b"asdf", b"ckde", 0)
    print(lookup_elem(fd, b"asdf", 4))
