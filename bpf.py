from ctypes import CDLL, c_int, get_errno, cast, c_void_p, create_string_buffer
from struct import pack

from os import strerror

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
        log_buf = addrof(create_string_buffer(log_size))
    license = license.encode("utf8")
    bpf(5, "IIQQIIQI", prog_type, int(len(insns) // 8), addrof(license),
        log_level, log_size, log_buf, kern_version)
    if log_level != 0:
        return log_buf.value

if __name__ == "__main__":
    fd = create_map(1, 4, 4, 10)
    update_elem(fd, b"asdf", b"ckde", 0)
    print(lookup_elem(fd, b"asdf", 4))
