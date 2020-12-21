from .xdp import set_link_xdp_fd
from .ebpf import EBPF
from .bpf import ProgType, create_map, update_elem, prog_test_run, lookup_elem

def script():
    fd = create_map(1, 4, 4, 7)
    update_elem(fd, b"AAAA", b"BBBB", 0)

    e = EBPF(ProgType.XDP, "GPL")
    e.r1 = e.get_fd(fd)
    e.r2 = e.r10
    e.r2 += -8
    e.m32[e.r10 - 8] = 0x41414141
    e.call(1)
    with e.If(e.r0 != 0):
        e.r1 = e.get_fd(fd)
        e.r2 = e.r10
        e.r2 += -8
        e.r3 = e.m32[e.r0]
        e.r3 += 1
        e.m32[e.r10 - 16] = e.r3
        e.r3 = e.r10
        e.r3 += -16
        e.r4 = 0
        e.call(2)
    e.r0 = 2  # XDP_PASS
    e.exit()
    return fd, e

async def install_ebpf(network):
    map_fd, e = script()
    fd, disas = e.load(log_level=1)
    prog_test_run(fd, 512, 512, 512, 512, repeat=10)
    print("bla", lookup_elem(map_fd, b"AAAAA", 4))
    await set_link_xdp_fd("eth0", fd)
    return map_fd

if __name__ == "__main__":
    from asyncio import get_event_loop
    loop = get_event_loop()
    loop.run_until_complete(install_ebpf("eth0"))
