from asyncio import get_event_loop, sleep
from ebpfcat.hashmap import HashMap
from ebpfcat.xdp import XDP, XDPExitCode, XDPFlags

class Count(XDP):
    license = "GPL"

    userspace = HashMap()
    count = userspace.globalVar()

    def program(self):
        self.count += 1
        self.exit(XDPExitCode.PASS)


async def main():
    c = Count()

    async with c.run("eth0", XDPFlags.DRV_MODE):
        for i in range(10):
            await sleep(0.1)
            print("packets arrived so far:", c.count)


if __name__ == "__main__":
    get_event_loop().run_until_complete(main())
