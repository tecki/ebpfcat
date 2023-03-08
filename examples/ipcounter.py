"""example program to count IPv4 and IPv6 packets"""

from asyncio import get_event_loop, sleep
from ebpfcat.arraymap import ArrayMap
from ebpfcat.xdp import PacketVar, XDP, XDPExitCode, XDPFlags

class IPCount(XDP):
    license = "GPL"

    minimumPacketSize = 14

    userspace = ArrayMap()
    ipv4count = userspace.globalVar()
    ipv6count = userspace.globalVar()
    ethertype = PacketVar(12, "!H")

    def program(self):
        with self.ethertype == 0x800 as Else:
            self.ipv4count += 1
        with Else, self.ethertype == 0x86dd: 
            self.ipv6count += 1
        self.exit(XDPExitCode.PASS)


async def main():
    c = IPCount()

    async with c.run("eth0", XDPFlags.DRV_MODE):
        for i in range(10):
            await sleep(0.1)
            print(f"packets arrived: IPv4 {c.ipv4count} IPv6 {c.ipv6count}")


if __name__ == "__main__":
    get_event_loop().run_until_complete(main())
