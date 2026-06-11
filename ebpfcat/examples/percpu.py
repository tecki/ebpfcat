from ebpfcat.arraymap import PerCPUArrayMap
from ebpfcat.xdp import XDP, XDPExitCode, XDPFlags
from time import sleep

class Count(XDP):
    license = "GPL"

    userspace = PerCPUArrayMap()
    count = userspace.globalVar()

    def program(self):
        self.count += 1
        self.exit(XDPExitCode.PASS)


def main():
    c = Count()

    with c.run("eth1"): #, XDPFlags.DRV_MODE):
        for i in range(10):
            sleep(0.1)
            c.userspace.read()
            print("packets arrived so far:", sum(c.count))


if __name__ == "__main__":
    get_event_loop().run_until_complete(main())
