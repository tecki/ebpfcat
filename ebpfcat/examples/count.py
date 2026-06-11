from ebpfcat.arraymap import ArrayMap
from ebpfcat.xdp import XDP, XDPExitCode, XDPFlags
from time import sleep

class Count(XDP):
    license = "GPL"

    userspace = ArrayMap()
    count = userspace.globalVar()

    def program(self):
        self.count += 1
        self.exit(XDPExitCode.PASS)


def main():
    c = Count()

    with c.run("eth0", XDPFlags.DRV_MODE):
        for i in range(10):
            sleep(0.1)
            print("packets arrived so far:", c.count)


if __name__ == "__main__":
    main()
