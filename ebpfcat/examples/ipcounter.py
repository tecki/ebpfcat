"""example program to count IPv4 and IPv6 packets"""

from argparse import ArgumentParser
from ebpfcat.arraymap import ArrayMap
from ebpfcat.xdp import PacketVar, XDP, XDPExitCode, XDPFlags
import os
from time import sleep

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


def show(counter):
    for i in range(10):
        sleep(0.1)
        print(f"IPv4 {counter.ipv4count} IPv6 {counter.ipv6count}")


def main():
    parser = ArgumentParser(
        prog="ipcount",
        description="Count IPv4 and IPv6 packets")

    parser.add_argument("interface",
                        help="the network interface to listen to")
    parser.add_argument("-a", "--attach", action="store_true",
                        help="attach the bpf program to the interface")
    parser.add_argument("-s", "--show", action="store_true",
                        help="show the number of received packets")
    parser.add_argument("-d", "--detach", action="store_true",
                        help="detach the bpf program from the interface")
    args = parser.parse_args()

    if args.attach or not args.show:
        c = IPCount()
    else:
        c = IPCount(load_maps="/sys/fs/bpf/ipcount/")

    if args.attach and args.detach:
        with c.run(args.interface, XDPFlags.SKB_MODE):
            if args.show:
                show(c)
    elif args.attach:
        c.attach(args.interface, XDPFlags.SKB_MODE)
        os.makedirs("/sys/fs/bpf/ipcount/", exist_ok=True)
        c.pin_maps("/sys/fs/bpf/ipcount/")
        if args.show:
            show(c)
    else:
        if args.show:
            show(c)
        if args.detach:
            c.detach(args.interface, XDPFlags.DRV_MODE)
            os.remove("/sys/fs/bpf/ipcount/userspace")


if __name__ == "__main__":
    main()
