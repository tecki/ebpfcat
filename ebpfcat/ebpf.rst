A Python-base EBPF code generator
=================================

Getting started
---------------

As a simple example for EBPF we write an XDP program which simply counts
incoming packages.

We start with declaring the variables that we want to see both in the
XDP program and in user space::

   from ebpfcat.hashmap import HashMap
   from ebpfcat.xdp import XDP, XDPExitCode

   class Count(XDP):
       license = "GPL"  # the Linux kernel wants to know that...

       userspace = HashMap()
       count = userspace.globalVar()  # declare one variable in the map

Next comes the program that we want to run in the kernel. Note that this
program looks as if it was just Python code, but it is not actually.
Instead it generates EBPF code that we can later load into the kernel::

    def program(self):
        self.count += 1
        self.exit(XDPExitCode.PASS)  # pass packet on to network stack

Now we can attach this program to a network. We use `asyncio`
for synchronization::

   async def main():
       c = Count()
       await c.attach("eth0")

once attached, we can read the result in a loop::

    for i in range(100):
        await sleep(0.1)
        print(c.count)

Note that here we access the member variable `count` from user space.
While generating EBPF, the code generator knows it needs to write out
commands to access that variable from EBPF, once accessed outside of
generation context, we access it from the user side.

For reference, this is the full example:

.. literalinclude:: /examples/count.py

Conditional statements
----------------------

During code generation, all code needs to be executed. This means that
we cannot use a Python `if` statement, as then the code actually does not
get exxecuted, so no code would be generated. So we replace `if` statements
by Python `with` statements like so::

    with self.If(self.some_variable > 6) as cond:
        do_someting
    with cond.Else():
        do_something_else

certainly an `Else` statement is not necessary.

Accessing the packet
--------------------

The entire point of XDP is to react to the arriving network packets.
The EBPF program will be checked statically that it can only access the
contents of the packet, and not beyond. This means an `if` statement
needs to be added that checks that the packet is large enough so every
packet access will be within the packet. To facilitate this, a special
variable `packetSize` is defined, that when compared to will generate
code that the static code checker understands, like so::

     with self.packetSize > 100 as p:  # assure packet has at least 100 bytes
         self.some_variable = p.pH[22]  # read word at position 22
     with p.Else():
         self.exit()

in this code, the variable `p` returned by the `with` statement also
allows to access the content of the packet. There are eight access modes
to access different sizes in the packet, whose naming follows the Python
`struct` module, indicated by the letters "BHIQbhiq".

Knowing this, we can modify the above example code to only count IP
packets::

    def program(self):
        with self.packetSize > 16 as p:
            # position 12 is the EtherType
            # 8 is the EtherType for IP, in network byte order
            with self.If(p.pH[12] == 8):
                self.count += 1
        self.exit(XDPExitCode.PASS)
