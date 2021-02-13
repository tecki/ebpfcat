A Python-base EBPF code generator
=================================

This library facilitates the generation of EBPF code. Instead of compiling
code, we generate it on-the-fly. This is fully done in Python, without
the need of an external compiler. This also allows us to entangle user-space
and EPBF-space code within the same program.

The code generator is designed such that the code looks mostly like Pyhton,
but it is important to remember that the Python code is not actually doing
anything while executed, but only generates code which later will be executed
by the kernel.

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
       count = userspace.globalVar()  # declare a variable in the map

Next comes the program that we want to run in the kernel. Note that this
program looks as if it was just Python code, but it is not actually.
Instead it generates EBPF code that we can later load into the kernel::

    def program(self):
        self.count += 1
        self.exit(XDPExitCode.PASS)  # pass packet on to network stack

Now we can attach this program to a network interface. We use ``asyncio``
for synchronization::

   async def main():
       c = Count()
       await c.attach("eth0")

Once attached, our little program will be executed each time a packet
arrives on the interface. We can read the result in a loop::

    for i in range(100):
        await sleep(0.1)
        print("packets arrived so far:", c.count)

Note that here we access the member variable ``count`` from user space.
While generating EBPF, the code generator knows it needs to write out
commands to access that variable from EBPF, once accessed outside of
generation context, we access it from the user side.

For reference, this is the full example:

.. literalinclude:: /examples/count.py

Conditional statements
----------------------

During code generation, all code needs to be executed. This means that
we cannot use a Python ``if`` statement, as then the code actually does not
get executed, so no code would be generated. So we replace ``if`` statements
by Python ``with`` statements like so::

    with self.some_variable > 6 as cond:
        do_someting
    with cond.Else():
        do_something_else

certainly an ``Else`` statement may be omitted if not needed.

No loops
--------

There is no way to declare a loop, simply because EBPF does not allow it.
You may simply write a ``for`` loop in Python as long as everything can
be calculated at generation time, but this just means that the code will show
up in the EPBF as often as the loop is iterated at generation time.

Accessing the packet
--------------------

The entire point of XDP is to react to the arriving network packets.
The EBPF program will be checked statically that it can only access the
contents of the packet, and not beyond. This means a ``with`` statement
(acting as an *if*) needs to be added that checks that the packet is large
enough so every packet access will be within the packet. To facilitate this,
a special variable ``packetSize`` is defined, that when compared to will
generate code that the static code checker understands, like so::

     with self.packetSize > 100 as p:  # assure packet has at least 100 bytes
         self.some_variable = p.pH[22]  # read word at position 22

in this code, the variable ``p`` returned by the ``with`` statement also
allows to access the content of the packet. There are eight access modes
to access different sizes in the packet, whose naming follows the Python
``struct`` module, indicated by the letters "BHIQbhiq".

Knowing this, we can modify the above example code to only count IP
packets::

    def program(self):
        with self.packetSize > 16 as p:
            # position 12 is the EtherType
            # 8 is the EtherType for IP, in network byte order
            with p.pH[12] == 8:
                self.count += 1
        self.exit(XDPExitCode.PASS)
