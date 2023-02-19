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

    with self.some_variable > 6 as Else:
        do_someting
    with Else:
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
allows to access the content of the packet. There are six access modes
to access different sizes in the packet, whose naming follows the Python
``struct`` module, indicated by the letters "BHIQiq".

Knowing this, we can modify the above example code to only count IP
packets::

    def program(self):
        with self.packetSize > 16 as p:
            # position 12 is the EtherType
            # 8 is the EtherType for IP, in network byte order
            with p.pH[12] == 8:
                self.count += 1
        self.exit(XDPExitCode.PASS)

Maps
----

Maps are used to communicate to the outside world. They look like instance
variables. They may be used from within the EBPF program, and once it is
loaded also from everywhere else. There are two flavors: `hashmap.HashMap`
and `arraymap.ArrayMap`. They have different use cases:

Hash Maps
~~~~~~~~~

all hash map variables have a fixed size of 8 bytes. Accessing them is
rather slow, but is done with proper locking: concurrent access is possible.
When accessing them from user space, they are read from the kernel each time
anew. They are declared as follows::

   class MyProgram(EBPF):
       hash_map = HashMap()
       a_variable = hash_map.globalVar()

They are used as normal variables, like in `self.a_variable = 5`, both
in EBPF and from user space once loaded.

Array Maps
~~~~~~~~~~

from an EBPF program's perspective, all EPBF programs are accessing the same
variables at the same time. So concurrent access may lead to problems. An
exception is the in-place addition operator `+=`, which works under a lock,
but only if the variable is of 4 or 8 bytes size.

Otherwise variables may be declared in all sizes. The declaration is like so::

   class MyProgram(EBPF):
       array_map = ArrayMap()
       a_byte_variable = array_map.globalVar("B")
       an_integer_variable = array_map.globalVar("i")

those variables can be accessed both from within the ebpf program, as from
outside. Both sides are actually accessing the same memory, so be aware of
race conditions.

Fixed-point arithmetic
~~~~~~~~~~~~~~~~~~~~~~

as a bonus beyond standard ebpf, we support fixed-point values as a type `x`.
Within ebpf they are calculated as per-10000, so a 0.2 is represented as
20000. From outside, the variables seem to be doubles. Vaguely following
Python, all true divisions `/` result in a fixed-point result, while all
floor divisions `//` result in a standard integer. Some examples:

    class FixedPoint(EPBF):
        array_map = ArrayMap()
        fixed_var = array_map.globalVar("x")  # declare a fixed-point variable
        normal_var = array_map.globalVar("i")

        def program(self):
            self.fixed_var = 3.5  # automatically converted to fixed
            self.normal_var = self.fixed_var  # automatically truncated
            self.fixed_var = self.normal_var / 5  # keep decimals
            self.fixed_var = self.normal_var // 5  # floor division
