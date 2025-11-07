.. currentmodule:: ebpfcat

A Python-base eBPF code generator
=================================

This library facilitates the generation of eBPF code. Instead of compiling
code, we generate it on-the-fly. This is fully done in Python, without
the need of an external compiler. This also allows us to entangle user-space
and EPBF-space code within the same program.

The code generator is designed such that the code looks mostly like Pyhton,
but it is important to remember that the Python code is not actually doing
anything while executed, but only generates code which later will be executed
by the kernel.

Getting started
---------------

As a simple example for eBPF we write an XDP program which simply counts
incoming packages.

We start with declaring the variables that we want to see both in the
XDP program and in user space::

   from ebpfcat.arraymap import ArrayMap
   from ebpfcat.xdp import XDP, XDPExitCode

   class Count(XDP):
       license = "GPL"  # the Linux kernel wants to know that...

       userspace = ArrayMap()
       count = userspace.globalVar()  # declare a variable in the map

Next comes the program that we want to run in the kernel. Note that this
program looks as if it was just Python code, but it is not actually.
Instead it generates eBPF code that we can later load into the kernel::

    def program(self):
        self.count += 1
        self.exit(XDPExitCode.PASS)  # pass packet on to network stack

Now we can attach this program to a network interface. We use :mod:`asyncio`
for synchronization::

   async def main():
       c = Count()
       await c.attach("eth0")

Once attached, our little program will be executed each time a packet
arrives on the interface. We can read the result in a loop::

    for i in range(10):
        await sleep(0.1)
        print("packets arrived so far:", c.count)

With :meth:`xdp.XDP.attach` the program is attached indefinitely on the
interface, even beyond the end of the program. Use :meth:`xdp.XDP.detach` to
detach it, or you may use the async contextmanager :meth:`xdp.XDP.run` to
detach automatically, as in::

   async with c.run("eth0"):
        await sleep(1)
        print("packets arrived so far:", c.count)

Note that here we access the member variable ``count`` from user space.
While generating eBPF, the code generator knows it needs to write out
commands to access that variable from eBPF, once accessed outside of
generation context, we access it from the user side.

Both :meth:`xdp.XDP.attach` and :meth:`xdp.XDP.detach` have an additional
parameter ``flags`` to choose in which mode to attach the program, use
:attr:`xdp.XDPFlags.SKB_MODE` (the default) to use the generic kernel driver,
or :attr:`xdp.XDPFlags.DRV_MODE` to let the interface device driver run the
program.

For reference, this is the full example:

.. literalinclude:: examples/count.py

Maps
----

Maps are used to communicate to the outside world. They look like instance
variables. They may be used from within the eBPF program, and once it is
loaded also from Python code. It is possible to write out the maps to a
bpf file system using :meth:`ebpf.EBPF.pin_maps`.

There are two flavors: :class:`arraymap.ArrayMap`
and :class:`hashmap.HashMap`. They have different use cases:

Array Maps
~~~~~~~~~~

Array maps are share memory between eBPF programs and user space. All programs
as well as user space are accessing the memory at the same time, so concurrent
access may lead to problems. An exception is the in-place addition operator
`+=`, which works under a lock, but only if the variable is of 4 or 8
bytes size.

Otherwise variables may be declared in all sizes. The declaration is like so::

   class MyProgram(EBPF):
       array_map = ArrayMap()
       a_byte_variable = array_map.globalVar("B")
       an_integer_variable = array_map.globalVar("i")

those variables can be accessed both from within the ebpf program, as from
outside. Both sides are actually accessing the same memory, so be aware of
race conditions.

Hash Maps
~~~~~~~~~

all hash map variables have a fixed size of 8 bytes. Accessing them is
rather slow, but is done with proper locking: concurrent access is possible.
When accessing them from user space, they are read from the kernel each time
anew. They are declared as follows::

   class MyProgram(EBPF):
       hash_map = HashMap()
       a_variable = hash_map.globalVar()

They are used as normal variables, like in ``self.a_variable = 5``, both
in eBPF and from user space once loaded.

Accessing the packet
--------------------

The entire point of XDP is to react to the arriving network packets.
The eBPF program will be checked statically that it can only access the
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
:mod:`struct` module, indicated by the letters "BHIQiq".

Knowing this, we can modify the above example code to only count IP
packets::

    def program(self):
        with self.packetSize > 16 as p:
            # position 12 is the EtherType
            # 8 is the EtherType for IP, in network byte order
            with p.pH[12] == 8:
                self.count += 1
        self.exit(XDPExitCode.PASS)

as a simplification, if the class attribute ``minimumPacketSize`` is set,
the ``program`` is called within a ``with`` statement like above, and all
the packet variables appear as variables of the object. The class
attribute ``defaultExitCode`` then gives the exit code in case the packet
is too small (by default ``XDPExitCode.PASS``). So the above example becomes::

    class Program(XDP):
        minimumPacketSize = 16
        userspace = ArrayMap()
        count = userspace.globalVar()

        def program(self):
            with self.pH[12] == 8:
                self.count += 1

With the :class:`xdp.PacketVar` descriptor it is possible to declare certain
positions in the packet as variables. As parameters it takes the position
within the packet, and the data format, following the conventions from the
Python :mod:`struct` package, including the endianness markers ``<>!``. So the
above example simplifies to::

    class Program(XDP):
        minimumPacketSize = 16
        userspace = ArrayMap()
        count = userspace.globalVar()
        etherType = PacketVar(12, "!H")  # use network byte order

        def program(self):
            with self.etherType == 0x800:
                self.count += 1

Programming
-----------

The actual XDP program is a class that inherits from :class:`xdp.XDP`. The
class body contains all variable declarations, and a method ``program`` which
is the program proper. It is executed by Python, and while executing an EPBF
program is created, which can then be loaded into the linux kernel.

Expressions
~~~~~~~~~~~

Once a variable is declared, it can be used very close to normal Python syntax.
Standard arithmetic works, like ``self.distance = self.speed * self.time``,
given that all are declared variables. Note that you cannot use usual Python
variables, as accessing them does not generate any eBPF code. Use local
variables for that.

Local variables
~~~~~~~~~~~~~~~

local variables are seen only by one eBPF program, they cannot be seen by
other programs or user space. They are declared in the class body like this::

    class Program(XDP):
        local_variable = LocalVar("I")

Conditional statements
~~~~~~~~~~~~~~~~~~~~~~

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
~~~~~~~~

There is no way to declare a loop, simply because eBPF does not allow it.
You may simply write a ``for`` loop in Python as long as everything can
be calculated at generation time, but this just means that the code will show
up in the EPBF as often as the loop is iterated at generation time.


Fixed-point arithmetic
~~~~~~~~~~~~~~~~~~~~~~

as a bonus beyond standard ebpf, we support fixed-point values as a type ``x``.
Within ebpf they are calculated as per-10000, so a 0.2 is represented as
20000. From outside, the variables seem to be doubles. Vaguely following
Python, all true divisions ``/`` result in a fixed-point result, while all
floor divisions ``//`` result in a standard integer. Some examples::

    class FixedPoint(EPBF):
        array_map = ArrayMap()
        fixed_var = array_map.globalVar("x")  # declare a fixed-point variable
        normal_var = array_map.globalVar("i")

        def program(self):
            self.fixed_var = 3.5  # automatically converted to fixed
            self.normal_var = self.fixed_var  # automatically truncated
            self.fixed_var = self.normal_var / 5  # keep decimals
            self.fixed_var = self.normal_var // 5  # floor division

Reference Documentation
-----------------------

.. automodule:: ebpfcat.ebpf
   :members:

.. automodule:: ebpfcat.xdp
   :members:

.. automodule:: ebpfcat.arraymap
   :members:
