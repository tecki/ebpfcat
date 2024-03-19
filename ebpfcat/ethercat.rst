.. currentmodule:: ebpfcat

The EtherCAT master
===================

Getting started
---------------

Ethercat terminals are usually connected in a loop with the EtherCAT master,
via an ethernet interface. So we create a master object, and connect to that
interface an scan the loop. This takes time, so in a good asyncronous fashion
we need to use await, which can only be done in an async function::

    from ebpfcat.ebpfcat import FastEtherCat

    # later, in an async function:
    master = FastEtherCat("eth0")
    await master.connect()
    await master.scan_bus()

Next we create an object for each terminal that we want to use. As an example,
take some Beckhoff output terminal::

    from ebpfcat.terminals import EL4104, Generic

    out = EL4104(master)

This terminal needs to be initialized. The initialization method takes two
arguments, the relative position in the loop, starting with 0 for the terminal
directly connected to the interface, counting downwards to negative values. The
second argument is the absolute address this terminal should be assigned to::

    await out.initialize(-1, 20)  # assign address 20 to the first terminal

The terminals are usually controlled by devices, where one terminal may be
controlled by several devices, or one device controls several terminals. The
devices are represented by :class:`~ebpfcat.Device` objects. Upon
instantiation, they are connected to the terminals::

    from ebpfcat.devices import AnalogOutput

    ao = AnalogOutput(out.ch1_value)

Devices are grouped into :class:`~ebpfcat.SyncGroup`, which means that their
terminals are always read and written at the same time. A device can only
belong to one :class:`~ebpfcat.SyncGroup`, but a terminal may be part of
several devices or sync groups.  The sync group is also responsible to
constantly transfer data to and from the terminals such that they do not time
out and go into a safe state::

    from ebpfcat.ebpfcat import SyncGroup

    sg = SyncGroup(master, [ao])  # this sync group only contains one terminal

    sg.start()  # start operating the terminals

The ``AnalogOutput`` in the examples is a pretty boring device, it can only
output a value like so::

    ao.value = 5  # set the value on the terminal


Writing a device
----------------

Equipment controlled via the EtherCAT terminals often requires that a dedicated
device is written for it. Devices inherit from :class:`ebpfcat.Device`. They
declare which kind of data they want to communicate to the terminals as a
:class:`ebpfcat.TerminalVar` like so::

    from ebpfcat.ebpfcat import Device, TerminalVar

    class Motor(Device):
        speed = TerminalVar()
        position = TerminalVar()

Before they can be used, their :class:`~ebpfcat.TerminalVar`\ s need to be
initialized::

    motor = Motor()
    motor.speed = outputTerminal.speed
    motor.position = encoderTerminal.value

whenever new data is read from the loop, the :meth:`~ebpfcat.Device.update`
method of the device is called, in which one can evaluate the
:class:`~ebpfcat.TerminalVar`\ s, or set them::

    def update(self):
        """a idiotic speed controller"""
        self.speed = (self.position - self.target) * self.pConst

Three methods of control
------------------------

The communication with the terminals can happen in three different ways:

- asynchronous: the communication happens ad-hoc whenever needed. This is
  done during initialization and for reading and writing configuration data,
  like CoE.
- slow: the data is sent, received and processed via Python. This is good
  enough to around 100 Hz operation.
- fast: the data is sent, received and processed using XDP in the Linux
  Kernel. Only very limited operations can be done, but the loop cycle
  frequency exceeds 10 kHz.

Adding new terminals
--------------------

The elements of an EtherCat loop were used to be called *slaves*, but nowadays
are referred to as *SubDevices*. As in a typical installation most of them are
simply terminals, we call them such.

Everything in a terminal is controlled by reading or writing parameters in the
CoE address space. These addresses are a pair of a 16 bit and an 8 bit number,
usually seperated by a colon, as in ``6010:13``. Most terminals allow these
parameters to be set asynchronously. Some of the parameters may be read or
written synchronously, so with every communication cycle.

The meaning of all these parameters can usually be found in the documentation
of the terminal. Additionally, terminals often have a self-description, which
can be read with the command line tool ``ec-info``::

    $ ec-info eth0 --terminal -1 --sdo

this reads the first (-1th) terminal's self description (``--sdo``). Add a
``--value`` to also get the current values of the parameters. This prints out
all known self descriptions of CoE parameters.

Once we know the meaning of parameters, they may be read or written
asynchronously using :meth:`~ethercat.Terminal.sdo_read` and
:meth:`~ethercat.Terminal.sdo_write`.

For synchronous data access, a class needs to be defined that defines the
parameters one want to use synchronously. The parameters available for
synchronous operations can be found with the ``--pdo`` parameter of the
``ec-info`` command. The class should inherit from
:class:`~ebpfcat.EBPFTerminal` and define a set of tuples called
``comptibility``. The tuples should be the pairs of Ethercat product and vendor
id for all terminals supported by this class. Those can be found out with the
``--ids`` parameter of the ``ec-info`` command.

Within the class, the synchronous parameters are defined via
:class:`~ebpfcat.ProcessDesc`. This descriptor takes the two parts of the CoE
address as parameters, plus an optional size parameter. This is usually
determined automatically, but this sometimes fails, in which case it may either
be defined via a format string like in the :mod:`python:struct` module, or it
is an integer which is then a reference to the position of the bit in the
parameter to define a boolean flag.

For terminals which have several equivalent channels, one can define a
structure by inheriting from :class:`~ebpfcat.ebpfcat.Struct`. Within this
class one defines the first set of parameters the same way one would do it
without. Once the class is defined, it can be instantiated in the terminal
class with a single argument which defines the offset in the CoE address space
for this structure. As an example, if on a two-channel terminal the first
channel has an address of ``0x6000:12`` and the following two ``0x6010:12`` and
``0x6020:12``, one would instantiate three structs with arguments ``0``,
``0x10`` and ``0x20``.

A complete example of a four channel terminal looks as follows::

    class EL3164(EBPFTerminal):
        compatibility = {(2, 0x0c5c3052)}

        class Channel(Struct):
            attrs = ProcessDesc(0x6000, 1, 'H') # this is 2 bytes ('H')
            value = ProcessDesc(0x6000, 0x11)
            factor = 10/32767  # add bonus information as desired
            offset = 0

        channel1 = Channel(0)  # adress 0x6000
        channel2 = Channel(0x10)  # address 0x6010
        channel3 = Channel(0x20)
        channel4 = Channel(0x30)


Reference Documentation
-----------------------

.. automodule:: ebpfcat.devices
   :members:

.. automodule:: ebpfcat.ethercat
   :members:

.. automodule:: ebpfcat.ebpfcat
   :members:
