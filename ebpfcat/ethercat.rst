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
devices are represented by `Device` objects. Upon instantiation, they are
connected to the terminals::

    from ebpfcat.devices import AnalogOutput

    ao = AnalogOutput(out.ch1_value)

Devices are grouped into `SyncGroup`, which means that their terminals are
always read and written at the same time. A device can only belong to one
`SyncGroup`, but a terminal may be part of several devices or sync groups.
The sync group is also responsible to constantly transfer data to and from
the terminals such that they do not time out and go into a safe state::

    from ebpfcat.ebpfcat import SyncGroup

    sg = SyncGroup(master, [ao])  # this sync group only contains one terminal

    sg.start()  # start operating the terminals

The `AnalogOutput` in the examples is a pretty boring device, it can only
output a value like so::

    ao.value = 5  # set the value on the terminal


Writing a device
----------------

Equipment controlled via the EtherCAT terminals often requires that a dedicated
device is written for it. Devices inherit from `ebpfcat.Device`. They declare
which kind of data they want to communicate to the terminals as a `TerminalVar`
like so::

    from ebpfcat.ebpfcat import Device

    class Motor(Device):
        speed = TerminalVar()
        position = TerminalVar()

Before they can be used, their `TerminalVar`\ s need to be initialized::

    motor = Motor()
    motor.speed = outputTerminal.speed
    motor.position = encoderTerminal.value

whenever new data is read from the loop, the `update` method of the device is
called, in which one can evaluate the `TerminalVar`\ s, or set them::

    def update(self):
        """a idiotic speed controller"""
        self.speed = (self.position - self.target) * self.pConst

Three methods of control
------------------------

The communication with the terminals can happen in three different ways:

- out-of-order: the communication happens ad-hoc whenever needed. This is
  done during initialization and for reading and writing configuration data,
  like CoE.
- slow: the data is sent, received and processed via Python. This is good
  enough to around 100 Hz operation.
- fast: the data is sent, received and processed using XDP in the Linux
  Kernel. Only very limited operations can be done, but the loop cycle
  frequency exceeds 10 kHz.


Reference Documentation
-----------------------

.. automodule:: ebpfcat.devices
   :members:

.. automodule:: ebpfcat.ethercat
   :members:
