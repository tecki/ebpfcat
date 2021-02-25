The EtherCAT master
===================

Getting started
---------------

Ethercat terminals are usually connected in a loop with the EtherCAT master.
The EtherCAT master has to know the order and function of these terminals.
The list of terminals then has to be given in correct order to the constructor
of the EtherCAT master object as follows::

    from ebpfcat.ebpfcat import FastEtherCat
    from ebpfcat.terminals import EL4104, Generic

    out = EL4104()
    unknown = Generic()  # use "Generic" for terminals of unknown type

    master = FastEtherCat("eth0", [out, unknown])

Once we have defined the order of devices, we can connect to the loop and
scan it to actually find all terminals. This takes time, so in a good
asyncronous fashion we need to use await, which can only be done in an
async function::

    await master.connect()
    await master.scan_bus()

The terminals usually control some devices, where one terminal may control
several devices, or one device is controlled by several terminals. The devices
are represented by `Device` objects. Upon instantiation, they are connected to
the terminals::

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
called, in which one can evaluate the `TerminalVar`\ s::

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


.. automodule:: ebpfcat.devices
   :members:

.. automodule:: ebpfcat.ethercat
   :members:
