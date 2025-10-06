.. currentmodule:: ebpfcat

The EtherCAT master
===================

Getting started
---------------

Ethercat terminals are usually connected in a loop with the EtherCAT master,
via an ethernet interface. So we create a master object, and connect to that
interface an scan the loop. This takes time, so in a good asyncronous fashion
we need to use await, which can only be done in an async function::

    import asyncio
    from ebpfcat.ebpfcat import FastEtherCat

    async def main():
        master = FastEtherCat("eth0")
        await master.connect()
        print('Number of terminals:', await master.count())

    asyncio.run(main())

Next we create an object for each terminal that we want to use. As an example,
take some Beckhoff output terminal::

    from ebpfcat.terminals import EL4104

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

    ao = AnalogOutput(out.ch1_value)  # use channel 1 of terminal "out"

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

For reference, here is a complete code example:

.. literalinclude:: /examples/ethercat.py


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

The communication with the terminals can happen in four different ways:

- asynchronous: the communication happens ad-hoc whenever needed. This is
  done during initialization and for reading and writing configuration data,
  like CoE.
- slow: the data is sent, received and processed via Python. This is good
  enough to around 100 Hz operation, depending on the overall load on the
  system
- parallel: the slow communication, but in a separate process. This is
  useful if the program needs to perform other tasks as well, which would
  block the event loop for too long to reach stable operation. Also
  got to some 100 Hz.
- fast: the data is sent, received and processed using XDP in the Linux
  Kernel. Only very limited operations can be done, namely integer arithmetic
  only, but the loop cycle frequency exceeds 10 kHz.

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

    $ ec-info eth0 --terminal 1 --sdo

this reads the first terminal's self description (``--sdo``). Add a ``--value``
to also get the current values of the parameters. This prints out all known
self descriptions of CoE parameters.

Once we know the meaning of parameters, they may be read or written
asynchronously using :meth:`~ethercat.Terminal.sdo_read` and
:meth:`~ethercat.Terminal.sdo_write`.

For synchronous data access, a class needs to be defined that defines the
parameters one want to use synchronously. The parameters available for
synchronous operations can be found with the ``--pdo`` parameter of the
``ec-info`` command. The class should inherit from
:class:`~ebpfcat.EBPFTerminal` and define a set of tuples called
``compatibility``. The tuples should be the pairs of Ethercat product and
vendor id for all terminals supported by this class. Those can be found out
with the ``--ids`` parameter of the ``ec-info`` command.

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


Inspecting the bus via the command line
---------------------------------------

.. highlight:: BashSession

Using the command line tool ``ec-info`` one can learn many details about the
terminals on an EtherCat bus. As its first parameter, it always takes the
interface the bus is connected to, in the following examples we always take
``eth0``. The ``--terminal`` (or ``-t``) parameter may be used with the
position of the terminal on the bus to be inspected, otherwise all terminals
will be inspected. All other parameters indicate which information should be
shown.

The ``--ids`` (or ``-i``) parameter shows the identification numbers of the
terminal from its EEPROM. As an example::

    $ sudo ec-info eth0 -i -t3
    terminal no 3
    2:1B813052 revision 100034 serial 0

This means that terminal number 3 has vendor ID 2 (that is Beckhoff
Automation), with product code 0x1B813052 (an EL7041 terminal), revision
0x100034 and serial number 0. Note that most vendors will leave the serial
number 0, though in principle this can be changed.

The ``--names`` (or ``-n``) parameter shows some readable text found in the
EEPROM of the terminal. This may be anything, but often is helpful in
identifying the terminal::

    $ sudo ec-info eth0 -n -t12
    terminal no 12
    EL7031
    DriveAxisTerminals
    Antriebs- und Achsklemmen (EL7xxx)
    EL7031 1K. Schrittmotor-Endstufe (24V, 1.5A)
    Synchron
    DC

A little less user friendly, but sometimes more informative variant is the
``--eeprom`` (or ``-e``) parameter, showing the content of the sections of the
EEPROM once as text and once as a hexadecimal representation::

    $ sudo ec-info eth0 -e -t12
    terminal no 12
     3: b'1P079532SBTN000jb1061KES7031                        Q1    2P242213130026'
        31503037393533325342544e3030306a62313036314b4553373033312020202020202020202020202020202020202020202020205131202020203250323432323133313330303236
    10: b'\x06\x06EL7031\x12DriveAxisTerminals"Antriebs- und Achsklemmen (EL7xxx),EL7031 1K. Schrittmotor-Endstufe (24V, 1.5A)\x08Synchron\x02DC\xff'
        0606454c37303331124472697665417869735465726d696e616c7322416e7472696562732d20756e6420416368736b6c656d6d656e2028454c37787878292c454c3730333120314b2e20536368726974746d6f746f722d456e64737475666520283234562c20312e3541290853796e6368726f6e024443ff
    30: b"\x02\x00\x01\x04\x0c'\x01\x00\x00\x00\x00\x04x\x00\x03\x003\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        020001040c270100000000047800030033000000000000000000000000000000
    40: b'\x01\x02\x03\xff'
        010203ff
    41: b'\x00\x10\x80\x00&\x00\x01\x01\x80\x10\x80\x00"\x00\x01\x02\x00\x11\x08\x00$\x00\x01\x03\x80\x11\x08\x00 \x00\x01\x04'
        0010800026000101801080002200010200110800240001038011080020000104
    60: b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x01\x00\x06\x00\x00\x00\x00\x00'
        000000000000000000000000000000000000050000000000000000000000000000000000000000030100060000000000

Using the ``--pdo`` (or ``-p``) parameter one can inspect the current PDO
configuration, this are the CoE parameters available for synchronous read and
write::

    $ sudo ec-info eth0 -p -t12
    terminal no 12
    7000:02 OUT 0 1
    7000:03 OUT 0 2
    7000:04 OUT 0 3
    7000:11 OUT 2 H
    7010:01 OUT 4 0
    7010:02 OUT 4 1
    7010:03 OUT 4 2
    7010:21 OUT 6 H
    6000:02 IN 0 1
    6000:03 IN 0 2
    6000:04 IN 0 3
    ...

The first columns shows the CoE address, the second shows OUT for data written
to the terminal, IN for those read from it. The third column indicates the byte
adress in the synchronous datagram, and the last column either the bit within
that byte, or an indicator of the ssize of the parameter. The meaning of the
parameters can be found in the terminal's documentation, or possibly via the
``--sdo`` parameter.

The CoE adresses shown here following a pattern that at least Beckhoff
Automation follows: the 7xxx:xx range are the output parameters, the 6xxx:xx
range are the input parameters.

The ``--sdo`` (or ``-s``) paramter shows the terminal's self description of
parameters. This self description, however, varies in quality depending on the
vendor. Let's go through some of the output::

    $ sudo ec-info eth0 -s -t12
    terminal no 12
    1000:
        0: Device type UNSIGNED32 (32 bit) flags 7
    1008:
        0: Device name VISIBLE_STRING (48 bit) flags 7
    1009:
        0: Hardware version VISIBLE_STRING (16 bit) flags 7
    100A:
        0: Software version VISIBLE_STRING (16 bit) flags 7
    1011:
        1: SubIndex 001 UNSIGNED32 (32 bit) flags 3F
    1018:
        1: Vendor ID UNSIGNED32 (32 bit) flags 7
        2: Product code UNSIGNED32 (32 bit) flags 7
        3: Revision UNSIGNED32 (32 bit) flags 7
        4: Serial number UNSIGNED32 (32 bit) flags 7
    ...

The output usually starts with some identification of the device itself. Note
that the output is grouped by CoE groups, so in the example the adress of the
serial number (last line) would be 1018:4. Adding the ``--values`` (or ``-v``)
parameter also shows the current values of the CoE parameter, for numbers both
in decimal and hexadecimal::

    $ sudo ec-info eth0 -s -v -t12
    terminal no 12
    1000:
        0: Device type UNSIGNED32 (32 bit) flags 7
                  5001     1389
    1008:
        0: Device name VISIBLE_STRING (48 bit) flags 7
            ES7031
            'ES7031'
    1009:
        0: Hardware version VISIBLE_STRING (16 bit) flags 7
            13
            '13'
    100A:
        0: Software version VISIBLE_STRING (16 bit) flags 7
            13
            '13'
    1011:
        1: SubIndex 001 UNSIGNED32 (32 bit) flags 3F
                     0        0
    1018:
        1: Vendor ID UNSIGNED32 (32 bit) flags 7
                     2        2
        2: Product code UNSIGNED32 (32 bit) flags 7
             460795986 1B773052
        3: Revision UNSIGNED32 (32 bit) flags 7
               1703936   1A0000
        4: Serial number UNSIGNED32 (32 bit) flags 7
                 72315    11A7B
    ...

Later on, the actual functionality of the terminal is shown. As an example, a
stepper motor terminal might be enabled with a boolean value, and a velocity
may be set::

    7010:
        1: Enable BOOLEAN (1 bit) flags 47
                     0        0
        2: Reset BOOLEAN (1 bit) flags 47
                     0        0
        3: Reduce torque BOOLEAN (1 bit) flags 47
                     0        0
        11: Position UNSIGNED32 (32 bit) flags 47
                     0        0
        21: Velocity INTEGER16 (16 bit) flags 47
                     0        0

So in this example, CoE address 7010:21 is a 16 bit integer that sets the drive
velocity of a stepper motor.

.. currentmodule:: examples

Using EBPFCat with the EPICS control system
-------------------------------------------

EBPFCat can be connected to EPICS using `pythonSoftIOC
<https://diamondlightsource.github.io/pythonSoftIOC/master/index.html>`_, which
can be easily installed with ``pip install softioc``. There are two examples,
:mod:`~examples.epics_aio` and :mod:`~examples.epics_motor`, which are based on
a minimal binding code :mod:`~examples.epics`.

Those can be started with ``python -m examples.epics_aio``, after you
have adopted the code to the hardware you use.

.. automodule:: examples.epics_aio

.. automodule:: examples.epics_motor

.. automodule:: examples.epics
   :members:


Reference Documentation
-----------------------

.. automodule:: ebpfcat.devices
   :members:

.. automodule:: ebpfcat.ethercat
   :members:

.. automodule:: ebpfcat.ebpfcat
   :members:
