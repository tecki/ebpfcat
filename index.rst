.. currentmodule:: karahoff

KaraHoff --- a Karabo driver for EtherCAT PLCs
==============================================

KaraHoff is the glue code between `EBPFCat <https://github.com/tecki/ebpfcat>`_
and `Karabo <https://www.karabo.eu>`_. It allows to run an entire EtherCAT PLC
from Karabo directly.

Concepts
--------

KaraHoff stores all data within Karabo projects. The entire configuration is
done via Karabo devices.

The EtherCAT loop is directly connected to an ethernet port on the computer
KaraHoff is running on. It is controlled by Karabo device servers, which run an
:class:`~master.EtherCATMaster`. An EtherCAT loop may be shared between several
device servers, however each terminal should only ever be used by one device
server.

Each terminal that one wants to use is represented by a Karabo device, most
often :class:`~master.GenericTerminal` is good enough. In that device one needs
to specify the terminal type, which needs to be supported by EBPFCat. The
terminal is identified by its serial number, which is usually set to the XFEL
QR code number. The :class:`~master.EtherCATMaster` contains all functionality
to store the QR code number into a terminal.

The functionality of the PLC is provided by devices which use the terminals.
One terminal may be used for several devices, as well as a device may use
several terminals.

A group of devices is then combined into a **sync group**. The sync group
assures that there is regular communication with all the terminals used by its
devices. In order to do that properly, the sync group effectively takes
ownership of a terminal: only one running sync group should ever write to a
terminal.

.. figure:: doc/karahoff.svg

   A simple example for sync groups: on the left are the terminals, M stands
   for motor, E for encoder. There are two sync groups, each containing two
   motors which use the terminals. Note that each sync group has its own group
   of terminals. All mentioned elements are Karabo devices, held together by
   a master device (not shown), which is also a Karabo device.

Troubleshooting
---------------

Should a device get stuck, or should it be needed to be configured differently,
it may be safely shut down. Note that upon restarting it, the sync group the
device belongs to also needs to be restarted.

Should a device really not work anymore, it may be advisable to shut down its
sync group and remove the device from the list of the sync group's members.

If all fails, one may restart the device server. Unfortunately that is often
not possible using the normal shutdown button, but the **Service Manager** in
the GUI should work. Once the device server is restarted, one may safely
instantiate all devices. Note that the instantiation may be slow, in which case
the GUI shows many errors of delayed instantiation, do not worry, just ignore
them.

The available devices
---------------------

.. automodule:: karahoff.devices

The devices that hold KaraHoff together
---------------------------------------

.. automodule:: karahoff.terminals

.. automodule:: karahoff.master
