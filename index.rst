************************************************
EPBFCat -- an EtherCAT master using eBPF and XDP
************************************************

EBPFCat is a controller for the industrial field bus
`EtherCAT <https://www.ethercat.org/>`_, written entirely in Python,
that uses `ePBF <https://ebpf.io>`_ and XDP to achieve real-time responses.
The eBPF code is generated on-the-fly using a built-in code generator,
which can also be used for other purposes.

.. toctree::
    :maxdepth: 2

    ebpfcat/ebpf.rst
    ebpfcat/ethercat.rst

Further reading
---------------

This project has been presented at `ICALEPCS 2025
<https://epics.anl.gov/icalepcs-2025/pdf/THBR004.pdf>`_, please
:download:`cite <ebpfcat.bib>` this paper if you make use of EBPFCat.
