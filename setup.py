#!/usr/bin/env python
from setuptools import setup, find_packages

setup(name="ebpfcat",
      version="0.6.0",
      author="Martin Teichmann",
      author_email="martin.teichmann@xfel.eu",
      description="A Karabo Beckhoff driver",
      package_dir={"": "."},
      packages=find_packages("."),
      entry_points={
          "console_scripts": [
              "ec-scanbus = ebpfcat.scripts:scanbus",
              "ec-info = ebpfcat.scripts:info",
              "ec-eeprom = ebpfcat.scripts:eeprom",
              "ec-create-test = ebpfcat.scripts:create_test",
          ],
      },
      requires=[],
      )
