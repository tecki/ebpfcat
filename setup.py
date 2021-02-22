#!/usr/bin/env python
from setuptools import setup, find_packages

setup(name="KaraHoff",
      version="0.0.1",
      author="Martin Teichmann",
      author_email="martin.teichmann@xfel.eu",
      description="A Karabo Beckhoff driver",
      package_dir={"": "."},
      packages=find_packages("."),
      entry_points={
          "karabo.middlelayer_device": [
              "EtherCATMaster = karahoff.master:EtherCATMaster",
              "EtherCATSyncGroup = karahoff.master:EtherCATSyncGroup",
              "AnalogInput = karahoff.devices:AnalogInput",
              "AnalogOutput = karahoff.devices:AnalogOutput",
          ],
      },
      requires=[],
      )
