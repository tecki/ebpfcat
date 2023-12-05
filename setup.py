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
              "FastEtherCATMaster = karahoff.master:FastEtherCATMaster",
              "EtherCATSyncGroup = karahoff.master:EtherCATSyncGroup",
              "FastEtherCATSyncGroup = karahoff.master:FastEtherCATSyncGroup",
              "AnalogInput = karahoff.devices:AnalogInput",
              "GenericInput = karahoff.devices:GenericInput",
              "AnalogOutput = karahoff.devices:AnalogOutput",
              "Motor = karahoff.devices:Motor",
              "TurboVac = karahoff.devices:TurboVac",
              "Inficon = karahoff.devices:Inficon",
              "Bronkhorst = karahoff.devices:Bronkhorst",
              "Counter = karahoff.devices:Counter",
              "Valve = karahoff.devices:Valve",
              "PressureGauge = karahoff.devices:PressureGauge",
          ],
      },
      requires=[],
      )
