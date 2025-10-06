"""Simple motor example

This shows how to integrate a simple stepper motor into EPICS. We loosely try
to follow EPICS motor record standards, but a full EPICS motor record would be
too much for a mere example.

We also add a simple counter that counts how often EtherCAT packets have been
processed, which can be used as a performance indicator.
"""
import asyncio

from ebpfcat.ebpfcat import ParallelEtherCat, FastSyncGroup
from ebpfcat.devices import Counter, Motor
from ebpfcat.terminals import EL7041
from softioc import builder

from .epics import setter, start_ethercat_ioc


async def main(start_ioc):
    # define which EtherNet port to use
    master = ParallelEtherCat("eth0")
    async with master.run():
        # we use a simple EL7041 terminal...
        tmotor = EL7041(master)
        # ...which is at position 17 in the bus
        await tmotor.initialize(-17)

        builder.SetDeviceName("MY-ETHERCAT-MOTOR")

        # connect the motor parameters to the terminal
        motor = Motor()
        motor.velocity = tmotor.velocity
        motor.encoder = tmotor.stepcounter
        motor.enable = tmotor.enable
        motor.low_switch = tmotor.low_switch
        motor.high_switch = tmotor.high_switch

        # connect he motor parameters to EPICS PSs
        builder.aOut('VAL', initial_value=0, always_update=True,
                     on_update=setter(motor.target))
        builder.aOut('SPMG', initial_value=0, always_update=True,
                     on_update=setter(motor.set_enable))
        position = builder.aIn('RBV', initial_value=0)
        rvel = builder.aIn('RVEL', initial_value=0)

        # add a counter (a simple example device)
        dcounter = Counter()
        counter = builder.aIn('CNT', initial_value=0)

        # combine both devices into a sync group
        sg = FastSyncGroup(master, [motor, dcounter])
        task = sg.start()

        # start the IOC
        start_ioc()
        await asyncio.sleep(1)

        # set more necessary motor parameters
        # (parameters can only be set after the sync group is running)
        motor.proportional = 1
        motor.max_velocity = 100
        motor.max_acceleration = 100
        
        # move over data from the devices to EPICS PVs
        while not task.done():
            position.set(motor.encoder)
            rvel.set(motor.velocity)
            counter.set(dcounter.count)
            await asyncio.sleep(0.1)


if __name__ == '__main__':
    start_ethercat_ioc(main)
