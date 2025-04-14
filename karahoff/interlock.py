import re
from time import monotonic

from karabo.middlelayer import (
    AccessMode, Bool, Configurable, Device, Float, Node, Slot, State, String,
    Unit)

from .master import EtherCATDevice

pattern = re.compile('[A-Z0-9]{1,6}_[A-Z0-9]{1,6}_[A-Z0-9]{1,9}(-[0-9])?'
                     '/[A-Z0-9]{1,6}/[A-Z0-9_]{1,24}')

myglobals = {}
exec('from numpy import *', myglobals)
exec('from karabo.middlelayer import *', myglobals)


def replace(deviceId):
    subs = {}
    def repl(match):
        s = match.group(0)
        r = s.replace('/', 'ノ').replace('-', 'ー') 
        subs[r] = s
        return r
    ret = pattern.sub(repl, deviceId)
    return ret, subs 


def InterlockSlot(**kwargs):
    def inner(func):
        @Slot(**kwargs)
        async def wrapper(self):
            func(self)
            await self.state_change.wait()
            await self.state_change.wait()
        wrapper.synchronous = func
        return wrapper
    return inner


class InterlockCondition(Configurable):
    condition = String(accessMode=AccessMode.INITONLY)
    override = Bool(defaultValue=False)
    timeout = Float(defaultValue=0, unitSymbol=Unit.SECOND)

    lastgood = 0

    def compile(self, parent):
        cond, subs = replace(self.condition)
        self.locals = {k: parent.getLocalDevice(v) for k, v in subs.items()}
        self.locals['self'] = parent
        self.compiled = compile(cond, parent.deviceId.value, 'eval')

    def check(self):
        msg = None
        for k, v in self.locals.items():
            if k != 'self' and v.state == State.ERROR:
                interlock = True
                msg = f'device {v.deviceId.value} in error'
                break
        else:
            try:
                interlock = eval(self.compiled, myglobals, self.locals)
            except Exception as e:
                msg = f'error in interlock: {e}'
                interlock = True

        if not interlock:
            self.lastgood = monotonic()
        if self.override and not interlock:
            self.override = False
        elif interlock and not self.override \
                and monotonic() - self.lastgood > self.timeout.value:
            return 'interlocked'


class Interlock(EtherCATDevice):
    def __init_subclass__(cls, **kwargs):
        for k, v, in cls.__dict__.items():
            if isinstance(v, Slot) and hasattr(v, synchronous):
                setattr(cls, f'{k}Interlock', Node(InterlockCondition))
        super().__init_subclass__(**kwargs)

    def join(self, syncgroup):
        self.interlock_conditions = []
        for attr in self._allattrs:
            v = getattr(self.__class__, attr)
            if isinstance(v, Node) and v.cls is InterlockCondition:
                vv = getattr(self, attr)
                vv.command = v.synchronous.__get__(self, self.__class__)
                self.interlock_conditions.append(vv)
                vv.compile(self)

    def update_properties(self):
        for cond in self.interlock_conditions:
            msg = cond.check()
            if msg is not None:
                return State.INTERLOCKED, msg


class SingleInterlock(Device):
    interlockCondition = String(accessMode=AccessMode.INITONLY,
                                defaultValue='False')
    interlockOverride = Bool(defaultValue=False)
    interlockTimeout = Float(defaultValue=0, unitSymbol=Unit.SECOND)
    interlock_lastgood = 0

    def join(self, syncgroup):
        cond, subs = replace(self.interlockCondition.value)
        self.interlock_locals = {k: self.getLocalDevice(v)
                                 for k, v in subs.items()}
        self.interlock_locals['self'] = self
        self.interlock_condition = compile(cond, self.deviceId.value, 'eval')
        super().join(syncgroup)

    def update_properties(self):
        msg = None
        for k, v in self.interlock_locals.items():
            if k != 'self' and v.state == State.ERROR:
                interlock = True
                msg = f'device {v.deviceId.value} in error'
                break
        else:
            try:
                interlock = eval(self.interlock_condition,
                                 myglobals, self.interlock_locals)
            except Exception as e:
                msg = f'error in interlock: {e}'
                interlock = True
        ret = super().update_properties()
        if not interlock:
            self.interlock_lastgood = monotonic()
        if self.interlockOverride and not interlock:
            self.interlockOverride = False
            return ret
        elif interlock and not self.interlockOverride \
                and monotonic() - self.interlock_lastgood \
                    > self.interlockTimeout.value:
            return State.INTERLOCKED, msg
        else:
            return ret
