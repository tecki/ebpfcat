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


class InterlockSlot(Slot):
    def __call__(self, func):
        async def wrapper(self):
            func(self)
            await self.state_change.wait()
            await self.state_change.wait()
        self.synchronous = func
        return super().__call__(wrapper)


class InterlockCondition(Configurable):
    condition = String(accessMode=AccessMode.INITONLY, defaultValue='False')
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
                msg = f'interlock {self.condition.value}'
            except Exception as e:
                msg = f'error in interlock: {e}'
                interlock = True

        if not interlock:
            self.lastgood = monotonic()
        if self.override and not interlock:
            self.override = False
        elif interlock and not self.override \
                and monotonic() - self.lastgood > self.timeout.value:
            return msg


class Interlock(EtherCATDevice):
    interlock_nodes = []

    def __init_subclass__(cls, **kwargs):
        nodes = [k for k, v in cls.__dict__.items()
                 if isinstance(v, InterlockSlot)]
        for k in nodes:
            node = Node(InterlockCondition)
            setattr(cls, f'{k}Interlock', node)
            node.__set_name__(cls, f'{k}Interlock')
        cls.interlock_nodes = cls.interlock_nodes + nodes
        super().__init_subclass__(**kwargs)

    def join(self, syncgroup):
        super().join(syncgroup)
        self.interlock_conditions = []
        for key in self.interlock_nodes:
            node = getattr(self, f'{key}Interlock')
            node.command = getattr(self.__class__, key).synchronous \
                    .__get__(self, self.__class__)
            self.interlock_conditions.append(node)
            node.compile(self)

    def update_properties(self):
        for cond in self.interlock_conditions:
            msg = cond.check()
            if msg is not None:
                cond.command()
                return State.INTERLOCKED, msg
        return super().update_properties()
