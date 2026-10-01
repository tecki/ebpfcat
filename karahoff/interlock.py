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

    def __get__(self, instance, owner):
        ret = super().__get__(instance, owner)
        if instance is not None:
            ret.__func__.synchronous = self.synchronous
        return ret


class InterlockCondition(Configurable):
    parent = None

    @String(defaultValue='False')
    async def condition(self, value):
        """if this Python expression becomes True, trigger the command

        You may use names of Karabo devices that follow the naming convention,
        they will magically be converted into Python variables that reference
        to these devices.
        """
        if self.parent is None:
            self.condition = value
            return
        local, compiled = self.compile(value)
        eval(compiled, myglobals, local)  # check it works at least once
        self.compiled = compiled
        self.locals = local
        self.condition = value

    def setParent(self, parent):
        self.parent = parent
        self.locals, self.compiled = self.compile(self.condition)

    override = Bool(
        description='Ignore this condition for now. It automatically becomes '
        'active again once the interlock condition is good.',
        defaultValue=False)
    timeout = Float(defaultValue=0, unitSymbol=Unit.SECOND)

    lastgood = 0

    def compile(self, condition):
        cond, subs = replace(condition)
        local = {k: self.parent.getLocalDevice(v)
                       for k, v in subs.items()}
        local['self'] = self.parent
        return local, compile(cond, self.parent.deviceId.value, 'eval')

    def check(self):
        msg = None
        for k, v in self.locals.items():
            if k != 'self' and v.state in {State.UNKNOWN, State.ERROR}:
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
            node = Node(InterlockCondition, displayedName=f'{k}-Interlock')
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
            node.setParent(self)

    def update_properties(self):
        for cond in self.interlock_conditions:
            msg = cond.check()
            if msg is not None:
                cond.command()
                return State.INTERLOCKED, msg
        return super().update_properties()
