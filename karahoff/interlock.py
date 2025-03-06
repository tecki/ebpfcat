import re

from karabo.middlelayer import AccessMode, Bool, Device, State, String

pattern = re.compile('[A-Z0-9]{1,6}_[A-Z0-9]{1,6}_[A-Z0-9]{1,9}(-[0-9])?'
                     '/[A-Z0-9]{1,6}/[A-Z0-9_]{1,24}')

myglobals = {}
exec('from numpy import *', myglobals)


def replace(deviceId):
    subs = {}
    def repl(match):
        s = match.group(0)
        r = s.replace('/', 'ノ').replace('-', 'ー') 
        subs[r] = s
        return r
    ret = pattern.sub(repl, deviceId)
    return ret, subs 


class SingleInterlock(Device):
    interlockCondition = String(accessMode=AccessMode.INITONLY,
                                defaultValue='False')
    interlockOverride = Bool(defaultValue=False)

    async def join(self, syncgroup):
        cond, subs = replace(self.interlockCondition.value)
        self.interlock_locals = {k: self.getLocalDevice(v)
                                 for k, v in subs.items()}
        self.interlock_locals['self'] = self
        self.interlock_condition = compile(cond, self.deviceId.value, 'eval')
        await super().join(syncgroup)

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
        if self.interlockOverride and not interlock:
            self.interlockOverride = False
            return ret
        elif interlock and not self.interlockOverride:
            return State.INTERLOCKED, msg
        else:
            return ret
