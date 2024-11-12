import fcntl
import os
from asyncio import Lock, sleep


class LockFile:
    def __init__(self, name, mininum, maximum):
        self.filename = f'/run/ebpf/{name}'
        self.minimum = minimum
        self.maximum = maximum
        try:
            self.file = open(self.filename, 'xb')
        except FileNotFoundError:
            self.file = open(self.filename, 'r+b')
        else:
            self.file.write(bytes(maximum - minimum))

    def close(self):
        self.file.close()

    def remove(self):
        os.

    def get_lock(self, no):
        assert self.minimum <= no < self.maximum
        return MailboxLock(self.file.fileno(), no - self.minimum)


class MailboxLock(Lock):
    def __init__(self):
        super().__init__()
        self.counter = 0

    def next_counter(self):
        assert self.locked()
        ret = self.counter
        self.counter = ret % 7 + 1
        return ret


class ParallelMailboxLock:
    def __init__(self, fd, no):
        self.fd = fd
        self.no = no
        self.counter = None

    async def __aenter__(self):
        while True:
            try:
                fcntl.lockf(self.fd, fcntl.LOCK_NB | fcntl.LOCK_EX, 1, self.no)
            except OSError:
                await sleep(0)
                continue
            break
        self.counter, = os.pread(self.fd, 1, self.no)

    async def __aexit__(self, a, b, c):
        os.pwrite(self.fd, bytes((self.counter,)), self.no)
        fcntl.lockf(self.fd, fcntl.LOCK_UN, 1, self.no)
        self.counter = None

    def next_counter(self):
        ret = self.counter
        self.counter = ret % 7 + 1
        return ret
