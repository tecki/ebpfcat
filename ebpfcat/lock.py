import fcntl
import os
from asyncio import Lock, sleep


class LockFile:
    def __init__(self, filename, minimum, maximum):
        self.filename = filename
        self.minimum = minimum
        self.maximum = maximum
        os.makedirs(filename.rsplit('/', 1)[0], exist_ok=True)
        try:
            self.file = open(self.filename, 'xb')
        except FileExistsError:
            self.file = open(self.filename, 'r+b')
        else:
            self.file.write(bytes(maximum - minimum))
        self.fd = self.file.fileno()

    def close(self):
        self.file.close()

    def remove(self):
        os.remove(self.filename)

    def __getstate__(self):
        return self.filename, self.minimum, self.maximum

    def __setstate__(self, state):
        self.__init__(*state)


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
    def __init__(self, lock_file, no):
        self.lock_file = lock_file
        assert self.lock_file.minimum <= no < self.lock_file.maximum
        self.no = no - self.lock_file.minimum
        self.counter = None

    async def __aenter__(self):
        while True:
            try:
                fcntl.lockf(self.lock_file.fd, fcntl.LOCK_NB | fcntl.LOCK_EX,
                            1, self.no)
            except OSError:
                await sleep(0)
                continue
            break
        self.counter, = os.pread(self.lock_file.fd, 1, self.no)

    async def __aexit__(self, a, b, c):
        os.pwrite(self.lock_file.fd, bytes((self.counter,)), self.no)
        fcntl.lockf(self.lock_file.fd, fcntl.LOCK_UN, 1, self.no)
        self.counter = None

    def next_counter(self):
        ret = self.counter
        self.counter = ret % 7 + 1
        return ret
