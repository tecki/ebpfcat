import fcntl
import os
from asyncio import Lock, sleep


class LockFile:
    """A lock file for all mailboxes in an EtherCAT loop"""
    def __init__(self, filename, minimum, maximum):
        self.filename = filename
        self.minimum = minimum
        self.maximum = maximum
        os.makedirs(filename.rsplit('/', 1)[0], exist_ok=True)
        try:
            self.fd = os.open(self.filename, os.O_CREAT | os.O_RDWR
                                             | os.O_EXCL | os.O_CLOEXEC)
        except FileExistsError:
            self.fd = os.open(self.filename, os.O_RDWR | os.O_CLOEXEC)
        else:
            os.write(self.fd, bytes(maximum - minimum))

    def close(self):
        os.close(self.fd)

    def remove(self):
        os.remove(self.filename)

    def __getstate__(self):
        return self.filename, self.minimum, self.maximum

    def __setstate__(self, state):
        self.__init__(*state)


class MailboxLock(Lock):
    """A simple lock that keeps a mailbox counter up-to-date

    Used for a single process program to assure two asyncio tasks
    do not use a mailbox at the same time, and keep the counter correct.
    """
    def __init__(self):
        super().__init__()
        self.counter = 0

    def next_counter(self):
        assert self.locked()
        ret = self.counter
        self.counter = ret % 7 + 1
        return ret


class ParallelMailboxLock:
    """A lock for the mailbox counter for multi-process programs

    Write the mailbox counter to a :class:`LockFile`, such that different
    processes can access the mailbox in order.
    """
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
