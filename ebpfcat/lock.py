import fcntl
import os
from asyncio import Lock, create_task, run, sleep
from functools import wraps
from multiprocessing import get_context
from unittest import TestCase, main


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


class FMMULock:
    def __init__(self, filename):
        self.filename = filename
        os.makedirs(filename.rsplit('/', 1)[0], exist_ok=True)
        try:
            self.fd = os.open(self.filename, os.O_CREAT | os.O_RDWR
                                             | os.O_EXCL | os.O_CLOEXEC)
        except FileExistsError:
            self.fd = os.open(self.filename, os.O_RDWR | os.O_CLOEXEC)
        else:
            os.write(self.fd, b'      4096')

    def get_next_addr(self):
        fcntl.lockf(self.fd, fcntl.LOCK_EX)
        try:
            ret = int(os.pread(self.fd, 10, 0).decode())
            os.pwrite(self.fd, f"{ret + 0x1000:10}".encode(), 0)
        finally:
            fcntl.lockf(self.fd, fcntl.LOCK_UN)
        return ret

    def remove(self):
        os.close(self.fd)
        os.remove(self.filename)


def asynctst(f):
    @wraps(f)
    def wrapper(self):
        run(f(self))
    return wrapper

class Tests(TestCase):
    @asynctst
    async def test_bla(self):
        async def locker(n):
            async with lock:
                self.assertEqual(lock.next_counter(), n)
        task = create_task(locker(1))
        lock = MailboxLock()
        async with lock:
            await sleep(0.001)
            self.assertEqual(lock.next_counter(), 0)
        await task
        task = create_task(locker(1))  # round-robin to 1
        async with lock:
            await sleep(0.001)
            self.assertEqual(lock.next_counter(), 2)
            for i in range(3, 8):
                await sleep(0.001)
                self.assertEqual(lock.next_counter(), i)
        await task

    def spawn(self):
        ctx = get_context('spawn')


if __name__ == '__main__':
    main()
