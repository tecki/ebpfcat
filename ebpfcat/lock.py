# ebpfcat, A Python-based EBPF generator and EtherCAT master
# Copyright (C) 2021 Martin Teichmann <martin.teichmann@xfel.eu>
# Copyright (C) 2026 European XFEL GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import fcntl
import os
from asyncio import Lock, create_task, run, sleep
from functools import wraps
from unittest import TestCase, main


class LockFile:
    """A lock file for all mailboxes in an EtherCAT loop

    The reason of existence for this class is that it can be pickled,
    so that lock files can be shared between processed."""

    def __init__(self, filename, minimum, maximum):
        self.filename = filename
        self.minimum = minimum
        self.maximum = maximum
        os.makedirs(filename.rsplit("/", 1)[0], exist_ok=True)
        try:
            self.fd = os.open(
                self.filename, os.O_CREAT | os.O_RDWR | os.O_EXCL | os.O_CLOEXEC
            )
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


class ParallelMailboxLock(MailboxLock):
    """A lock for the mailbox counter for multi-process programs

    Write the mailbox counter to a :class:`LockFile`, such that different
    processes can access the mailbox in order.
    """

    def __init__(self, lock_file, no):
        super().__init__()
        self.lock_file = lock_file
        assert self.lock_file.minimum <= no < self.lock_file.maximum
        self.no = no - self.lock_file.minimum

    async def __aenter__(self):
        await super().__aenter__()
        while True:
            try:
                fcntl.lockf(
                    self.lock_file.fd, fcntl.LOCK_NB | fcntl.LOCK_EX, 1, self.no
                )
                break
            except OSError:
                await sleep(0)
                continue
        (self.counter,) = os.pread(self.lock_file.fd, 1, self.no)

    async def __aexit__(self, a, b, c):
        os.pwrite(self.lock_file.fd, bytes((self.counter,)), self.no)
        fcntl.lockf(self.lock_file.fd, fcntl.LOCK_UN, 1, self.no)
        await super().__aexit__(a, b, c)


def asynctst(f):
    @wraps(f)
    def wrapper(self):
        run(f(self))

    return wrapper


async def run_async(pno, lock, queue):
    from random import random

    async def f(no):
        for i in range(3):
            async with lock:
                for j in range(4):
                    await sleep(0.03 * random())
                    queue.put((pno, no, i, j, lock.next_counter()))
                await sleep(0.03 * random())

    from asyncio import create_task, gather

    tasks = [create_task(f(i)) for i in range(4)]
    await gather(*tasks)


def run_tst(pno, lock, queue):
    from asyncio import run

    run(run_async(pno, lock, queue))


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

    def test_parallel(self):
        from multiprocessing import get_context
        from queue import Empty

        ctx = get_context("spawn")
        lockfile = LockFile("/tmp/test", 7, 33)
        try:
            lock = ParallelMailboxLock(lockfile, 10)
            queue = ctx.Queue()
            processes = [
                ctx.Process(target=run_tst, args=(i, lock, queue)) for i in range(7)
            ]
            for p in processes:
                p.start()
            switch = 0
            last_pno, last_no, last_i, last_j, last_cnt = queue.get()
            while True:
                try:
                    pno, no, i, j, cnt = queue.get(timeout=0.1)
                    self.assertEqual(cnt, last_cnt % 7 + 1)
                    if j != 0:
                        self.assertEqual(last_i, i)
                        self.assertEqual(last_no, no)
                        self.assertEqual(last_pno, pno)
                    switch += pno != last_pno
                    last_cnt = cnt
                    last_j = j
                    last_i = i
                    last_no = no
                    last_pno = pno
                except Empty:
                    for p in processes:
                        if p.is_alive():
                            break
                    else:
                        break
            self.assertGreater(switch, 70)
        except AssertionError as exc:
            for p in processes:
                p.join()
            raise exc
        finally:
            lockfile.close()
            lockfile.remove()

    def test_parallel_boxes(self):
        from multiprocessing import get_context
        from queue import Empty

        ctx = get_context("spawn")
        lockfile = LockFile("/tmp/test", 7, 33)
        try:
            queue = ctx.Queue()
            processes = [
                ctx.Process(
                    target=run_tst,
                    args=(i, ParallelMailboxLock(lockfile, i + 10), queue),
                )
                for i in range(7)
            ]
            for p in processes:
                p.start()
            switch = 0
            last_pno, last_no, last_i, last_j, last_cnt = queue.get()
            while True:
                try:
                    pno, no, i, j, cnt = queue.get(timeout=0.1)
                    switch += pno != last_pno
                    last_cnt = cnt
                    last_j = j
                    last_i = i
                    last_no = no
                    last_pno = pno
                except Empty:
                    for p in processes:
                        if p.is_alive():
                            break
                    else:
                        break
            self.assertGreater(switch, 300)
        except AssertionError as exc:
            for p in processes:
                p.join()
            raise exc
        finally:
            lockfile.close()
            lockfile.remove()


if __name__ == "__main__":
    main()
