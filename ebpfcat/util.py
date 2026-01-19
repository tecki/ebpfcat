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

from itertools import chain
from logging import getLogger


logger = getLogger('ebpfcat')


class sub:
    def __init__(self, cls, base, default=False):
        self.cls = cls
        self.base = base

    def __getattr__(self, name):
        mro = self.base.__class__.__mro__[::-1]
        i = mro.index(self.cls)
        for cls in chain(mro[i + 1 :], mro[:i + 1]):
            func = cls.__dict__.get(name)
            if func is not None:
                return func.__get__(self.base, cls)
        raise AttributeError(f"'sub' object has no attribute '{name}'")


if __name__ == "__main__":
    class A:
        def g(self):
            print("A.f")

    class B(A):
        def f(self):
            print("B.f")

    class C(A):
        def f(self):
            print("C.f")

    class D(C, B):
        def f(self):
            print("D.f")


    b = D()
    print(D.__mro__)
    sub(A, b).f()
    sub(B, b).f()
    sub(C, b).f()
    sub(D, b).f()

