from itertools import chain


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

