# ebpfcat, A Python-based EBPF generator and EtherCAT master
# Copyright (C) 2021 Martin Teichmann <martin.teichmann@gmail.com>
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

"""The ``ebpf`` module contains the core ebpf code generation"""

__all__ = ["EBPF", "LocalVar", "prandom", "ktime"]

import os
from abc import ABC, abstractmethod
from collections import namedtuple
from contextlib import contextmanager, ExitStack
from operator import index
from struct import pack, unpack, calcsize
from enum import Enum

from . import bpf
from .util import sub

Instruction = namedtuple("Instruction",
                         ["opcode", "dst", "src", "off", "imm"])


class FuncId(Enum):
    unspec = 0
    map_lookup_elem = 1
    map_update_elem = 2
    map_delete_elem = 3
    probe_read = 4
    ktime_get_ns = 5
    trace_printk = 6
    get_prandom_u32 = 7
    get_smp_processor_id = 8
    skb_store_bytes = 9
    l3_csum_replace = 10
    l4_csum_replace = 11
    tail_call = 12
    clone_redirect = 13
    get_current_pid_tgid = 14
    get_current_uid_gid = 15
    get_current_comm = 16
    get_cgroup_classid = 17
    skb_vlan_push = 18
    skb_vlan_pop = 19
    skb_get_tunnel_key = 20
    skb_set_tunnel_key = 21
    perf_event_read = 22
    redirect = 23
    get_route_realm = 24
    perf_event_output = 25
    skb_load_bytes = 26
    get_stackid = 27
    csum_diff = 28
    skb_get_tunnel_opt = 29
    skb_set_tunnel_opt = 30
    skb_change_proto = 31
    skb_change_type = 32
    skb_under_cgroup = 33
    get_hash_recalc = 34
    get_current_task = 35
    probe_write_user = 36
    current_task_under_cgroup = 37
    skb_change_tail = 38
    skb_pull_data = 39
    csum_update = 40
    set_hash_invalid = 41
    get_numa_node_id = 42
    skb_change_head = 43
    xdp_adjust_head = 44
    probe_read_str = 45
    get_socket_cookie = 46
    get_socket_uid = 47
    set_hash = 48
    setsockopt = 49
    skb_adjust_room = 50
    redirect_map = 51
    sk_redirect_map = 52
    sock_map_update = 53
    xdp_adjust_meta = 54
    perf_event_read_value = 55
    perf_prog_read_value = 56
    getsockopt = 57
    override_return = 58
    sock_ops_cb_flags_set = 59
    msg_redirect_map = 60
    msg_apply_bytes = 61
    msg_cork_bytes = 62
    msg_pull_data = 63
    bind = 64
    xdp_adjust_tail = 65
    skb_get_xfrm_state = 66
    get_stack = 67
    skb_load_bytes_relative = 68
    fib_lookup = 69
    sock_hash_update = 70
    msg_redirect_hash = 71
    sk_redirect_hash = 72
    lwt_push_encap = 73
    lwt_seg6_store_bytes = 74
    lwt_seg6_adjust_srh = 75
    lwt_seg6_action = 76
    rc_repeat = 77
    rc_keydown = 78
    skb_cgroup_id = 79
    get_current_cgroup_id = 80
    get_local_storage = 81
    sk_select_reuseport = 82
    skb_ancestor_cgroup_id = 83
    sk_lookup_tcp = 84
    sk_lookup_udp = 85
    sk_release = 86
    map_push_elem = 87
    map_pop_elem = 88
    map_peek_elem = 89
    msg_push_data = 90
    msg_pop_data = 91
    rc_pointer_rel = 92
    spin_lock = 93
    spin_unlock = 94
    sk_fullsock = 95
    tcp_sock = 96
    skb_ecn_set_ce = 97
    get_listener_sock = 98
    skc_lookup_tcp = 99
    tcp_check_syncookie = 100
    sysctl_get_name = 101
    sysctl_get_current_value = 102
    sysctl_get_new_value = 103
    sysctl_set_new_value = 104
    strtol = 105
    strtoul = 106
    sk_storage_get = 107
    sk_storage_delete = 108
    send_signal = 109
    tcp_gen_syncookie = 110
    skb_output = 111
    probe_read_user = 112
    probe_read_kernel = 113
    probe_read_user_str = 114
    probe_read_kernel_str = 115
    tcp_send_ack = 116
    send_signal_thread = 117
    jiffies64 = 118
    read_branch_records = 119
    get_ns_current_pid_tgid = 120
    xdp_output = 121
    get_netns_cookie = 122
    get_current_ancestor_cgroup_id = 123
    sk_assign = 124
    ktime_get_boot_ns = 125
    seq_printf = 126
    seq_write = 127
    sk_cgroup_id = 128
    sk_ancestor_cgroup_id = 129
    ringbuf_output = 130
    ringbuf_reserve = 131
    ringbuf_submit = 132
    ringbuf_discard = 133
    ringbuf_query = 134
    csum_level = 135
    skc_to_tcp6_sock = 136
    skc_to_tcp_sock = 137
    skc_to_tcp_timewait_sock = 138
    skc_to_tcp_request_sock = 139
    skc_to_udp6_sock = 140
    get_task_stack = 141
    load_hdr_opt = 142
    store_hdr_opt = 143
    reserve_hdr_opt = 144
    inode_storage_get = 145
    inode_storage_delete = 146
    d_path = 147
    copy_from_user = 148
    snprintf_btf = 149
    seq_printf_btf = 150
    skb_cgroup_classid = 151
    redirect_neigh = 152
    per_cpu_ptr = 153
    this_cpu_ptr = 154
    redirect_peer = 155

class Opcode(Enum):
    ADD = 4
    SUB = 0x14
    MUL = 0x24
    DIV = 0x34
    OR = 0x44
    AND = 0x54
    LSH = 0x64
    RSH = 0x74
    NEG = 0x84
    MOD = 0x94
    XOR = 0xa4
    MOV = 0xb4
    ARSH = 0xc4

    JMP = 5
    JEQ = 0x15
    JGT = 0x25
    JGE = 0x35
    JSET = 0x45
    JNE = 0x55
    JSGT = 0x65
    JSGE = 0x75
    JLT = 0xa5
    JLE = 0xb5
    JSLT = 0xc5
    JSLE = 0xd5

    CALL = 0x85
    EXIT = 0x95

    REG = 8
    LONG = 3

    W = 0
    H = 8
    B = 0x10
    DW = 0x18

    LD = 0x61
    ST = 0x62
    STX = 0x63
    XADD = 0xc3
    LE = 0xd4
    BE = 0xdc

    def __mul__(self, value):
        if value:
            return OpcodeFlags({self})
        else:
            return OpcodeFlags(set())

    def __add__(self, value):
        return OpcodeFlags({self}) + value

    def __repr__(self):
        return 'O.' + self.name

class OpcodeFlags:
    def __init__(self, opcodes):
        self.opcodes = opcodes

    @property
    def value(self):
        return sum(op.value for op in self.opcodes)

    def __add__(self, value):
        if isinstance(value, Opcode):
            return OpcodeFlags(self.opcodes | {value})
        else:
            return OpcodeFlags(self.opcodes | value.opcodes)

    def __repr__(self):
        return "+".join(repr(op) for op in self.opcodes)

    def __eq__(self, value):
        return self.value == value.value


class AssembleError(Exception):
    pass


def comparison(uposop, unegop, sposop, snegop):
    def ret(self, value):
        value = ensure_expression(self.ebpf, value)
        myself = self
        if self.fixed != value.fixed:
            if self.fixed:
                value *= self.FIXED_BASE
            else:
                myself *= self.FIXED_BASE

        if self.signed or value.signed:
            return SimpleComparison(self.ebpf, myself, value, (sposop, snegop))
        else:
            return SimpleComparison(self.ebpf, myself, value, (uposop, unegop))
    return ret


class Elser:
    def __init__(self, comp):
        self.comp = comp

    def __enter__(self):
        return self.comp.Else()

    def __exit__(self, exc_type, exc, tb):
        self.comp.__exit__(exc_type, exc, tb)


class Comparison(ABC):
    """Base class for all logical operations"""

    def __init__(self, ebpf):
        self.ebpf = ebpf
        self.else_origin = None

    def __enter__(self):
        if self.else_origin is None:
            self.compare(True)
        return Elser(self)

    def __exit__(self, exc_type, exc, tb):
        if self.else_origin is None:
            self.target()
            return
        assert self.ebpf.opcodes[self.else_origin] is None
        self.ebpf.opcodes[self.else_origin] = Instruction(
                Opcode.JMP, 0, 0,
                len(self.ebpf.opcodes) - self.else_origin - 1, 0)
        self.ebpf.owners, self.owners = \
                self.ebpf.owners & self.owners, self.ebpf.owners

    @abstractmethod
    def compare(self, negative):
        """issue the actual comparison code

        the issued code should either jump to a position later
        determined by the `target` method, or just fall through.
        If `negative` is true, the code should jump away if the
        condition in question is false, and vice versa.
        """
        raise NotImplementedError

    @abstractmethod
    def target(self, retarget=False):
        """modify the already issued jumps to jump here

        you may re-set the target a second time, but then `retarget` needs
        to be true.
        """
        raise NotImplementedError

    def Else(self):
        self.else_origin = len(self.ebpf.opcodes)
        self.ebpf.opcodes.append(None)
        self.target(True)
        return self

    def __and__(self, value):
        return AndOrComparison(self.ebpf, self, value, True)

    def __or__(self, value):
        return AndOrComparison(self.ebpf, self, value, False)

    def __invert__(self):
        return InvertComparison(self.ebpf, self)

    def __bool__(self):
        raise AssembleError("Use with statement for comparisons")


class SimpleComparison(Comparison):
    """A simple numerical comparison, results in a jump instruction"""

    def __init__(self, ebpf, left, right, opcode):
        super().__init__(ebpf)
        self.left = left
        self.right = right
        self.opcode = opcode

    def compare(self, negative):
        with self.left.calculate(None, None) as (self.dst, _):
            with ExitStack() as exitStack:
                if not self.right.small_constant:
                    self.src, _ = exitStack.enter_context(
                        self.right.calculate(None, None))
                self.origin = len(self.ebpf.opcodes)
                self.ebpf.opcodes.append(None)
                self.opcode = self.opcode[negative]
        self.owners = self.ebpf.owners.copy()

    def target(self, retarget=False):
        assert retarget or self.ebpf.opcodes[self.origin] is None
        if self.opcode == Opcode.JMP:
            inst = Instruction(Opcode.JMP, 0, 0,
                               len(self.ebpf.opcodes) - self.origin - 1, 0)
        elif self.right.small_constant:
            inst = Instruction(
                self.opcode, self.dst, 0,
                len(self.ebpf.opcodes) - self.origin - 1,
                int(self.right.value))
        else:
            inst = Instruction(
                self.opcode + Opcode.REG, self.dst, self.src,
                len(self.ebpf.opcodes) - self.origin - 1, 0)
        self.ebpf.opcodes[self.origin] = inst
        if not retarget:
            self.ebpf.owners, self.owners = \
                    self.ebpf.owners & self.owners, self.ebpf.owners


class AndOrComparison(Comparison):
    def __init__(self, ebpf, left, right, is_and):
        super().__init__(ebpf)
        self.left = left
        self.right = right
        self.is_and = is_and

    def compare(self, negative):
        self.negative = negative
        self.left.compare(self.is_and)
        self.right.compare(negative)
        self.origin = len(self.ebpf.opcodes)
        if self.is_and != negative:
            self.left.target()
        self.owners = self.ebpf.owners.copy()

    def target(self, retarget=False):
        if self.is_and == self.negative:
            self.left.target(retarget)
        self.right.target(retarget)


class InvertComparison(Comparison):
    def __init__(self, ebpf, value):
        super().__init__(ebpf)
        self.value = value

    def compare(self, negative):
        self.value.compare(not negative)
        self.owners = self.value.owners

    def target(self, retarget=False):
        self.value.target(retarget)


def ensure_expression(ebpf, value):
    if isinstance(value, Expression):
        return value
    else:
        return Constant(ebpf, value)


class Expression:
    """the base class for all numerical expressions"""

    FIXED_BASE = 100000
    small_constant = False

    def _binary(self, value, opcode):
        value = ensure_expression(self.ebpf, value)
        return Binary(self.ebpf, self, value, opcode,
                      self.signed or value.signed, False)

    __ror__ = __or__ = lambda self, value: self._binary(value, Opcode.OR)
    __lshift__ = lambda self, value: self._binary(value, Opcode.LSH)
    __rlshift__ = lambda self, value: Constant(self.ebpf, value) << self
    __rxor__ = __xor__ = lambda self, value: self._binary(value, Opcode.XOR)

    __gt__ = comparison(Opcode.JGT, Opcode.JLE, Opcode.JSGT, Opcode.JSLE)
    __ge__ = comparison(Opcode.JGE, Opcode.JLT, Opcode.JSGE, Opcode.JSLT)
    __lt__ = comparison(Opcode.JLT, Opcode.JGE, Opcode.JSLT, Opcode.JSGE)
    __le__ = comparison(Opcode.JLE, Opcode.JGT, Opcode.JSLE, Opcode.JSGT)
    __ne__ = comparison(Opcode.JNE, Opcode.JEQ, Opcode.JNE, Opcode.JEQ)

    def _sum(self, value, opcode):
        value = ensure_expression(self.ebpf, value)
        myself = self
        if self.fixed != value.fixed:
            if self.fixed:
                value *= self.FIXED_BASE
            else:
                myself *= self.FIXED_BASE

        return Binary(self.ebpf, myself, value, opcode,
                      self.signed or value.signed, self.fixed or value.fixed)

    __radd__ = __add__ = lambda self, value: self._sum(value, Opcode.ADD)
    __sub__ = lambda self, value: self._sum(value, Opcode.SUB)
    __rsub__ = lambda self, value: Constant(self.ebpf, value) - self
    __mod__ = lambda self, value: self._sum(value, Opcode.MOD)
    __rmod__ = lambda self, value: Constant(self.ebpf, value) % self

    def __mul__(self, value):
        value = ensure_expression(self.ebpf, value)
        ret = Binary(self.ebpf, self, value, Opcode.MUL,
                     self.signed or value.signed, self.fixed or value.fixed)
        if self.fixed and value.fixed:
            ret /= self.FIXED_BASE
        return ret
    __rmul__ = __mul__

    def __truediv__(self, value):
        value = ensure_expression(self.ebpf, value)
        myself = self
        if not self.fixed and value.fixed:
            myself *= self.FIXED_BASE ** 2
        elif self.fixed == value.fixed:
            myself *= self.FIXED_BASE

        return Binary(self.ebpf, myself, value, Opcode.DIV,
                      self.signed or value.signed, True)

    def _reverse(self, op, value):
        return op(Constant(self.ebpf, value), self)

    __rtruediv__ = lambda self, value: Constant(self.ebpf, value) / self

    def __floordiv__(self, value):
        value = ensure_expression(self.ebpf, value)
        myself = self
        if not self.fixed and value.fixed:
            myself *= self.FIXED_BASE
        elif self.fixed and not value.fixed:
            value *= self.FIXED_BASE

        return Binary(self.ebpf, myself, value, Opcode.DIV,
                      self.signed or value.signed, False)

    def __rfloordiv__(self, value):
        if self.fixed:
            value = Constant(self.ebpf, value)
            if not value.fixed:
                value *= self.FIXED_BASE
        else:
            value = Constant(self.ebpf, int(value))

        return Binary(self.ebpf, value, self, Opcode.DIV,
                      self.signed or value.signed, False)

    def __rshift__(self, value):
        opcode = Opcode.ARSH if self.signed else Opcode.RSH
        return Binary(self.ebpf, self, ensure_expression(self.ebpf, value),
                      opcode, self.signed, False)

    __rrshift__ = lambda self, value: Constant(self.ebpf, value) >> self

    def __and__(self, value):
        return AndExpression(self.ebpf, self,
                             ensure_expression(self.ebpf, value))

    def __eq__(self, value):
        return ~(self != value)

    __rand__ = __and__

    def __neg__(self):
        return Negate(self)

    def __abs__(self):
        return Absolute(self)

    def switch_endian(self, fmt):
        if isinstance(fmt, str) and len(fmt) > 1:
            return SwitchEndian(self, fmt)
        return self

    def __bool__(self):
        raise AssembleError("Expression only has a value at execution time")

    def __enter__(self):
        ret = self != 0
        self.as_comparison = ret
        return ret.__enter__()

    def __exit__(self, exc_type, exc, tb):
        return self.as_comparison.__exit__(exc_type, exc, tb)

    def load(self, dst, src, offset, fmt, long):
         self.ebpf.append(Opcode.LD + fmt_to_opcode(fmt), dst, src, offset, 0)
         if isinstance(fmt, str) and (fmt in "hb" or long and fmt == 'i'):
             shift = (64 if long else 32) - calcsize(fmt) * 8
             regs = self.ebpf.sr if long else self.ebpf.sw
             regs[dst] = (regs[dst] << shift) >> shift

    @contextmanager
    def calculate(self, dst, long, force=False):
        """issue the code that calculates the value of this expression

        this method returns three values:

        - the number of the register with the result
        - a boolean indicating whether this is a 64 bit value

        this method is a contextmanager to be used in a `with`
        statement. At the end of the `with` block the result is
        freed again, i.e. the register will not be reserved for the
        result anymore.

        the default implementation calls `get_address` for values
        which actually are in memory and moves that into a register.

        :param dst: the number of the register to put the result in,
           or `None` if that does not matter.
        :param long: True if the result is supposed to be 64 bit. None
           if it does not matter.
        :param force: if true, `dst` must be respected, otherwise this
           is optional.
        """
        with self.ebpf.get_free_register(dst) as dst:
            with self.get_address(dst, long) as (src, fmt):
                self.load(dst, src, 0, fmt, long)
                yield dst, long

    @contextmanager
    def get_address(self, dst, long, force=False):
        """get the address of the value of this expression

        this method returns the address of the result of this expression,
        and its format letter. The default implementation uses
        `calculate` to evaluate the expression and pushes the result onto
        the stack.
        """
        with self.ebpf.get_stack(4 + 4 * long) as stack:
            with self.calculate(dst, long) as (src, _):
                self.ebpf.append(Opcode.STX + Opcode.DW * long,
                                 10, src, stack, 0)
                self.ebpf.append(Opcode.MOV + Opcode.LONG + Opcode.REG,
                                 dst, 10, 0, 0)
                self.ebpf.append(Opcode.ADD + Opcode.LONG, dst, 0, 0, stack)
            yield dst, "Q" if long else "I"

    def contains(self, no):
        """return whether this expression contains the register `no`"""
        return False


class Binary(Expression):
    """represent all binary expressions"""
    def __init__(self, ebpf, left, right, operator, signed, fixed):
        self.ebpf = ebpf
        self.left = left
        self.right = right
        self.operator = operator
        self.signed = signed
        self.fixed = fixed

    @contextmanager
    def calculate(self, dst, long, force=False):
        orig_dst = dst
        if isinstance(self.right, Expression) and self.right.contains(dst):
            dst = None
        with self.ebpf.get_free_register(dst) as dst:
            with self.left.calculate(dst, long, True) as (dst, l_long):
                if long is None:
                    long = l_long
            if self.right.small_constant:
                self.ebpf.append(self.operator + Opcode.LONG * long,
                                 dst, 0, 0, int(self.right.value))
            else:
                with self.right.calculate(None, long) as (src, r_long):
                    self.ebpf.append(
                        self.operator + Opcode.REG
                        + Opcode.LONG * ((r_long or l_long)
                                         if long is None else long),
                        dst, src, 0, 0)
            if orig_dst is None or orig_dst == dst:
                yield dst, long
                return
        self.ebpf.append(Opcode.MOV + Opcode.REG + Opcode.LONG * long, orig_dst, dst, 0, 0)
        yield orig_dst, long

    def contains(self, no):
        return self.left.contains(no) or (isinstance(self.right, Expression)
                                          and self.right.contains(no))


class Unary(Expression):
    def __init__(self, arg):
        self.arg = arg
        self.ebpf = arg.ebpf
        self.signed = arg.signed
        self.fixed = arg.fixed

    @contextmanager
    def calculate(self, dst, long, force=False):
        with self.arg.calculate(dst, long, force) as (dst, long):
            self.calculate_unary(dst, long)
            yield dst, long

    def contains(self, no):
        return self.arg.contains(no)


class Negate(Unary):
    def __init__(self, arg):
        super().__init__(arg)
        self.signed = True

    def calculate_unary(self, dst, long):
        self.ebpf.append(Opcode.NEG + Opcode.LONG * long, dst, 0, 0, 0)


class Absolute(Unary):
    def __init__(self, arg):
        super().__init__(arg)
        self.signed = False

    def calculate_unary(self, dst, long):
        with self.ebpf.sr[dst] < 0:
            self.ebpf.sr[dst] = -self.ebpf.sr[dst]


class SwitchEndian(Unary):
    def __init__(self, arg, fmt):
        super().__init__(arg)
        self.fmt = fmt

    def calculate_unary(self, dst, long):
        endian, size = self.fmt
        if endian == "<":
            opcode = Opcode.LE
        elif endian in ">!":
            opcode = Opcode.BE
        self.ebpf.append(opcode, dst, 0, 0, calcsize(size) * 8)


class Sum(Binary):
    """represent the sum of one register and a constant value

    this is used to optimize memory addressing code.
    """
    def __init__(self, ebpf, left, right):
        super().__init__(ebpf, left, right, Opcode.ADD, right.value < 0, False)

    def __add__(self, value):
        try:
            self.right.value += index(value)
        except TypeError:
            return super().__add__(value)

    __radd__ = __add__

    def __sub__(self, value):
        try:
            self.right.value -= index(value)
        except TypeError:
            return super().__add__(value)


class AndExpression(Binary):
    # there is a special comparison with & instruction
    def __init__(self, ebpf, left, right):
        super().__init__(ebpf, left, right, Opcode.AND, False, False)

    def __ne__(self, value):
        if isinstance(value, int) and value == 0:
            return AndComparison(self.ebpf, self.left, self.right)
        return super().__ne__(value)


class AndComparison(SimpleComparison):
    # there is a special comparison with & instruction
    # it is the only one which has not inversion
    def __init__(self, ebpf, left, right):
        Binary.__init__(self, ebpf, left, right, Opcode.AND, False, False)
        SimpleComparison.__init__(self, ebpf, left, right, Opcode.JSET)
        self.opcode = (Opcode.JSET, None, Opcode.JSET, None)
        self.invert = None

    def compare(self, negative):
        super().compare(False)
        if negative:
            origin = len(self.ebpf.opcodes)
            self.ebpf.opcodes.append(None)
            self.target()
            self.origin = origin
            self.opcode = Opcode.JMP

    def __exit__(self, exc, etype, tb):
        super().__exit__(exc, etype, tb)
        if self.invert is not None:
            olen = len(self.ebpf.opcodes)
            assert self.ebpf.opcodes[self.invert].opcode == Opcode.JMP
            self.ebpf.opcodes[self.invert:self.invert] = \
                    self.ebpf.opcodes[self.else_origin+1:]
            del self.ebpf.opcodes[olen-1:]
            op, dst, src, off, imm = self.ebpf.opcodes[self.invert - 1]
            self.ebpf.opcodes[self.invert - 1] = \
                    Instruction(op, dst, src,
                                len(self.ebpf.opcodes) - self.else_origin + 1, imm)

    def Else(self):
        op, dst, src, off, imm = self.ebpf.opcodes[self.origin]
        if op is Opcode.JMP:
            self.invert = self.origin
        else:
            self.ebpf.opcodes[self.origin] = \
                Instruction(op, dst, src, off+1, imm)
        self.else_origin = len(self.ebpf.opcodes)
        self.ebpf.opcodes.append(None)
        return self

class Constant(Expression):
    def __init__(self, ebpf, value):
        try:
            self.value = index(value)
            self.fixed = False
        except TypeError:
            self.value = float(value) * Expression.FIXED_BASE
            self.fixed = True
        self.ebpf = ebpf
        self.signed = value < 0

    @property
    def small_constant(self):
        return -0x80000000 <= self.value < 0x80000000

    def __imul__(self, value):
        self.value *= value
        return self

    @contextmanager
    def calculate(self, dst, long, force=False):
        value = int(self.value)
        with self.ebpf.get_free_register(dst) as dst:
            if self.small_constant:
                self.ebpf.append(Opcode.MOV + Opcode.LONG, dst, 0, 0, value)
            else:
                self.ebpf.append(Opcode.DW, dst, 0, 0, value & 0xffffffff)
                self.ebpf.append(Opcode.W, 0, 0, 0, value >> 32)
            yield dst, not (-0x80000000 <= value < 0x100000000)

    def switch_endian(self, fmt):
        if not isinstance(fmt, str) or len(fmt) == 1:
            return self
        return Constant(self.ebpf, *unpack(fmt, pack(fmt[-1], self.value)))


class Register(Expression):
    """represent one EBPF register"""
    offset = 0

    def __init__(self, no, ebpf, long, signed, fixed=False):
        self.no = no
        self.ebpf = ebpf
        self.long = long
        self.signed = signed
        self.fixed = fixed

    def __add__(self, value):
        if self.long and not self.fixed:
            try:
                return Sum(self.ebpf, self, Constant(self.ebpf, index(value)))
            except TypeError:
                pass
        return super().__add__(value)

    __radd__ = __add__

    def __sub__(self, value):
        if self.long and not self.fixed:
            try:
                return Sum(self.ebpf, self, Constant(self.ebpf, -index(value)))
            except TypeError:
                pass
        return super().__sub__(value)

    @contextmanager
    def calculate(self, dst, long, force=False):
        if self.no not in self.ebpf.owners:
            raise AssembleError("register has no value")
        if dst != self.no and force:
            self.ebpf.append(Opcode.MOV + Opcode.REG + Opcode.LONG * self.long,
                             dst, self.no, 0, 0)
            yield dst, self.long
        else:
            yield self.no, self.long

    def contains(self, no):
        return self.no == no


class IAdd:
    """represent an in-place addition"""
    def __init__(self, ebpf, value):
        if isinstance(value, Expression):
            self.value = value
        else:
            self.value = Constant(ebpf, value)


def fmt_to_opcode(fmt):
    fmt_to_opcode = {'I': Opcode.W, 'H': Opcode.H, 'B': Opcode.B, 'Q': Opcode.DW,
                     'i': Opcode.W, 'h': Opcode.H, 'b': Opcode.B, 'q': Opcode.DW,
                     'A': Opcode.W, 'x': Opcode.DW}
    if isinstance(fmt, str):
        return fmt_to_opcode[fmt[-1]]
    else:
        return Opcode.B

class Memory(Expression):
    bits_to_opcode = {32: Opcode.W, 16: Opcode.H, 8: Opcode.B, 64: Opcode.DW}

    def __init__(self, ebpf, fmt, address):
        self.ebpf = ebpf
        self.fmt = fmt
        self.address = address

    def __iadd__(self, value):
        if self.fmt in "qQiIx":
            return IAdd(self.ebpf, value)
        else:
            return NotImplemented

    def __isub__(self, value):
        if self.fmt in "qQiIx":
            return IAdd(self.ebpf, -value)
        else:
            return NotImplemented

    @contextmanager
    def calculate(self, dst, long, force=False):
        if self.has_endian():
            with self.without_endian().switch_endian(self.fmt) \
                 .calculate(dst, long, force) as (dst, long):
                yield dst, long
                return
        with ExitStack() as exitStack:
            if isinstance(self.address, Sum):
                dst = exitStack.enter_context(self.ebpf.get_free_register(dst))
                self.load(dst, self.address.left.no, self.address.right.value,
                          self.fmt, long)
            else:
                dst, _ = exitStack.enter_context(
                    super().calculate(dst, long, force))
            if isinstance(self.fmt, tuple):
                self.ebpf.r[dst] &= ((1 << self.fmt[1]) - 1) << self.fmt[0]
                if self.fmt[0] > 0:
                    self.ebpf.r[dst] >>= self.fmt[0]
                yield dst, "B"
            else:
                yield dst, self.fmt[-1] in "QqAx"

    @contextmanager
    def get_address(self, dst, long, force=False):
        with self.address.calculate(dst, True) as (src, _):
            yield src, self.fmt

    def contains(self, no):
        return self.address.contains(no)

    @property
    def signed(self):
        return isinstance(self.fmt, str) and self.fmt.islower()

    @property
    def fixed(self):
        return isinstance(self.fmt, str) and self.fmt == "x"

    def has_endian(self):
        return isinstance(self.fmt, str) and len(self.fmt) > 1

    def without_endian(self):
        if self.has_endian():
            return Memory(self.ebpf, self.fmt[-1], self.address)
        return self

    def __invert__(self):
        if not isinstance(self.fmt, tuple) or self.fmt[1] != 1:
            return NotImplemented
        return self == 0

    def __ne__(self, value):
        if isinstance(self.fmt, tuple) and isinstance(value, int) \
                and value == 0:
            mask = ((1 << self.fmt[1]) - 1) << self.fmt[0]
            return Memory(self.ebpf, "B", self.address) & mask != 0
        return super().__ne__(value)

    def _set(self, value):
        opcode = Opcode.STX
        with ExitStack() as exitStack:
            if isinstance(self.fmt, tuple):
                pos, bits = self.fmt
                self.fmt = "B"
                if bits == 1:
                    try:
                        if value:
                            value = self | (1 << pos)
                        else:
                            value = self & ~(1 << pos)
                    except AssembleError:
                        exitStack.enter_context(self.ebpf.wtmp)
                        with value as Else:
                            self.ebpf.wtmp = self | (1 << pos)
                        with Else:
                            self.ebpf.wtmp = self & ~(1 << pos)
                        value = self.ebpf.wtmp
                else:
                    mask = ((1 << bits) - 1) << pos
                    value = (mask & (value << pos) | ~mask & self)
            elif isinstance(value, IAdd):
                value = value.value
                opcode = Opcode.XADD
            elif not isinstance(value, Expression):
                value = Constant(self.ebpf, value)
            if self.fmt == "x" and not value.fixed:
                value *= Expression.FIXED_BASE
            elif self.fmt != "x" and value.fixed:
                value /= Expression.FIXED_BASE
            if isinstance(self.address, Sum):
                dst = self.address.left.no
                offset = self.address.right.value
            else:
                dst, _ = exitStack.enter_context(
                    self.address.calculate(None, True))
                offset = 0
            value = value.switch_endian(self.fmt)
            if value.small_constant and opcode == Opcode.STX:
                self.ebpf.append(Opcode.ST + fmt_to_opcode(self.fmt), dst, 0,
                                 offset, int(value.value))
                return
            src, _ = exitStack.enter_context(
                value.calculate(None, isinstance(self.fmt, str)
                                      and self.fmt[-1] in 'qQx'))
            self.ebpf.append(opcode + fmt_to_opcode(self.fmt),
                             dst, src, offset, 0)



class MemoryDesc:
    """A base class used by descriptors for memory

    All memory access is relative to a base register. This is
    defined by the member variable `base_register` in deriving
    classes.
    """

    fixed = False  # only selected memory can have fixe value vars

    def __get__(self, instance, owner):
        if instance is None:
            return self
        fmt, addr = self.fmt_addr(instance)
        return Memory(instance.ebpf, fmt,
                      instance.ebpf.r[self.base_register] + addr)

    def __set__(self, instance, value):
        fmt, addr = self.fmt_addr(instance)
        memory = Memory(instance.ebpf, fmt,
                        instance.ebpf.r[self.base_register] + addr)
        memory._set(value)

class LocalVar(MemoryDesc):
    """variables on the stack"""
    base_register = 10

    def __init__(self, fmt='I'):
        self.fmt = fmt
        self.fixed = fmt == "x"

    def __set_name__(self, owner, name):
        if self.fmt == "x":
            size = 8
        elif isinstance(self.fmt, str):
            size = calcsize(self.fmt)
        else:  # this is to support bit addressing, mostly for testing
            size = 1
        owner.stack -= size
        owner.stack &= -size
        self.relative_addr = owner.stack
        self.name = name

    def fmt_addr(self, instance):
        if isinstance(instance, SubProgram):
            return self.fmt, (instance.ebpf.stack & -8) + self.relative_addr
        else:
            return self.fmt, self.relative_addr


class MemoryMap:
    def __init__(self, ebpf, fmt):
        self.ebpf = ebpf
        self.fmt = fmt

    def __setitem__(self, addr, value):
        memory = Memory(self.ebpf, self.fmt, addr)
        memory._set(value)

    def __getitem__(self, addr):
        if isinstance(addr, Register):
            addr = addr + 0
        return Memory(self.ebpf, self.fmt, addr)


class Map(ABC):
    """The base class for all maps"""
    def __set_name__(self, owner, name):
        self.filename = name

    @abstractmethod
    def init(self, ebpf):
        """create the map and initialize its values"""

    def load(self, ebpf):
        """called after the program has been loaded"""


class PseudoFd(Expression):
    """represent a file descriptor to a map"""
    def __init__(self, ebpf, fd):
        self.ebpf = ebpf
        self.fd = fd
        self.fixed = False

    @contextmanager
    def calculate(self, dst, long, force=False):
        with self.ebpf.get_free_register(dst) as dst:
            self.ebpf.append(Opcode.DW, dst, 1, 0, self.fd)
            self.ebpf.append(Opcode.W, 0, 0, 0, 0)
            yield dst, long


class ktime(Expression):
    """a function that returns the current ktime in ns"""
    def __init__(self, ebpf):
        self.ebpf = ebpf
        self.fixed = False

    @contextmanager
    def calculate(self, dst, long, force=False):
        with self.ebpf.get_free_register(dst) as dst:
            with self.ebpf.save_registers([i for i in range(6) if i != dst]):
                self.ebpf.call(FuncId.ktime_get_ns)
                if dst != 0:
                    self.ebpf.r[dst] = self.ebpf.r0
            yield dst, True


class prandom(Expression):
    """a function that returns the current ktime in ns"""
    def __init__(self, ebpf):
        self.ebpf = ebpf

    @contextmanager
    def calculate(self, dst, long, force=False):
        with self.ebpf.get_free_register(dst) as dst:
            with self.ebpf.save_registers([i for i in range(6) if i != dst]):
                self.ebpf.call(FuncId.get_prandom_u32)
                if dst != 0:
                    self.ebpf.r[dst] = self.ebpf.r0
            yield dst, True


class RegisterDesc:
    def __init__(self, no, array):
        self.no = no
        self.array = array

    def __get__(self, instance, owner=None):
        if instance is None:
            return self
        else:
            return getattr(instance, self.array)[self.no]

    def __set__(self, instance, value):
        getattr(instance, self.array)[self.no] = value


class RegisterArray:
    def __init__(self, ebpf, long, signed, fixed=False):
        self.ebpf = ebpf
        self.long = long
        self.signed = signed
        self.fixed = fixed

    def __setitem__(self, no, value):
        self.ebpf.owners.add(no)
        value = ensure_expression(self.ebpf, value)
        if self.fixed and not value.fixed:
            value *= Expression.FIXED_BASE
        elif not self.fixed and value.fixed:
            value /= Expression.FIXED_BASE
        with value.calculate(no, self.long, True):
            pass

    def __getitem__(self, no):
        return Register(no, self.ebpf, self.long, self.signed, self.fixed)



class Temporary(Register):
    def __init__(self, ebpf, long, signed, fixed):
        super().__init__(None, ebpf, long, signed, fixed)
        self.nos = []
        self.gfrs = []

    def __enter__(self):
        gfr = self.ebpf.get_free_register(None)
        self.nos.append(self.no)
        self.no = gfr.__enter__()
        self.gfrs.append(gfr)

    def __exit__(self, a, b, c):
        gfr = self.gfrs.pop()
        gfr.__exit__(a, b, c)
        self.no = self.nos.pop()


class TemporaryDesc(RegisterDesc):
    def __set_name__(self, owner, name):
        self.name = name

    def __get__(self, instance, owner=None):
        if instance is None:
            return self
        arr = getattr(instance, self.array)
        ret = instance.__dict__.get(self.name, None)
        if ret is None:
            ret = instance.__dict__[self.name] = \
                    Temporary(instance, arr.long, arr.signed, arr.fixed)
        return ret

    def __set__(self, instance, value):
        no = getattr(instance, self.name).no
        getattr(instance, self.array)[no] = value


class EBPFBase:
    name = None

    def __init__(self, name=None, subprograms=()):
        if name is None:
            if self.name is None:
                self.name = self.__class__.__name__
        else:
            self.name = name

        self.subprograms = subprograms
        for p in subprograms:
            p.ebpf = self

    @property
    def ebpf(self):
        return self


class SimulatedEBPF(EBPFBase):
    loaded = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        unique = set()
        for cls in self.__class__.__mro__:
            for k, v in cls.__dict__.items():
                if k not in unique and isinstance(v, Map):
                    size = v.collect(self)
                    setattr(self, k, self.get_array(size))
                    unique.add(k)


class EBPF(EBPFBase):
    """The base class for all EBPF programs

    Usually this class is sub-classed, and the actual program is defined
    in the overwritten `program` method. Then the program may be loaded into
    the kernel. Alternatively, this class may even be instantiated directly,
    in which case you can just issue the program before it is loaded.

    After a program is loaded, its maps may be written to a bpf file system
    using :meth:`pin_maps`. Those maps may be used at a later time, especially
    also in a different task, if the parameter `load_maps` is given, in which
    case we assume the program has already been loaded.

    :param load_maps: a prefix to load pinned maps from. Must be existing in a
        bpf file system, and usually ends in a "/".
    """
    stack = 0
    license = None

    def __init__(self, prog_type=0, license=None, *, kern_version=0,
                 load_maps=None, **kwargs):
        self.opcodes = []
        self.prog_type = prog_type
        if license is not None:
            self.license = license
        self.kern_version = kern_version
        self.loaded = load_maps is not None

        self.mB = MemoryMap(self, "B")
        self.mH = MemoryMap(self, "H")
        self.mI = MemoryMap(self, "I")
        self.mA = MemoryMap(self, "A")  # actually I, but treat as Q
        self.mQ = MemoryMap(self, "Q")
        self.mb = MemoryMap(self, "b")
        self.mh = MemoryMap(self, "h")
        self.mi = MemoryMap(self, "i")
        self.mq = MemoryMap(self, "q")
        self.mx = MemoryMap(self, "x")

        self.r = RegisterArray(self, True, False)
        self.sr = RegisterArray(self, True, True)
        self.w = RegisterArray(self, False, False)
        self.sw = RegisterArray(self, False, True)
        self.x = RegisterArray(self, True, True, True)

        self.owners = {1, 10}

        super().__init__(**kwargs)

        for k, v in self.__class__.__dict__.items():
            if isinstance(v, Map):
                if load_maps is None:
                    v.init(self, None)
                else:
                    v.init(self, bpf.obj_get(load_maps + k))

    def pin_maps(self, path):
        """pin the maps of this program to files with prefix `path`

        This path must be in a bpf file system, and all parent
        directories must already exist, while the individual files
        must not exist.
        """
        for k, v in self.__class__.__dict__.items():
            if isinstance(v, Map):
                bpf.obj_pin(path + k, getattr(self, v.name).fd)

    def program(self):
        """overwrite this method with your program while subclassing"""

    def append(self, opcode, dst, src, off, imm):
        self.opcodes.append(Instruction(opcode, dst, src, off, imm))

    def append_endian(self, fmt, dst):
        if not isinstance(fmt, str) or len(fmt) != 2:
            return
        endian, size = fmt
        if endian == "<":
            opcode = Opcode.LE
        elif endian in ">!":
            opcode = Opcode.BE
        self.append(opcode, dst, 0, 0, calcsize(fmt) * 8)

    def assemble(self):
        """return the assembled program"""
        sub(EBPF, self).program()
        return b"".join(
            pack("<BBHI", i.opcode.value, i.dst | i.src << 4,
                 i.off % 0x10000, i.imm % 0x100000000)
            for i in self.opcodes)

    def load(self, log_level=0, log_size=10 * 4096):
        """load the program into the kernel"""
        name = ''.join(c if c in bpf.allowed_chars else '_'
                       for c in self.name[:15])
        fd, log = bpf.prog_load(self.prog_type, self.assemble(), self.license,
                                log_level, log_size, self.kern_version,
                                name=name)
        self.loaded = True
        self.file_descriptor = fd

        for v in self.__class__.__dict__.values():
            if isinstance(v, Map):
                v.load(self)

        return log

    def close(self):
        os.close(self.file_descriptor)
        self.file_descriptor = None

    def test_run(self, *args, **kwargs):
        return bpf.prog_test_run(self.file_descriptor, *args, **kwargs)

    def jumpIf(self, comp):
        """jump if `comp` is true to a later defined `target`"""
        if isinstance(comp, Expression):
            comp = comp != 0
        comp.compare(False)
        return comp

    def jump(self):
        """unconditionally jump to a later defined `target`"""
        comp = SimpleComparison(self, None, 0, Opcode.JMP)
        comp.origin = len(self.opcodes)
        comp.dst = 0
        comp.owners = self.owners.copy()
        self.owners = set(range(11))
        self.opcodes.append(None)
        return comp

    def get_fd(self, fd):
        """return the file descriptor `fd` of a map"""
        return PseudoFd(self, fd)

    def call(self, no):
        """call the kernel function `no` from enum `FuncId`"""
        assert isinstance(no, FuncId)
        self.append(Opcode.CALL, 0, 0, 0, no.value)
        self.owners.add(0)
        self.owners -= set(range(1, 6))

    def exit(self, no=None):
        """Exit the program with return value `no`"""
        if no is not None:
            self.r0 = no.value
        self.append(Opcode.EXIT, 0, 0, 0, 0)

    @contextmanager
    def get_free_register(self, dst):
        if dst is not None:
            yield dst
            return
        for i in range(10):
            if i not in self.owners:
                self.owners.add(i)
                yield i
                self.owners.discard(i)
                return
        raise AssembleError("not enough registers")

    @contextmanager
    def save_registers(self, registers):
        oldowners = self.owners.copy()
        self.owners |= set(registers)
        save = []
        with ExitStack() as exitStack:
            for i in registers:
                if i in oldowners:
                    tmp = exitStack.enter_context(self.get_free_register(None))
                    self.append(Opcode.MOV+Opcode.LONG+Opcode.REG,
                                tmp, i, 0, 0)
                    save.append((tmp, i))
            yield
            for tmp, i in save:
                self.append(Opcode.MOV+Opcode.LONG+Opcode.REG, i, tmp, 0, 0)
            self.owners = oldowners

    @contextmanager
    def get_stack(self, size):
        oldstack = self.stack
        self.stack = (self.stack - size) & -size
        yield self.stack
        self.stack = oldstack

    tmp = TemporaryDesc(None, "r")
    stmp = TemporaryDesc(None, "sr")
    wtmp = TemporaryDesc(None, "w")
    swtmp = TemporaryDesc(None, "sw")
    xtmp = TemporaryDesc(None, "x")


for i in range(11):
    setattr(EBPF, f"r{i}", RegisterDesc(i, "r"))

for i in range(10):
    setattr(EBPF, f"sr{i}", RegisterDesc(i, "sr"))

for i in range(10):
    setattr(EBPF, f"w{i}", RegisterDesc(i, "w"))

for i in range(10):
    setattr(EBPF, f"sw{i}", RegisterDesc(i, "sw"))

for i in range(10):
    setattr(EBPF, f"x{i}", RegisterDesc(i, "x"))


class SubProgram:
    stack = 0
