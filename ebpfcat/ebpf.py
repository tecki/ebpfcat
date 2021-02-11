from collections import namedtuple
from contextlib import contextmanager, ExitStack
from struct import pack, unpack
from enum import Enum

from . import bpf

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


def comparison(uposop, unegop, sposop=None, snegop=None):
    if sposop is None:
        sposop = uposop
        snegop = unegop
    def ret(self, value):
        return SimpleComparison(self.ebpf, self, value,
                                (uposop, unegop, sposop, snegop))
    return ret


class Comparison:
    def __init__(self, ebpf):
        self.ebpf = ebpf
        self.invert = None
        self.else_origin = None

    def __enter__(self):
        if self.else_origin is None:
            self.compare(True)
        return self

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
        if op == Opcode.JMP:
            self.invert = self.origin
        else:
            self.ebpf.opcodes[self.origin] = \
                    Instruction(op, dst, src, off+1, imm)
        self.else_origin = len(self.ebpf.opcodes)
        self.ebpf.opcodes.append(None)
        return self

    def invert_result(self):
        origin = len(self.ebpf.opcodes)
        self.ebpf.opcodes.append(None)
        self.target()
        self.origin = origin
        self.right = self.dst = 0
        self.opcode = Opcode.JMP

    def __and__(self, value):
        return AndOrComparison(self.ebpf, self, value, True)

    def __or__(self, value):
        return AndOrComparison(self.ebpf, self, value, False)

    def __invert__(self):
        return InvertComparison(self.ebpf, self)

    def __bool__(self):
        raise RuntimeError("Use with statement for comparisons")


class SimpleComparison(Comparison):
    def __init__(self, ebpf, left, right, opcode):
        super().__init__(ebpf)
        self.left = left
        self.right = right
        self.opcode = opcode

    def compare(self, negative):
        with self.left.calculate(None, None, None) as (self.dst, _, lsigned):
            with ExitStack() as exitStack:
                if not isinstance(self.right, int):
                    self.src, _, rsigned = exitStack.enter_context(
                            self.right.calculate(None, None, None))
                    if rsigned != rsigned:
                        raise AssembleError("need same signedness for comparison")
                self.origin = len(self.ebpf.opcodes)
                self.ebpf.opcodes.append(None)
                self.opcode = self.opcode[negative + 2 * lsigned]
        self.owners = self.ebpf.owners.copy()

    def target(self):
        assert self.ebpf.opcodes[self.origin] is None
        if isinstance(self.right, int):
            inst = Instruction(
                self.opcode, self.dst, 0,
                len(self.ebpf.opcodes) - self.origin - 1, self.right)
        else:
            inst = Instruction(
                self.opcode + Opcode.REG, self.dst, self.src,
                len(self.ebpf.opcodes) - self.origin - 1, 0)
        self.ebpf.opcodes[self.origin] = inst
        self.ebpf.owners, self.owners = \
                self.ebpf.owners & self.owners, self.ebpf.owners


class AndOrComparison(Comparison):
    def __init__(self, ebpf, left, right, is_and):
        super().__init__(ebpf)
        self.left = left
        self.right = right
        self.is_and = is_and
        self.targetted = False

    def compare(self, negative):
        self.left.compare(self.is_and != negative)
        self.right.compare(self.is_and != negative)
        if self.is_and != negative:
            self.invert_result()
            self.owners = self.ebpf.owners.copy()

    def target(self):
        if self.targetted:
            super().target()
        else:
            self.left.target()
            self.right.target()
            self.targetted = True


class InvertComparison(Comparison):
    def __init__(self, ebpf, value):
        self.ebpf = ebpf
        self.value = value

    def compare(self, negative):
        self.value.compare(not negative)


def binary(opcode):
    def ret(self, value):
        return Binary(self.ebpf, self, value, opcode)
    return ret

def rbinary(opcode):
    def ret(self, value):
        return ReverseBinary(self.ebpf, value, self, opcode)
    return ret


class Expression:
    __radd__ = __add__ = binary(Opcode.ADD)
    __sub__ = binary(Opcode.SUB)
    __rsub__ = rbinary(Opcode.SUB)
    __rmul__ = __mul__ = binary(Opcode.MUL)
    __truediv__ = binary(Opcode.DIV)
    __rtruediv__ = rbinary(Opcode.DIV)
    __ror__ = __or__ = binary(Opcode.OR)
    __lshift__ = binary(Opcode.LSH)
    __rlshift__ = rbinary(Opcode.LSH)
    __rshift__ = binary(Opcode.RSH)
    __rrshift__ = rbinary(Opcode.RSH)
    __mod__ = binary(Opcode.MOD)
    __rmod__ = rbinary(Opcode.MOD)
    __rxor__ = __xor__ = binary(Opcode.XOR)

    __eq__ = comparison(Opcode.JEQ, Opcode.JNE)
    __gt__ = comparison(Opcode.JGT, Opcode.JLE, Opcode.JSGT, Opcode.JSLE)
    __ge__ = comparison(Opcode.JGE, Opcode.JLT, Opcode.JSGE, Opcode.JSLT)
    __lt__ = comparison(Opcode.JLT, Opcode.JGE, Opcode.JSLT, Opcode.JSGE)
    __le__ = comparison(Opcode.JLE, Opcode.JGT, Opcode.JSLE, Opcode.JSGT)
    __ne__ = comparison(Opcode.JNE, Opcode.JEQ)

    def __and__(self, value):
        return AndExpression(self.ebpf, self, value)

    __rand__ = __and__

    def __neg__(self):
        return Negate(self.ebpf, self)

    def __bool__(self):
        raise RuntimeError("Expression only has a value at execution time")

    def __enter__(self):
        ret = self != 0
        self.as_comparison = ret
        return ret.__enter__()

    def __exit__(self, exc_type, exc, tb):
        return self.as_comparison.__exit__(exc_type, exc, tb)

    @contextmanager
    def calculate(self, dst, long, signed, force=False):
        with self.ebpf.get_free_register(dst) as dst:
            with self.get_address(dst, long, signed) as (src, bits):
                self.ebpf.append(Opcode.LD + bits, dst, src, 0, 0)
                yield dst, long, self.signed

    @contextmanager
    def get_address(self, dst, long, signed, force=False):
        with self.ebpf.get_stack(4 + 4 * long) as stack:
            with self.calculate(dst, long, signed) as (src, _, _):
                self.ebpf.append(Opcode.STX + Opcode.DW * long,
                                 10, src, stack, 0)
                self.ebpf.append(Opcode.MOV + Opcode.LONG + Opcode.REG, dst, 10, 0, 0)
                self.ebpf.append(Opcode.ADD + Opcode.LONG, dst, 0, 0, stack)
            yield


class Binary(Expression):
    def __init__(self, ebpf, left, right, operator):
        self.ebpf = ebpf
        self.left = left
        self.right = right
        self.operator = operator

    @contextmanager
    def calculate(self, dst, long, signed, force=False):
        orig_dst = dst
        if not isinstance(self.right, int) and self.right.contains(dst):
            dst = None
        with self.ebpf.get_free_register(dst) as dst:
            with self.left.calculate(dst, long, signed, True) \
                    as (dst, long, signed):
                pass
            if self.operator is Opcode.RSH and signed:  # >>=
                operator = Opcode.ARSH
            else:
                operator = self.operator
            if isinstance(self.right, int):
                self.ebpf.append(operator + (Opcode.LONG if long is None
                                             else Opcode.LONG * long),
                                 dst, 0, 0, self.right)
            else:
                with self.right.calculate(None, long, None) as (src, long, _):
                    self.ebpf.append(operator + Opcode.LONG*long + Opcode.REG,
                                     dst, src, 0, 0)
            if orig_dst is None or orig_dst == dst:
                yield dst, long, signed
                return
        self.ebpf.append(Opcode.MOV + Opcode.LONG * long, orig_dst, dst, 0, 0)
        yield orig_dst, long, signed

    def contains(self, no):
        return self.left.contains(no) or (not isinstance(self.right, int)
                                          and self.right.contains(no))


class ReverseBinary(Expression):
    def __init__(self, ebpf, left, right, operator):
        self.ebpf = ebpf
        self.left = left
        self.right = right
        self.operator = operator

    @contextmanager
    def calculate(self, dst, long, signed, force=False):
        with self.ebpf.get_free_register(dst) as dst:
            self.ebpf._load_value(dst, self.left)
            if self.operator is Opcode.RSH and self.left < 0:  # >>=
                operator = Opcode.ARSH
            else:
                operator = self.operator

            with self.right.calculate(None, long, None) as (src, long, _):
                self.ebpf.append(operator + Opcode.LONG * long + Opcode.REG,
                                 dst, src, 0, 0)
            yield dst, long, signed

    def contains(self, no):
        return self.right.contains(no)


class Negate(Expression):
    def __init__(self, ebpf, arg):
        self.ebpf = ebpf
        self.arg = arg

    @contextmanager
    def calculate(self, dst, long, signed, force=False):
        with self.arg.calculate(dst, long, signed, force) as \
                (dst, long, signed):
            self.ebpf.append(Opcode.NEG + Opcode.LONG * long, dst, 0, 0, 0)
            yield dst, long, signed

    def contains(self, no):
        return self.arg.contains(no)


class Sum(Binary):
    def __init__(self, ebpf, left, right):
        super().__init__(ebpf, left, right, Opcode.ADD)

    def __add__(self, value):
        if isinstance(value, int):
            return Sum(self.ebpf, self.left, self.right + value)
        else:
            return super().__add__(value)

    __radd__ = __add__

    def __sub__(self, value):
        if isinstance(value, int):
            return Sum(self.ebpf, self.left, self.right - value)
        else:
            return super().__sub__(value)


class AndExpression(SimpleComparison, Binary):
    def __init__(self, ebpf, left, right):
        Binary.__init__(self, ebpf, left, right, Opcode.AND)
        SimpleComparison.__init__(self, ebpf, left, right, Opcode.JSET)
        self.opcode = (Opcode.JSET, None, Opcode.JSET, None)

    def compare(self, negative):
        super().compare(False)
        if negative:
            self.invert_result()

class Register(Expression):
    offset = 0

    def __init__(self, no, ebpf, long, signed):
        self.no = no
        self.ebpf = ebpf
        self.long = long
        self.signed = signed

    def __add__(self, value):
        if isinstance(value, int) and self.long:
            return Sum(self.ebpf, self, value)
        else:
            return super().__add__(value)

    __radd__ = __add__

    def __sub__(self, value):
        if isinstance(value, int) and self.long:
            return Sum(self.ebpf, self, -value)
        else:
            return super().__sub__(value)

    @contextmanager
    def calculate(self, dst, long, signed, force=False):
        if long is not None and long != self.long:
            raise AssembleError("cannot compile")
        if signed is not None and signed != self.signed:
            raise AssembleError("cannot compile")
        if self.no not in self.ebpf.owners:
            raise AssembleError("register has no value")
        if dst != self.no and force:
            self.ebpf.append(Opcode.MOV + Opcode.REG + Opcode.LONG * self.long,
                             dst, self.no, 0, 0)
            yield dst, self.long, self.signed
        else:
            yield self.no, self.long, self.signed

    def contains(self, no):
        return self.no == no


class IAdd:
    def __init__(self, value):
        self.value = value


class Memory(Expression):
    bits_to_opcode = {32: Opcode.W, 16: Opcode.H, 8: Opcode.B, 64: Opcode.DW}
    fmt_to_opcode = {'I': Opcode.W, 'H': Opcode.H, 'B': Opcode.B, 'Q': Opcode.DW,
                     'i': Opcode.W, 'h': Opcode.H, 'b': Opcode.B, 'q': Opcode.DW}
    fmt_to_size = {'I': 4, 'H': 2, 'B': 1, 'Q': 8,
                   'i': 4, 'h': 2, 'b': 1, 'q': 8}

    def __init__(self, ebpf, bits, address, signed=False):
        self.ebpf = ebpf
        self.bits = bits
        self.address = address
        self.signed = signed

    def __iadd__(self, value):
        return IAdd(value)

    def __isub__(self, value):
        return IAdd(-value)

    @contextmanager
    def calculate(self, dst, long, signed, force=False):
        if not long and self.bits == Opcode.DW:
            raise AssembleError("cannot compile")
        if isinstance(self.address, Sum):
            with self.ebpf.get_free_register(dst) as dst:
                self.ebpf.append(Opcode.LD + self.bits, dst,
                                 self.address.left.no, self.address.right, 0)
                yield dst, long, self.signed
        else:
            with super().calculate(dst, long, signed, force) as ret:
                yield ret

    @contextmanager
    def get_address(self, dst, long, signed, force=False):
        with self.address.calculate(dst, None, None) as (src, _, _):
            yield src, self.bits

    def contains(self, no):
        return self.address.contains(no)


class MemoryDesc:
    def __init__(self, fmt='I'):
        self.fmt = fmt

    @property
    def signed(self):
        return self.fmt.islower()

    def __get__(self, instance, owner):
        if instance is None:
            return self
        elif isinstance(instance, SubProgram):
            ebpf = instance.ebpf
        else:
            ebpf = instance
        return Memory(ebpf, Memory.fmt_to_opcode[self.fmt],
                      ebpf.r[self.base_register] + self.addr(instance),
                      self.signed)

    def __set__(self, instance, value):
        if isinstance(instance, SubProgram):
            ebpf = instance.ebpf
        else:
            ebpf = instance
        bits = Memory.fmt_to_opcode[self.fmt]
        if isinstance(value, int):
            ebpf.append(Opcode.ST + bits, self.base_register, 0,
                        self.addr(instance), value)
            return
        elif isinstance(value, IAdd):
            value = value.value
            if isinstance(value, int):
                with ebpf.get_free_register(None) as src:
                    ebpf.r[src] = value
                    ebpf.append(Opcode.XADD + bits, self.base_register,
                                src, self.addr(instance), 0)
                return
            opcode = Opcode.XADD
        else:
            opcode = Opcode.STX
        with value.calculate(None, self.fmt in 'qQ', self.signed) \
                as (src, _, _):
            ebpf.append(opcode + bits, self.base_register,
                        src, self.addr(instance), 0)


class LocalVar(MemoryDesc):
    base_register = 10

    def __set_name__(self, owner, name):
        size = Memory.fmt_to_size[self.fmt]
        owner.stack -= size
        owner.stack &= -size
        self.relative_addr = owner.stack
        self.name = name

    def addr(self, instance):
        if isinstance(instance, SubProgram):
            return (instance.ebpf.stack & -8) + self.relative_addr
        else:
            return self.relative_addr


class MemoryMap:
    def __init__(self, ebpf, bits):
        self.ebpf = ebpf
        self.bits = bits

    def __setitem__(self, addr, value):
        with ExitStack() as exitStack:
            if isinstance(addr, Sum):
                dst = addr.left.no
                offset = addr.right
            else:
                dst, _, _ = exitStack.enter_context(
                        addr.calculate(None, None, None))
                offset = 0
            if isinstance(value, int):
                self.ebpf.append(Opcode.ST + self.bits, dst, 0, offset, value)
                return
            elif isinstance(value, IAdd):
                value = value.value
                if isinstance(value, int):
                    with self.ebpf.get_free_register(None) as src:
                        self.ebpf.r[src] = value
                        self.ebpf.append(
                            Opcode.XADD + self.bits, dst, src, offset, 0)
                    return
                opcode = Opcode.XADD
            else:
                opcode = Opcode.STX
            with value.calculate(None, None, None) as (src, _, _):
                self.ebpf.append(opcode + self.bits, dst, src, offset, 0)

    def __getitem__(self, addr):
        if isinstance(addr, Register):
            addr = addr + 0
        return Memory(self.ebpf, self.bits, addr)


class Map:
    def init(self, ebpf):
        pass

    def load(self, ebpf):
        pass


class PseudoFd(Expression):
    def __init__(self, ebpf, fd):
        self.ebpf = ebpf
        self.fd = fd

    @contextmanager
    def calculate(self, dst, long, signed, force):
        with self.ebpf.get_free_register(dst) as dst:
            self.ebpf.append(Opcode.DW, dst, 1, 0, self.fd)
            self.ebpf.append(Opcode.W, 0, 0, 0, 0)
            yield dst, long, signed


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
    def __init__(self, ebpf, long, signed):
        self.ebpf = ebpf
        self.long = long
        self.signed = signed

    def __setitem__(self, no, value):
        self.ebpf.owners.add(no)
        if isinstance(value, int):
            self.ebpf._load_value(no, value)
        elif isinstance(value, Expression):
            with value.calculate(no, self.long, self.signed, True):
                pass
        else:
            raise AssembleError("cannot compile")

    def __getitem__(self, no):
        return Register(no, self.ebpf, self.long, self.signed)



class Temporary(Register):
    def __init__(self, ebpf, long, signed):
        super().__init__(None, ebpf, long, signed)
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
                    Temporary(instance, arr.long, arr.signed)
        return ret

    def __set__(self, instance, value):
        no = getattr(instance, self.name).no
        getattr(instance, self.array)[no] = value


class EBPF:
    stack = 0
    name = None
    license = None

    def __init__(self, prog_type=0, license=None, kern_version=0,
                 name=None, subprograms=()):
        self.opcodes = []
        self.prog_type = prog_type
        if license is not None:
            self.license = license
        self.kern_version = kern_version
        if name is None:
            if self.name is None:
                self.name = self.__class__.__name__[:16]
        else:
            self.name = name
        self.loaded = False

        self.mB = MemoryMap(self, Opcode.B)
        self.mH = MemoryMap(self, Opcode.H)
        self.mI = MemoryMap(self, Opcode.W)
        self.mQ = MemoryMap(self, Opcode.DW)

        self.r = RegisterArray(self, True, False)
        self.sr = RegisterArray(self, True, True)
        self.w = RegisterArray(self, False, False)
        self.sw = RegisterArray(self, False, True)

        self.owners = {1, 10}

        self.subprograms = subprograms
        for p in subprograms:
            p.ebpf = self

        for v in self.__class__.__dict__.values():
            if isinstance(v, Map):
                v.init(self)

    def program(self):
        pass

    def append(self, opcode, dst, src, off, imm):
        self.opcodes.append(Instruction(opcode, dst, src, off, imm))

    def assemble(self):
        self.program()
        return b"".join(
            pack("<BBHI", i.opcode.value, i.dst | i.src << 4,
                 i.off % 0x10000, i.imm % 0x100000000)
            for i in self.opcodes)

    def load(self, log_level=0, log_size=4096):
        ret = bpf.prog_load(self.prog_type, self.assemble(), self.license,
                            log_level, log_size, self.kern_version,
                            name=self.name)
        self.loaded = True

        for v in self.__class__.__dict__.values():
            if isinstance(v, Map):
                v.load(self)

        return ret

    def jumpIf(self, comp):
        comp.compare(False)
        return comp

    def jump(self):
        comp = SimpleComparison(self, None, 0, Opcode.JMP)
        comp.origin = len(self.opcodes)
        comp.dst = 0
        comp.owners = self.owners.copy()
        self.owners = set(range(11))
        self.opcodes.append(None)
        return comp

    def If(self, comp):
        return comp

    def get_fd(self, fd):
        return PseudoFd(self, fd)

    def call(self, no):
        assert isinstance(no, FuncId)
        self.append(Opcode.CALL, 0, 0, 0, no.value)
        self.owners.add(0)
        self.owners -= set(range(1, 6))

    def exit(self, no=None):
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

    def _load_value(self, no, value):
        if -0x80000000 <= value < 0x80000000:
            self.append(Opcode.MOV + Opcode.LONG, no, 0, 0, value)
        else:
            self.append(Opcode.DW, no, 0, 0, value & 0xffffffff)
            self.append(Opcode.W, 0, 0, 0, value >> 32)

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


for i in range(11):
    setattr(EBPF, f"r{i}", RegisterDesc(i, "r"))

for i in range(10):
    setattr(EBPF, f"sr{i}", RegisterDesc(i, "sr"))

for i in range(10):
    setattr(EBPF, f"w{i}", RegisterDesc(i, "w"))

for i in range(10):
    setattr(EBPF, f"sw{i}", RegisterDesc(i, "sw"))


class SubProgram:
    stack = 0
