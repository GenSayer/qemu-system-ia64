# IA-64 instruction encoders split on translator family boundaries.

from .encoding_common import bitfield, nop_m, op

def br_call(b1, source, target, qp=0):
    field = branch_target_field(source, target)
    return (
        op(5)
        | bitfield(b1, 6, 3)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )

def br_call_indirect(b1, b2, wh=1, many=False, clear=False, ignored=0, bit36=0,
                     qp=0):
    return (
        op(1)
        | bitfield(b1, 6, 3)
        | bitfield(1 if many else 0, 12, 1)
        | bitfield(b2, 13, 3)
        | bitfield(ignored, 16, 16)
        | bitfield(wh, 32, 3)
        | bitfield(1 if clear else 0, 35, 1)
        | bitfield(bit36, 36, 1)
        | bitfield(qp, 0, 6)
    )

def br_indirect(b2, btype=0, wh=0, many=False, clear=False, bit36=0, qp=0):
    return (
        bitfield(0x20, 27, 6)
        | bitfield(b2, 13, 3)
        | bitfield(1 if many else 0, 12, 1)
        | bitfield(btype, 6, 3)
        | bitfield(wh, 33, 2)
        | bitfield(1 if clear else 0, 35, 1)
        | bitfield(bit36, 36, 1)
        | bitfield(qp, 0, 6)
    )

def ip_relative_branch_btype(btype, source, target, qp=0):
    field = branch_target_field(source, target)
    return (
        op(4)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(btype, 6, 3)
        | bitfield(qp, 0, 6)
    )

def br_ret(b2, qp=0):
    return (bitfield(0x21, 27, 6) | bitfield(4, 6, 3) |
            bitfield(b2, 13, 3) | bitfield(qp, 0, 6))

def branch_target_field(source, target):
    delta = target - source
    if delta % 16 != 0:
        raise ValueError("branch target is not bundle aligned")
    return (delta // 16) & 0x1fffff

def long_branch_target_field(source, target):
    delta = target - source
    if delta % 16 != 0:
        raise ValueError("branch target is not bundle aligned")
    return (delta // 16) & ((1 << 60) - 1)

def br_cond(source, target, qp=0):
    field = branch_target_field(source, target)
    return (
        op(4)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )

def br_wexit(source, target, qp):
    field = branch_target_field(source, target)
    return (
        op(4)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(2, 6, 3)
        | bitfield(qp, 0, 6)
    )

def br_wtop(source, target, qp):
    field = branch_target_field(source, target)
    return (
        op(4)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(3, 6, 3)
        | bitfield(qp, 0, 6)
    )

def brl_call_mlx(b1, source, target, qp=0, ignored_l=0, template=0x05):
    field = long_branch_target_field(source, target)
    l_slot = (
        bitfield(ignored_l & 0x3, 0, 2)
        | bitfield((field >> 20) & ((1 << 39) - 1), 2, 39)
    )
    x_slot = (
        op(0xd)
        | bitfield((field >> 59) & 1, 36, 1)
        | bitfield(1, 33, 2)
        | bitfield(1, 12, 1)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield(b1, 6, 3)
        | bitfield(qp, 0, 6)
    )
    return (template, nop_m(), l_slot, x_slot)

def brl_cond_mlx(source, target, qp=0, many=False, wh=0, clear=False,
                 ignored_l=0, template=0x05):
    field = long_branch_target_field(source, target)
    l_slot = (
        bitfield(ignored_l & 0x3, 0, 2)
        | bitfield((field >> 20) & ((1 << 39) - 1), 2, 39)
    )
    x_slot = (
        op(0xc)
        | bitfield((field >> 59) & 1, 36, 1)
        | bitfield(1 if clear else 0, 35, 1)
        | bitfield(wh, 33, 2)
        | bitfield(1 if many else 0, 12, 1)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield(qp, 0, 6)
    )
    return (template, nop_m(), l_slot, x_slot)

def br_cloop(source, target, qp=0):
    field = branch_target_field(source, target)
    return (
        op(4)
        | bitfield(5, 6, 3)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )

def br_ctop_many(source, target, qp=0):
    field = branch_target_field(source, target)
    return (
        op(4)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(1, 12, 1)
        | bitfield(7, 6, 3)
        | bitfield(qp, 0, 6)
    )

def br_ctop_few(source, target, qp=0):
    field = branch_target_field(source, target)
    return (
        op(4)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(7, 6, 3)
        | bitfield(qp, 0, 6)
    )

__all__ = (
    'br_call',
    'br_call_indirect',
    'br_indirect',
    'ip_relative_branch_btype',
    'br_ret',
    'branch_target_field',
    'long_branch_target_field',
    'br_cond',
    'br_wexit',
    'br_wtop',
    'brl_call_mlx',
    'brl_cond_mlx',
    'br_cloop',
    'br_ctop_many',
    'br_ctop_few',
)
