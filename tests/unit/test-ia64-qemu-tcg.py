#!/usr/bin/env python3
#
# QEMU-level smoke tests for the IA-64 TCG translator.  These tests inject
# small hand-encoded bundles with the generic loader, let the vCPU execute, and
# verify architectural state through HMP "info registers".

import re
import subprocess
import sys
import time


IA64_EXCP_BREAK = 1
IA64_EXCP_ILLEGAL = 2
IA64_EXCP_RESERVED_TEMPLATE = 3


def bitfield(value, low, width):
    return (value & ((1 << width) - 1)) << low


def op(major):
    return bitfield(major, 37, 4)


def nop_m():
    return bitfield(1, 27, 4)


def nop_i():
    return bitfield(1, 27, 6)


def nop_b():
    return op(2)


def break_m(imm=0, qp=0):
    return (
        bitfield(imm & 0xfffff, 6, 20)
        | bitfield((imm >> 20) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )


def illegal_m():
    return op(15)


def adds(r1, imm, r3, qp=0):
    encoded = imm & 0x3fff
    return (
        op(8)
        | bitfield(2, 34, 2)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield((encoded >> 7) & 0x3f, 27, 6)
        | bitfield((encoded >> 13) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def addl(r1, imm, r3, qp=0):
    encoded = imm & 0x3FFFFF
    return (
        op(9)
        | bitfield((encoded >> 21) & 1, 36, 1)
        | bitfield((encoded >> 7) & 0x1FF, 27, 9)
        | bitfield((encoded >> 16) & 0x1F, 22, 5)
        | bitfield(r3, 20, 2)
        | bitfield(encoded & 0x7F, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def alu(x4, x2b, r1, r2, r3, qp=0):
    return (
        op(8)
        | bitfield(x4, 29, 4)
        | bitfield(x2b, 27, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def alu_imm(x4, x2b, r1, imm, r3, qp=0):
    encoded = imm & 0xFF
    return (
        op(8)
        | bitfield((encoded >> 7) & 1, 36, 1)
        | bitfield(x4, 29, 4)
        | bitfield(x2b, 27, 2)
        | bitfield(r3, 20, 7)
        | bitfield(encoded & 0x7F, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def andcm(r1, r2, r3, qp=0):
    return alu(3, 1, r1, r2, r3, qp)


def add(r1, r2, r3, qp=0):
    return alu(0, 0, r1, r2, r3, qp)


def add_one(r1, r2, r3, qp=0):
    return alu(0, 1, r1, r2, r3, qp)


def sub_one(r1, r2, r3, qp=0):
    return alu(1, 0, r1, r2, r3, qp)


def shladd(r1, r2, shift, r3, qp=0):
    return alu(4, shift - 1, r1, r2, r3, qp)


def shl_reg(r1, r2, r3, qp=0):
    return (
        op(7)
        | bitfield(1, 36, 1)
        | bitfield(1, 33, 1)
        | bitfield(8, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def shru_reg(r1, r2, r3, qp=0):
    return (
        op(7)
        | bitfield(1, 36, 1)
        | bitfield(1, 33, 1)
        | bitfield(0, 27, 6)
        | bitfield(r2, 20, 7)
        | bitfield(r3, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def shr_reg(r1, r2, r3, qp=0):
    return (
        op(7)
        | bitfield(1, 36, 1)
        | bitfield(1, 33, 1)
        | bitfield(4, 27, 6)
        | bitfield(r2, 20, 7)
        | bitfield(r3, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def shrp_imm(r1, r2, r3, count, qp=0):
    return (
        op(5)
        | bitfield(3, 34, 2)
        | bitfield(count & 0x3F, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def sub_imm(r1, imm, r3, qp=0):
    return alu_imm(9, 1, r1, imm, r3, qp)


def and_imm(r1, imm, r3, qp=0):
    return alu_imm(0xB, 0, r1, imm, r3, qp)


def andcm_imm(r1, imm, r3, qp=0):
    return alu_imm(0xB, 1, r1, imm, r3, qp)


def or_imm(r1, imm, r3, qp=0):
    return alu_imm(0xB, 2, r1, imm, r3, qp)


def xor_imm(r1, imm, r3, qp=0):
    return alu_imm(0xB, 3, r1, imm, r3, qp)


def load_mem(x6, r1, r3, qp=0):
    return (
        op(4)
        | bitfield(x6, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def ld1(r1, r3, qp=0):
    return load_mem(0x00, r1, r3, qp)


def ld2(r1, r3, qp=0):
    return load_mem(0x01, r1, r3, qp)


def ld4(r1, r3, qp=0):
    return load_mem(0x02, r1, r3, qp)


def ld8(r1, r3, qp=0):
    return load_mem(0x03, r1, r3, qp)


def store_mem(x6, r3, r2, qp=0):
    return (
        op(4)
        | bitfield(x6, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(qp, 0, 6)
    )


def st1(r3, r2, qp=0):
    return store_mem(0x30, r3, r2, qp)


def st2(r3, r2, qp=0):
    return store_mem(0x31, r3, r2, qp)


def st4(r3, r2, qp=0):
    return store_mem(0x32, r3, r2, qp)


def st8(r3, r2, qp=0):
    return store_mem(0x33, r3, r2, qp)


def fetchadd4_acq(r1, r3, inc, qp=0):
    inc3 = {16: 0, 8: 1, 4: 2, 1: 3, -16: 4, -8: 5, -4: 6, -1: 7}[inc]
    return (
        op(4)
        | bitfield(0x12, 30, 6)
        | bitfield(1, 27, 1)
        | bitfield(inc3, 13, 3)
        | bitfield(r3, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def store_post_imm(x6a, r3, r2, imm, qp=0):
    encoded = imm & 0x1ff
    return (
        op(5)
        | bitfield(x6a, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(encoded & 0x7f, 6, 7)
        | bitfield((encoded >> 7) & 1, 27, 1)
        | bitfield((encoded >> 8) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )


def st8_post_imm(r3, r2, imm, qp=0):
    return store_post_imm(0x33, r3, r2, imm, qp)


def st1_post_imm(r3, r2, imm, qp=0):
    return store_post_imm(0x30, r3, r2, imm, qp)


def st1_rel_post_imm(r3, r2, imm, qp=0):
    return store_post_imm(0x34, r3, r2, imm, qp)


def stf_spill(r3, f2, qp=0):
    return (
        op(6)
        | bitfield(0x3B, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(qp, 0, 6)
    )


def stf_spill_nta(r3, f2, qp=0):
    return stf_spill(r3, f2, qp) | bitfield(3, 28, 2)


def stf_spill_nta_post(r3, f2, imm, qp=0):
    encoded = imm & 0x1ff
    return (
        op(7)
        | bitfield(3, 28, 2)
        | bitfield(0x3B, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(encoded & 0x7F, 6, 7)
        | bitfield((encoded >> 7) & 1, 27, 1)
        | bitfield((encoded >> 8) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )


def stf8(r3, f2, qp=0):
    return (
        op(6)
        | bitfield(0x31, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(qp, 0, 6)
    )


def ld8_s(r1, r3, qp=0):
    return (
        op(4)
        | bitfield(0, 36, 1)
        | bitfield(1, 27, 2)
        | bitfield(0x03, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def ld8_a(r1, r3, qp=0):
    return (
        op(4)
        | bitfield(0, 36, 1)
        | bitfield(2, 27, 2)
        | bitfield(0x0B, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def ld8_fill(r1, r3, qp=0):
    return (
        op(4)
        | bitfield(0x1B, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def ld8_fill_nta(r1, r3, qp=0):
    return ld8_fill(r1, r3, qp) | bitfield(3, 28, 2)


def ld8_fill_nta_post(r1, r3, imm, qp=0):
    return (
        op(5)
        | bitfield(3, 28, 2)
        | bitfield(0x1B, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(imm & 0x7F, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def chk_a_clr(r2, qp=0):
    return (
        op(0)
        | bitfield(1, 33, 1)
        | bitfield(2, 34, 2)
        | bitfield(r2, 6, 7)
        | bitfield(qp, 0, 6)
    )


def chk_a_clr_fp(r2, source, target, qp=0):
    field = branch_target_field(source, target)
    return (
        op(0)
        | bitfield(7, 33, 3)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(r2, 6, 7)
        | bitfield(qp, 0, 6)
    )


def sync_m(x6, qp=0):
    return bitfield(x6, 27, 6) | bitfield(qp, 0, 6)


def flushrs(qp=0):
    return sync_m(0x0C, qp)


def loadrs(qp=0):
    return sync_m(0x0A, qp)


def invala(qp=0):
    return sync_m(0x10, qp)


def srlz_d(qp=0):
    return sync_m(0x30, qp)


def mf(qp=0):
    return sync_m(0x22, qp)


def mf_a(qp=0):
    return sync_m(0x23, qp)


def tnat_nz(p1, p2, r2, qp=0):
    return (
        op(0xe)
        | bitfield(1, 12, 1)
        | bitfield(1, 33, 1)
        | bitfield(3, 34, 2)
        | bitfield(1, 36, 1)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(r2, 13, 7)
        | bitfield(qp, 0, 6)
    )


def tnat_z(p1, p2, r2, qp=0):
    return (
        op(0xe)
        | bitfield(1, 12, 1)
        | bitfield(1, 33, 1)
        | bitfield(1, 34, 2)
        | bitfield(0, 36, 1)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(r2, 13, 7)
        | bitfield(qp, 0, 6)
    )


def tnat_nz(p1, p2, r2, qp=0):
    return (
        op(0xe)
        | bitfield(1, 12, 1)
        | bitfield(1, 33, 1)
        | bitfield(1, 34, 2)
        | bitfield(1, 36, 1)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(r2, 13, 7)
        | bitfield(qp, 0, 6)
    )


def cmp_eq(p1, p2, r2, r3, qp=0):
    return (
        op(0xe)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def cmp_eq_or(p1, p2, r2, r3, qp=0):
    return (
        op(0xD)
        | bitfield(1, 33, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def cmp_ne_or(p1, p2, r2, r3, qp=0):
    return (
        op(0xD)
        | bitfield(1, 12, 1)
        | bitfield(1, 33, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def cmp_eq_or_andcm(p1, p2, r2, r3, qp=0):
    return (
        op(0xE)
        | bitfield(1, 33, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def cmp4_eq_or_andcm(p1, p2, r2, r3, qp=0):
    return (
        op(0xE)
        | bitfield(1, 33, 1)
        | bitfield(1, 34, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def cmp_le_or_andcm_zero(p1, p2, r3, qp=0):
    return (
        op(0xE)
        | bitfield(1, 36, 1)
        | bitfield(1, 12, 1)
        | bitfield(r3, 20, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def cmp_eq_imm(p1, p2, imm, r3, qp=0):
    encoded = imm & 0xFF
    return (
        op(0xE)
        | bitfield((encoded >> 7) & 1, 36, 1)
        | bitfield(2, 34, 2)
        | bitfield(r3, 20, 7)
        | bitfield(encoded & 0x7F, 13, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def cmp_lt_imm(p1, p2, imm, r3, qp=0):
    encoded = imm & 0xFF
    return (
        op(0xC)
        | bitfield(2, 34, 2)
        | bitfield((encoded >> 7) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(encoded & 0x7F, 13, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def cmp_ne_or_andcm_imm(p1, p2, imm, r3, qp=0):
    encoded = imm & 0xFF
    return (
        op(0xE)
        | bitfield(1, 12, 1)
        | bitfield(1, 33, 1)
        | bitfield(2, 34, 2)
        | bitfield((encoded >> 7) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(encoded & 0x7F, 13, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def cmp4_ne_or_andcm_imm(p1, p2, imm, r3, qp=0):
    encoded = imm & 0xFF
    return (
        op(0xE)
        | bitfield(1, 12, 1)
        | bitfield(1, 33, 1)
        | bitfield(3, 34, 2)
        | bitfield((encoded >> 7) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(encoded & 0x7F, 13, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def cmp4_eq_or_andcm_imm(p1, p2, imm, r3, qp=0):
    encoded = imm & 0xFF
    return (
        op(0xE)
        | bitfield(1, 33, 1)
        | bitfield(3, 34, 2)
        | bitfield((encoded >> 7) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(encoded & 0x7F, 13, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def cmp_eq_or_andcm_imm(p1, p2, imm, r3, qp=0):
    encoded = imm & 0xFF
    return (
        op(0xE)
        | bitfield(1, 33, 1)
        | bitfield(2, 34, 2)
        | bitfield((encoded >> 7) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(encoded & 0x7F, 13, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def cmp4_eq_imm(p1, p2, imm8, r3, qp=0):
    encoded = imm8 & 0xFF
    return (
        op(0xE)
        | bitfield((encoded >> 7) & 1, 36, 1)
        | bitfield(3, 34, 2)
        | bitfield(r3, 20, 7)
        | bitfield(encoded & 0x7F, 13, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def cmp4_lt_imm(p1, p2, imm, r3, qp=0):
    encoded = imm & 0xFF
    return (
        op(0xC)
        | bitfield(3, 34, 2)
        | bitfield((encoded >> 7) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(encoded & 0x7F, 13, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def cmp_ltu_imm(p1, p2, imm, r3, qp=0):
    return (
        op(0xD)
        | bitfield(2, 34, 2)
        | bitfield(r3, 20, 7)
        | bitfield(imm & 0x7F, 13, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def cmp4_ltu_imm(p1, p2, imm, r3, qp=0):
    return (
        op(0xD)
        | bitfield(3, 34, 2)
        | bitfield(r3, 20, 7)
        | bitfield(imm & 0x7F, 13, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def cmp_ltu(p1, p2, r2, r3, qp=0):
    return (
        op(0xD)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def cmp_lt(p1, p2, r2, r3, qp=0):
    return (
        op(0xC)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def cmp4_eq(p1, p2, r2, r3, qp=0):
    return (
        op(0xE)
        | bitfield(1, 34, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def cmp4_lt(p1, p2, r2, r3, qp=0):
    return (
        op(0xC)
        | bitfield(1, 34, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def cmp4_ltu(p1, p2, r2, r3, qp=0):
    return (
        op(0xD)
        | bitfield(1, 34, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def mux1_brcst(r1, r2, qp=0):
    return (
        op(0x7)
        | bitfield(3, 34, 2)
        | bitfield(2, 30, 2)
        | bitfield(2, 28, 2)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def tbit_z(p1, p2, r3, bitnum, qp=0):
    return (
        op(5)
        | bitfield(bitnum & 0x3F, 14, 6)
        | bitfield(r3, 20, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def tbit_z_or_andcm(p1, p2, r3, bitnum, qp=0):
    return (
        op(5)
        | bitfield(1, 36, 1)
        | bitfield(1, 33, 1)
        | bitfield(bitnum & 0x3F, 14, 6)
        | bitfield(r3, 20, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def tnat_nz_and(p1, p2, r3, qp=0):
    return (
        op(5)
        | bitfield(1, 36, 1)
        | bitfield(1, 12, 1)
        | bitfield(r3, 20, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def extr(r1, r3, pos, length, signed=False, qp=0):
    return (
        op(5)
        | bitfield(1, 34, 2)
        | bitfield(((pos & 0x3F) << 1) | (1 if signed else 0), 13, 7)
        | bitfield(r3, 20, 7)
        | bitfield((length - 1) & 0x3F, 27, 6)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def dep_imm(r1, imm1, r3, pos, length, qp=0):
    return (
        op(5)
        | bitfield(1, 33, 1)
        | bitfield(3, 34, 2)
        | bitfield(1 if imm1 else 0, 36, 1)
        | bitfield((63 - (pos & 0x3F)) << 1, 13, 7)
        | bitfield(r3, 20, 7)
        | bitfield((length - 1) & 0x3F, 27, 6)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def branch_target_field(source, target):
    delta = target - source
    if delta % 16 != 0:
        raise ValueError("branch target is not bundle aligned")
    return (delta // 16) & 0x1fffff


def br_cond(source, target, qp=0):
    field = branch_target_field(source, target)
    return op(4) | bitfield(field & 0xfffff, 13, 20) | bitfield((field >> 20) & 1, 36, 1) | bitfield(qp, 0, 6)


def br_many(source, target, qp=0):
    return br_cond(source, target, qp) | bitfield(1, 12, 1)


def br_call(b1, source, target, qp=0):
    field = branch_target_field(source, target)
    return (
        op(5)
        | bitfield(b1, 6, 3)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )


def br_call_many(b1, source, target, qp=0):
    field = branch_target_field(source, target)
    return (
        op(5)
        | bitfield(1, 12, 1)
        | bitfield(b1, 6, 3)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )


def br_call_indirect(ret_b, target_b, qp=0):
    return (
        op(1)
        | bitfield(1, 12, 1)
        | bitfield(ret_b, 6, 3)
        | bitfield(target_b, 13, 3)
        | bitfield(0x20, 27, 6)
        | bitfield(qp, 0, 6)
    )


def br_ret(b2, qp=0):
    return bitfield(0x21, 27, 6) | bitfield(4, 6, 3) | bitfield(b2, 13, 3) | bitfield(qp, 0, 6)


def br_indirect(b2, qp=0):
    return bitfield(0x20, 27, 6) | bitfield(b2, 13, 3) | bitfield(qp, 0, 6)


def br_cloop(source, target, qp=0):
    field = branch_target_field(source, target)
    return (
        op(4)
        | bitfield(5, 6, 3)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )


def brp_loop_imp():
    return (
        op(7)
        | bitfield(0x100, 27, 9)
        | bitfield(1, 6, 1)
        | bitfield(8, 0, 4)
    )


def brp_sptk_windows():
    return 0xF1FCF84840


def mov_grbr(b1, r2, qp=0):
    return (
        op(0)
        | bitfield(7, 33, 3)
        | bitfield(b1, 6, 3)
        | bitfield(r2, 13, 7)
        | bitfield(qp, 0, 6)
    )


def mov_grbr_sptk(b1, r2, qp=0):
    return (
        mov_grbr(b1, r2, qp)
        | bitfield(64, 20, 7)
        | bitfield(1, 27, 6)
    )


def mov_ip(r1, qp=0):
    return (
        op(0)
        | bitfield(0x30, 27, 6)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def mov_grpr(r2, mask, qp=0):
    encoded = ((mask & 0x1FFFE) >> 1)
    return (
        op(0)
        | bitfield(3, 33, 3)
        | bitfield(encoded & 0x7F, 6, 7)
        | bitfield(r2, 13, 7)
        | bitfield((encoded >> 7) & 0xFF, 24, 8)
        | bitfield((encoded >> 15) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )


def mov_pr_rot_imm(imm, qp=0):
    encoded = (imm >> 16) & ((1 << 28) - 1)
    return (
        op(0)
        | bitfield(1, 34, 2)
        | bitfield(encoded & 0x7F, 6, 7)
        | bitfield((encoded >> 7) & 0x7F, 13, 7)
        | bitfield((encoded >> 14) & 0xF, 20, 4)
        | bitfield((encoded >> 18) & 0xFF, 24, 8)
        | bitfield((encoded >> 26) & 1, 32, 1)
        | bitfield((encoded >> 27) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )


def mov_prgr(r1, qp=0):
    return (
        op(0)
        | bitfield(r1, 6, 7)
        | bitfield(0x33, 27, 6)
        | bitfield(qp, 0, 6)
    )


def mov_i_grar(ar, r2, qp=0):
    return (
        op(0)
        | bitfield(0x2A, 27, 6)
        | bitfield(ar, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(qp, 0, 6)
    )


def mov_i_argr(r1, ar, qp=0):
    return (
        op(0)
        | bitfield(0x32, 27, 6)
        | bitfield(ar, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def mov_m_grar(ar, r2, qp=0):
    return (
        op(1)
        | bitfield(0x2A, 27, 6)
        | bitfield(ar, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(qp, 0, 6)
    )


def mov_m_argr(r1, ar, qp=0):
    return (
        op(1)
        | bitfield(0x22, 27, 6)
        | bitfield(ar, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def ldf_fill(f1, r3, qp=0):
    return (
        op(6)
        | bitfield(0x1B, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def ldf_fill_post(f1, r3, imm, qp=0):
    encoded = imm & 0x1ff
    return (
        op(7)
        | bitfield(0x1B, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(encoded & 0x7F, 13, 7)
        | bitfield((encoded >> 7) & 1, 27, 1)
        | bitfield((encoded >> 8) & 1, 36, 1)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def ldf_fill_nta_post(f1, r3, imm, qp=0):
    encoded = imm & 0x1ff
    return (
        op(7)
        | bitfield(3, 28, 2)
        | bitfield(0x1B, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(encoded & 0x7F, 13, 7)
        | bitfield((encoded >> 7) & 1, 27, 1)
        | bitfield((encoded >> 8) & 1, 36, 1)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def setf_sig(f1, r2, qp=0):
    return (
        op(0x6)
        | bitfield(0xE1, 27, 9)
        | bitfield(r2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def getf_sig(r1, f2, qp=0):
    return (
        op(0x4)
        | bitfield(0xE1, 27, 9)
        | bitfield(f2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def setf_d(f1, r2, qp=0):
    return (
        op(0x6)
        | bitfield(0xF9, 27, 9)
        | bitfield(r2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def getf_d(r1, f2, qp=0):
    return (
        op(0x4)
        | bitfield(0xF9, 27, 9)
        | bitfield(f2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def fnorm_d_s0(f1, f3, qp=0):
    return (
        op(0x9)
        | bitfield(1, 27, 7)
        | bitfield(f3, 20, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def fmpy_d_s0(f1, f3, f4, qp=0):
    return (
        op(0x9)
        | bitfield(f4, 27, 7)
        | bitfield(f3, 20, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def fcmp_lt_unc_s0(p1, p2, f2, f3, qp=0):
    return (
        op(0x4)
        | bitfield(1, 36, 1)
        | bitfield(1, 12, 1)
        | bitfield(f3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )


def xma_l(f1, f3, f4, f2, qp=0):
    return (
        op(0xE)
        | bitfield(1, 36, 1)
        | bitfield(f4, 27, 7)
        | bitfield(f3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def xmpy_hu(f1, f3, f4, qp=0):
    return (
        op(0xE)
        | bitfield(1, 36, 1)
        | bitfield(2, 34, 2)
        | bitfield(f4, 27, 7)
        | bitfield(f3, 20, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def fnorm(f1, f3, qp=0):
    return (
        op(0x8)
        | bitfield(1, 34, 2)
        | bitfield(1, 27, 7)
        | bitfield(f3, 20, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def frcpa(f1, p2, f3, f4, qp=0):
    return (
        bitfield(0x18, 30, 6)
        | bitfield(p2, 27, 6)
        | bitfield(f4, 20, 7)
        | bitfield(f3, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def fcvt_fxu(f1, f2, qp=0):
    return (
        bitfield(0x13, 30, 6)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def alloc(r1, sof, sol, sor, rrb, qp=0):
    return (
        op(1)
        | bitfield(6, 33, 3)
        | bitfield(rrb & 1, 32, 1)
        | bitfield(sor & 0x0f, 27, 4)
        | bitfield(sol & 0x7f, 20, 7)
        | bitfield(sof & 0x7f, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def movl_mlx(r1, imm64, qp=0):
    imm64 &= 0xFFFFFFFFFFFFFFFF
    imm7b = (imm64 >> 0) & 0x7F
    imm9d = (imm64 >> 7) & 0x1FF
    imm5c = (imm64 >> 16) & 0x1F
    ic = (imm64 >> 21) & 1
    imm41 = (imm64 >> 22) & 0x1FFFFFFFFFF
    i = (imm64 >> 63) & 1

    l_slot = imm41
    x_slot = (
        bitfield(qp, 0, 6)
        | bitfield(r1, 6, 7)
        | bitfield(imm7b, 13, 7)
        | bitfield(ic, 21, 1)
        | bitfield(imm5c, 22, 5)
        | bitfield(imm9d, 27, 9)
        | bitfield(i, 36, 1)
        | bitfield(6, 37, 4)
    )
    return (0x04, nop_m(), l_slot, x_slot)


def mov_from_cr(r1, cr_num, qp=0):
    return (
        op(1)
        | bitfield(0x24, 27, 6)
        | bitfield(cr_num & 0x7f, 20, 7)
        | bitfield(r1 & 0x7f, 6, 7)
        | bitfield(qp & 0x3f, 0, 6)
    )


def mov_to_cr(r1, cr_num, qp=0):
    return (
        op(1)
        | bitfield(0x2c, 27, 6)
        | bitfield(cr_num & 0x7f, 20, 7)
        | bitfield(r1 & 0x7f, 13, 7)
        | bitfield(qp & 0x3f, 0, 6)
    )


def mov_m_from_cr(r1, cr_num, qp=0):
    return (
        op(1)
        | bitfield(0x24, 27, 6)
        | bitfield(cr_num & 0x7f, 20, 7)
        | bitfield(r1 & 0x7f, 6, 7)
        | bitfield(qp & 0x3f, 0, 6)
    )


def bundle_words(template, slot0, slot1, slot2):
    raw = template | (slot0 << 5) | (slot1 << 46) | (slot2 << 87)
    return raw & ((1 << 64) - 1), raw >> 64


def loader_args(address, low, high):
    return [
        "-device",
        f"loader,data=0x{low:016x},data-len=8,addr={address}",
        "-device",
        f"loader,data=0x{high:016x},data-len=8,addr={address + 8}",
    ]


def data_loader_args(address, value, size):
    return [
        "-device",
        f"loader,data=0x{value:x},data-len={size},addr={address}",
    ]


def parse_registers(output):
    regs = {}
    ip_match = re.search(r"IP:\s+0x([0-9a-fA-F]+)", output)
    if ip_match:
        regs["ip"] = int(ip_match.group(1), 16)

    exception_match = re.search(
        r"exception:\s+([0-9]+)\s+fault_ip:\s+0x([0-9a-fA-F]+)\s+fault_imm:\s+0x([0-9a-fA-F]+)",
        output,
    )
    if exception_match:
        regs["exception"] = int(exception_match.group(1), 10)
        regs["fault_ip"] = int(exception_match.group(2), 16)
        regs["fault_imm"] = int(exception_match.group(3), 16)

    for reg, value in re.findall(r"\br([0-9]+)\s+0x([0-9a-fA-F]+)", output):
        regs[f"r{reg}"] = int(value, 16)
    for reg, value in re.findall(r"\bb([0-9]+):\s+0x([0-9a-fA-F]+)", output):
        regs[f"b{reg}"] = int(value, 16)
    for reg, value in re.findall(r"\bp([0-9]+):\s+([0-9]+)", output):
        regs[f"p{reg}"] = int(value, 10)
    isr_match = re.search(r"ISR:\s+0x([0-9a-fA-F]+)", output)
    if isr_match:
        regs["isr"] = int(isr_match.group(1), 16)
    return regs


def run_program(qemu, bundles, entry=0x10, delay=0.5, data=()):
    args = [
        qemu,
        "-machine",
        "ia64-vpc,alat=full",
        "-smp",
        "1",
        "-display",
        "none",
        "-serial",
        "none",
        "-monitor",
        "stdio",
    ]

    for address, template, slot0, slot1, slot2 in bundles:
        low, high = bundle_words(template, slot0, slot1, slot2)
        args += loader_args(address, low, high)

    for address, value, size in data:
        args += data_loader_args(address, value, size)

    args += ["-device", f"loader,addr={entry},cpu-num=0"]

    proc = subprocess.Popen(
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        time.sleep(delay)
        # Stop first so direct TB chaining cannot leave live CPU state cached.
        proc.stdin.write("stop\ninfo registers\nquit\n")
        proc.stdin.flush()
        output, _ = proc.communicate(timeout=4)
    except Exception:
        proc.kill()
        output, _ = proc.communicate()
        raise RuntimeError(f"qemu did not complete:\n{output}")

    if proc.returncode != 0:
        raise RuntimeError(f"qemu exited with {proc.returncode}:\n{output}")

    return parse_registers(output), output


def require_registers(qemu, name, bundles, expected, entry=0x10, data=()):
    regs, output = run_program(qemu, bundles, entry=entry, data=data)
    missing = []
    for reg, value in expected.items():
        if regs.get(reg) != value:
            actual = regs.get(reg)
            missing.append(f"{reg}: expected 0x{value:x}, got {actual!r}")
    if missing:
        raise RuntimeError(f"{name} failed: {', '.join(missing)}\n{output}")


def test_arithmetic_and_branch(qemu):
    require_registers(
        qemu,
        "arithmetic branch",
        [
            (0x10, 0x11, nop_m(), adds(1, 42, 0), br_cond(0x10, 0x20)),
            (0x20, 0x11, nop_m(), adds(2, 7, 0), br_cond(0x20, 0x20)),
        ],
        {"ip": 0x20, "r1": 42, "r2": 7},
    )


def test_addl_immediate22(qemu):
    require_registers(
        qemu,
        "addl immediate22",
        [
            (0x10, 0x00, nop_m(), addl(1, 0x12345, 0), addl(2, -4, 1)),
            (0x20, 0x11, nop_m(), addl(3, 0x1FFFF, 0, qp=1),
             br_cond(0x20, 0x20)),
        ],
        {"ip": 0x20, "r1": 0x12345, "r2": 0x12341, "r3": 0},
    )


def test_movl_mlx_predicate_source(qemu):
    tmpl1, s0_1, s1_1, s2_1 = movl_mlx(1, 0x1000)
    tmpl2, s0_2, s1_2, s2_2 = movl_mlx(14, 0xFFFFFFFFFFFFF610)
    require_registers(
        qemu,
        "movl mlx predicate source",
        [
            (0x10, tmpl1, s0_1, s1_1, s2_1),
            (0x20, tmpl2, s0_2, s1_2, s2_2),
            (0x30, 0x00, nop_m(), add(14, 1, 14), nop_i()),
            (0x40, 0x11, nop_m(), nop_i(), br_cond(0x40, 0x40)),
        ],
        {"ip": 0x40, "r14": 0x610},
    )


def test_alu_immediate_ops(qemu):
    require_registers(
        qemu,
        "alu immediate ops",
        [
            (0x10, 0x00, nop_m(), adds(1, 0x55, 0), adds(2, 0x0F, 0)),
            (0x20, 0x00, nop_m(), andcm(3, 1, 2), sub_imm(4, -2, 1)),
            (0x30, 0x00, nop_m(), and_imm(5, -16, 1), andcm_imm(6, -16, 1)),
            (0x40, 0x00, nop_m(), or_imm(7, 0x12, 1), xor_imm(8, -1, 1)),
            (0x50, 0x00, nop_m(), sub_one(10, 1, 2), shladd(11, 2, 2, 1)),
            (0x60, 0x00, nop_m(), add_one(12, 1, 2), nop_i()),
            (0x70, 0x11, nop_m(), nop_i(), br_cond(0x70, 0x70)),
        ],
        {
            "ip": 0x70,
            "r3": 0x50,
            "r4": 0xFFFFFFFFFFFFFFA9,
            "r5": 0x50,
            "r6": 0xFFFFFFFFFFFFFFA0,
            "r7": 0x57,
            "r8": 0xFFFFFFFFFFFFFFAA,
            "r10": 0x45,
            "r11": 0x91,
            "r12": 0x65,
        },
    )


def test_memory_load_store(qemu):
    require_registers(
        qemu,
        "memory load store",
        [
            (0x10, 0x00, nop_m(), adds(1, 0x80, 0), adds(2, 0x55, 0)),
            (0x20, 0x08, st8(1, 2), ld8(3, 1), adds(4, 1, 0)),
            (0x30, 0x11, nop_m(), adds(5, 5, 0), br_cond(0x30, 0x30)),
        ],
        {"ip": 0x30, "r1": 0x80, "r2": 0x55, "r3": 0x55, "r4": 1, "r5": 5},
    )


def test_fetchadd4_acq(qemu):
    require_registers(
        qemu,
        "fetchadd4.acq",
        [
            (0x10, 0x00, nop_m(), adds(1, 0x80, 0), adds(2, 0x20, 0)),
            (0x20, 0x01, st4(1, 2), nop_i(), nop_i()),
            (0x30, 0x01, fetchadd4_acq(3, 1, 1), nop_i(), nop_i()),
            (0x40, 0x11, ld4(4, 1), nop_i(), br_cond(0x40, 0x40)),
        ],
        {"ip": 0x40, "r3": 0x20, "r4": 0x21},
    )


def test_store_post_increment(qemu):
    require_registers(
        qemu,
        "store post-increment",
        [
            (0x10, 0x00, nop_m(), addl(15, 0x200, 0), adds(16, 0x55, 0)),
            (0x20, 0x08, st8_post_imm(15, 16, 40), addl(19, 0x200, 0), nop_i()),
            (0x30, 0x11, ld8(18, 19), nop_i(), br_cond(0x30, 0x30)),
        ],
        {"ip": 0x30, "r15": 0x228, "r18": 0x55},
    )


def test_ld8_fill_nta_post_increment(qemu):
    value = 0x1122334455667788
    require_registers(
        qemu,
        "ld8.fill.nta post-increment",
        [
            (0x10, 0x00, nop_m(), addl(16, 0x200, 0), nop_i()),
            (0x20, 0x08, ld8_fill_nta_post(1, 16, 8), addl(17, 0x200, 0), nop_i()),
            (0x30, 0x08, ld8_fill_nta(2, 17), nop_m(), nop_i()),
            (0x40, 0x11, nop_m(), nop_i(), br_cond(0x40, 0x40)),
        ],
        {"ip": 0x40, "r1": value, "r2": value, "r16": 0x208},
        data=[(0x200, value, 8)],
    )


def test_narrow_memory_load_store(qemu):
    require_registers(
        qemu,
        "narrow memory load store",
        [
            (0x10, 0x00, nop_m(), adds(1, 0x100, 0), adds(5, 0x120, 0)),
            (0x20, 0x00, nop_m(), adds(6, 0x121, 0), adds(7, 0x128, 0)),
            (0x30, 0x08, ld1(2, 1), ld2(3, 1), nop_i()),
            (0x40, 0x08, ld4(4, 1), nop_m(), nop_i()),
            (0x50, 0x08, st1(5, 4), st2(6, 4), nop_i()),
            (0x60, 0x08, st4(7, 4), ld1(9, 5), nop_i()),
            (0x70, 0x08, ld2(10, 6), ld4(11, 7), nop_i()),
            (0x80, 0x11, nop_m(), adds(12, 7, 0), br_cond(0x80, 0x80)),
        ],
        {
            "ip": 0x80,
            "r2": 0x34,
            "r3": 0x1234,
            "r4": 0xEEFF1234,
            "r9": 0x34,
            "r10": 0x1234,
            "r11": 0xEEFF1234,
            "r12": 7,
        },
        data=[(0x100, 0xAABBCCDDEEFF1234, 8)],
    )


def test_predication(qemu):
    require_registers(
        qemu,
        "predication",
        [
            (0x10, 0x00, nop_m(), adds(1, 5, 0), adds(2, 5, 0)),
            (0x20, 0x00, nop_m(), cmp_eq(1, 2, 1, 2), adds(3, 9, 0, qp=1)),
            (0x30, 0x11, nop_m(), adds(4, 7, 0, qp=2), br_cond(0x30, 0x30)),
        ],
        {"ip": 0x30, "r3": 9, "r4": 0, "p1": 1, "p2": 0},
    )


def test_cmp4_eq_imm_predication(qemu):
    require_registers(
        qemu,
        "cmp4.eq immediate predication",
        [
            (0x10, 0x00, nop_m(), adds(14, 13, 0), nop_i()),
            (0x20, 0x00, nop_m(), cmp4_eq_imm(6, 7, 0, 14), nop_i()),
            (0x30, 0x00, nop_m(), adds(1, 1, 0, qp=6), adds(2, 2, 0, qp=7)),
            (0x40, 0x11, nop_m(), nop_i(), br_cond(0x40, 0x40)),
        ],
        {"ip": 0x40, "r1": 0, "r2": 2},
    )


def test_cmp_ltu_immediate(qemu):
    require_registers(
        qemu,
        "cmp register and immediate",
        [
            (0x10, 0x00, nop_m(), adds(14, 0x100, 0), cmp_ltu_imm(6, 7, 63, 14)),
            (0x20, 0x00, nop_m(), adds(1, 1, 0, qp=6), adds(2, 2, 0, qp=7)),
            (0x30, 0x00, nop_m(), adds(15, 0x20, 0), cmp_ltu(8, 9, 14, 15)),
            (0x40, 0x00, nop_m(), adds(3, 3, 0, qp=8), adds(4, 4, 0, qp=9)),
            (0x50, 0x00, nop_m(), adds(16, -1, 0), cmp_lt(10, 11, 16, 0)),
            (0x60, 0x00, nop_m(), adds(5, 5, 0, qp=10), adds(6, 6, 0, qp=11)),
            (0x70, 0x00, nop_m(), adds(18, 32, 0), cmp_lt_imm(12, 13, 16, 18)),
            (0x80, 0x00, nop_m(), adds(7, 7, 0, qp=12), cmp4_lt_imm(14, 15, -1, 0)),
            (0x90, 0x00, nop_m(), adds(8, 8, 0, qp=14), adds(9, 9, 0, qp=15)),
            (0xA0, 0x00, adds(20, 0xE4, 0), cmp4_ltu_imm(16, 17, 25, 20), nop_i()),
            (0xB0, 0x00, nop_m(), adds(10, 10, 0, qp=16), adds(11, 11, 0, qp=17)),
            (0xC0, 0x11, nop_m(), nop_i(), br_cond(0xC0, 0xC0)),
        ],
        {
            "ip": 0xC0,
            "r1": 1,
            "r2": 0,
            "r3": 0,
            "r4": 4,
            "r5": 5,
            "r6": 0,
            "r7": 7,
            "r8": 8,
            "r9": 0,
            "r10": 10,
            "r11": 0,
        },
    )


def test_cmp_eq_or_andcm(qemu):
    require_registers(
        qemu,
        "cmp.eq.or.andcm",
        [
            (0x10, 0x00, nop_m(), cmp_eq_imm(6, 7, 0, 0), nop_i()),
            (0x20, 0x00, nop_m(), adds(14, 5, 0), adds(15, 5, 0)),
            (0x30, 0x00, nop_m(), cmp_eq_or_andcm(7, 6, 14, 15), nop_i()),
            (0x40, 0x00, nop_m(), adds(1, 1, 0, qp=7), adds(2, 2, 0, qp=6)),
            (0x50, 0x00, nop_m(), cmp_eq_imm(7, 6, 0, 0), nop_i()),
            (0x60, 0x00, nop_m(), adds(16, 1, 0), cmp_ne_or_andcm_imm(6, 7, 0, 16)),
            (0x70, 0x00, nop_m(), adds(3, 3, 0, qp=6), adds(4, 4, 0, qp=7)),
            (0x80, 0x00, nop_m(), adds(17, 0, 0), cmp_eq_or_andcm_imm(6, 7, 0, 17)),
            (0x90, 0x00, nop_m(), adds(5, 5, 0, qp=6), adds(6, 6, 0, qp=7)),
            (0xA0, 0x11, nop_m(), nop_i(), br_cond(0xA0, 0xA0)),
        ],
        {"ip": 0xA0, "r1": 1, "r2": 0, "r3": 3, "r4": 0, "r5": 5, "r6": 0},
    )


def test_cmp_or_register(qemu):
    require_registers(
        qemu,
        "cmp.or register",
        [
            (0x10, 0x00, nop_m(), adds(23, 1, 0), nop_i()),
            (0x20, 0x00, nop_m(), cmp_ne_or(18, 0, 0, 23), nop_i()),
            (0x30, 0x00, nop_m(), cmp_eq_or(19, 20, 0, 23), nop_i()),
            (0x40, 0x00, nop_m(), adds(1, 1, 0, qp=18),
             adds(2, 2, 0, qp=19)),
            (0x50, 0x00, nop_m(), adds(3, 3, 0, qp=20), nop_i()),
            (0x60, 0x11, nop_m(), nop_i(), br_cond(0x60, 0x60)),
        ],
        {"ip": 0x60, "r1": 1, "r2": 0, "r3": 3},
    )


def test_cmp4_ne_or_andcm_immediate(qemu):
    tmpl, s0, s1, s2 = movl_mlx(14, 0x100000001)
    require_registers(
        qemu,
        "cmp4.ne.or.andcm immediate",
        [
            (0x10, 0x00, nop_m(), cmp_eq_imm(6, 7, 0, 0), nop_i()),
            (0x20, tmpl, s0, s1, s2),
            (0x30, 0x00, nop_m(), cmp4_ne_or_andcm_imm(6, 7, 1, 14), nop_i()),
            (0x40, 0x00, nop_m(), adds(1, 1, 0, qp=6), adds(2, 2, 0, qp=7)),
            (0x50, 0x00, nop_m(), adds(15, 2, 0), cmp4_ne_or_andcm_imm(8, 9, 1, 15)),
            (0x60, 0x00, nop_m(), adds(3, 3, 0, qp=8), adds(4, 4, 0, qp=9)),
            (0x70, 0x11, nop_m(), nop_i(), br_cond(0x70, 0x70)),
        ],
        {"ip": 0x70, "r1": 1, "r2": 0, "r3": 3, "r4": 0},
    )


def test_cmp4_eq_or_andcm_immediate(qemu):
    require_registers(
        qemu,
        "cmp4.eq.or.andcm immediate",
        [
            (0x10, 0x00, adds(14, 0, 0), cmp_eq_imm(7, 6, 0, 0), nop_i()),
            (0x20, 0x00, nop_m(), cmp4_eq_or_andcm_imm(6, 7, 0, 14), nop_i()),
            (0x30, 0x00, nop_m(), adds(1, 1, 0, qp=6), adds(2, 2, 0, qp=7)),
            (0x40, 0x00, adds(15, 1, 0), cmp_eq_imm(9, 8, 0, 0), nop_i()),
            (0x50, 0x00, nop_m(), cmp4_eq_or_andcm_imm(8, 9, 0, 15), nop_i()),
            (0x60, 0x00, nop_m(), adds(3, 3, 0, qp=8), adds(4, 4, 0, qp=9)),
            (0x70, 0x11, nop_m(), nop_i(), br_cond(0x70, 0x70)),
        ],
        {"ip": 0x70, "r1": 1, "r2": 0, "r3": 0, "r4": 4},
    )


def test_cmp4_eq_or_andcm_register(qemu):
    tmpl, s0, s1, s2 = movl_mlx(14, 0x10000008B)
    require_registers(
        qemu,
        "cmp4.eq.or.andcm register",
        [
            (0x10, tmpl, s0, s1, s2),
            (0x20, 0x00, adds(15, 0x8B, 0), cmp_eq_imm(7, 6, 0, 0), nop_i()),
            (0x30, 0x00, nop_m(), cmp4_eq_or_andcm(6, 7, 14, 15), nop_i()),
            (0x40, 0x00, nop_m(), adds(1, 1, 0, qp=6), adds(2, 2, 0, qp=7)),
            (0x50, 0x00, adds(16, 0x8C, 0), cmp_eq_imm(9, 8, 0, 0), nop_i()),
            (0x60, 0x00, nop_m(), cmp4_eq_or_andcm(8, 9, 14, 16), nop_i()),
            (0x70, 0x00, nop_m(), adds(3, 3, 0, qp=8), adds(4, 4, 0, qp=9)),
            (0x80, 0x11, nop_m(), nop_i(), br_cond(0x80, 0x80)),
        ],
        {"ip": 0x80, "r1": 1, "r2": 0, "r3": 0, "r4": 4},
    )


def test_cmp4_register_and_tbit_predication(qemu):
    require_registers(
        qemu,
        "cmp4 register and tbit predication",
        [
            (0x10, 0x00, adds(16, -1, 0), cmp4_lt(6, 7, 16, 0), adds(1, 0x11, 0, qp=6)),
            (0x20, 0x00, adds(14, 0x58, 0), tbit_z(7, 6, 14, 3), adds(2, 0x22, 0, qp=6)),
            (0x30, 0x00, nop_m(), cmp4_eq(10, 11, 14, 14), adds(3, 0x33, 0, qp=10)),
            (0x40, 0x00, nop_m(), cmp4_ltu(8, 9, 0, 14), adds(4, 0x44, 0, qp=8)),
            (0x50, 0x11, nop_m(), nop_i(), br_cond(0x50, 0x50)),
        ],
        {"ip": 0x50, "r1": 0x11, "r2": 0x22, "r3": 0x33, "r4": 0x44},
    )


def test_cmp_le_or_andcm_zero_uses_64bit_relation(qemu):
    tmpl, s0, s1, s2 = movl_mlx(31, 0x000000009DEA862C)
    require_registers(
        qemu,
        "cmp.le.or.andcm zero uses 64-bit relation",
        [
            (0x10, tmpl, s0, s1, s2),
            (0x20, 0x00, nop_m(), cmp_eq_imm(0, 11, 1, 0), nop_i()),
            (0x30, 0x00, nop_m(), cmp_le_or_andcm_zero(0, 11, 31), nop_i()),
            (0x40, 0x00, nop_m(), adds(1, 0x11, 0, qp=11), nop_i()),
            (0x50, 0x11, nop_m(), nop_i(), br_cond(0x50, 0x50)),
        ],
        {"ip": 0x50, "r1": 0},
    )


def test_tbit_z_or_andcm(qemu):
    require_registers(
        qemu,
        "tbit.z.or.andcm",
        [
            (0x10, 0x00, adds(8, 2, 0), cmp_eq_imm(7, 6, 0, 0), nop_i()),
            (0x20, 0x00, nop_m(), tbit_z_or_andcm(6, 7, 8, 1), nop_i()),
            (0x30, 0x00, nop_m(), adds(1, 0x11, 0, qp=7), adds(2, 0x22, 0, qp=6)),
            (0x40, 0x00, adds(8, 0, 0), cmp_eq_imm(9, 8, 0, 0), nop_i()),
            (0x50, 0x00, nop_m(), tbit_z_or_andcm(8, 9, 8, 1), nop_i()),
            (0x60, 0x00, nop_m(), adds(3, 0x33, 0, qp=8), adds(4, 0x44, 0, qp=9)),
            (0x70, 0x11, nop_m(), nop_i(), br_cond(0x70, 0x70)),
        ],
        {"ip": 0x70, "r1": 0x11, "r2": 0, "r3": 0x33, "r4": 0},
    )


def test_tnat_nz_and(qemu):
    require_registers(
        qemu,
        "tnat.nz.and",
        [
            (0x10, 0x00, adds(14, 0, 0), cmp_eq_imm(7, 6, 0, 0), nop_i()),
            (0x20, 0x00, nop_m(), tnat_nz_and(7, 0, 14), adds(1, 0x11, 0, qp=7)),
            (0x30, 0x11, nop_m(), nop_i(), br_cond(0x30, 0x30)),
        ],
        {"ip": 0x30, "r1": 0, "p7": 0},
    )


def test_mux1_brcst(qemu):
    require_registers(
        qemu,
        "mux1 brcst",
        [
            (0x10, 0x00, nop_m(), adds(14, 0x5A, 0), mux1_brcst(1, 14)),
            (0x20, 0x11, nop_m(), nop_i(), br_cond(0x20, 0x20)),
        ],
        {"ip": 0x20, "r1": 0x5A5A5A5A5A5A5A5A},
    )


def test_extract_immediate(qemu):
    tmpl, s0, s1, s2 = movl_mlx(14, 0x00500000)
    require_registers(
        qemu,
        "extract immediate",
        [
            (0x10, tmpl, s0, s1, s2),
            (0x20, 0x00, nop_m(), extr(1, 14, 20, 4), extr(2, 14, 0, 64)),
            (0x30, 0x00, adds(15, -1, 0), extr(3, 15, 0, 4), extr(4, 15, 0, 4, signed=True)),
            (0x40, 0x11, nop_m(), nop_i(), br_cond(0x40, 0x40)),
        ],
        {
            "ip": 0x40,
            "r1": 5,
            "r2": 0x00500000,
            "r3": 0xF,
            "r4": 0xFFFFFFFFFFFFFFFF,
        },
    )


def test_deposit_immediate(qemu):
    tmpl, s0, s1, s2 = movl_mlx(14, 0x123456789ABCDEF0)
    require_registers(
        qemu,
        "deposit immediate",
        [
            (0x10, tmpl, s0, s1, s2),
            (0x20, 0x00, nop_m(), dep_imm(1, 1, 14, 3, 6), dep_imm(2, 0, 14, 7, 8)),
            (0x30, 0x11, nop_m(), nop_i(), br_cond(0x30, 0x30)),
        ],
        {
            "ip": 0x30,
            "r1": 0x123456789ABCDFF8,
            "r2": 0x123456789ABC8070,
        },
    )


def test_register_shifts(qemu):
    tmpl, s0, s1, s2 = movl_mlx(14, 0x8000000000000000)
    require_registers(
        qemu,
        "register shifts",
        [
            (0x10, tmpl, s0, s1, s2),
            (0x20, 0x00, nop_m(), adds(15, 3, 0), adds(16, 4, 0)),
            (0x30, 0x00, nop_m(), shl_reg(1, 15, 16), adds(19, 63, 0)),
            (0x40, 0x00, nop_m(), shru_reg(2, 14, 19), adds(18, -16, 0)),
            (0x50, 0x00, nop_m(), shr_reg(3, 18, 15), nop_i()),
            (0x60, 0x11, nop_m(), nop_i(), br_cond(0x60, 0x60)),
        ],
        {
            "ip": 0x60,
            "r1": 48,
            "r2": 1,
            "r3": 0xFFFFFFFFFFFFFFFE,
        },
    )


def test_register_shift_large_counts(qemu):
    tmpl, s0, s1, s2 = movl_mlx(14, 0xFFFFFFFFFFFFFFFF)
    require_registers(
        qemu,
        "register shift large counts",
        [
            (0x10, tmpl, s0, s1, s2),
            (0x20, 0x00, nop_m(), adds(15, 64, 0), adds(16, 1, 0)),
            (0x30, 0x00, nop_m(), adds(17, -16, 0), shru_reg(1, 14, 15)),
            (0x40, 0x00, nop_m(), shl_reg(2, 16, 15), shr_reg(3, 17, 15)),
            (0x50, 0x00, nop_m(), shr_reg(4, 16, 15), nop_i()),
            (0x60, 0x11, nop_m(), nop_i(), br_cond(0x60, 0x60)),
        ],
        {
            "ip": 0x60,
            "r1": 0,
            "r2": 0,
            "r3": 0xFFFFFFFFFFFFFFFF,
            "r4": 0,
        },
    )


def test_shrp_immediate(qemu):
    tmpl1, s0_1, s1_1, s2_1 = movl_mlx(14, 0x0123456789ABCDEF)
    tmpl2, s0_2, s1_2, s2_2 = movl_mlx(15, 0xF)
    require_registers(
        qemu,
        "shrp immediate",
        [
            (0x10, tmpl1, s0_1, s1_1, s2_1),
            (0x20, tmpl2, s0_2, s1_2, s2_2),
            (0x30, 0x00, nop_m(), shrp_imm(1, 14, 15, 4), shrp_imm(2, 14, 15, 0)),
            (0x40, 0x11, nop_m(), nop_i(), br_cond(0x40, 0x40)),
        ],
        {
            "ip": 0x40,
            "r1": 0xF000000000000000,
            "r2": 0xF,
        },
    )


def test_call_and_return(qemu):
    require_registers(
        qemu,
        "call return",
        [
            (0x10, 0x11, nop_m(), adds(1, 1, 0), br_call(0, 0x10, 0x30)),
            (0x20, 0x11, nop_m(), adds(3, 3, 0), br_cond(0x20, 0x20)),
            (0x30, 0x11, nop_m(), adds(2, 2, 0), br_ret(0)),
        ],
        {"ip": 0x20, "r1": 1, "r2": 2, "r3": 3, "b0": 0x20},
    )


def test_call_many_and_return(qemu):
    require_registers(
        qemu,
        "call.many return",
        [
            (0x10, 0x11, nop_m(), adds(1, 1, 0), br_call_many(0, 0x10, 0x30)),
            (0x20, 0x11, nop_m(), adds(3, 3, 0), br_cond(0x20, 0x20)),
            (0x30, 0x11, nop_m(), adds(2, 2, 0), br_ret(0)),
        ],
        {"ip": 0x20, "r1": 1, "r2": 2, "r3": 3, "b0": 0x20},
    )


def test_indirect_call_and_return(qemu):
    require_registers(
        qemu,
        "indirect call return",
        [
            (0x10, 0x00, nop_m(), adds(14, 0x40, 0), mov_grbr(6, 14)),
            (0x20, 0x11, nop_m(), nop_i(), br_call_indirect(0, 6)),
            (0x30, 0x11, nop_m(), nop_i(), br_cond(0x30, 0x30)),
            (0x40, 0x11, nop_m(), adds(1, 7, 0), br_ret(0)),
        ],
        {"ip": 0x30, "r1": 7, "b0": 0x30},
    )


def test_indirect_call_through_return_register(qemu):
    require_registers(
        qemu,
        "indirect call through return register",
        [
            (0x10, 0x00, nop_m(), adds(14, 0x40, 0), mov_grbr(0, 14)),
            (0x20, 0x11, nop_m(), nop_i(), br_call_indirect(0, 0)),
            (0x30, 0x11, nop_m(), nop_i(), br_cond(0x30, 0x30)),
            (0x40, 0x11, nop_m(), adds(1, 9, 0), br_ret(0)),
        ],
        {"ip": 0x30, "r1": 9, "b0": 0x30},
    )


def test_indirect_call_masks_target_low_bits(qemu):
    require_registers(
        qemu,
        "indirect call masks target low bits",
        [
            (0x10, 0x00, nop_m(), adds(14, 0x41, 0), mov_grbr(6, 14)),
            (0x20, 0x11, nop_m(), nop_i(), br_call_indirect(0, 6)),
            (0x30, 0x11, nop_m(), nop_i(), br_cond(0x30, 0x30)),
            (0x40, 0x11, nop_m(), adds(1, 7, 0), br_ret(0)),
        ],
        {"ip": 0x30, "r1": 7, "b0": 0x30},
    )


def test_return_masks_target_low_bits(qemu):
    require_registers(
        qemu,
        "return masks target low bits",
        [
            (0x10, 0x00, nop_m(), adds(14, 0x41, 0), mov_grbr(0, 14)),
            (0x20, 0x11, nop_m(), nop_i(), br_ret(0)),
            (0x30, 0x11, nop_m(), nop_i(), br_cond(0x30, 0x30)),
            (0x40, 0x11, nop_m(), adds(1, 7, 0), br_cond(0x40, 0x40)),
        ],
        {"ip": 0x40, "r1": 7},
    )


def test_mov_grbr_sptk_hint_updates_branch_register(qemu):
    require_registers(
        qemu,
        "mov.sptk b=gr updates branch register",
        [
            (0x10, *movl_mlx(14, 0x40)),
            (0x20, 0x01, nop_m(), mov_grbr_sptk(0, 14), adds(1, 1, 0)),
            (0x30, 0x11, nop_m(), nop_i(), br_ret(0)),
            (0x40, 0x11, nop_m(), adds(2, 2, 0), br_cond(0x40, 0x40)),
        ],
        {"ip": 0x40, "exception": 0, "b0": 0x40, "r1": 1, "r2": 2},
    )


def test_m_unit_x3_7_decodes_chk_a_fp(qemu):
    require_registers(
        qemu,
        "M-unit opcode 0 x3=7 remains chk.a",
        [
            (0x10, 0x09, chk_a_clr_fp(16, 0x10, 0x30), nop_m(), nop_i()),
            (0x20, 0x11, nop_m(), adds(1, 0x11, 0), br_cond(0x20, 0x20)),
            (0x30, 0x11, nop_m(), adds(1, 0x33, 0), br_cond(0x30, 0x30)),
        ],
        {"ip": 0x30, "exception": 0, "r1": 0x33},
    )


def test_indirect_branch(qemu):
    require_registers(
        qemu,
        "indirect branch",
        [
            (0x10, 0x00, nop_m(), adds(14, 0x30, 0), mov_grbr(6, 14)),
            (0x20, 0x11, nop_m(), nop_i(), br_indirect(6)),
            (0x30, 0x11, nop_m(), adds(1, 3, 0), br_cond(0x30, 0x30)),
        ],
        {"ip": 0x30, "r1": 3},
    )


def test_mov_current_ip(qemu):
    require_registers(
        qemu,
        "mov current ip",
        [
            (0x10, 0x00, nop_m(), mov_ip(1), mov_ip(2)),
            (0x20, 0x11, nop_m(), nop_i(), br_cond(0x20, 0x20)),
        ],
        {"ip": 0x20, "r1": 0x10, "r2": 0x10},
    )


def test_iip_control_register_roundtrip(qemu):
    require_registers(
        qemu,
        "iip control-register roundtrip",
        [
            (0x10, 0x00, nop_m(), adds(3, 0x70, 0), nop_i()),
            # CR19 is IIP.  This exercises mov cr=gr/mov gr=cr; mov r=ip
            # current-IP capture is covered by test_mov_current_ip above.
            (0x20, 0x00, mov_to_cr(3, 19), nop_i(), nop_i()),
            (0x30, 0x00, mov_from_cr(1, 19), nop_i(), nop_i()),
            (0x40, 0x11, nop_m(), nop_i(), br_cond(0x40, 0x40)),
        ],
        {"ip": 0x40, "r1": 0x70},
    )


def test_br_many(qemu):
    require_registers(
        qemu,
        "br.many",
        [
            (0x10, 0x11, nop_m(), adds(1, 1, 0), br_many(0x10, 0x30)),
            (0x20, 0x11, nop_m(), adds(2, 2, 0), br_cond(0x20, 0x20)),
            (0x30, 0x11, nop_m(), adds(3, 3, 0), br_cond(0x30, 0x30)),
        ],
        {"ip": 0x30, "r1": 1, "r2": 0, "r3": 3},
    )


def test_brp_loop_imp(qemu):
    require_registers(
        qemu,
        "brp.loop.imp",
        [
            (0x10, 0x11, nop_m(), adds(1, 1, 0), brp_loop_imp()),
            (0x20, 0x11, nop_m(), nop_i(), br_cond(0x20, 0x20)),
        ],
        {"ip": 0x20, "r1": 1},
    )


def test_brp_sptk_windows(qemu):
    require_registers(
        qemu,
        "brp.sptk windows",
        [
            (0x10, 0x11, nop_m(), adds(1, 1, 0), brp_sptk_windows()),
            (0x20, 0x11, nop_m(), nop_i(), br_cond(0x20, 0x20)),
        ],
        {"ip": 0x20, "r1": 1},
    )


def test_predicate_register_moves(qemu):
    require_registers(
        qemu,
        "predicate register moves",
        [
            (0x10, 0x00, nop_m(), adds(1, 0xA, 0), mov_grpr(1, 0xE)),
            (0x20, 0x00, nop_m(), adds(2, 5, 0, qp=2), adds(3, 7, 0, qp=3)),
            (0x30, 0x00, nop_m(), mov_prgr(4), mov_grpr(4, -2)),
            (0x40, 0x00, nop_m(), adds(5, 9, 0, qp=1), adds(6, 9, 0, qp=2)),
            (0x50, 0x11, nop_m(), nop_i(), br_cond(0x50, 0x50)),
        ],
        {"ip": 0x50, "r2": 0, "r3": 7, "r4": 0xB, "r5": 9, "r6": 0},
    )


def test_predicate_rot_immediate(qemu):
    require_registers(
        qemu,
        "predicate rotating immediate",
        [
            (0x10, 0x00, nop_m(), mov_pr_rot_imm(0x10000), nop_i()),
            (0x20, 0x00, nop_m(), adds(1, 1, 0, qp=16), adds(2, 2, 0, qp=17)),
            (0x30, 0x00, nop_m(), mov_pr_rot_imm(0x20000), nop_i()),
            (0x40, 0x00, nop_m(), adds(3, 3, 0, qp=16), adds(4, 4, 0, qp=17)),
            (0x50, 0x11, nop_m(), nop_i(), br_cond(0x50, 0x50)),
        ],
        {"ip": 0x50, "r1": 1, "r2": 0, "r3": 0, "r4": 4},
    )


def test_mov_m_application_register(qemu):
    require_registers(
        qemu,
        "mov.m application register",
        [
            (0x10, 0x08, adds(14, 0x5A, 0), mov_m_grar(36, 14), nop_i()),
            (0x20, 0x08, mov_m_argr(1, 36), nop_m(), nop_i()),
            (0x30, 0x11, nop_m(), nop_i(), br_cond(0x30, 0x30)),
        ],
        {"ip": 0x30, "r1": 0x5A},
    )


def test_mov_i_application_register_and_cloop(qemu):
    require_registers(
        qemu,
        "mov.i application register and br.cloop",
        [
            (0x10, 0x00, nop_m(), adds(14, 3, 0), mov_i_grar(65, 14)),
            (0x20, 0x00, nop_m(), adds(1, 1, 1), nop_i()),
            (0x30, 0x11, nop_m(), nop_i(), br_cloop(0x30, 0x20)),
            (0x40, 0x11, nop_m(), mov_i_argr(2, 65), br_cond(0x40, 0x40)),
        ],
        {"ip": 0x40, "r1": 4, "r2": 0},
    )


def test_self_cloop_store_post_increment(qemu):
    require_registers(
        qemu,
        "self br.cloop store post-increment",
        [
            (0x10, 0x00, nop_m(), adds(14, 5000, 0), mov_i_grar(65, 14)),
            (0x20, 0x00, nop_m(), addl(15, 0x200, 0), adds(16, 0x5A, 0)),
            (0x30, 0x11, st1_post_imm(15, 16, 1), nop_i(),
             br_cloop(0x30, 0x30)),
            (0x40, 0x00, nop_m(), addl(19, 0x200, 0), adds(20, -1, 15)),
            (0x50, 0x08, ld8(18, 19), ld1(21, 20), nop_i()),
            (0x60, 0x11, nop_m(), mov_i_argr(2, 65),
             br_cond(0x60, 0x60)),
        ],
        {
            "ip": 0x60,
            "r2": 0,
            "r15": 0x200 + 5001,
            "r18": 0x5A5A5A5A5A5A5A5A,
            "r21": 0x5A,
        },
    )


def test_self_cloop_zero_st1_release(qemu):
    count = 70000
    start = 0x200

    require_registers(
        qemu,
        "self br.cloop st1.rel zero post-increment",
        [
            (0x10, 0x00, nop_m(), addl(14, count, 0), mov_i_grar(65, 14)),
            (0x20, 0x00, nop_m(), addl(15, start, 0), nop_i()),
            (0x30, 0x11, st1_rel_post_imm(15, 0, 1), nop_i(),
             br_cloop(0x30, 0x30)),
            (0x40, 0x00, nop_m(), addl(19, start, 0),
             addl(20, start + count, 0)),
            (0x50, 0x08, ld1(18, 19), ld1(21, 20),
             addl(22, start + count + 1, 0)),
            (0x60, 0x08, ld1(23, 22), nop_m(), nop_i()),
            (0x70, 0x11, nop_m(), mov_i_argr(2, 65),
             br_cond(0x70, 0x70)),
        ],
        {
            "ip": 0x70,
            "r2": 0,
            "r15": start + count + 1,
            "r18": 0,
            "r21": 0,
            "r23": 0xEE,
        },
        data=[
            (start, 0xFF, 1),
            (start + count, 0xDD, 1),
            (start + count + 1, 0xEE, 1),
        ],
    )


def test_float_spill_fill(qemu):
    require_registers(
        qemu,
        "stf.spill and ldf.fill",
        [
            (0x10, 0x00, nop_m(), addl(16, 0x100, 0), addl(18, 0x110, 0)),
            (0x20, 0x00, nop_m(), adds(1, 0x35, 0), nop_i()),
            (0x30, 0x09, setf_sig(2, 1), nop_m(), nop_i()),
            (0x40, 0x09, stf_spill(16, 2), stf8(18, 2), nop_i()),
            (0x50, 0x09, ldf_fill(3, 16), nop_m(), nop_i()),
            (0x60, 0x09, nop_m(), getf_sig(2, 3), addl(17, 0x108, 0)),
            (0x70, 0x08, ld8(4, 17), ld8(5, 18), nop_i()),
            (0x80, 0x11, nop_m(), nop_i(), br_cond(0x80, 0x80)),
        ],
        {"ip": 0x80, "r2": 0x35, "r4": 0x1003e, "r5": 0x35},
    )


def test_float_f0_immutable(qemu):
    require_registers(
        qemu,
        "f0 immutable",
        [
            (0x10, 0x00, nop_m(), addl(16, 0x100, 0), addl(17, 0x108, 0)),
            (0x20, 0x00, nop_m(), adds(1, 0x35, 0), nop_i()),
            (0x30, 0x09, setf_sig(0, 1), nop_m(), nop_i()),
            (0x40, 0x09, getf_sig(2, 0), stf_spill(16, 0), nop_i()),
            (0x50, 0x08, ld8(4, 16), ld8(5, 17), nop_i()),
            (0x60, 0x11, nop_m(), nop_i(), br_cond(0x60, 0x60)),
        ],
        {"ip": 0x60, "r2": 0, "r4": 0, "r5": 0},
    )


def test_ldf_fill_post_increment(qemu):
    require_registers(
        qemu,
        "ldf.fill post-increment",
        [
            (0x10, 0x00, nop_m(), addl(16, 0x100, 0), nop_i()),
            (0x20, 0x00, nop_m(), adds(1, 0x35, 0), nop_i()),
            (0x30, 0x09, setf_sig(2, 1), nop_m(), nop_i()),
            (0x40, 0x09, stf_spill(16, 2), nop_m(), nop_i()),
            (0x50, 0x09, ldf_fill_post(3, 16, 32), nop_m(), nop_i()),
            (0x60, 0x09, nop_m(), getf_sig(2, 3), nop_i()),
            (0x70, 0x11, nop_m(), nop_i(), br_cond(0x70, 0x70)),
        ],
        {"ip": 0x70, "r2": 0x35, "r16": 0x120},
    )


def test_ldf_fill_nta_post_increment(qemu):
    require_registers(
        qemu,
        "ldf.fill.nta post-increment",
        [
            (0x10, 0x00, nop_m(), addl(16, 0x100, 0), nop_i()),
            (0x20, 0x00, nop_m(), adds(1, 0x35, 0), nop_i()),
            (0x30, 0x09, setf_sig(2, 1), nop_m(), nop_i()),
            (0x40, 0x09, stf_spill(16, 2), nop_m(), nop_i()),
            (0x50, 0x09, ldf_fill_nta_post(3, 16, 32), nop_m(), nop_i()),
            (0x60, 0x09, nop_m(), getf_sig(2, 3), nop_i()),
            (0x70, 0x11, nop_m(), nop_i(), br_cond(0x70, 0x70)),
        ],
        {"ip": 0x70, "r2": 0x35, "r16": 0x120},
    )


def test_stf_spill_nta_post_increment(qemu):
    require_registers(
        qemu,
        "stf.spill.nta post-increment",
        [
            (0x10, 0x00, nop_m(), addl(16, 0x120, 0), adds(1, 0x42, 0)),
            (0x20, 0x09, setf_sig(2, 1), stf_spill_nta_post(16, 2, 32), nop_i()),
            (0x30, 0x00, addl(17, 0x128, 0), addl(18, 0x150, 0), nop_i()),
            (0x40, 0x08, ld8(3, 17), nop_m(), nop_i()),
            (0x50, 0x09, stf_spill_nta(18, 2), nop_m(), nop_i()),
            (0x60, 0x11, nop_m(), nop_i(), br_cond(0x60, 0x60)),
        ],
        {"ip": 0x60, "r3": 0x1003e, "r16": 0x140, "r18": 0x150},
    )


def test_xmpy_hu(qemu):
    tmpl, s0, s1, s2 = movl_mlx(1, 0x8000000000000000)
    require_registers(
        qemu,
        "xmpy.hu",
        [
            (0x10, tmpl, s0, s1, s2),
            (0x20, 0x00, nop_m(), adds(2, 2, 0), nop_i()),
            (0x30, 0x09, setf_sig(9, 1), setf_sig(2, 2), nop_i()),
            (0x40, 0x1D, nop_m(), xmpy_hu(8, 9, 2), nop_b()),
            (0x50, 0x09, getf_sig(4, 8), nop_m(), nop_i()),
            (0x60, 0x11, nop_m(), nop_i(), br_cond(0x60, 0x60)),
        ],
        {"ip": 0x60, "r4": 1},
    )


def test_setf_sig_xma_frcpa_predicate(qemu):
    tmpl, s0, s1, s2 = movl_mlx(1, 7)
    require_registers(
        qemu,
        "setf/getf sig, xma.l, and frcpa predicate",
        [
            (0x10, tmpl, s0, s1, s2),
            (0x20, 0x09, setf_sig(8, 1), nop_m(), nop_i()),
            (0x30, 0x00, nop_m(), adds(2, 3, 0), adds(3, 5, 0)),
            (0x40, 0x09, setf_sig(10, 2), setf_sig(9, 3), nop_i()),
            (0x50, 0x1d, nop_m(), xma_l(11, 10, 9, 8), nop_b()),
            (0x60, 0x09, getf_sig(4, 11), nop_m(), nop_i()),
            (0x70, 0x09, setf_sig(14, 0), nop_m(), nop_i()),
            (0x80, 0x0d, nop_m(), fnorm(12, 14), nop_i()),
            (0x90, 0x09, getf_sig(5, 12), nop_m(), nop_i()),
            # r6 observes frcpa's predicate result: frcpa sets p6 for a
            # usable approximation, then the predicated adds copies 6 to r6.
            (0xA0, 0x0d, nop_m(), frcpa(10, 6, 8, 9), nop_i()),
            (0xB0, 0x00, nop_m(), adds(6, 6, 0, qp=6), nop_i()),
            # fcvt.fxu is retained as no-fault coverage here. Its setf.sig
            # payload behavior is asserted directly in test-ia64-qemu-tcg-2.
            (0xC0, 0x0d, nop_m(), fcvt_fxu(11, 10), nop_i()),
            (0xD0, 0x11, nop_m(), nop_i(), br_cond(0xD0, 0xD0)),
        ],
        {"ip": 0xD0, "r4": 22, "r5": 0, "r6": 6},
    )


def test_windows_fp_decode(qemu):
    one_tmpl, one_s0, one_s1, one_s2 = movl_mlx(1, 0x3ff0000000000000)
    two_tmpl, two_s0, two_s1, two_s2 = movl_mlx(2, 0x4000000000000000)

    require_registers(
        qemu,
        "windows fp decode",
        [
            (0x10, one_tmpl, one_s0, one_s1, one_s2),
            (0x20, 0x09, setf_d(10, 1), nop_m(), nop_i()),
            (0x30, two_tmpl, two_s0, two_s1, two_s2),
            (0x40, 0x09, setf_d(8, 2), nop_m(), nop_i()),
            (0x50, 0x0d, nop_m(), fmpy_d_s0(9, 10, 8), nop_i()),
            (0x60, 0x09, getf_d(3, 9), nop_m(), nop_i()),
            (0x70, 0x0d, nop_m(), fnorm_d_s0(11, 9), nop_i()),
            (0x80, 0x09, getf_d(4, 11), nop_m(), nop_i()),
            (0x90, 0x0d, nop_m(), fcmp_lt_unc_s0(6, 7, 10, 8), nop_i()),
            (0xA0, 0x00, nop_m(), adds(5, 6, 0, qp=6),
             adds(6, 7, 0, qp=7)),
            (0xB0, 0x11, nop_m(), nop_i(), br_cond(0xB0, 0xB0)),
        ],
        {"ip": 0xB0, "r3": 0x4000000000000000,
         "r4": 0x4000000000000000, "r5": 6, "r6": 0},
    )


def test_sync_m_decode(qemu):
    require_registers(
        qemu,
        "sync.m decode",
        [
            (0x10, 0x00, mf(), adds(1, 1, 0), adds(2, 2, 0)),
            (0x20, 0x00, mf_a(), adds(3, 3, 0), adds(4, 4, 0)),
            (0x30, 0x00, srlz_d(), adds(5, 5, 0), adds(6, 6, 0)),
            (0x40, 0x11, nop_m(), nop_i(), br_cond(0x40, 0x40)),
        ],
        {"ip": 0x40, "r1": 1, "r2": 2, "r3": 3, "r4": 4, "r5": 5, "r6": 6},
    )


def test_rse_maintenance_decode(qemu):
    require_registers(
        qemu,
        "rse maintenance decode",
        [
            (0x10, 0x08, flushrs(), loadrs(), adds(1, 1, 0)),
            (0x20, 0x08, invala(), nop_m(), adds(2, 2, 0)),
            (0x30, 0x11, nop_m(), nop_i(), br_cond(0x30, 0x30)),
        ],
        {"ip": 0x30, "r1": 1, "r2": 2},
    )


def test_call_stack_register_mapping(qemu):
    require_registers(
        qemu,
        "call stacked register mapping",
        [
            (0x10, 0x11, alloc(2, 39, 31, 0, 0), adds(63, 42, 0), br_call(0, 0x10, 0x30)),
            (0x20, 0x11, nop_m(), nop_i(), br_cond(0x20, 0x20)),
            (0x30, 0x11, nop_m(), add(4, 32, 0), br_ret(0)),
        ],
        {"ip": 0x20, "r4": 42},
    )


def test_call_preserves_caller_stacked_locals(qemu):
    require_registers(
        qemu,
        "call preserves caller stacked locals",
        [
            (0x10, 0x00, alloc(2, 12, 6, 0, 0), adds(32, 5, 0), adds(38, 9, 0)),
            (0x20, 0x11, nop_m(), nop_i(), br_call(0, 0x20, 0x50)),
            (0x30, 0x00, nop_m(), add(4, 32, 0), add(5, 38, 0)),
            (0x40, 0x11, nop_m(), nop_i(), br_cond(0x40, 0x40)),
            (0x50, 0x11, nop_m(), adds(32, 0, 0), br_ret(0)),
        ],
        {"ip": 0x40, "r4": 5, "r5": 0, "b0": 0x30},
    )


def test_call_maps_multiple_output_registers(qemu):
    require_registers(
        qemu,
        "call maps multiple output registers",
        [
            (0x10, 0x00, alloc(2, 12, 10, 0, 0), adds(42, 0x12, 0), adds(43, 0x34, 0)),
            (0x20, 0x11, nop_m(), nop_i(), br_call(0, 0x20, 0x50)),
            (0x30, 0x11, nop_m(), nop_i(), br_cond(0x30, 0x30)),
            (0x50, 0x00, nop_m(), add(4, 32, 0), add(5, 33, 0)),
            (0x60, 0x11, nop_m(), nop_i(), br_ret(0)),
        ],
        {"ip": 0x30, "r4": 0x12, "r5": 0x34, "b0": 0x30},
    )


def test_nested_call_preserves_high_output_argument(qemu):
    require_registers(
        qemu,
        "nested call preserves high output argument",
        [
            (0x10, 0x00, alloc(60, 36, 31, 0, 0), addl(36, 0x1000, 0), nop_i()),
            (0x20, 0x00, ld8(22, 36), nop_i(), nop_i()),
            (0x30, 0x00, nop_m(), adds(21, 32, 22), nop_i()),
            (0x40, 0x11, ld8(63, 21), nop_i(), br_call(0, 0x40, 0x80)),
            (0x50, 0x11, nop_m(), nop_i(), br_cond(0x50, 0x50)),
            (0x80, 0x11, alloc(41, 14, 11, 0, 0), add(43, 32, 0), br_call(1, 0x80, 0xB0)),
            (0x90, 0x11, nop_m(), mov_i_grar(64, 41), br_ret(0)),
            (0xB0, 0x11, alloc(40, 13, 10, 0, 0), add(4, 32, 0), br_ret(1)),
        ],
        {"ip": 0x50, "r4": 0x12345678, "b0": 0x50, "b1": 0x90},
        data=[
            (0x1000, 0x2000, 8),
            (0x2020, 0x12345678, 8),
        ],
    )


def test_fault_reporting(qemu):
    require_registers(
        qemu,
        "break fault",
        [
            (0x10, 0x00, break_m(0x123), adds(1, 1, 0), adds(2, 2, 0)),
        ],
        {
            "ip": 0x10,
            "exception": IA64_EXCP_BREAK,
            "fault_ip": 0x10,
            "fault_imm": 0x123,
            "r1": 0,
            "r2": 0,
        },
    )
    require_registers(
        qemu,
        "illegal instruction fault",
        [
            (0x10, 0x00, illegal_m(), adds(1, 1, 0), adds(2, 2, 0)),
        ],
        {
            "ip": 0x10,
            "exception": IA64_EXCP_ILLEGAL,
            "fault_ip": 0x10,
            "fault_imm": illegal_m(),
            "r1": 0,
            "r2": 0,
        },
    )
    require_registers(
        qemu,
        "reserved template fault",
        [
            (0x40, 0x06, nop_m(), adds(1, 1, 0), adds(2, 2, 0)),
        ],
        {
            "ip": 0x40,
            "exception": IA64_EXCP_RESERVED_TEMPLATE,
            "fault_ip": 0x40,
            "fault_imm": 0x06,
            "r1": 0,
            "r2": 0,
        },
        entry=0x40,
    )


def test_speculative_load_nat(qemu):
    require_registers(
        qemu,
        "speculative load nat cleared via tnat",
        [
            (0x10, 0x08, adds(4, 0x200, 0), adds(8, 0, 0), nop_i()),
            (0x20, 0x08, ld8_s(5, 4), tnat_z(1, 2, 5), nop_i()),
            (0x30, 0x00, nop_m(), adds(6, 0xFF, 0, qp=1), adds(7, 0xEE, 0, qp=2)),
            (0x40, 0x09, ld8_a(16, 4), nop_m(), nop_i()),
            (0x50, 0x09, chk_a_clr(16), nop_m(), nop_i()),
            (0x60, 0x11, nop_m(), adds(9, 0x42, 0), br_cond(0x60, 0x60)),
        ],
        {"ip": 0x60, "r5": 0xDEAD, "r6": 0xFF, "r7": 0, "r9": 0x42, "r16": 0xDEAD, "p1": 1, "p2": 0},
        data=[(0x200, 0xDEAD, 8)],
    )


def test_smci_store_reload(qemu):
    low, high = bundle_words(0x11, nop_m(), adds(9, 0x99, 0), br_cond(0x100, 0x100))
    regs, output = run_program(
        qemu,
        [
            (0x10, 0x11, nop_m(), adds(1, 0x100, 0), br_cond(0x10, 0x100)),
        ],
        entry=0x10,
        data=[(0x100, low, 8), (0x108, high, 8)],
        delay=1.0,
    )
    r9_ok = regs.get("r9") == 0x99
    if not r9_ok:
        raise RuntimeError(f"SMCI store-reload: r9 expected 0x99, got {regs.get('r9')!r}\n{output}")


def test_sapic_read(qemu):
    require_registers(
        qemu,
        "sapic read IVR/TPR",
        [
            (0x10, 0x00, mov_from_cr(16, 65, qp=0), nop_i(), nop_i()),
            (0x20, 0x00, mov_from_cr(17, 66, qp=0), nop_i(), nop_i()),
            (0x30, 0x00, mov_to_cr(0, 67, qp=0), nop_i(), nop_i()),
            (0x40, 0x00, mov_from_cr(18, 65, qp=0), nop_i(), nop_i()),
            (0x50, 0x11, nop_m(), nop_i(), break_m(0, qp=0)),
        ],
        {"r16": 0x0f, "r17": 0, "r18": 0x0f},
    )


def test_srlz_resumes_at_next_slot_before_cr_read(qemu):
    require_registers(
        qemu,
        "srlz resumes at next slot before CR read",
        [
            (0x10, 0x0b, srlz_d(), mov_m_from_cr(16, 65), nop_i()),
            (0x20, 0x11, nop_m(), nop_i(), break_m(0, qp=0)),
        ],
        {"r16": 0x0f},
    )


def test_sapic_ivr_accepts_pending_timer(qemu):
    require_registers(
        qemu,
        "sapic IVR accepts pending timer",
        [
            (0x10, 0x00, adds(3, 239, 0), nop_i(), nop_i()),
            (0x20, 0x00, mov_to_cr(3, 72, qp=0), nop_i(), nop_i()),
            (0x30, 0x00, adds(2, 0, 0), nop_i(), nop_i()),
            (0x40, 0x00, mov_m_grar(44, 2), nop_i(), nop_i()),
            (0x50, 0x00, mov_to_cr(2, 1, qp=0), nop_i(), nop_i()),
            (0x60, 0x00, mov_from_cr(16, 65, qp=0), nop_i(), nop_i()),
            (0x70, 0x00, mov_to_cr(0, 67, qp=0), nop_i(), nop_i()),
            (0x80, 0x00, mov_from_cr(17, 65, qp=0), nop_i(), nop_i()),
            (0x90, 0x11, nop_m(), nop_i(), break_m(0, qp=0)),
        ],
        {"r16": 239, "r17": 0x0f},
    )


def test_itv_mask_blocks_pending_timer(qemu):
    require_registers(
        qemu,
        "itv mask blocks pending timer",
        [
            (0x10, 0x00, nop_m(), addl(3, 1 << 16, 0), nop_i()),
            (0x20, 0x00, mov_to_cr(3, 72, qp=0), nop_i(), nop_i()),
            (0x30, 0x00, adds(2, 0, 0), nop_i(), nop_i()),
            (0x40, 0x00, mov_m_grar(44, 2), nop_i(), nop_i()),
            (0x50, 0x00, mov_to_cr(2, 1, qp=0), nop_i(), nop_i()),
            (0x60, 0x00, mov_from_cr(16, 65, qp=0), nop_i(), nop_i()),
            (0x70, 0x11, nop_m(), nop_i(), break_m(0, qp=0)),
        ],
        {"r16": 0x0f},
    )


def aliases_for_test(name, fn):
    aliases = {name, fn.__name__}
    if fn.__name__.startswith("test_"):
        aliases.add(fn.__name__[5:])
    return aliases


def select_tests(tests, selectors):
    if not selectors:
        return tests, []

    by_alias = {}
    for test in tests:
        name, fn = test
        for alias in aliases_for_test(name, fn):
            by_alias[alias] = test

    selected = []
    missing = []
    for selector in selectors:
        test = by_alias.get(selector)
        if test is None:
            missing.append(selector)
        else:
            selected.append(test)

    return selected, missing


def main():
    if len(sys.argv) < 2:
        print("Bail out! usage: test-ia64-qemu-tcg.py "
              "QEMU_SYSTEM_IA64 [TEST_NAME ...]")
        return 1

    qemu = sys.argv[1]
    tests = [
        ("arithmetic and branch", test_arithmetic_and_branch),
        ("addl immediate22", test_addl_immediate22),
        ("movl mlx predicate source", test_movl_mlx_predicate_source),
        ("alu immediate ops", test_alu_immediate_ops),
        ("memory load/store", test_memory_load_store),
        ("fetchadd4.acq", test_fetchadd4_acq),
        ("store post-increment", test_store_post_increment),
        ("ld8.fill.nta post-increment", test_ld8_fill_nta_post_increment),
        ("narrow memory load/store", test_narrow_memory_load_store),
        ("predication", test_predication),
        ("cmp4.eq immediate predication", test_cmp4_eq_imm_predication),
        ("cmp.ltu immediate", test_cmp_ltu_immediate),
        ("cmp.eq.or.andcm", test_cmp_eq_or_andcm),
        ("cmp.or register", test_cmp_or_register),
        ("cmp4.ne.or.andcm immediate", test_cmp4_ne_or_andcm_immediate),
        ("cmp4.eq.or.andcm immediate", test_cmp4_eq_or_andcm_immediate),
        ("cmp4.eq.or.andcm register", test_cmp4_eq_or_andcm_register),
        ("cmp4 register and tbit predication", test_cmp4_register_and_tbit_predication),
        ("cmp.le.or.andcm zero uses 64-bit relation", test_cmp_le_or_andcm_zero_uses_64bit_relation),
        ("tbit.z.or.andcm", test_tbit_z_or_andcm),
        ("tnat.nz.and", test_tnat_nz_and),
        ("mux1 brcst", test_mux1_brcst),
        ("extract immediate", test_extract_immediate),
        ("deposit immediate", test_deposit_immediate),
        ("register shifts", test_register_shifts),
        ("register shift large counts", test_register_shift_large_counts),
        ("shrp immediate", test_shrp_immediate),
        ("call and return", test_call_and_return),
        ("call.many and return", test_call_many_and_return),
        ("indirect call and return", test_indirect_call_and_return),
        ("indirect call through return register", test_indirect_call_through_return_register),
        ("indirect call masks target low bits", test_indirect_call_masks_target_low_bits),
        ("return masks target low bits", test_return_masks_target_low_bits),
        ("mov.sptk b=gr updates branch register", test_mov_grbr_sptk_hint_updates_branch_register),
        ("M-unit opcode 0 x3=7 remains chk.a", test_m_unit_x3_7_decodes_chk_a_fp),
        ("indirect branch", test_indirect_branch),
        ("mov current ip", test_mov_current_ip),
        ("iip control-register roundtrip", test_iip_control_register_roundtrip),
        ("br.many", test_br_many),
        ("brp.loop.imp", test_brp_loop_imp),
        ("brp.sptk windows", test_brp_sptk_windows),
        ("predicate register moves", test_predicate_register_moves),
        ("predicate rotating immediate", test_predicate_rot_immediate),
        ("mov.m application register", test_mov_m_application_register),
        ("mov.i application register and br.cloop", test_mov_i_application_register_and_cloop),
        ("self br.cloop store post-increment", test_self_cloop_store_post_increment),
        ("self br.cloop st1.rel zero post-increment", test_self_cloop_zero_st1_release),
        ("stf.spill and ldf.fill", test_float_spill_fill),
        ("f0 immutable", test_float_f0_immutable),
        ("ldf.fill post-increment", test_ldf_fill_post_increment),
        ("ldf.fill.nta post-increment", test_ldf_fill_nta_post_increment),
        ("stf.spill.nta post-increment", test_stf_spill_nta_post_increment),
        ("xmpy.hu", test_xmpy_hu),
        ("setf/getf sig, xma.l, and frcpa predicate",
         test_setf_sig_xma_frcpa_predicate),
        ("windows fp decode", test_windows_fp_decode),
        ("sync.m decode", test_sync_m_decode),
        ("rse maintenance decode", test_rse_maintenance_decode),
        ("call stacked register mapping", test_call_stack_register_mapping),
        ("call preserves caller stacked locals", test_call_preserves_caller_stacked_locals),
        ("call maps multiple output registers", test_call_maps_multiple_output_registers),
        ("nested high output argument", test_nested_call_preserves_high_output_argument),
        ("fault reporting", test_fault_reporting),
        ("speculative load nat", test_speculative_load_nat),
        ("smci store-reload", test_smci_store_reload),
        ("sapic read IVR/TPR/EOI", test_sapic_read),
        ("srlz resumes at next slot before CR read", test_srlz_resumes_at_next_slot_before_cr_read),
        ("sapic IVR accepts pending timer", test_sapic_ivr_accepts_pending_timer),
        ("ITV mask blocks pending timer", test_itv_mask_blocks_pending_timer),
    ]

    all_tests = tests
    tests, missing = select_tests(all_tests, sys.argv[2:])
    if missing:
        print(f"Bail out! unknown test name(s): {', '.join(missing)}")
        print("# known tests:")
        for name, fn in all_tests:
            print(f"#   {name} ({fn.__name__})")
        return 1

    print("TAP version 13")
    print(f"1..{len(tests)}")
    failed = 0
    for index, (name, fn) in enumerate(tests, start=1):
        try:
            fn(qemu)
            print(f"ok {index} - {name}")
        except Exception as exc:
            failed += 1
            print(f"not ok {index} - {name}")
            for line in str(exc).splitlines():
                print(f"# {line}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
