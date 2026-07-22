"""Interrupt, timer, and interruption-delivery microprograms."""

from __future__ import annotations

from .case import (CaseMetadata, CaseObservation, bind_cases)
from .encoding import (
    HIGH_TR_BASE,
    IA64_ALT_DTLB_VECTOR,
    IA64_BREAK_VECTOR,
    IA64_CR_ITM,
    IA64_CR_ITV,
    IA64_CR_SAPIC_EOI,
    IA64_CR_SAPIC_IRR3,
    IA64_CR_SAPIC_IVR,
    IA64_CR_SAPIC_TPR,
    IA64_DATA_NESTED_TLB_VECTOR,
    IA64_DCR_BE,
    IA64_DCR_PP,
    IA64_EXCP_BREAK,
    IA64_EXCP_DISABLED_ISA_TRANSITION,
    IA64_EXCP_ILLEGAL,
    IA64_EXCP_NONE,
    IA64_EXCP_RESERVED_TEMPLATE,
    IA64_EXCP_UNALIGNED,
    IA64_GENERAL_VECTOR,
    IA64_GENEX_UNIMPL_INST_ADDR,
    IA64_IMPL_PA_BITS,
    IA64_ISR_EI_SHIFT,
    IA64_ISR_IR,
    IA64_ISR_NI,
    IA64_ISR_R,
    IA64_ISR_RS,
    IA64_ISR_X,
    IA64_ITC_TICKS_PER_MILLISECOND,
    IA64_LOWER_PRIV_TRANSFER_VECTOR,
    IA64_PSR_AC,
    IA64_PSR_BE,
    IA64_PSR_BN,
    IA64_PSR_DFH,
    IA64_PSR_DFL,
    IA64_PSR_DI,
    IA64_PSR_DT,
    IA64_PSR_I,
    IA64_PSR_IC,
    IA64_PSR_IS,
    IA64_PSR_MC,
    IA64_PSR_MFH,
    IA64_PSR_MFL,
    IA64_PSR_PK,
    IA64_PSR_PP,
    IA64_PSR_RT,
    IA64_PSR_SI,
    IA64_PSR_SP,
    IA64_PSR_UP,
    IA64_TPR_MMI,
    IA64_UNALIGNED_VECTOR,
    IA64_VECTOR_MASKED,
    LOW_VECTOR_TR_PTE,
    add,
    addl,
    adds,
    alloc,
    br_call,
    br_cloop,
    br_cond,
    br_indirect,
    br_ret,
    break_f,
    break_m,
    break_x_mlx,
    bsw0,
    bsw1,
    cmp4_eq_imm,
    cmp4_eq_unc_imm,
    cmp_eq_and,
    cover_b,
    dtr_setup_bundles,
    extr_u,
    illegal_m,
    itc_d,
    ld2,
    ld2_bias,
    ld2_c_clr,
    ld2_sa,
    ld8,
    mov_ar,
    mov_ar_lc,
    mov_br_gr,
    mov_gr_psr_full,
    mov_lc_gr,
    mov_m_ar_gr,
    mov_m_cr_gr,
    mov_m_gr_ar,
    mov_m_gr_cr,
    mov_m_psr_gr,
    mov_pkr_indexed,
    mov_pkr_indexed_read,
    movl_mlx,
    nop_i,
    nop_m,
    pal_break,
    require_exception,
    require_qemu_failure,
    require_registers,
    rfi_b,
    rfi_to_gr,
    rsm,
    run_program,
    srlz_d,
    ssm,
    st1_postinc,
    st2,
    st8,
    st8_postinc,
)

FOUR_K_ITIR = 12 << 2

test_rfi_target_rse_fill_fault_uses_restored_psr = require_registers(
    "rfi_target_rse_fill_fault_uses_restored_psr", [
        (0x10, *movl_mlx(3, HIGH_TR_BASE + 0x10000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(), nop_i()),
        (0x30, *movl_mlx(20, (1 << 63) | 1)),
        (0x40, 0x00, mov_m_gr_cr(20, 23), nop_i(), nop_i()),
        (0x50, *movl_mlx(20, 0x200)),
        (0x60, 0x00, mov_m_gr_cr(20, 19), nop_i(), nop_i()),
        (0x70, *movl_mlx(20, IA64_PSR_IC | IA64_PSR_DT | IA64_PSR_RT)),
        (0x80, 0x00, mov_m_gr_cr(20, 16), nop_i(), nop_i()),
        (0x90, 0x10, nop_m(), nop_i(), rfi_b()),
        (IA64_ALT_DTLB_VECTOR, 0x00, mov_m_cr_gr(31, 17), nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x00, mov_m_cr_gr(30, 20),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_ALT_DTLB_VECTOR + 0x20,
                 IA64_ALT_DTLB_VECTOR + 0x20)),
        (IA64_DATA_NESTED_TLB_VECTOR, 0x10, nop_m(), adds(29, 1, 0),
         br_cond(IA64_DATA_NESTED_TLB_VECTOR,
                 IA64_DATA_NESTED_TLB_VECTOR)),
    ], {
        "ip": IA64_ALT_DTLB_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r29": 0,
        "r30": HIGH_TR_BASE + 0xfff8,
        "r31": IA64_ISR_R | IA64_ISR_RS | IA64_ISR_IR,
    }, entry=0x10)

test_rfi_retries_interrupted_current_frame_fill = require_registers(
    "rfi_retries_interrupted_current_frame_fill", [
        (0x10, *movl_mlx(3, 0x4000fe8)),
        (0x20, *movl_mlx(4, 0x1122334455667788)),
        (0x30, 0x00, st8(3, 4), nop_i(), nop_i()),
        (0x40, *movl_mlx(3, 0x4000ff0)),
        (0x50, *movl_mlx(4, 0x8877665544332211)),
        (0x60, 0x00, st8(3, 4), nop_i(), nop_i()),
        (0x70, *movl_mlx(3, 0x4000ff8)),
        (0x80, 0x00, st8(3, 0), nop_i(), nop_i()),
        (0x90, *movl_mlx(3, HIGH_TR_BASE + 0x10000)),
        (0xa0, 0x00, mov_ar(3, 18), nop_i(), nop_i()),
        (0xb0, *movl_mlx(20, (1 << 63) | 2)),
        (0xc0, 0x00, mov_m_gr_cr(20, 23), nop_i(), nop_i()),
        (0xd0, *movl_mlx(20, 0x200)),
        (0xe0, 0x00, mov_m_gr_cr(20, 19), nop_i(), nop_i()),
        (0xf0, *movl_mlx(20, IA64_PSR_IC | IA64_PSR_DT | IA64_PSR_RT)),
        (0x100, 0x00, mov_m_gr_cr(20, 16), nop_i(), nop_i()),
        (0x110, 0x10, nop_m(), nop_i(), rfi_b()),
        (0x200, 0x00, nop_m(), adds(8, 0, 32), nop_i()),
        (0x210, 0x00, nop_m(), adds(9, 0, 33), nop_i()),
        (0x220, 0x10, nop_m(), nop_i(), br_cond(0x220, 0x220)),
        (IA64_ALT_DTLB_VECTOR, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x00, nop_m(),
         adds(7, FOUR_K_ITIR, 0), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x20, 0x00, mov_m_gr_cr(7, 21),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x30, 0x00, itc_d(18), nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x40, 0x10, nop_m(), nop_i(), rfi_b()),
    ], {
        "ip": 0x220,
        "exception": IA64_EXCP_NONE,
        "r8": 0x1122334455667788,
        "r9": 0x8877665544332211,
        "cfm_sof": 2,
        "cfm_sol": 0,
    }, entry=0x10)

test_unimplemented_physical_instruction_traps = require_registers(
    "unimplemented_physical_instruction_traps", [
        (0x10, *movl_mlx(3, 1 << IA64_IMPL_PA_BITS)),
        (0x20, *movl_mlx(19, IA64_PSR_IC)),
        (0x30, 0x00, mov_gr_psr_full(19), nop_i(), nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x50, 0x00, nop_m(), mov_br_gr(7, 3), nop_i()),
        (0x60, 0x11, nop_m(), nop_i(), br_indirect(7)),
        (IA64_LOWER_PRIV_TRANSFER_VECTOR, 0x00,
         mov_m_cr_gr(8, 19), nop_i(), nop_i()),
        (IA64_LOWER_PRIV_TRANSFER_VECTOR + 0x10, 0x00,
         mov_m_cr_gr(9, 17), nop_i(), nop_i()),
        (IA64_LOWER_PRIV_TRANSFER_VECTOR + 0x20, 0x10,
         nop_m(), nop_i(),
         br_cond(IA64_LOWER_PRIV_TRANSFER_VECTOR + 0x20,
                 IA64_LOWER_PRIV_TRANSFER_VECTOR + 0x20)),
    ], {
        "ip": IA64_LOWER_PRIV_TRANSFER_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r8": 0,
        "r9": IA64_GENEX_UNIMPL_INST_ADDR | IA64_ISR_X,
    }, entry=0x10)

def test_ar_itc_advances_in_guest_loop(qemu):
    result = run_program(qemu, [
        (0x10, 0x02, mov_m_ar_gr(16, 44), nop_i(),
         addl(8, 4095, 0)),
        (0x20, 0x02, nop_m(), mov_lc_gr(8),
         nop_i()),
        (0x30, 0x10, nop_m(), nop_i(),
         br_cloop(0x30, 0x30)),
        (0x40, 0x02, mov_m_ar_gr(17, 44), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
    ], entry=0x10, terminal_ip=0x50)
    state = result.state
    if state.gr[17] <= state.gr[16]:
        raise RuntimeError(
            "ar_itc_advances_in_guest_loop failed: "
            f"r16={state.gr[16]!r} r17={state.gr[17]!r}\n"
            f"{result.register_output}")

def test_cloop_zero_st1_timer_interrupts_batched_loop(qemu):
    result = run_program(qemu, [
        (0x10, *movl_mlx(2, 0x8000)),
        (0x20, *movl_mlx(8, 0x100000000)),
        (0x30, 0x02, nop_m(), mov_lc_gr(8),
         nop_i()),
        (0x40, 0x02, mov_m_ar_gr(3, 44), nop_i(),
         nop_i()),
        (0x50, 0x00, addl(4, 10 * IA64_ITC_TICKS_PER_MILLISECOND, 3),
         nop_i(), nop_i()),
        (0x60, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x70, 0x00, adds(3, 0xef, 0), nop_i(),
         nop_i()),
        (0x80, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x90, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0xa0, 0x08, mov_gr_psr_full(19), srlz_d(),
         nop_i()),
        (0xb0, 0x10, st1_postinc(2, 0, 1), nop_i(),
         br_cloop(0xb0, 0xb0)),
        (0xc0, 0x10, nop_m(), nop_i(),
         br_cond(0xc0, 0xc0)),
        (0x3000, 0x02, nop_m(), mov_ar_lc(9),
         nop_i()),
        (0x3010, 0x00, nop_m(), adds(8, 0, 2),
         nop_i()),
        (0x3020, 0x10, nop_m(), nop_i(),
         br_cond(0x3020, 0x3020)),
    ], entry=0x10, terminal_ip=0x3020)
    state = result.state
    advanced = state.gr[8] - 0x8000
    if (state.ip != 0x3020 or
        state.exception != IA64_EXCP_NONE or
        advanced <= 0 or
        state.gr[9] >= 0x100000000):
        raise RuntimeError(
            "cloop_zero_st1_timer_interrupts_batched_loop failed: "
            f"advanced={advanced!r} lc={state.gr[9]!r} "
            f"ip={state.ip!r} exception={state.exception!r}\n"
            f"{result.register_output}")

test_mov_to_ivr_illegal = require_exception(
    "mov_to_ivr_illegal", [
        (0x10, 0x00, mov_m_gr_cr(0, IA64_CR_SAPIC_IVR), nop_i(),
         nop_i()),
    ], IA64_EXCP_ILLEGAL, fault_ip=0x10)

test_mov_to_irr_illegal = require_exception(
    "mov_to_irr_illegal", [
        (0x10, 0x00, mov_m_gr_cr(0, IA64_CR_SAPIC_IRR3), nop_i(),
         nop_i()),
    ], IA64_EXCP_ILLEGAL, fault_ip=0x10)

test_mov_to_read_only_cr_predicate_false = require_registers(
    "mov_to_read_only_cr_predicate_false", [
        (0x10, 0x00, mov_m_gr_cr(0, IA64_CR_SAPIC_IVR, qp=1),
         nop_i(), nop_i()),
        (0x20, 0x00, mov_m_gr_cr(0, IA64_CR_SAPIC_IRR3, qp=1),
         nop_i(), nop_i()),
        (0x30, 0x10, nop_m(), nop_i(),
         br_cond(0x30, 0x30)),
    ], {
        "ip": 0x30,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_async_timer_interrupt_enters_ivt = require_registers(
    "async_timer_interrupt_enters_ivt", [
        (0x10, 0x00, adds(3, 0xef, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_ar(0, 44), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(0, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x50, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0x60, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0x60, 0x60)),
        (0x3000, 0x10, nop_m(), adds(31, 0x55, 0),
         br_cond(0x3000, 0x3010)),
        (0x3010, 0x10, nop_m(), nop_i(),
         br_cond(0x3010, 0x3010)),
    ], {
        "ip": 0x3010,
        "exception": IA64_EXCP_NONE,
        "r31": 0x55,
    }, entry=0x10)

test_async_timer_interrupt_records_boundary_ri = require_registers(
    "async_timer_interrupt_records_boundary_ri", [
        (0x10, 0x00, adds(3, 0xef, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_ar(0, 44), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(0, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x50, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0x60, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0x60, 0x60)),
        (0x3000, 0x00, mov_m_cr_gr(31, 16), nop_i(),
         nop_i()),
        (0x3010, 0x10, mov_m_cr_gr(30, 19), nop_i(),
         br_cond(0x3010, 0x3020)),
        (0x3020, 0x10, nop_m(), nop_i(),
         br_cond(0x3020, 0x3020)),
    ], {
        "ip": 0x3020,
        "exception": IA64_EXCP_NONE,
        "r30": 0x60,
        "r31": (1 << 13) | (1 << 14),
    }, entry=0x10)

def test_async_timer_interrupt_never_resumes_mlx_slot2(qemu):
    program = [
        (0x10, 0x02, mov_m_ar_gr(3, 44), nop_i(), nop_i()),
        (0x20, 0x00,
         addl(4, 10 * IA64_ITC_TICKS_PER_MILLISECOND, 3),
         nop_i(), nop_i()),
        (0x30, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(), nop_i()),
        (0x40, 0x00, adds(3, 0xef, 0), nop_i(), nop_i()),
        (0x50, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(), nop_i()),
        (0x60, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0x70, 0x08, mov_gr_psr_full(19), srlz_d(), nop_i()),
    ]
    mlx_addresses = set()
    loop_addresses = set()
    loop_start = 0x80
    address = loop_start

    # Alternate fully occupied bundles with MLX bundles.  A host timer kick
    # at a bundle boundary must never combine the following MLX address with
    # the completed preceding bundle's slot-2 restart state.
    for index in range(32):
        loop_addresses.add(address)
        program.append((address, 0x01,
                        adds(22, index, 0),
                        adds(23, index + 1, 0),
                        adds(24, index + 2, 0)))
        address += 0x10
        mlx_addresses.add(address)
        loop_addresses.add(address)
        program.append((address, *movl_mlx(25, index)))
        address += 0x10

    loop_addresses.add(address)
    program.extend([
        (address, 0x10, nop_m(), nop_i(),
         br_cond(address, loop_start)),
        (0x3000, 0x00, mov_m_cr_gr(30, 19), nop_i(), nop_i()),
        (0x3010, 0x10, mov_m_cr_gr(31, 16), nop_i(),
         br_cond(0x3010, 0x3010)),
    ])

    result = run_program(qemu, program, entry=0x10, terminal_ip=0x3010)
    state = result.state
    interrupted_ip = state.gr[30]
    interrupted_ri = (state.gr[31] >> 41) & 3
    if (state.ip != 0x3010 or
        state.exception != IA64_EXCP_NONE or
        interrupted_ip not in loop_addresses or
        (interrupted_ip in mlx_addresses and interrupted_ri not in (0, 1))):
        raise RuntimeError(
            "async_timer_interrupt_never_resumes_mlx_slot2 failed: "
            f"iip={interrupted_ip:#x} ri={interrupted_ri} "
            f"ip={state.ip!r} exception={state.exception!r}\n"
            f"{result.register_output}")


def test_repeated_timer_rfi_preserves_word_rmw(qemu):
    iterations = 0x100001
    result = run_program(qemu, [
        (0x10, *movl_mlx(2, 0x8000)),
        (0x20, 0x00, st2(2, 0), nop_i(), nop_i()),
        (0x30, *movl_mlx(3, 0x8010)),
        (0x40, 0x00, st8(3, 0), nop_i(), nop_i()),
        (0x50, 0x00, mov_m_gr_ar(0, 44), nop_i(), nop_i()),
        (0x60, *movl_mlx(4, IA64_ITC_TICKS_PER_MILLISECOND)),
        (0x70, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(), nop_i()),
        (0x80, 0x00, adds(4, 0xef, 0), nop_i(), nop_i()),
        (0x90, 0x00, mov_m_gr_cr(4, IA64_CR_ITV), nop_i(), nop_i()),
        (0xa0, *movl_mlx(8, iterations - 1)),
        (0xb0, 0x02, nop_m(), mov_lc_gr(8), nop_i()),
        (0xc0, *movl_mlx(19, (1 << 13) | (1 << 14) | (1 << 44))),
        (0xd0, 0x08, mov_gr_psr_full(19), srlz_d(), nop_i()),
        (0xe0, 0x00, ld2(4, 2), nop_i(), nop_i()),
        (0xf0, 0x00, nop_m(), adds(4, 1, 4), nop_i()),
        (0x100, 0x10, st2(2, 4), nop_i(), br_cloop(0x100, 0xe0)),
        (0x110, 0x00, rsm(1 << 14), nop_i(), nop_i()),
        (0x120, 0x00, ld2(8, 2), nop_i(), nop_i()),
        (0x130, 0x00, ld8(9, 3), nop_i(), nop_i()),
        (0x140, 0x10, nop_m(), nop_i(), br_cond(0x140, 0x140)),

        (0x3000, 0x00, mov_m_cr_gr(16, IA64_CR_SAPIC_IVR),
         nop_i(), nop_i()),
        (0x3010, 0x00, mov_m_ar_gr(17, 44), nop_i(), nop_i()),
        (0x3020, *movl_mlx(20, IA64_ITC_TICKS_PER_MILLISECOND)),
        (0x3030, 0x00, nop_m(), add(17, 17, 20), nop_i()),
        (0x3040, 0x00, mov_m_gr_cr(17, IA64_CR_ITM), nop_i(), nop_i()),
        (0x3050, *movl_mlx(18, 0x8010)),
        (0x3060, 0x00, ld8(19, 18), nop_i(), nop_i()),
        (0x3070, 0x00, nop_m(), adds(19, 1, 19), nop_i()),
        (0x3080, 0x00, st8(18, 19), nop_i(), nop_i()),
        (0x3090, 0x10, mov_m_gr_cr(0, IA64_CR_SAPIC_EOI), nop_i(),
         rfi_b()),
    ], entry=0x10, terminal_ip=0x140, timeout=8.0)
    state = result.state
    expected = iterations & 0xffff
    if (state.ip != 0x140 or
        state.exception != IA64_EXCP_NONE or
        state.gr[8] != expected or
        state.gr[9] < 2):
        raise RuntimeError(
            "repeated_timer_rfi_preserves_word_rmw failed: "
            f"counter={state.gr[8]!r} expected={expected!r} "
            f"interrupts={state.gr[9]!r} ip={state.ip!r} "
            f"exception={state.exception!r}\n{result.register_output}")


def test_timer_interrupt_preserves_banked_word_rmw(qemu):
    iterations = 0x100001
    result = run_program(qemu, [
        (0x10, *movl_mlx(2, 0x8000)),
        (0x20, 0x00, st2(2, 0), nop_i(), nop_i()),
        (0x30, *movl_mlx(3, 0x8010)),
        (0x40, 0x00, st8(3, 0), nop_i(), nop_i()),
        (0x50, 0x02, mov_m_ar_gr(4, 44), nop_i(), nop_i()),
        (0x60, *movl_mlx(5, IA64_ITC_TICKS_PER_MILLISECOND)),
        (0x70, 0x00, nop_m(), add(4, 4, 5), nop_i()),
        (0x80, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(), nop_i()),
        (0x90, 0x00, adds(4, 0xef, 0), nop_i(), nop_i()),
        (0xa0, 0x00, mov_m_gr_cr(4, IA64_CR_ITV), nop_i(), nop_i()),
        (0xb0, *movl_mlx(8, iterations - 1)),
        (0xc0, 0x02, nop_m(), mov_lc_gr(8), nop_i()),
        (0xd0, *movl_mlx(7, IA64_PSR_IC | IA64_PSR_I | IA64_PSR_BN)),
        (0xe0, 0x10, nop_m(), nop_i(), bsw1()),
        (0xf0, 0x08, mov_gr_psr_full(7), srlz_d(), nop_i()),
        (0x100, 0x10, nop_m(), nop_i(), br_cond(0x100, 0x1fe0)),
        (0x1fe0, 0x00, nop_m(), adds(22, 0, 2), nop_i()),
        # Match the page-table accounting sequence: a banked address and
        # loaded value survive an interruptible host-TB boundary before the
        # 16-bit store.  Splitting the two bundles across an 8 KiB page makes
        # that boundary deterministic; the handler clobbers the other bank.
        (0x1ff0, 0x08, ld2_bias(21, 22), adds(19, 1, 21), nop_i()),
        (0x2000, 0x10, st2(22, 19), nop_i(),
         br_cloop(0x2000, 0x1ff0)),
        (0x2010, 0x00, rsm(IA64_PSR_I), nop_i(), nop_i()),
        (0x2020, 0x00, ld2(8, 2), nop_i(), nop_i()),
        (0x2030, 0x00, ld8(9, 3), nop_i(), nop_i()),
        (0x2040, 0x10, nop_m(), nop_i(), br_cond(0x2040, 0x2040)),

        (0x3000, 0x00, mov_m_cr_gr(16, IA64_CR_SAPIC_IVR),
         nop_i(), nop_i()),
        (0x3010, 0x02, mov_m_ar_gr(17, 44), nop_i(), nop_i()),
        (0x3020, *movl_mlx(20, IA64_ITC_TICKS_PER_MILLISECOND)),
        (0x3030, 0x00, nop_m(), add(17, 17, 20), nop_i()),
        (0x3040, 0x00, mov_m_gr_cr(17, IA64_CR_ITM), nop_i(), nop_i()),
        (0x3050, *movl_mlx(18, 0x8010)),
        (0x3060, 0x00, ld8(19, 18), nop_i(), nop_i()),
        (0x3070, 0x00, nop_m(), adds(19, 1, 19), nop_i()),
        (0x3080, 0x00, st8(18, 19), adds(21, 0x55, 0),
         adds(22, 0x66, 0)),
        (0x3090, 0x10, mov_m_gr_cr(0, IA64_CR_SAPIC_EOI), nop_i(),
         rfi_b()),
    ], entry=0x10, terminal_ip=0x2040, timeout=8.0)
    state = result.state
    expected = iterations & 0xffff
    if (state.ip != 0x2040 or
        state.exception != IA64_EXCP_NONE or
        state.psr != IA64_PSR_IC | IA64_PSR_BN or
        state.gr[8] != expected or
        state.gr[9] < 1):
        raise RuntimeError(
            "timer_interrupt_preserves_banked_word_rmw failed: "
            f"counter={state.gr[8]!r} expected={expected!r} "
            f"interrupts={state.gr[9]!r} ip={state.ip!r} "
            f"exception={state.exception!r}\n{result.register_output}")


def test_timer_cover_rfi_preserves_large_frame_halfword_rmw(qemu):
    result = run_program(qemu, [
        # Place a 73-register frame beside an RNAT collection boundary.
        # Derive r91 from a movl temporary exactly as the page-table mapping
        # helper derives its PFN-database bias.  Recompute r44 from that high
        # local for every interrupted RMW so an RSE restore cannot silently
        # preserve the cached address while corrupting the bias itself.
        (0x10, *movl_mlx(2, 0x1001e8)),
        (0x20, 0x00, mov_ar(2, 18), nop_i(), nop_i()),
        (0x30, 0x00, nop_m(), alloc(100, 73, 70, 0, 0), nop_i()),
        (0x40, *movl_mlx(80, 0x7ff8)),
        (0x50, 0x01, nop_m(), adds(91, 8, 80), nop_i()),
        (0x60, 0x00, st2(91, 0), nop_i(), nop_i()),
        (0x70, *movl_mlx(13, 0x8010)),
        (0x80, 0x00, st8(13, 0), nop_i(), nop_i()),
        (0x90, *movl_mlx(5, 0x8020)),
        (0xa0, 0x00, st8(5, 0), nop_i(), nop_i()),
        (0xb0, 0x02, mov_m_ar_gr(3, 44), nop_i(), nop_i()),
        (0xc0, 0x00,
         addl(4, 10 * IA64_ITC_TICKS_PER_MILLISECOND, 3),
         nop_i(), nop_i()),
        (0xd0, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(), nop_i()),
        (0xe0, 0x00, adds(3, 0xef, 0), nop_i(), nop_i()),
        (0xf0, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(), nop_i()),
        (0x100, *movl_mlx(7, IA64_PSR_IC | IA64_PSR_I | IA64_PSR_BN)),
        (0x110, 0x10, nop_m(), nop_i(), bsw1()),
        (0x120, 0x08, mov_gr_psr_full(7), srlz_d(), nop_i()),
        (0x130, 0x00, nop_m(), adds(47, 0, 0), nop_i()),
        (0x140, 0x10, nop_m(), nop_i(), br_cond(0x140, 0x1fb0)),

        # Match the non-atomic page-table entry accounting sequence.  The
        # unfinished instruction group crosses an 8 KiB boundary between
        # the checked load/add and store, making an interrupt there
        # deterministic once the timer is due.
        (0x1fb0, 0x01, nop_m(), adds(44, 0, 91), nop_i()),
        (0x1fc0, 0x03, ld2_sa(29, 44), nop_i(), nop_i()),
        (0x1fd0, 0x01, nop_m(), nop_i(), nop_i()),
        (0x1fe0, 0x01, nop_m(), nop_i(), nop_i()),
        (0x1ff0, 0x00, ld2_c_clr(29, 44), adds(31, 1, 29),
         addl(52, 2, 0)),
        (0x2000, 0x0b, adds(47, 1, 47), st2(44, 31), nop_i()),
        (0x2010, 0x00, ld8(9, 13), nop_i(), nop_i()),
        (0x2020, 0x01, nop_m(), cmp4_eq_imm(6, 7, 0, 9), nop_i()),
        (0x2030, 0x10, nop_m(), nop_i(),
         br_cond(0x2030, 0x1fb0, qp=6)),
        (0x2040, 0x00, rsm(IA64_PSR_I), nop_i(), nop_i()),
        (0x2050, 0x00, ld2(8, 44), adds(10, 0, 44),
         adds(11, 0, 47)),
        (0x2060, 0x00, ld8(12, 5), adds(14, 0, 91), nop_i()),
        (0x2070, 0x10, nop_m(), nop_i(), br_cond(0x2070, 0x2070)),

        # A realistic low-level handler covers the interrupted frame, calls
        # code with a full-size nested frame (forcing RSE spill/reload),
        # unwinds to the vector's zero frame, and only then executes rfi.
        (0x3000, 0x18, nop_m(), nop_m(), cover_b()),
        (0x3010, 0x00, mov_m_ar_gr(20, 64), nop_i(), nop_i()),
        (0x3020, 0x10, nop_m(), nop_i(),
         br_call(0, 0x3020, 0x4000)),
        (0x3030, 0x00, mov_m_gr_ar(20, 64), nop_i(), nop_i()),
        (0x3040, 0x10, mov_m_gr_cr(0, IA64_CR_SAPIC_EOI), nop_i(),
         rfi_b()),

        (0x4000, 0x00, nop_m(), alloc(36, 96, 88, 0, 0), nop_i()),
        (0x4010, 0x00, mov_m_cr_gr(16, IA64_CR_SAPIC_IVR), nop_i(),
         nop_i()),
        (0x4020, 0x00, mov_m_cr_gr(21, 19), nop_i(), nop_i()),
        (0x4030, *movl_mlx(23, 0x2000)),
        (0x4040, 0x01, nop_m(), cmp4_eq_unc_imm(6, 7, 0, 0),
         nop_i()),
        (0x4050, 0x01, nop_m(), cmp_eq_and(6, 7, 23, 21), nop_i()),
        (0x4060, 0x02, mov_m_ar_gr(17, 44), nop_i(), nop_i()),
        (0x4070, *movl_mlx(24, 10 * IA64_ITC_TICKS_PER_MILLISECOND)),
        (0x4080, 0x00, nop_m(), add(17, 17, 24), nop_i()),
        (0x4090, 0x00, mov_m_gr_cr(17, IA64_CR_ITM), nop_i(), nop_i()),
        (0x40a0, *movl_mlx(22, 0x8020)),
        (0x40b0, 0x00, st8(22, 21, qp=6), nop_i(), nop_i()),
        (0x40c0, *movl_mlx(18, 0x8010)),
        (0x40d0, 0x00, ld8(19, 18, qp=6), nop_i(), nop_i()),
        (0x40e0, 0x00, nop_m(), adds(19, 1, 19, qp=6), nop_i()),
        (0x40f0, 0x00, st8(18, 19, qp=6), nop_i(), nop_i()),
        (0x4100, 0x00, mov_m_gr_ar(36, 64), nop_i(), nop_i()),
        (0x4110, 0x10, nop_m(), nop_i(), br_ret(0)),
    ], entry=0x10, terminal_ip=0x2070, timeout=10.0,
       alat=None, smp="4")
    state = result.state
    expected = state.gr[11] & 0xffff
    if (state.ip != 0x2070 or
        state.exception != IA64_EXCP_NONE or
        state.psr != IA64_PSR_IC | IA64_PSR_BN or
        state.gr[8] != expected or
        state.gr[9] < 1 or
        state.gr[10] != 0x8000 or
        state.gr[14] != 0x8000 or
        state.gr[12] != 0x2000 or
        state.cfm.get("sof") != 73 or
        state.cfm.get("sol") != 70):
        raise RuntimeError(
            "timer_cover_rfi_preserves_large_frame_halfword_rmw failed: "
            f"counter={state.gr[8]!r} expected={expected!r} "
            f"interrupts={state.gr[9]!r} address={state.gr[10]!r} "
            f"bias={state.gr[14]!r} "
            f"iip={state.gr[12]!r} "
            f"sof={state.cfm.get('sof')!r} sol={state.cfm.get('sol')!r} "
            f"ip={state.ip!r} exception={state.exception!r}\n"
            f"{result.register_output}")


def test_rse_large_frame_timer_rfi_preserves_high_caller_local(qemu):
    sentinels = {
        53: 0x1111111111111153,
        54: 0x2222222222222254,
        55: 0x3333333333333355,
        76: 0x4444444444444476,
        91: 0x5555555555555591,
        98: 0x6666666666666698,
    }
    iterations = 0x100001
    result = run_program(qemu, [
        (0x10, *movl_mlx(2, 0x100000)),
        (0x20, 0x00, mov_ar(2, 18), nop_i(), nop_i()),
        # Shift the caller's bottom-of-frame before constructing the exact
        # 73-register kernel frame.  Its high locals then wrap around the
        # 96-entry physical stacked-register file.
        (0x30, 0x00, nop_m(), alloc(40, 45, 41, 0, 0), nop_i()),
        (0x40, 0x10, nop_m(), nop_i(), br_call(0, 0x40, 0x100)),

        (0x100, 0x00, nop_m(), alloc(100, 73, 70, 0, 0), nop_i()),
        (0x110, *movl_mlx(53, sentinels[53])),
        (0x120, *movl_mlx(54, sentinels[54])),
        (0x130, *movl_mlx(55, sentinels[55])),
        (0x140, *movl_mlx(76, sentinels[76])),
        (0x150, *movl_mlx(91, sentinels[91])),
        (0x160, *movl_mlx(98, sentinels[98])),
        (0x170, *movl_mlx(3, 0x8010)),
        (0x180, 0x00, st8(3, 0), nop_i(), nop_i()),
        (0x190, 0x00, nop_m(), nop_i(), nop_i()),
        (0x1a0, 0x10, nop_m(), nop_i(), br_call(0, 0x1a0, 0x300)),
        (0x1b0, 0x00, ld8(2, 3), adds(8, 0, 53), adds(9, 0, 54)),
        (0x1c0, 0x00, nop_m(), adds(10, 0, 55), adds(11, 0, 76)),
        (0x1d0, 0x00, nop_m(), adds(14, 0, 91), adds(15, 0, 98)),
        (0x1e0, 0x10, nop_m(), nop_i(), br_cond(0x1e0, 0x1e0)),

        (0x300, 0x00, nop_m(), alloc(36, 96, 88, 0, 0), nop_i()),
        (0x310, 0x02, mov_m_ar_gr(2, 44), nop_i(), nop_i()),
        (0x320, 0x00,
         addl(4, IA64_ITC_TICKS_PER_MILLISECOND, 2), nop_i(), nop_i()),
        (0x330, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(), nop_i()),
        (0x340, 0x00, adds(4, 0xef, 0), nop_i(), nop_i()),
        (0x350, 0x00, mov_m_gr_cr(4, IA64_CR_ITV), nop_i(), nop_i()),
        (0x360, *movl_mlx(8, iterations - 1)),
        (0x370, 0x02, nop_m(), mov_lc_gr(8), nop_i()),
        (0x380, *movl_mlx(7, (1 << 13) | (1 << 14) | (1 << 44))),
        (0x390, 0x08, mov_gr_psr_full(7), srlz_d(), nop_i()),
        (0x3a0, 0x10, nop_m(), adds(10, 1, 10),
         br_cloop(0x3a0, 0x3a0)),
        (0x3b0, 0x00, rsm(1 << 14), nop_i(), nop_i()),
        (0x3c0, 0x00, mov_m_gr_ar(36, 64), nop_i(), nop_i()),
        (0x3d0, 0x10, nop_m(), nop_i(), br_ret(0)),

        (0x3000, 0x00, mov_m_cr_gr(16, IA64_CR_SAPIC_IVR),
         nop_i(), nop_i()),
        (0x3010, 0x02, mov_m_ar_gr(17, 44), nop_i(), nop_i()),
        (0x3020, *movl_mlx(20, IA64_ITC_TICKS_PER_MILLISECOND)),
        (0x3030, 0x00, nop_m(), add(17, 17, 20), nop_i()),
        (0x3040, 0x00, mov_m_gr_cr(17, IA64_CR_ITM), nop_i(), nop_i()),
        (0x3050, *movl_mlx(18, 0x8010)),
        (0x3060, 0x00, ld8(19, 18), nop_i(), nop_i()),
        (0x3070, 0x00, nop_m(), adds(19, 1, 19), nop_i()),
        (0x3080, 0x00, st8(18, 19), nop_i(), nop_i()),
        (0x3090, 0x10, mov_m_gr_cr(0, IA64_CR_SAPIC_EOI), nop_i(),
         rfi_b()),
    ], entry=0x10, terminal_ip=0x1e0, timeout=8.0)
    state = result.state
    observed = {
        53: state.gr[8],
        54: state.gr[9],
        55: state.gr[10],
        76: state.gr[11],
        91: state.gr[14],
        98: state.gr[15],
    }
    if (state.ip != 0x1e0 or
        state.exception != IA64_EXCP_NONE or
        observed != sentinels or
        state.gr[2] < 1 or
        state.cfm.get("sof") != 73 or
        state.cfm.get("sol") != 70):
        raise RuntimeError(
            "rse_large_frame_timer_rfi_preserves_high_caller_local failed: "
            f"caller_locals={observed!r} expected={sentinels!r} "
            f"interrupts={state.gr[2]!r} sof={state.cfm.get('sof')!r} "
            f"sol={state.cfm.get('sol')!r} ip={state.ip!r} "
            f"exception={state.exception!r}\n{result.register_output}")

def test_timer_interrupt_exits_chained_loop_after_virtual_deadline(qemu):
    result = run_program(qemu, [
        (0x10, 0x02, mov_m_ar_gr(3, 44), nop_i(),
         nop_i()),
        (0x20, 0x00, addl(4, 10 * IA64_ITC_TICKS_PER_MILLISECOND, 3),
         nop_i(), nop_i()),
        (0x30, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x40, 0x00, adds(3, 0xef, 0), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x60, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0x70, 0x08, mov_gr_psr_full(19), srlz_d(),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
        (0x3000, 0x02, mov_m_cr_gr(30, IA64_CR_ITM),
         nop_i(), nop_i()),
        (0x3010, 0x02, mov_m_ar_gr(31, 44),
         nop_i(), nop_i()),
        (0x3020, 0x10, nop_m(), nop_i(),
         br_cond(0x3020, 0x3020)),
    ], entry=0x10, terminal_ip=0x3020,
       poll_initial_s=0.100, poll_max_s=0.100)
    state = result.state
    delta = state.gr[31] - state.gr[30]
    if (state.ip != 0x3020 or
        state.exception != IA64_EXCP_NONE or
        state.gr[31] < state.gr[30] or
        delta > 100 * IA64_ITC_TICKS_PER_MILLISECOND or
        result.polls != 1):
        raise RuntimeError(
            "timer_interrupt_exits_chained_loop_after_virtual_deadline "
            f"failed: itm={state.gr[30]!r} itc={state.gr[31]!r} "
            f"delta={delta!r} polls={result.polls} ip={state.ip!r} "
            f"exception={state.exception!r}\n{result.register_output}")

test_async_timer_interrupt_preserves_bank1_grs = require_registers(
    "async_timer_interrupt_preserves_bank1_grs", [
        (0x10, *movl_mlx(16, 0x1116)),
        (0x20, *movl_mlx(27, 0x1127)),
        (0x30, 0x10, nop_m(), nop_i(),
         bsw1()),
        (0x40, *movl_mlx(16, 0x2216)),
        (0x50, *movl_mlx(27, 0x2227)),
        (0x60, 0x00, adds(3, 0xef, 0), nop_i(),
         nop_i()),
        (0x70, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x80, 0x00, mov_m_gr_ar(0, 44), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(0, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0xa0, *movl_mlx(19, (1 << 13) | (1 << 14) | (1 << 44))),
        (0xb0, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0xb0, 0xb0)),
        (0x3000, 0x00, mov_m_cr_gr(5, IA64_CR_SAPIC_IVR), nop_i(),
         nop_i()),
        (0x3010, *movl_mlx(16, 0xa016)),
        (0x3020, *movl_mlx(27, 0xa027)),
        (0x3030, 0x10, nop_m(), nop_i(),
         bsw1()),
        (0x3040, 0x00, nop_m(), adds(2, 0, 16),
         nop_i()),
        (0x3050, 0x00, nop_m(), adds(3, 0, 27),
         nop_i()),
        (0x3060, 0x10, nop_m(), nop_i(),
         bsw0()),
        (0x3070, *movl_mlx(4, 0x100)),
        (0x3080, 0x00, mov_m_gr_cr(4, 19), nop_i(),
         nop_i()),
        (0x3090, 0x10, mov_m_gr_cr(0, IA64_CR_SAPIC_EOI), nop_i(),
         rfi_b()),
        (0x100, 0x00, nop_m(), adds(8, 0, 16),
         nop_i()),
        (0x110, 0x00, nop_m(), adds(9, 0, 27),
         nop_i()),
        (0x120, 0x10, nop_m(), nop_i(),
         br_cond(0x120, 0x120)),
    ], {
        "ip": 0x120,
        "exception": IA64_EXCP_NONE,
        "psr": (1 << 13) | (1 << 14) | (1 << 44),
        "r2": 0x2216,
        "r3": 0x2227,
        "r8": 0x2216,
        "r9": 0x2227,
        "r16": 0x2216,
        "r27": 0x2227,
    }, entry=0x10)

test_tpr_preserves_mmi_and_mic = require_registers(
    "tpr_preserves_mmi_and_mic", [
        (0x10, *movl_mlx(3, 0x12345678900100ff)),
        (0x20, 0x00, mov_m_gr_cr(3, IA64_CR_SAPIC_TPR), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_cr_gr(31, IA64_CR_SAPIC_TPR), nop_i(),
         nop_i()),
        (0x40, 0x10, nop_m(), nop_i(),
         br_cond(0x40, 0x40)),
    ], {
        "ip": 0x40,
        "exception": IA64_EXCP_NONE,
        "r31": IA64_TPR_MMI | 0xf0,
    }, entry=0x10)

test_tpr_mmi_masks_timer_until_cleared = require_registers(
    "tpr_mmi_masks_timer_until_cleared", [
        (0x10, *movl_mlx(3, IA64_TPR_MMI)),
        (0x20, 0x00, mov_m_gr_cr(3, IA64_CR_SAPIC_TPR), nop_i(),
         nop_i()),
        (0x30, 0x00, adds(4, 0xef, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(4, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_ar(0, 44), nop_i(),
         nop_i()),
        (0x60, 0x00, mov_m_gr_cr(0, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0x80, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x90, 0x00, nop_m(), adds(8, 0x2a, 0),
         nop_i()),
        (0xa0, 0x00, mov_m_gr_cr(0, IA64_CR_SAPIC_TPR), nop_i(),
         nop_i()),
        (0xb0, 0x10, nop_m(), nop_i(),
         br_cond(0xb0, 0xb0)),
        (0x3000, 0x10, nop_m(), adds(31, 0x63, 0),
         br_cond(0x3000, 0x3010)),
        (0x3010, 0x10, nop_m(), nop_i(),
         br_cond(0x3010, 0x3010)),
    ], {
        "ip": 0x3010,
        "exception": IA64_EXCP_NONE,
        "r8": 0x2a,
        "r31": 0x63,
    }, entry=0x10)

def sapic_nested_timer_priority_program(first_vector, second_vector):
    psr_ic_i = (1 << 13) | (1 << 14)

    return [
        (0x10, *movl_mlx(3, first_vector)),
        (0x20, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_ar(4, 44), nop_i(),
         nop_i()),
        (0x40, 0x00, adds(4, 0x1000, 4), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x60, *movl_mlx(19, psr_ic_i)),
        (0x70, 0x08, mov_gr_psr_full(19), srlz_d(),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
        (0x3000, 0x00, mov_m_cr_gr(5, IA64_CR_SAPIC_IVR),
         adds(31, 1, 31), nop_i()),
        (0x3010, 0x00, nop_m(), cmp4_eq_imm(6, 7, 1, 31),
         nop_i()),
        (0x3020, 0x10, nop_m(), nop_i(),
         br_cond(0x3020, 0x3100, qp=7)),
        (0x3030, *movl_mlx(3, second_vector)),
        (0x3040, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x3050, 0x00, mov_m_gr_ar(4, 44), nop_i(),
         nop_i()),
        (0x3060, 0x00, adds(4, 0x1000, 4), nop_i(),
         nop_i()),
        (0x3070, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x3080, *movl_mlx(19, psr_ic_i)),
        (0x3090, 0x08, mov_gr_psr_full(19), srlz_d(),
         nop_i()),
        (0x30a0, 0x10, nop_m(), nop_i(),
         br_cond(0x30a0, 0x30a0)),
        (0x3100, 0x00, nop_m(), adds(8, 0x5a, 0),
         nop_i()),
        (0x3110, 0x10, nop_m(), nop_i(),
         br_cond(0x3110, 0x3110)),
    ]

test_sapic_extint_masks_external_until_eoi = require_registers(
    "sapic_extint_masks_external_until_eoi",
    sapic_nested_timer_priority_program(0x00, 0xf0),
    {
        "ip": 0x30a0,
        "exception": IA64_EXCP_NONE,
        "r5": 0x00,
        "r8": 0,
        "r31": 1,
    }, entry=0x10)

test_sapic_same_class_higher_vector_preempts = require_registers(
    "sapic_same_class_higher_vector_preempts",
    sapic_nested_timer_priority_program(0xf0, 0xf1),
    {
        "ip": 0x3110,
        "exception": IA64_EXCP_NONE,
        "r5": 0xf1,
        "r8": 0x5a,
        "r31": 2,
    }, entry=0x10)

test_masked_itv_discards_due_timer = require_registers(
    "masked_itv_discards_due_timer", [
        (0x10, *movl_mlx(3, IA64_VECTOR_MASKED | 0xef)),
        (0x20, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_ar(0, 44), nop_i(),
         nop_i()),
        (0x40, *movl_mlx(4, 0x1000)),
        (0x50, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x60, *movl_mlx(8, 0x10000)),
        (0x70, 0x02, nop_m(), mov_lc_gr(8),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cloop(0x80, 0x80)),
        (0x90, 0x00, adds(3, 0xef, 0), nop_i(),
         nop_i()),
        (0xa0, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0xb0, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0xc0, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(),
         br_cond(0xd0, 0xd0)),
        (0x3000, 0x10, nop_m(), adds(31, 0x64, 0),
         br_cond(0x3000, 0x3000)),
    ], {
        "ip": 0xd0,
        "exception": IA64_EXCP_NONE,
        "r31": 0,
    }, entry=0x10)

test_invalid_itv_vector_is_ignored = require_registers(
    "invalid_itv_vector_is_ignored", [
        (0x10, *movl_mlx(3, 1)),
        (0x20, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_ar(0, 44), nop_i(),
         nop_i()),
        (0x40, *movl_mlx(4, 0x1000)),
        (0x50, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x60, *movl_mlx(8, 0x10000)),
        (0x70, 0x02, nop_m(), mov_lc_gr(8),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cloop(0x80, 0x80)),
        (0x90, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0xa0, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0xb0, 0x10, nop_m(), nop_i(),
         br_cond(0xb0, 0xb0)),
        (0x3000, 0x10, nop_m(), adds(31, 0x66, 0),
         br_cond(0x3000, 0x3000)),
    ], {
        "ip": 0xb0,
        "exception": IA64_EXCP_NONE,
        "r31": 0,
    }, entry=0x10)

test_past_itm_does_not_fire = require_registers(
    "past_itm_does_not_fire", [
        (0x10, *movl_mlx(4, 0x200000)),
        (0x20, 0x00, adds(3, 0xef, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_ar(4, 44), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(0, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x60, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0x70, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0x70, 0x80)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
        (0x3000, 0x10, nop_m(), adds(31, 0x55, 0),
         br_cond(0x3000, 0x3000)),
    ], {
        "ip": 0x80,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_past_rearmed_itm_does_not_interrupt = require_registers(
    "past_rearmed_itm_does_not_interrupt", [
        (0x10, 0x00, adds(3, 0xef, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_ar(0, 44), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(0, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x50, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0x60, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0x60, 0x70)),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x3000, 0x00, mov_m_cr_gr(5, IA64_CR_SAPIC_IVR),
         adds(31, 1, 31),
         nop_i()),
        (0x3010, 0x00, nop_m(), cmp4_eq_imm(6, 7, 1, 31),
         nop_i()),
        (0x3020, 0x10, nop_m(), nop_i(),
         br_cond(0x3020, 0x3080, qp=7)),
        (0x3030, *movl_mlx(4, 0x200000)),
        (0x3040, 0x00, mov_m_gr_ar(4, 44), nop_i(),
         nop_i()),
        (0x3050, *movl_mlx(6, 0x100)),
        (0x3060, 0x00, mov_m_gr_cr(6, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x3070, 0x10, mov_m_gr_cr(0, IA64_CR_SAPIC_EOI), nop_i(),
         rfi_b()),
        (0x3080, 0x00, mov_m_gr_cr(0, IA64_CR_SAPIC_EOI),
         adds(8, 0x2a, 0),
         nop_i()),
        (0x3090, 0x10, nop_m(), nop_i(),
         br_cond(0x3090, 0x3090)),
    ], {
        "ip": 0x70,
        "exception": IA64_EXCP_NONE,
        "r31": 1,
    }, entry=0x10)

test_future_itm_rearm_preserves_pended_timer_irr = require_registers(
    "future_itm_rearm_preserves_pended_timer_irr", [
        (0x10, 0x00, adds(3, 0xef, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_ar(4, 44), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x50, *movl_mlx(5, 0x100000000)),
        (0x60, 0x00, add(5, 4, 5), nop_i(),
         nop_i()),
        (0x70, 0x00, mov_m_gr_cr(5, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x80, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0x90, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0xa0, 0x10, nop_m(), adds(8, 0x2a, 0),
         br_cond(0xa0, 0xa0)),
        (0x3000, 0x10, nop_m(), adds(31, 0x66, 0),
         br_cond(0x3000, 0x3010)),
        (0x3010, 0x10, nop_m(), nop_i(),
         br_cond(0x3010, 0x3010)),
    ], {
        "ip": 0x3010,
        "exception": IA64_EXCP_NONE,
        "r31": 0x66,
    }, entry=0x10)

test_masking_itv_preserves_pended_timer_irr = require_registers(
    "masking_itv_preserves_pended_timer_irr", [
        (0x10, 0x00, adds(3, 0xef, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_ar(4, 44), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x50, *movl_mlx(3, IA64_VECTOR_MASKED | 0xef)),
        (0x60, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0x80, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x90, 0x10, nop_m(), adds(8, 0x2a, 0),
         br_cond(0x90, 0x90)),
        (0x3000, 0x10, nop_m(), adds(31, 0x67, 0),
         br_cond(0x3000, 0x3010)),
        (0x3010, 0x10, nop_m(), nop_i(),
         br_cond(0x3010, 0x3010)),
    ], {
        "ip": 0x3010,
        "exception": IA64_EXCP_NONE,
        "r31": 0x67,
    }, entry=0x10)

INTERRUPTION_PSR_INPUT = (
    IA64_PSR_UP | IA64_PSR_MFL | IA64_PSR_MFH |
    IA64_PSR_AC | IA64_PSR_IC | IA64_PSR_I | IA64_PSR_PK |
    IA64_PSR_DFL | IA64_PSR_DFH | IA64_PSR_SP |
    IA64_PSR_DI | IA64_PSR_SI | IA64_PSR_DT | IA64_PSR_RT |
    IA64_PSR_MC
)

INTERRUPTION_PSR_EXPECTED = (
    IA64_PSR_BE | IA64_PSR_UP | IA64_PSR_MFL | IA64_PSR_MFH |
    IA64_PSR_PK | IA64_PSR_DT | IA64_PSR_PP | IA64_PSR_RT |
    IA64_PSR_MC
)

test_exception_entry_initializes_psr = require_registers(
    "exception_entry_initializes_psr", [
        (0x10, *movl_mlx(16, IA64_DCR_BE | IA64_DCR_PP)),
        (0x20, *movl_mlx(19, INTERRUPTION_PSR_INPUT)),
        (0x30, 0x00, mov_m_gr_cr(16, 0), adds(31, 0x60, 0),
         nop_i()),
        *rfi_to_gr(0x40, 19, 31),
        (0x60, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x70, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR, 0x00, mov_m_psr_gr(29), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x10, 0x00, mov_m_cr_gr(30, 16),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x20, IA64_BREAK_VECTOR + 0x20)),
    ], {
        "ip": IA64_BREAK_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r29": INTERRUPTION_PSR_EXPECTED,
        "r30": INTERRUPTION_PSR_INPUT,
    }, entry=0x10)

test_mov_pkr_does_not_alias_interruption_crs = require_registers(
    "mov_pkr_does_not_alias_interruption_crs", [
        (0x10, 0x00, addl(2, 0x1234, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, mov_m_gr_cr(2, 19), nop_i(),
         nop_i()),
        (0x30, 0x00, addl(3, 0x103, 0), addl(4, 0x5601, 0),
         nop_i()),
        (0x40, 0x00, mov_pkr_indexed(3, 4, bit36=1), nop_i(),
         nop_i()),
        (0x50, 0x09, mov_m_cr_gr(5, 19), mov_pkr_indexed_read(6, 3, bit36=1),
         nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
    ], {
        "ip": 0x60,
        "exception": IA64_EXCP_NONE,
        "r5": 0x1234,
        "r6": 0x5601,
    }, entry=0x10)

test_rfi_resumes_at_ipsr_ri_slot = require_registers(
    "rfi_resumes_at_ipsr_ri_slot", [
        (0x10, *movl_mlx(19, 1 << 41)),
        (0x20, *movl_mlx(20, 0x60)),
        (0x30, 0x00, mov_m_gr_cr(19, 16), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         rfi_b()),
        (0x60, 0x10, adds(30, 0x11, 0), adds(31, 0x22, 0),
         br_cond(0x60, 0x70)),
        (0x70, 0x00, mov_m_psr_gr(29), nop_i(),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
    ], {
        "ip": 0x80,
        "exception": IA64_EXCP_NONE,
        "r29": 0,
        "r30": 0,
        "r31": 0x22,
    }, entry=0x10)

test_mov_from_psr_does_not_copy_execution_slot_to_rfi = require_registers(
    "mov_from_psr_does_not_copy_execution_slot_to_rfi", [
        (0x10, *movl_mlx(20, 0x60)),
        (0x20, 0x08, nop_m(), mov_m_psr_gr(19), nop_i()),
        (0x30, 0x08, mov_m_gr_cr(19, 16), mov_m_gr_cr(20, 19),
         nop_i()),
        (0x40, 0x10, nop_m(), nop_i(), rfi_b()),
        (0x60, 0x10, adds(30, 0x11, 0), adds(31, 0x22, 0),
         br_cond(0x60, 0x70)),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
    ], {
        "ip": 0x70,
        "exception": IA64_EXCP_NONE,
        "r19": 0,
        "r30": 0x11,
        "r31": 0x22,
    }, entry=0x10)

test_rfi_ignores_iip_low_bits = require_registers(
    "rfi_ignores_iip_low_bits", [
        (0x10, *movl_mlx(19, 1 << 41)),
        (0x20, *movl_mlx(20, 0x6f)),
        (0x30, 0x00, mov_m_gr_cr(19, 16), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         rfi_b()),
        (0x60, 0x10, adds(30, 0x11, 0), adds(31, 0x22, 0),
         br_cond(0x60, 0x70)),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
    ], {
        "ip": 0x70,
        "exception": IA64_EXCP_NONE,
        "r30": 0,
        "r31": 0x22,
    }, entry=0x10)

# ── Exception tests ──

test_exception_break = require_exception("exception_break", [
    (0x10, 0x11, nop_m(), break_m(0x42), nop_m()),
], IA64_EXCP_BREAK, fault_ip=0x10, fault_imm=0x42)

test_exception_syscall_break = require_exception("exception_syscall_break", [
    (0x10, 0x11, nop_m(), pal_break(), nop_m()),
], IA64_EXCP_BREAK, fault_ip=0x10, fault_imm=0x100000)

test_exception_break_f = require_exception("exception_break_f", [
    (0x10, 0x0d, nop_m(), break_f(0x42), nop_i()),
], IA64_EXCP_BREAK, fault_ip=0x10, fault_imm=0x42)

test_exception_break_x = require_registers("exception_break_x", [
    (0x100000, *movl_mlx(2, 1 << 13)),
    (0x100010, 0x10, mov_gr_psr_full(2), nop_i(),
     br_cond(0x100010, 0x10)),
    (0x10, *break_x_mlx(0x34b630b4b820032b)),
    (IA64_BREAK_VECTOR, 0x00, nop_m(), nop_i(), nop_i()),
    (IA64_BREAK_VECTOR + 0x10, 0x00, nop_m(), nop_i(), nop_i()),
    (IA64_BREAK_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
     br_cond(IA64_BREAK_VECTOR + 0x20, IA64_BREAK_VECTOR + 0x20)),
], {
    "ip": IA64_BREAK_VECTOR + 0x20,
    "exception": IA64_EXCP_NONE,
    "fault_ip": 0x10,
    "fault_imm": 0x34b630b4b820032b,
}, entry=0x100000)

test_exception_records_slot_ri = require_registers(
    "exception_records_slot_ri", [
        (0x10, *movl_mlx(19, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0x20, 0x30)),
        (0x30, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x40, 0x11, nop_m(), break_m(0x42), nop_m()),
        (IA64_BREAK_VECTOR, 0x00, mov_m_cr_gr(16, 16), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x10, 0x00, mov_m_cr_gr(17, 17), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x20, 0x00, mov_m_psr_gr(18), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x30, IA64_BREAK_VECTOR + 0x30)),
    ], {
        "ip": IA64_BREAK_VECTOR + 0x30,
        "exception": IA64_EXCP_NONE,
        "r16": (1 << 13) | (1 << 41),
        "r17": (1 << 41),
        "r18": 0,
    }, entry=0x10)

test_break_preserves_ifa_and_records_iim_isr = require_registers(
    "break_preserves_ifa_and_records_iim_isr", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, *movl_mlx(20, 0x1111222233334444)),
        (0x30, 0x00, mov_m_gr_cr(20, 20), nop_i(),
         nop_i()),
        (0x40, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x40, 0x50)),
        (0x50, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x60, 0x11, nop_m(), break_m(0x42), nop_m()),
        (IA64_BREAK_VECTOR, 0x00, mov_m_cr_gr(8, 20), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x10, 0x00, mov_m_cr_gr(9, 24), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x20, 0x00, mov_m_cr_gr(10, 17), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x30, IA64_BREAK_VECTOR + 0x30)),
    ], {
        "ip": IA64_BREAK_VECTOR + 0x30,
        "exception": IA64_EXCP_NONE,
        "r8": 0x1111222233334444,
        "r9": 0x42,
        "r10": (1 << 41),
    }, entry=0x10)

test_iipa_reports_previous_successful_bundle_for_slot0_fault = require_registers(
    "iipa_reports_previous_successful_bundle_for_slot0_fault", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, 0x00, nop_m(), nop_i(), nop_i()),
        (0x50, 0x00, break_m(0x42), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR, 0x00, mov_m_cr_gr(8, 22), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x10, IA64_BREAK_VECTOR + 0x10)),
    ], {
        "ip": IA64_BREAK_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r8": 0x40,
    }, entry=0x10)

test_iipa_reports_current_bundle_after_prior_slot_success = require_registers(
    "iipa_reports_current_bundle_after_prior_slot_success", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, 0x11, nop_m(), break_m(0x42), nop_m()),
        (IA64_BREAK_VECTOR, 0x00, mov_m_cr_gr(8, 22), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x10, IA64_BREAK_VECTOR + 0x10)),
    ], {
        "ip": IA64_BREAK_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r8": 0x40,
    }, entry=0x10)

test_iipa_preserved_for_rfi_to_fault = require_registers(
    "iipa_preserved_for_rfi_to_fault", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, 0x00, nop_m(), nop_i(), nop_i()),
        (0x50, 0x00, break_m(0x42), nop_i(), nop_i()),
        (0x90, 0x00, break_m(0x43), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR, 0x00, mov_m_cr_gr(9, 24), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x10, 0x00,
         cmp4_eq_unc_imm(6, 7, 0x42, 9), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x20, IA64_BREAK_VECTOR + 0x50, qp=6)),
        (IA64_BREAK_VECTOR + 0x30, 0x00, mov_m_cr_gr(8, 22), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x40, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x40, IA64_BREAK_VECTOR + 0x40)),
        (IA64_BREAK_VECTOR + 0x50, *movl_mlx(19, 1 << 13)),
        (IA64_BREAK_VECTOR + 0x60, *movl_mlx(20, 0x90)),
        (IA64_BREAK_VECTOR + 0x70, 0x00, mov_m_gr_cr(19, 16), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x80, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x90, 0x10, nop_m(), nop_i(), rfi_b()),
    ], {
        "ip": IA64_BREAK_VECTOR + 0x40,
        "exception": IA64_EXCP_NONE,
        "r8": 0x40,
    }, entry=0x10)

test_exception_clears_ifs_keeps_cfm = require_registers(
    "exception_clears_ifs_keeps_cfm", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, 0x00, alloc(38, 7, 4, 0, 0), nop_i(),
         nop_i()),
        (0x50, 0x11, nop_m(), break_m(0x42), nop_m()),
        (IA64_BREAK_VECTOR, 0x00, mov_m_cr_gr(8, 23), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x10, IA64_BREAK_VECTOR + 0x10)),
    ], {
        "ip": IA64_BREAK_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r8": 0,
        "cfm_sof": 7,
        "cfm_sol": 4,
    }, entry=0x10)

test_cover_saves_interrupted_cfm_to_ifs = require_registers(
    "cover_saves_interrupted_cfm_to_ifs", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, 0x00, alloc(38, 7, 4, 0, 0), nop_i(),
         nop_i()),
        (0x50, 0x11, nop_m(), break_m(0x42), nop_m()),
        (IA64_BREAK_VECTOR, 0x00, mov_m_cr_gr(8, 23), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         cover_b()),
        (IA64_BREAK_VECTOR + 0x20, 0x00, mov_m_cr_gr(9, 23), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x30, IA64_BREAK_VECTOR + 0x30)),
    ], {
        "ip": IA64_BREAK_VECTOR + 0x30,
        "exception": IA64_EXCP_NONE,
        "r8": 0,
        "r9": (1 << 63) | 0x207,
        "cfm_sof": 0,
        "cfm_sol": 0,
    }, entry=0x10)

test_rfi_restores_interrupted_bsp_after_cover = require_registers(
    "rfi_restores_interrupted_bsp_after_cover", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, alloc(38, 7, 4, 0, 0), nop_i(),
         nop_i()),
        (0x70, 0x00, mov_m_ar_gr(8, 17), nop_i(),
         nop_i()),
        (0x80, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_ar_gr(9, 17), nop_i(),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
        (IA64_BREAK_VECTOR, 0x10, nop_m(), nop_i(),
         cover_b()),
        (IA64_BREAK_VECTOR + 0x10, *movl_mlx(20, 0x90)),
        (IA64_BREAK_VECTOR + 0x20, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0xa0,
        "exception": IA64_EXCP_NONE,
        "r8": 0x100000,
        "r9": 0x100000,
        "cfm_sof": 7,
        "cfm_sol": 4,
    }, entry=0x10)

test_nested_exception_keeps_handler_return_state = require_registers(
    "nested_exception_keeps_handler_return_state", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, *movl_mlx(3, IA64_BREAK_VECTOR + 0x50)),
        (0x30, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x30, 0x40)),
        (0x40, 0x11, nop_m(), break_m(0x42), nop_m()),
        (IA64_BREAK_VECTOR, 0x08, nop_m(), cmp4_eq_imm(1, 2, 0, 6),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x10, IA64_BREAK_VECTOR + 0x30, qp=1)),
        (IA64_BREAK_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x20, IA64_BREAK_VECTOR + 0x70, qp=2)),
        (IA64_BREAK_VECTOR + 0x30, 0x10, mov_gr_psr_full(2), adds(6, 1, 0),
         br_cond(IA64_BREAK_VECTOR + 0x30, IA64_BREAK_VECTOR + 0x40)),
        (IA64_BREAK_VECTOR + 0x40, 0x11, nop_m(), break_m(0x43), nop_m()),
        (IA64_BREAK_VECTOR + 0x50, 0x00, mov_m_cr_gr(4, 16), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x60, 0x10, mov_m_cr_gr(5, 19), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x60, IA64_BREAK_VECTOR + 0xa0)),
        (IA64_BREAK_VECTOR + 0xa0, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0xa0, IA64_BREAK_VECTOR + 0xa0)),
        (IA64_BREAK_VECTOR + 0x70, 0x00, mov_m_gr_cr(0, 16), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x80, 0x00, mov_m_gr_cr(3, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x90, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": IA64_BREAK_VECTOR + 0xa0,
        "exception": IA64_EXCP_NONE,
        "r4": 0,
        "r5": IA64_BREAK_VECTOR + 0x50,
        "r6": 1,
    }, entry=0x10)

test_nested_exception_keeps_handler_interruption_state = require_registers(
    "nested_exception_keeps_handler_interruption_state", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, *movl_mlx(3, IA64_BREAK_VECTOR + 0x180)),
        (0x30, *movl_mlx(20, 1 << 41)),
        (0x40, 0x00, mov_m_gr_cr(20, 17), nop_i(), nop_i()),
        (0x50, *movl_mlx(20, 0x12345600 | (16 << 2))),
        (0x60, 0x00, mov_m_gr_cr(20, 21), nop_i(), nop_i()),
        (0x70, *movl_mlx(20, 0x9999aaaabbbbcccc)),
        (0x80, 0x00, mov_m_gr_cr(20, 25), nop_i(), nop_i()),
        (0x90, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x90, 0xa0)),
        (0xa0, 0x00, srlz_d(), nop_i(), nop_i()),
        (0xb0, 0x11, nop_m(), break_m(0x42), nop_m()),
        (IA64_BREAK_VECTOR, 0x08, nop_m(), cmp4_eq_imm(1, 2, 0, 31),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x10, IA64_BREAK_VECTOR + 0x30, qp=1)),
        (IA64_BREAK_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x20, IA64_BREAK_VECTOR + 0x100, qp=2)),
        (IA64_BREAK_VECTOR + 0x30, 0x10, mov_gr_psr_full(2), adds(31, 1, 0),
         br_cond(IA64_BREAK_VECTOR + 0x30, IA64_BREAK_VECTOR + 0x40)),
        (IA64_BREAK_VECTOR + 0x40, 0x00, srlz_d(), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x50, 0x11, nop_m(), break_m(0x43), nop_m()),
        (IA64_BREAK_VECTOR + 0x100, *movl_mlx(20, 1 << 42)),
        (IA64_BREAK_VECTOR + 0x110, 0x00, mov_m_gr_cr(20, 17), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x120,
         *movl_mlx(20, 0x87654300 | (20 << 2))),
        (IA64_BREAK_VECTOR + 0x130, 0x00, mov_m_gr_cr(20, 21), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x140, *movl_mlx(20, 0xdeadbeef10002500)),
        (IA64_BREAK_VECTOR + 0x150, 0x00, mov_m_gr_cr(20, 25), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x160, 0x00, mov_m_gr_cr(0, 16), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x170, 0x10, mov_m_gr_cr(3, 19), nop_i(),
         rfi_b()),
        (IA64_BREAK_VECTOR + 0x180, 0x00, mov_m_cr_gr(4, 17), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x190, 0x00, mov_m_cr_gr(5, 21), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x1a0, 0x00, mov_m_cr_gr(6, 25), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x1b0, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x1b0, IA64_BREAK_VECTOR + 0x1b0)),
    ], {
        "ip": IA64_BREAK_VECTOR + 0x1b0,
        "exception": IA64_EXCP_NONE,
        "r4": (1 << 42),
        "r5": 0x87654300 | (20 << 2),
        "r6": 0xdeadbeef10002500,
    }, entry=0x10)

test_exception_illegal = require_exception("exception_illegal", [
    (0x10, 0x11, nop_m(),
     illegal_m(), nop_m()),
], IA64_EXCP_ILLEGAL, fault_ip=0x10)

test_exception_illegal_enters_general_vector = require_registers(
        "exception_illegal_enters_general_vector", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x30)),
        (0x30, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x40, 0x11, nop_m(), illegal_m(), nop_m()),
        (IA64_GENERAL_VECTOR, 0x00, mov_m_cr_gr(8, 17), nop_i(),
         nop_i()),
        (IA64_GENERAL_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_GENERAL_VECTOR + 0x10,
                 IA64_GENERAL_VECTOR + 0x10)),
    ], {
        "ip": IA64_GENERAL_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r8": (1 << 41),
    }, entry=0x10)

test_exception_reserved_template = require_exception(
    "exception_reserved_template",
    [(0x10, 0x1f, nop_m(), nop_m(), nop_m())],
    IA64_EXCP_RESERVED_TEMPLATE, fault_ip=0x10,
)

test_exception_unaligned = require_exception(
    "exception_unaligned",
    [
        (0x10, 0x00, nop_m(), adds(3, 0xff9, 0), nop_i()),
        (0x20, 0x00, ld8(4, 3), nop_i(), nop_i()),
    ],
    IA64_EXCP_UNALIGNED, fault_ip=0x20,
)

test_exception_unaligned_sets_ifa_isr = require_registers(
    "exception_unaligned_sets_ifa_isr",
    [
        (0x10, 0x00, nop_m(), adds(3, 0xff9, 0), nop_i()),
        (0x20, 0x00, ssm(1 << 13), nop_i(), nop_i()),
        (0x30, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x40, 0x00, ld8(4, 3), nop_i(), nop_i()),
        (0x5a00, 0x00, mov_m_cr_gr(14, 20), nop_i(), nop_i()),
        (0x5a10, 0x00, mov_m_cr_gr(15, 17), nop_i(), nop_i()),
        (0x5a20, 0x10, nop_m(), nop_i(), br_cond(0x5a20, 0x5a20)),
    ],
    {"ip": 0x5a20, "r14": 0xff9, "r15": IA64_ISR_R},
)

test_exception_unaligned_slot1_uses_psr_ri = require_registers(
    "exception_unaligned_slot1_uses_psr_ri",
    [
        (0x10, 0x00, nop_m(), adds(3, 0xff9, 0), nop_i()),
        (0x20, 0x00, ssm(1 << 13), nop_i(), nop_i()),
        (0x30, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x40, 0x08, nop_m(), ld8(4, 3), nop_i()),
        (IA64_UNALIGNED_VECTOR, 0x00, mov_m_cr_gr(14, 20),
         nop_i(), nop_i()),
        (IA64_UNALIGNED_VECTOR + 0x10, 0x00, mov_m_cr_gr(15, 17),
         nop_i(), nop_i()),
        (IA64_UNALIGNED_VECTOR + 0x20, 0x00, mov_m_cr_gr(16, 19),
         nop_i(), nop_i()),
        (IA64_UNALIGNED_VECTOR + 0x30, 0x10, nop_m(), nop_i(),
         br_cond(IA64_UNALIGNED_VECTOR + 0x30,
                 IA64_UNALIGNED_VECTOR + 0x30)),
    ],
    {
        "ip": IA64_UNALIGNED_VECTOR + 0x30,
        "r14": 0xff9,
        "r15": IA64_ISR_R | (1 << IA64_ISR_EI_SHIFT),
        "r16": 0x40,
    },
)

test_counted_self_loop_fault_has_slot1_ri = require_registers(
    "counted_self_loop_fault_has_slot1_ri", [
        *dtr_setup_bundles(0x10, HIGH_TR_BASE, 0x400000),
        (0x70, *movl_mlx(3, HIGH_TR_BASE + 0xfff8)),
        (0x80, 0x00, adds(8, 1, 0), nop_i(), nop_i()),
        (0x90, 0x02, nop_m(), mov_lc_gr(8), nop_i()),
        (0xa0, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT)),
        (0xb0, 0x00, mov_gr_psr_full(19), nop_i(), nop_i()),
        (0xc0, 0x19, nop_m(), st8_postinc(3, 0, 8),
         br_cloop(0xc0, 0xc0)),
        (IA64_ALT_DTLB_VECTOR, 0x02, mov_m_cr_gr(31, 16),
         extr_u(31, 31, 41, 2), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_ALT_DTLB_VECTOR + 0x10,
                 IA64_ALT_DTLB_VECTOR + 0x10)),
    ], {
        "ip": IA64_ALT_DTLB_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r31": 1,
    }, entry=0x10)

test_rfi_to_ia32_unsupported_aborts_with_byte_ip = require_qemu_failure(
    "rfi_to_ia32_unsupported_aborts_with_byte_ip",
    [
        (0x10, *movl_mlx(2, IA64_PSR_IS)),
        (0x20, *movl_mlx(3, 0x1234567800000045)),
        *rfi_to_gr(0x30, 2, 3),
    ], [
        "IA-32 instruction set execution is not implemented",
        "IP=0x0000000000000045",
        f"PSR=0x{IA64_PSR_IS:016x}",
    ], entry=0x10, cpu="madison")

test_rfi_montecito_native_ia32_disabled_fault = require_registers(
    "rfi_montecito_native_ia32_disabled_fault", [
        (0x10, *movl_mlx(2, IA64_PSR_IS)),
        (0x20, *movl_mlx(3, 0x1234567800000045)),
        (0x30, 0x00, mov_m_gr_cr(2, 16), nop_i(), nop_i()),
        (0x40, 0x00, mov_m_gr_cr(3, 19), nop_i(), nop_i()),
        (0x50, *movl_mlx(4, IA64_PSR_IC)),
        (0x60, 0x00, mov_gr_psr_full(4), nop_i(), nop_i()),
        (0x70, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x80, 0x11, nop_m(), nop_i(), rfi_b()),
        (IA64_GENERAL_VECTOR, 0x00, mov_m_cr_gr(8, 19), nop_i(), nop_i()),
        (IA64_GENERAL_VECTOR + 0x10, 0x00, mov_m_cr_gr(9, 17), nop_i(),
         nop_i()),
        (IA64_GENERAL_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_GENERAL_VECTOR + 0x20,
                 IA64_GENERAL_VECTOR + 0x20)),
    ], {
        "ip": IA64_GENERAL_VECTOR + 0x20,
        "r8": 0x80,
        "r9": 0x40 | (2 << IA64_ISR_EI_SHIFT),
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_rfi_montecito_uncollected_transition_preserves_target = \
    require_registers(
        "rfi_montecito_uncollected_transition_preserves_target", [
            (0x10, *movl_mlx(5, 0x10000)),
            (0x20, 0x00, mov_m_gr_cr(5, 2), nop_i(), nop_i()),
            (0x30, *movl_mlx(2, IA64_PSR_IS)),
            (0x40, *movl_mlx(3, 0x1234567800000045)),
            (0x50, 0x00, mov_m_gr_cr(2, 16), nop_i(), nop_i()),
            (0x60, 0x00, mov_m_gr_cr(3, 19), nop_i(), nop_i()),
            (0x70, 0x11, nop_m(), nop_i(), rfi_b()),
            (0x15400, 0x00, mov_m_cr_gr(8, 19), nop_i(), nop_i()),
            (0x15410, 0x00, mov_m_cr_gr(9, 16), nop_i(), nop_i()),
            (0x15420, 0x00, mov_m_cr_gr(10, 17), nop_i(), nop_i()),
            (0x15430, 0x10, nop_m(), nop_i(), br_cond(0x15430, 0x15430)),
        ], {
            "ip": 0x15430,
            "r8": 0x1234567800000045,
            "r9": IA64_PSR_IS,
            "r10": 0x40 | IA64_ISR_NI | (2 << IA64_ISR_EI_SHIFT),
            "fault_code": IA64_EXCP_DISABLED_ISA_TRANSITION,
            "fault_ip": 0x70,
            "exception": IA64_EXCP_NONE,
        }, entry=0x10)

GROUP = 'interrupt'
CASE_NAMES = (

    'ar_itc_advances_in_guest_loop',
    'async_timer_interrupt_enters_ivt',
    'async_timer_interrupt_never_resumes_mlx_slot2',
    'async_timer_interrupt_preserves_bank1_grs',
    'async_timer_interrupt_records_boundary_ri',
    'break_preserves_ifa_and_records_iim_isr',
    'cloop_zero_st1_timer_interrupts_batched_loop',
    'counted_self_loop_fault_has_slot1_ri',
    'cover_saves_interrupted_cfm_to_ifs',
    'exception_break',
    'exception_break_f',
    'exception_break_x',
    'exception_clears_ifs_keeps_cfm',
    'exception_entry_initializes_psr',
    'exception_illegal',
    'exception_illegal_enters_general_vector',
    'exception_records_slot_ri',
    'exception_reserved_template',
    'exception_syscall_break',
    'exception_unaligned',
    'exception_unaligned_sets_ifa_isr',
    'exception_unaligned_slot1_uses_psr_ri',
    'future_itm_rearm_preserves_pended_timer_irr',
    'iipa_preserved_for_rfi_to_fault',
    'iipa_reports_current_bundle_after_prior_slot_success',
    'iipa_reports_previous_successful_bundle_for_slot0_fault',
    'invalid_itv_vector_is_ignored',
    'masked_itv_discards_due_timer',
    'masking_itv_preserves_pended_timer_irr',
    'mov_from_psr_does_not_copy_execution_slot_to_rfi',
    'mov_pkr_does_not_alias_interruption_crs',
    'mov_to_irr_illegal',
    'mov_to_ivr_illegal',
    'mov_to_read_only_cr_predicate_false',
    'nested_exception_keeps_handler_interruption_state',
    'nested_exception_keeps_handler_return_state',
    'past_itm_does_not_fire',
    'past_rearmed_itm_does_not_interrupt',
    'rfi_ignores_iip_low_bits',
    'rfi_restores_interrupted_bsp_after_cover',
    'rfi_resumes_at_ipsr_ri_slot',
    'rfi_retries_interrupted_current_frame_fill',
    'rfi_target_rse_fill_fault_uses_restored_psr',
    'rfi_montecito_native_ia32_disabled_fault',
    'rfi_montecito_uncollected_transition_preserves_target',
    'rfi_to_ia32_unsupported_aborts_with_byte_ip',
    'rse_large_frame_timer_rfi_preserves_high_caller_local',
    'repeated_timer_rfi_preserves_word_rmw',
    'timer_cover_rfi_preserves_large_frame_halfword_rmw',
    'timer_interrupt_preserves_banked_word_rmw',
    'sapic_extint_masks_external_until_eoi',
    'sapic_same_class_higher_vector_preempts',
    'timer_interrupt_exits_chained_loop_after_virtual_deadline',
    'tpr_mmi_masks_timer_until_cleared',
    'tpr_preserves_mmi_and_mic',
    'unimplemented_physical_instruction_traps',
)

CASE_METADATA = {
    'async_timer_interrupt_enters_ivt': CaseMetadata(nonterminal_effect_loop=True),
    'async_timer_interrupt_preserves_bank1_grs': CaseMetadata(nonterminal_effect_loop=True),
    'async_timer_interrupt_records_boundary_ri': CaseMetadata(nonterminal_effect_loop=True),
    'future_itm_rearm_preserves_pended_timer_irr': CaseMetadata(nonterminal_effect_loop=True),
    'invalid_itv_vector_is_ignored': CaseMetadata(nonterminal_effect_loop=True),
    'masked_itv_discards_due_timer': CaseMetadata(nonterminal_effect_loop=True),
    'masking_itv_preserves_pended_timer_irr': CaseMetadata(nonterminal_effect_loop=True),
    'past_itm_does_not_fire': CaseMetadata(nonterminal_effect_loop=True),
    'rfi_target_rse_fill_fault_uses_restored_psr': CaseMetadata(nonterminal_effect_loop=True),
}

CASE_ALIASES = {
}

CASES = bind_cases(GROUP, CASE_NAMES, globals(),
                   aliases=CASE_ALIASES,
                   metadata=CASE_METADATA)
