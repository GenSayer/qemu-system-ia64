/*
 * IA-64 TCG helper routines.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu-common.h"
#include "exec/cputlb.h"
#include "exec/tb-flush.h"
#include "exec/translation-block.h"
#include "exec/target_page.h"
#include "accel/tcg/cpu-ldst.h"
#include "accel/tcg/probe.h"
#include "fpu/softfloat.h"
#include "qemu/timer.h"

#define IA64_PTE_PPN_MASK 0x0003fffffffff000ULL
#define IA64_PTE_PL_SHIFT 7
#define IA64_PTE_PL_MASK  (3ULL << IA64_PTE_PL_SHIFT)
#define IA64_PTE_AR_SHIFT 9
#define IA64_PTE_AR_MASK  (7ULL << IA64_PTE_AR_SHIFT)

#define IA64_PKR_VALID    (1ULL << 0)
#define IA64_PKR_WD       (1ULL << 1)
#define IA64_PKR_RD       (1ULL << 2)
#define IA64_PKR_XD       (1ULL << 3)
#define IA64_PKR_KEY_SHIFT 8
#define IA64_PKR_KEY_MASK \
    (((1ULL << IA64_IMPL_KEY_BITS) - 1) << IA64_PKR_KEY_SHIFT)
#define IA64_PKR_MASK     (IA64_PKR_VALID | IA64_PKR_WD | IA64_PKR_RD | \
                           IA64_PKR_XD | IA64_PKR_KEY_MASK)

#define IA64_CPUID_VENDOR0           0x49656e69756e6547ULL /* "GenuineI" */
#define IA64_CPUID_VENDOR1           0x000000006c65746eULL /* "ntel" */
#define IA64_CPUID_SERIAL            0x0000000000000000ULL
#define IA64_CPUID_VERSION_ITANIUM2  0x000000001f010504ULL
#define IA64_CPUID_FEATURES          ((1ULL << 0) | (1ULL << 1) | \
                                      (1ULL << 2) | (1ULL << 32) | \
                                      (1ULL << 33))

static inline void ia64_fr_write(CPUIA64State *env, uint32_t reg,
                                 uint64_t value)
{
    if (reg > 1) {
        env->fr[reg] = value;
        env->fr_nat[reg / 64] &= ~(1ULL << (reg % 64));
        env->fr_sig[reg / 64] &= ~(1ULL << (reg % 64));
    }
}

static inline void ia64_fr_write_sig(CPUIA64State *env, uint32_t reg,
                                     uint64_t value)
{
    if (reg > 1) {
        env->fr[reg] = value;
        env->fr_nat[reg / 64] &= ~(1ULL << (reg % 64));
        env->fr_sig[reg / 64] |= 1ULL << (reg % 64);
    }
}

static void ia64_pr_write(CPUIA64State *env, uint32_t reg, bool value)
{
    if (reg != 0) {
        env->pr[reg] = value ? 1 : 0;
    }
    env->pr[0] = 1;
}

static bool ia64_fr_nat_get(const CPUIA64State *env, uint32_t reg)
{
    if (reg <= 1) {
        return false;
    }
    return (env->fr_nat[reg / 64] >> (reg % 64)) & 1;
}

static bool ia64_fr_sig_get(const CPUIA64State *env, uint32_t reg)
{
    if (reg <= 1) {
        return false;
    }
    return (env->fr_sig[reg / 64] >> (reg % 64)) & 1;
}

static bool ia64_fr_nat_any2(const CPUIA64State *env, uint32_t reg1,
                             uint32_t reg2)
{
    return ia64_fr_nat_get(env, reg1) || ia64_fr_nat_get(env, reg2);
}

static bool ia64_fr_nat_any3(const CPUIA64State *env, uint32_t reg1,
                             uint32_t reg2, uint32_t reg3)
{
    return ia64_fr_nat_any2(env, reg1, reg2) ||
           ia64_fr_nat_get(env, reg3);
}

static void ia64_fr_nat_set(CPUIA64State *env, uint32_t reg, bool nat)
{
    if (reg <= 1) {
        return;
    }

    if (nat) {
        env->fr_nat[reg / 64] |= 1ULL << (reg % 64);
        env->fr_sig[reg / 64] &= ~(1ULL << (reg % 64));
    } else {
        env->fr_nat[reg / 64] &= ~(1ULL << (reg % 64));
    }
}

static void ia64_fr_write_nat(CPUIA64State *env, uint32_t reg)
{
    if (reg > 1) {
        env->fr[reg] = 0;
        ia64_fr_nat_set(env, reg, true);
        env->fr_sig[reg / 64] &= ~(1ULL << (reg % 64));
    }
}

static bool ia64_fr_write_nat_if_any2(CPUIA64State *env, uint32_t dst,
                                      uint32_t src1, uint32_t src2)
{
    if (!ia64_fr_nat_any2(env, src1, src2)) {
        return false;
    }
    ia64_fr_write_nat(env, dst);
    return true;
}

static bool ia64_fr_write_nat_if_any3(CPUIA64State *env, uint32_t dst,
                                      uint32_t src1, uint32_t src2,
                                      uint32_t src3)
{
    if (!ia64_fr_nat_any3(env, src1, src2, src3)) {
        return false;
    }
    ia64_fr_write_nat(env, dst);
    return true;
}

static uint8_t ia64_pte_ar(uint64_t pte)
{
    return (pte & IA64_PTE_AR_MASK) >> IA64_PTE_AR_SHIFT;
}

static uint8_t ia64_pte_pl(uint64_t pte)
{
    return (pte & IA64_PTE_PL_MASK) >> IA64_PTE_PL_SHIFT;
}

static uint8_t ia64_pte_perm(uint64_t pte, uint8_t access_level)
{
    if (!(pte & IA64_PTE_PRESENT)) {
        return 0;
    }

    return ia64_tlb_effective_perm(ia64_pte_ar(pte), ia64_pte_pl(pte),
                                   access_level);
}

static uint64_t ia64_page_size_from_shift(uint64_t ps_bits)
{
    if (ps_bits < 12) {
        ps_bits = 12;
    }
    return 1ULL << ps_bits;
}

static uint64_t ia64_itir_page_size(CPUIA64State *env)
{
    uint64_t ps_bits = (env->cr_itir >> IA64_ITIR_PS_SHIFT) & IA64_ITIR_PS_MASK;

    return ia64_page_size_from_shift(ps_bits);
}

static uint64_t ia64_gr_page_size(uint64_t value)
{
    return ia64_page_size_from_shift((value >> IA64_ITIR_PS_SHIFT) &
                                     IA64_ITIR_PS_MASK);
}

static bool ia64_tlb_entry_overlaps(const IA64TlbEntry *entry,
                                    uint64_t va, uint32_t rid, uint64_t ps)
{
    uint64_t start, end, entry_start, entry_end;

    if (!entry->valid || entry->rid != rid || entry->ps == 0) {
        return false;
    }

    start = (va & IA64_REGION7_PHYS_MASK) & ~(ps - 1);
    end = start + ps - 1;
    if (end < start || end > IA64_REGION7_PHYS_MASK) {
        end = IA64_REGION7_PHYS_MASK;
    }

    entry_start = (entry->va & IA64_REGION7_PHYS_MASK) & ~(entry->ps - 1);
    entry_end = entry_start + entry->ps - 1;
    if (entry_end < entry_start || entry_end > IA64_REGION7_PHYS_MASK) {
        entry_end = IA64_REGION7_PHYS_MASK;
    }

    return start <= entry_end && entry_start <= end;
}

static void ia64_qemu_tlb_flush_entry(CPUIA64State *env,
                                      const IA64TlbEntry *entry)
{
    uint64_t base;

    if (!entry->valid || entry->ps < TARGET_PAGE_SIZE) {
        return;
    }

    base = entry->va & ~(entry->ps - 1);
    tlb_flush_range_by_mmuidx(env_cpu(env), base, entry->ps,
                              1u << MMU_IDX_VIRT, TARGET_LONG_BITS);
}

static bool ia64_data_address_to_mapped_phys(CPUIA64State *env, uint64_t va,
                                             uint64_t *pa);
static bool ia64_data_address_to_phys(CPUIA64State *env, uint64_t va,
                                      uint64_t *pa);
static bool ia64_rse_address_to_phys(CPUIA64State *env, uint64_t va,
                                     uint64_t *pa);
static uint64_t ia64_rse_mapped_bsp(CPUIA64State *env, uint64_t bsp);
static void ia64_raise_data_reference_fault_if_needed(CPUIA64State *env,
                                                      uint64_t va,
                                                      uint32_t is_write,
                                                      uint32_t is_rw,
                                                      uint8_t access_level,
                                                      bool is_non_access);
static void ia64_rse_drop_snapshots(CPUIA64State *env);
static void ia64_rse_pop_return_frame(CPUIA64State *env, uint64_t pfs,
                                      bool restore_untracked_frame);
static uint64_t ia64_rse_spill_exception_frame(CPUIA64State *env,
                                               const IA64ExceptionFrame *frame);
static uint64_t ia64_rse_bsp_advance(uint64_t bsp, uint32_t words);
static uint64_t ia64_rse_bsp_retreat(uint64_t bsp, uint32_t words);
static void ia64_rse_restore_current_frame_from_bsp(CPUIA64State *env,
                                                    uint32_t sof);
static void ia64_swap_banked_gr(CPUIA64State *env);
static void ia64_invalidate_alat_store(CPUIA64State *env, uint64_t addr,
                                       uint32_t size);
static void ia64_gr_nat_set(CPUIA64State *env, uint32_t reg, bool nat);

static uint64_t ia64_rse_canonical_bsp(CPUIA64State *env, uint64_t bsp)
{
    uint64_t pa;

    if (ia64_rse_address_to_phys(env, bsp, &pa)) {
        return pa;
    }
    return bsp;
}

static int ia64_rse_mmu_index(CPUIA64State *env)
{
    return env->psr & IA64_PSR_RT ? MMU_IDX_VIRT : MMU_PHYS_IDX;
}

static void ia64_rse_write_u64(CPUIA64State *env, uint64_t addr,
                               uint64_t value)
{
    cpu_stq_mmuidx_ra(env, addr, value, ia64_rse_mmu_index(env), GETPC());
}

static uint64_t ia64_rse_read_u64(CPUIA64State *env, uint64_t addr)
{
    return cpu_ldq_mmuidx_ra(env, addr, ia64_rse_mmu_index(env), GETPC());
}

/*
 * PAL function indices (Intel IA-64 PAL specification).
 * GR28 holds the function index on entry.
 * Results are returned in GR8 (status), GR9-GR11 (outputs).
 */
#define PAL_CACHE_FLUSH     0x0001
#define PAL_CACHE_INFO      0x0002
#define PAL_CACHE_INIT      0x0003
#define PAL_CACHE_SUMMARY   0x0004
#define PAL_MEM_ATTRIB      0x0005
#define PAL_PTCE_INFO       0x0006
#define PAL_VM_INFO         0x0007
#define PAL_VM_SUMMARY      0x0008
#define PAL_BUS_GET_FEATURES 0x0009
#define PAL_BUS_SET_FEATURES 0x000A
#define PAL_DEBUG_INFO      0x000B
#define PAL_FIXED_ADDR      0x000C
#define PAL_FREQ_BASE       0x000D
#define PAL_FREQ_RATIOS     0x000E
#define PAL_PERF_MON_INFO   0x000F
#define PAL_PLATFORM_ADDR   0x0010
#define PAL_PROC_GET_FEATURES 0x0011
#define PAL_PROC_SET_FEATURES 0x0012
#define PAL_RSE_INFO        0x0013
#define PAL_VERSION         0x0014
#define PAL_MC_CLEAR_LOG    0x0015
#define PAL_MC_DRAIN        0x0016
#define PAL_MC_EXPECTED     0x0017
#define PAL_MC_DYNAMIC_STATE 0x0018
#define PAL_MC_ERROR_INFO   0x0019
#define PAL_MC_RESUME       0x001A
#define PAL_MC_REGISTER_MEM 0x001B
#define PAL_HALT_LIGHT      0x001D
#define PAL_COPY_INFO       0x001E
#define PAL_CACHE_LINE_INIT 0x001F
#define PAL_PMI_ENTRYPOINT  0x0020
#define PAL_VM_PAGE_SIZE    0x0022
#define PAL_MEM_FOR_TEST    0x0025
#define PAL_CACHE_PROT_INFO 0x0026
#define PAL_REGISTER_INFO   0x0027
#define PAL_PREFETCH_VIS    0x0029

#define IA64_STACKED_GR_BASE   32
#define IA64_STACKED_GR_COUNT  (IA64_GR_COUNT - IA64_STACKED_GR_BASE)
#define IA64_ROTATING_FR_BASE  32
#define IA64_ROTATING_FR_COUNT (IA64_FR_COUNT - IA64_ROTATING_FR_BASE)
#define PAL_COPY_PAL       0x0100
#define PAL_HALT_INFO       0x0101
#define PAL_TEST_PROC       0x0102
#define PAL_VM_TR_READ      0x0105

#define PAL_COPY_BUFFER_SIZE  0x1000ULL
#define PAL_COPY_BUFFER_ALIGN 0x1000ULL
#define PAL_COPY_PROC_OFFSET  0
#define PAL_COPY_CODE_SIZE    0x20ULL
#define PAL_COPY_TARGET_CACHE_ATTR (1ULL << 63)
#define PAL_SELF_TEST_STATE_TESTED (1ULL << 2)
#define PAL_MEM_ATTR_WB            (1ULL << 0)
#define PAL_MEM_ATTR_VALID_MASK    0xffffULL
#define PAL_CACHE_FLUSH_OPERATION_MASK 0x3ULL
#define PAL_HALT_STATE_COUNT       8
#define PAL_HALT_STATE_IMPLEMENTED (1ULL << 60)
#define PAL_HALT_STATE_COHERENT    (1ULL << 61)
#define IA64_L0_CACHE_LINE_SIZE    64ULL
#define IA64_L1_CACHE_LINE_SIZE    128ULL
#define IA64_L2_CACHE_LINE_SIZE    128ULL

static bool pal_reserved_args_are_zero(CPUIA64State *env);

static uint64_t pal_stacked_arg(CPUIA64State *env, uint32_t arg)
{
    return env->gr[IA64_STACKED_GR_BASE + 1 + arg];
}

static void ia64_invalidate_alat_reg_range(CPUIA64State *env,
                                           uint32_t first, uint32_t last,
                                           bool fp)
{
    uint32_t i;

    for (i = 0; i < IA64_ALAT_ENTRIES; i++) {
        if (env->alat[i].valid &&
            env->alat[i].fp == fp &&
            env->alat[i].reg >= first && env->alat[i].reg < last) {
            env->alat[i].valid = false;
        }
    }
}

static bool ia64_ranges_overlap(uint64_t start, uint64_t size,
                                uint64_t other_start, uint64_t other_size)
{
    uint64_t end;
    uint64_t other_end;

    if (size == 0 || other_size == 0) {
        return false;
    }

    end = start + size - 1;
    if (end < start) {
        end = UINT64_MAX;
    }
    other_end = other_start + other_size - 1;
    if (other_end < other_start) {
        other_end = UINT64_MAX;
    }

    return start <= other_end && other_start <= end;
}

static void ia64_invalidate_alat_phys_range(CPUIA64State *env,
                                            uint64_t pa, uint64_t size)
{
    uint32_t i;

    for (i = 0; i < IA64_ALAT_ENTRIES; i++) {
        if (env->alat[i].valid &&
            ia64_ranges_overlap(pa, size, env->alat[i].phys_addr,
                                env->alat[i].size)) {
            env->alat[i].valid = false;
        }
    }
}

static void ia64_invalidate_alat_tlb_entry(CPUIA64State *env,
                                           const IA64TlbEntry *entry)
{
    if (entry->valid && entry->ps != 0) {
        ia64_invalidate_alat_phys_range(env, entry->pa, entry->ps);
    }
}

static void ia64_queue_itlb_tb_flush(CPUIA64State *env)
{
    queue_tb_flush(env_cpu(env));
}

static void ia64_invalidate_stacked_alat(CPUIA64State *env)
{
    ia64_invalidate_alat_reg_range(env, IA64_STACKED_GR_BASE, IA64_GR_COUNT,
                                   false);
}

static void ia64_invalidate_rotating_fp_alat(CPUIA64State *env)
{
    ia64_invalidate_alat_reg_range(env, IA64_ROTATING_FR_BASE, IA64_FR_COUNT,
                                   true);
}

static uint64_t ia64_current_cfm(const CPUIA64State *env)
{
    return env->cfm_sof
        | ((uint64_t)env->cfm_sol << IA64_CFM_SOL_SHIFT)
        | ((uint64_t)env->cfm_sor << IA64_CFM_SOR_SHIFT)
        | ((uint64_t)env->cfm_rrb_gr << IA64_CFM_RRB_GR_SHIFT);
}

static uint64_t ia64_current_pfs(const CPUIA64State *env)
{
    return ia64_current_cfm(env)
        | ((env->ar_ec & 0x3fULL) << IA64_PFS_PEC_SHIFT)
        | ((uint64_t)ia64_psr_cpl(env->psr) << IA64_PFS_PPL_SHIFT);
}

static void ia64_rse_resize_current_frame(CPUIA64State *env, uint32_t sof)
{
    uint32_t old_sof = env->cfm_sof;

    if (env->rse_cumulative_words >= old_sof) {
        env->rse_cumulative_words =
            env->rse_cumulative_words - old_sof + sof;
    } else {
        env->rse_cumulative_words = sof;
    }
}

static void ia64_rse_restore_exception_snapshots(CPUIA64State *env,
                                                 const IA64ExceptionFrame *frame)
{
    env->rse_frame_depth = frame->rse_frame_depth;
    env->rse_cover_depth = frame->rse_cover_depth;
    memcpy(env->rse_frame_gr, frame->rse_frame_gr,
           frame->rse_frame_depth * sizeof(env->rse_frame_gr[0]));
    memcpy(env->rse_frame_nat, frame->rse_frame_nat,
           frame->rse_frame_depth * sizeof(env->rse_frame_nat[0]));
    memcpy(env->rse_frame_sof, frame->rse_frame_sof,
           frame->rse_frame_depth * sizeof(env->rse_frame_sof[0]));
    memcpy(env->rse_frame_sol, frame->rse_frame_sol,
           frame->rse_frame_depth * sizeof(env->rse_frame_sol[0]));
    memcpy(env->rse_frame_sor, frame->rse_frame_sor,
           frame->rse_frame_depth * sizeof(env->rse_frame_sor[0]));
    memcpy(env->rse_frame_rrb_gr, frame->rse_frame_rrb_gr,
           frame->rse_frame_depth * sizeof(env->rse_frame_rrb_gr[0]));
    memcpy(env->rse_frame_bsp, frame->rse_frame_bsp,
           frame->rse_frame_depth * sizeof(env->rse_frame_bsp[0]));
    memcpy(env->rse_frame_return_ip, frame->rse_frame_return_ip,
           frame->rse_frame_depth *
           sizeof(env->rse_frame_return_ip[0]));
    memcpy(env->rse_frame_cumulative_words,
           frame->rse_frame_cumulative_words,
           frame->rse_frame_depth *
           sizeof(env->rse_frame_cumulative_words[0]));
    memcpy(env->rse_cover_gr, frame->rse_cover_gr,
           frame->rse_cover_depth * sizeof(env->rse_cover_gr[0]));
    memcpy(env->rse_cover_nat, frame->rse_cover_nat,
           frame->rse_cover_depth * sizeof(env->rse_cover_nat[0]));
    memcpy(env->rse_cover_sof, frame->rse_cover_sof,
           frame->rse_cover_depth * sizeof(env->rse_cover_sof[0]));
    memcpy(env->rse_cover_bsp, frame->rse_cover_bsp,
           frame->rse_cover_depth * sizeof(env->rse_cover_bsp[0]));
}

static bool ia64_rse_exception_top_matches_pfs(CPUIA64State *env,
                                               const IA64ExceptionFrame *frame)
{
    uint64_t pfs = env->ar_pfs;
    uint32_t depth;
    uint64_t caller_end;

    if (frame->rse_frame_depth == 0) {
        return false;
    }

    depth = frame->rse_frame_depth - 1;
    caller_end = ia64_rse_bsp_advance(frame->rse_frame_bsp[depth],
                                      frame->rse_frame_sol[depth]);

    return ia64_rse_mapped_bsp(env, caller_end) ==
           ia64_rse_mapped_bsp(env, env->ar_bsp) &&
           frame->rse_frame_sof[depth] == (pfs & IA64_CFM_SOF_MASK) &&
           frame->rse_frame_sol[depth] ==
           ((pfs & IA64_CFM_SOL_MASK) >> IA64_CFM_SOL_SHIFT) &&
           frame->rse_frame_sor[depth] ==
           ((pfs & IA64_CFM_SOR_MASK) >> IA64_CFM_SOR_SHIFT) &&
           frame->rse_frame_rrb_gr[depth] ==
           ((pfs & IA64_CFM_RRB_GR_MASK) >> IA64_CFM_RRB_GR_SHIFT);
}

#define PAL_STATUS_SUCCESS         0
#define PAL_STATUS_NOT_IMPLEMENTED (-1)
#define PAL_STATUS_INVALID_ARGUMENT (-2)
#define PAL_STATUS_ERROR           (-3)
#define PAL_STATUS_NO_INFORMATION  (-6)

void helper_raise_exception(CPUIA64State *env, uint32_t exception,
                            uint64_t fault_ip, uint64_t fault_imm,
                            uint32_t fault_slot)
{
    CPUState *cs = env_cpu(env);

    env->ip = fault_ip;
    env->fault_ip = fault_ip;
    env->fault_imm = fault_imm;
    env->fault_slot = fault_slot;
    env->exception = exception;
    cs->exception_index = exception;
    cpu_loop_exit(cs);
}

void helper_raise_unaligned(CPUIA64State *env, uint64_t addr,
                            uint64_t isr_access, uint64_t fault_ip,
                            uint32_t fault_slot)
{
    env->cr_ifa = addr;
    env->cr_isr = isr_access;
    helper_raise_exception(env, IA64_EXCP_UNALIGNED, fault_ip, 0,
                           fault_slot);
}

void helper_raise_nat_consumption(CPUIA64State *env, uint64_t isr_access,
                                  uint32_t is_non_access,
                                  uint64_t fault_ip, uint32_t fault_slot)
{
    env->cr_ifa = 0;
    env->cr_isr = (is_non_access ? IA64_ISR_NA : 0) |
                  isr_access;
    helper_raise_exception(env, IA64_EXCP_NAT_CONSUMPTION, fault_ip, 0,
                           fault_slot);
}


uint64_t helper_cmpxchg(CPUIA64State *env, uint64_t addr, uint64_t cmp,
                        uint64_t val, uint32_t size)
{
    uintptr_t ra = GETPC();
    uint64_t old;

    switch (size) {
    case 1:
        old = cpu_ldub_data_ra(env, addr, ra);
        if ((uint8_t)old == (uint8_t)cmp) {
            cpu_stb_data_ra(env, addr, val, ra);
            ia64_invalidate_alat_store(env, addr, size);
        }
        return old;
    case 2:
        old = cpu_lduw_le_data_ra(env, addr, ra);
        if ((uint16_t)old == (uint16_t)cmp) {
            cpu_stw_le_data_ra(env, addr, val, ra);
            ia64_invalidate_alat_store(env, addr, size);
        }
        return old;
    case 4:
        old = cpu_ldl_le_data_ra(env, addr, ra);
        if ((uint32_t)old == (uint32_t)cmp) {
            cpu_stl_le_data_ra(env, addr, val, ra);
            ia64_invalidate_alat_store(env, addr, size);
        }
        return old;
    case 8:
        old = cpu_ldq_le_data_ra(env, addr, ra);
        if (old == cmp) {
            cpu_stq_le_data_ra(env, addr, val, ra);
            ia64_invalidate_alat_store(env, addr, size);
        }
        return old;
    default:
        g_assert_not_reached();
    }
}

uint64_t helper_cmp8xchg16(CPUIA64State *env, uint64_t addr, uint64_t cmp,
                           uint64_t val, uint64_t csd)
{
    uintptr_t ra = GETPC();
    uint64_t base = addr & ~8ULL;
    uint64_t old;
    int mmu_idx = cpu_mmu_index(env_cpu(env), false);

    probe_write(env, base, 16, mmu_idx, ra);
    old = cpu_ldq_le_data_ra(env, addr, ra);
    if (old == cmp) {
        cpu_stq_le_data_ra(env, base, val, ra);
        cpu_stq_le_data_ra(env, base + 8, csd, ra);
        ia64_invalidate_alat_store(env, base, 16);
    }
    return old;
}

void helper_rfi(CPUIA64State *env)
{
    uint64_t ipsr = env->cr_ipsr;
    uint64_t iip = ia64_ip_bundle_addr(env->cr_iip);
    uint64_t cfm_val = env->cr_ifs;
    bool ifs_valid = cfm_val & IA64_IFS_V;

    if (ifs_valid) {
        env->cfm_sof = cfm_val & IA64_CFM_SOF_MASK;
        env->cfm_sol = (cfm_val & IA64_CFM_SOL_MASK) >> IA64_CFM_SOL_SHIFT;
        env->cfm_sor = (cfm_val & IA64_CFM_SOR_MASK) >> IA64_CFM_SOR_SHIFT;
        env->cfm_rrb_gr =
            (cfm_val & IA64_CFM_RRB_GR_MASK) >> IA64_CFM_RRB_GR_SHIFT;
    }
    if (env->excp_frame_depth > 0) {
        uint32_t depth = --env->excp_frame_depth;
        IA64ExceptionFrame *frame = &env->excp_frames[depth];
        bool same_bspstore =
            ia64_rse_mapped_bsp(env, env->ar_bspstore) ==
            ia64_rse_mapped_bsp(env, frame->bspstore);
        bool ifm_match =
            ifs_valid &&
            ((cfm_val & IA64_IFS_IFM_MASK) ==
             (frame->ifm & IA64_IFS_IFM_MASK));
        bool restore_frame =
            same_bspstore &&
            (ifm_match ||
             !ifs_valid);
        bool advanced_bspstore_return =
            frame->rse_bspstore_switched &&
            iip != frame->interrupted_iip;
        bool restore_advanced_call_cache =
            same_bspstore && ifs_valid && ifm_match &&
            advanced_bspstore_return;

        if (restore_frame && advanced_bspstore_return) {
            restore_frame = false;
        }

        if (restore_frame) {
            memcpy(&env->gr[32], frame->gr, sizeof(frame->gr));
            memcpy(env->nat, frame->nat, sizeof(frame->nat));
            env->ar_bsp = frame->bsp;
            env->ar_bspstore = frame->bspstore;
            env->ar_rnat = frame->rnat;
            env->rse_cumulative_words = frame->rse_cumulative_words;
            env->rse_spill_words = frame->rse_spill_words;
            env->rse_spill_base = frame->rse_spill_base;
            env->rse_bspstore_switched = frame->rse_bspstore_switched;
            env->rse_flushed = frame->rse_flushed;
            ia64_rse_restore_exception_snapshots(env, frame);
        } else {
            if (same_bspstore) {
                env->ar_rnat = ia64_rse_spill_exception_frame(env, frame);
            }
            ia64_rse_drop_snapshots(env);
            if (ifs_valid) {
                ia64_rse_restore_current_frame_from_bsp(env, env->cfm_sof);
            }
            if (restore_advanced_call_cache &&
                ia64_rse_exception_top_matches_pfs(env, frame)) {
                ia64_rse_restore_exception_snapshots(env, frame);
            }
        }
        env->cr_ipsr = frame->ipsr;
        env->cr_iip = frame->iip;
        env->cr_ifs = frame->ifs;
        env->cr_ifa = frame->ifa;
        env->cr_isr = frame->isr;
        env->cr_itir = frame->itir;
        env->cr_iipa = frame->iipa;
        env->cr_iim = frame->iim;
        env->cr_iha = frame->iha;
    } else {
        env->cr_ipsr = 0;
        env->cr_iip = 0;
        env->cr_ifs = 0;
    }
    env->exception = IA64_EXCP_NONE;
    env->fault_ip = 0;
    env->fault_imm = 0;
    env->fault_slot = 0;
    ia64_invalidate_stacked_alat(env);
    /*
     * RSE restore can fault; publish the restored PSR/IP only after it
     * succeeds.
     */
    ia64_set_psr(env, ipsr);
    env->ip = iip;
    helper_tlb_serialize(env, 1, 1);
    tlb_flush(env_cpu(env));
}

uint64_t helper_read_pr(CPUIA64State *env)
{
    uint64_t value = 0;

    for (uint32_t i = 0; i < IA64_PR_COUNT; i++) {
        value |= (env->pr[i] & 1) << i;
    }

    return value;
}

static void ia64_rse_trim_frames_to_bsp(CPUIA64State *env, uint64_t bsp)
{
    uint64_t trim_bsp = ia64_rse_canonical_bsp(env, bsp);

    while (env->rse_frame_depth > 0 &&
           ia64_rse_canonical_bsp(
               env, env->rse_frame_bsp[env->rse_frame_depth - 1]) > trim_bsp) {
        env->rse_frame_depth--;
    }
    while (env->rse_cover_depth > 0 &&
           ia64_rse_canonical_bsp(
               env, env->rse_cover_bsp[env->rse_cover_depth - 1]) > trim_bsp) {
        env->rse_cover_depth--;
    }
}

void helper_epc(CPUIA64State *env, uint64_t fault_ip, uint64_t raw,
                uint32_t fault_slot)
{
    uint8_t current_cpl = ia64_psr_cpl(env->psr);
    uint8_t pfs_ppl = (env->ar_pfs & IA64_PFS_PPL_MASK) >> IA64_PFS_PPL_SHIFT;
    uint8_t new_cpl = current_cpl;

    if (pfs_ppl < current_cpl) {
        helper_raise_exception(env, IA64_EXCP_ILLEGAL, fault_ip, raw,
                               fault_slot);
    }

    if (env->psr & IA64_PSR_IT) {
        uint32_t rid = ia64_region_rid(env, fault_ip);

        for (uint8_t i = 0; i < env->tlb_inst_count; i++) {
            IA64TlbEntry *entry = &env->tlb_inst[i];

            if (ia64_tlb_match(entry, fault_ip, rid, true) &&
                entry->ar == 7 && entry->pl < current_cpl) {
                new_cpl = entry->pl;
                break;
            }
        }
    } else {
        new_cpl = 0;
    }

    ia64_set_psr(env, (env->psr & ~IA64_PSR_CPL_MASK) |
                      ((uint64_t)new_cpl << IA64_PSR_CPL_SHIFT));
}

static bool ia64_rse_is_rnat_slot(uint64_t bsp)
{
    return ((bsp >> 3) & 0x3f) == 0x3f;
}

static uint64_t ia64_rse_bsp_advance(uint64_t bsp, uint32_t words)
{
    uint32_t i;

    for (i = 0; i < words; i++) {
        if (ia64_rse_is_rnat_slot(bsp)) {
            bsp += 8;
        }
        bsp += 8;
    }
    return bsp;
}

static uint64_t ia64_rse_bsp_retreat(uint64_t bsp, uint32_t words)
{
    uint32_t i;

    for (i = 0; i < words; i++) {
        bsp -= 8;
        if (ia64_rse_is_rnat_slot(bsp)) {
            bsp -= 8;
        }
    }
    return bsp;
}

static uint64_t ia64_rse_mapped_bsp(CPUIA64State *env, uint64_t bsp)
{
    uint64_t pa;

    if (ia64_rse_address_to_phys(env, bsp, &pa)) {
        return pa;
    }
    return ia64_rse_canonical_bsp(env, bsp);
}

static bool ia64_rse_bsp_distance(CPUIA64State *env, uint64_t start,
                                  uint64_t end, uint32_t *words)
{
    uint64_t start_slot = ia64_rse_mapped_bsp(env, start) >> 3;
    uint64_t end_slot = ia64_rse_mapped_bsp(env, end) >> 3;
    uint64_t total_slots;
    uint64_t rnat_slots;

    if (end_slot < start_slot) {
        return false;
    }

    total_slots = end_slot - start_slot;
    rnat_slots = end_slot / 64 - start_slot / 64;
    *words = total_slots - rnat_slots;
    return *words <= UINT32_MAX;
}

static void ia64_rse_rebase_spilled_snapshots(CPUIA64State *env,
                                              uint64_t old_bspstore,
                                              uint64_t new_bspstore)
{
    uint32_t i;

    for (i = 0; i < env->rse_frame_depth; i++) {
        uint32_t offset;

        if (ia64_rse_bsp_distance(env, env->rse_frame_bsp[i],
                                  old_bspstore, &offset)) {
            env->rse_frame_bsp[i] =
                ia64_rse_bsp_retreat(new_bspstore, offset);
        }
    }
    for (i = 0; i < env->rse_cover_depth; i++) {
        uint32_t offset;

        if (ia64_rse_bsp_distance(env, env->rse_cover_bsp[i],
                                  old_bspstore, &offset)) {
            env->rse_cover_bsp[i] =
                ia64_rse_bsp_retreat(new_bspstore, offset);
        }
    }
}

static uint32_t ia64_rse_count_register_slots(uint64_t start, uint64_t end)
{
    uint64_t addr = start & ~7ULL;
    uint64_t limit = end & ~7ULL;
    uint32_t words = 0;

    while (addr < limit && words < UINT32_MAX) {
        if (!ia64_rse_is_rnat_slot(addr)) {
            words++;
        }
        addr += 8;
    }
    return words;
}

static uint32_t ia64_rse_modeled_dirty_words(const CPUIA64State *env)
{
    return env->rse_cumulative_words > env->cfm_sof ?
           env->rse_cumulative_words - env->cfm_sof : 0;
}

static uint32_t ia64_rse_dirty_words(CPUIA64State *env)
{
    return ia64_rse_modeled_dirty_words(env);
}

static void ia64_rse_refresh_cumulative(CPUIA64State *env)
{
    uint32_t dirty;

    if (ia64_rse_bsp_distance(env, env->ar_bspstore, env->ar_bsp, &dirty)) {
        env->rse_cumulative_words = dirty + env->cfm_sof;
    } else if (ia64_rse_mapped_bsp(env, env->ar_bsp) <=
               ia64_rse_mapped_bsp(env, env->ar_bspstore)) {
        env->rse_cumulative_words = env->cfm_sof;
    }
}

static void ia64_rse_redirty_current_frame(CPUIA64State *env)
{
    /*
     * The architectural clean/dirty split is finer-grained than this model's
     * frame snapshots.  Before the current frame leaves the current partition,
     * make the whole frame dirty so later spills preserve any writes performed
     * after it was last loaded.
     */
    if (ia64_rse_mapped_bsp(env, env->ar_bspstore) >
        ia64_rse_mapped_bsp(env, env->ar_bsp)) {
        env->ar_bspstore = env->ar_bsp;
    }
}

static void ia64_rse_drop_snapshots(CPUIA64State *env)
{
    env->rse_frame_depth = 0;
    env->rse_cover_depth = 0;
}

static bool ia64_rse_rebased_bsp(CPUIA64State *env, uint64_t old_bspstore,
                                 uint64_t new_bspstore, uint32_t dirty_words,
                                 uint64_t bsp, uint32_t words,
                                 uint64_t *rebased_bsp)
{
    uint64_t frame_end = ia64_rse_bsp_advance(bsp, words);
    uint32_t offset;
    uint32_t overlap_words;

    if (words == 0) {
        return false;
    }

    if (ia64_rse_bsp_distance(env, old_bspstore, bsp, &offset)) {
        if (offset >= dirty_words) {
            return false;
        }
        *rebased_bsp = ia64_rse_bsp_advance(new_bspstore, offset);
        return true;
    }

    if (!ia64_rse_bsp_distance(env, bsp, old_bspstore, &offset) ||
        !ia64_rse_bsp_distance(env, old_bspstore, frame_end,
                               &overlap_words) ||
        overlap_words == 0) {
        return false;
    }

    *rebased_bsp = ia64_rse_bsp_retreat(new_bspstore, offset);
    return true;
}

static void ia64_rse_rebase_dirty_snapshots(CPUIA64State *env,
                                            uint64_t old_bspstore,
                                            uint64_t new_bspstore,
                                            uint32_t dirty_words)
{
    uint32_t out = 0;
    uint32_t i;

    for (i = 0; i < env->rse_frame_depth; i++) {
        uint64_t rebased_bsp;

        if (!ia64_rse_rebased_bsp(env, old_bspstore, new_bspstore,
                                  dirty_words, env->rse_frame_bsp[i],
                                  env->rse_frame_sol[i], &rebased_bsp)) {
            continue;
        }
        if (out != i) {
            memcpy(env->rse_frame_gr[out], env->rse_frame_gr[i],
                   sizeof(env->rse_frame_gr[out]));
            memcpy(env->rse_frame_nat[out], env->rse_frame_nat[i],
                   sizeof(env->rse_frame_nat[out]));
            env->rse_frame_sof[out] = env->rse_frame_sof[i];
            env->rse_frame_sol[out] = env->rse_frame_sol[i];
            env->rse_frame_sor[out] = env->rse_frame_sor[i];
            env->rse_frame_rrb_gr[out] = env->rse_frame_rrb_gr[i];
            env->rse_frame_return_ip[out] = env->rse_frame_return_ip[i];
            env->rse_frame_cumulative_words[out] =
                env->rse_frame_cumulative_words[i];
        }
        env->rse_frame_bsp[out] = rebased_bsp;
        out++;
    }
    env->rse_frame_depth = out;

    out = 0;
    for (i = 0; i < env->rse_cover_depth; i++) {
        uint64_t rebased_bsp;

        if (!ia64_rse_rebased_bsp(env, old_bspstore, new_bspstore,
                                  dirty_words, env->rse_cover_bsp[i],
                                  env->rse_cover_sof[i], &rebased_bsp)) {
            continue;
        }
        if (out != i) {
            memcpy(env->rse_cover_gr[out], env->rse_cover_gr[i],
                   sizeof(env->rse_cover_gr[out]));
            memcpy(env->rse_cover_nat[out], env->rse_cover_nat[i],
                   sizeof(env->rse_cover_nat[out]));
            env->rse_cover_sof[out] = env->rse_cover_sof[i];
        }
        env->rse_cover_bsp[out] = rebased_bsp;
        out++;
    }
    env->rse_cover_depth = out;
}

static bool ia64_rse_dirty_pointer_offset(CPUIA64State *env,
                                          uint64_t old_bspstore,
                                          uint32_t dirty_words,
                                          uint64_t ptr,
                                          uint32_t *offset)
{
    return ia64_rse_bsp_distance(env, old_bspstore, ptr, offset) &&
           *offset <= dirty_words;
}

static uint64_t ia64_rse_rebase_dirty_pointer(CPUIA64State *env,
                                              uint64_t old_bspstore,
                                              uint64_t new_bspstore,
                                              uint32_t dirty_words,
                                              uint64_t ptr)
{
    uint32_t offset;

    if (ia64_rse_dirty_pointer_offset(env, old_bspstore, dirty_words, ptr,
                                      &offset)) {
        return ia64_rse_bsp_advance(new_bspstore, offset);
    }
    return ptr;
}

static void ia64_rse_rebase_exception_frame(CPUIA64State *env,
                                            IA64ExceptionFrame *frame,
                                            uint64_t old_bspstore,
                                            uint64_t new_bspstore,
                                            uint32_t dirty_words)
{
    uint32_t out = 0;
    uint32_t i;
    uint32_t offset;
    bool same_bspstore =
        ia64_rse_mapped_bsp(env, frame->bspstore) ==
        ia64_rse_mapped_bsp(env, old_bspstore);

    if (!same_bspstore &&
        !ia64_rse_dirty_pointer_offset(env, old_bspstore, dirty_words,
                                       frame->bspstore, &offset)) {
        return;
    }
    frame->bsp = ia64_rse_rebase_dirty_pointer(env, old_bspstore,
                                               new_bspstore, dirty_words,
                                               frame->bsp);
    frame->bspstore = ia64_rse_rebase_dirty_pointer(env, old_bspstore,
                                                    new_bspstore, dirty_words,
                                                    frame->bspstore);
    frame->rse_spill_base =
        ia64_rse_rebase_dirty_pointer(env, old_bspstore, new_bspstore,
                                      dirty_words, frame->rse_spill_base);
    frame->rse_bspstore_switched = true;

    for (i = 0; i < frame->rse_frame_depth; i++) {
        uint64_t rebased_bsp;

        if (!ia64_rse_rebased_bsp(env, old_bspstore, new_bspstore,
                                  dirty_words, frame->rse_frame_bsp[i],
                                  frame->rse_frame_sol[i], &rebased_bsp)) {
            continue;
        }
        if (out != i) {
            memcpy(frame->rse_frame_gr[out], frame->rse_frame_gr[i],
                   sizeof(frame->rse_frame_gr[out]));
            memcpy(frame->rse_frame_nat[out], frame->rse_frame_nat[i],
                   sizeof(frame->rse_frame_nat[out]));
            frame->rse_frame_sof[out] = frame->rse_frame_sof[i];
            frame->rse_frame_sol[out] = frame->rse_frame_sol[i];
            frame->rse_frame_sor[out] = frame->rse_frame_sor[i];
            frame->rse_frame_rrb_gr[out] = frame->rse_frame_rrb_gr[i];
            frame->rse_frame_return_ip[out] =
                frame->rse_frame_return_ip[i];
            frame->rse_frame_cumulative_words[out] =
                frame->rse_frame_cumulative_words[i];
        }
        frame->rse_frame_bsp[out] = rebased_bsp;
        out++;
    }
    frame->rse_frame_depth = out;

    out = 0;
    for (i = 0; i < frame->rse_cover_depth; i++) {
        uint64_t rebased_bsp;

        if (!ia64_rse_rebased_bsp(env, old_bspstore, new_bspstore,
                                  dirty_words, frame->rse_cover_bsp[i],
                                  frame->rse_cover_sof[i], &rebased_bsp)) {
            continue;
        }
        if (out != i) {
            memcpy(frame->rse_cover_gr[out], frame->rse_cover_gr[i],
                   sizeof(frame->rse_cover_gr[out]));
            memcpy(frame->rse_cover_nat[out], frame->rse_cover_nat[i],
                   sizeof(frame->rse_cover_nat[out]));
            frame->rse_cover_sof[out] = frame->rse_cover_sof[i];
        }
        frame->rse_cover_bsp[out] = rebased_bsp;
        out++;
    }
    frame->rse_cover_depth = out;
}

static void ia64_rse_evict_parent_frames(CPUIA64State *env)
{
    /*
     * The hardware register stack is only a resident cache of backing-store
     * frames.  Once every dirty parent has been written back, this simplified
     * model may drop its frame snapshots and refill them later from memory.
     */
    helper_flushrs_rse(env);
    ia64_rse_drop_snapshots(env);
    env->rse_spill_words = 0;
    env->rse_spill_base = env->ar_bspstore;
    env->rse_cumulative_words = env->cfm_sof;
}

static bool ia64_rse_bsp_in_spill_range(CPUIA64State *env, uint64_t bsp,
                                        uint64_t old_bspstore)
{
    uint64_t new_bsp = ia64_rse_mapped_bsp(env, bsp);
    uint64_t base = ia64_rse_mapped_bsp(env, env->rse_spill_base);
    uint64_t end =
        ia64_rse_mapped_bsp(env,
                            ia64_rse_bsp_advance(
                                old_bspstore,
                                env->rse_cumulative_words));

    if (env->rse_frame_depth > 0) {
        uint32_t depth = env->rse_frame_depth - 1;
        uint64_t frame_end =
            ia64_rse_mapped_bsp(
                env, ia64_rse_bsp_advance(env->rse_frame_bsp[depth],
                                          env->rse_frame_sof[depth]));

        if (frame_end > end) {
            end = frame_end;
        }
    }
    if (env->rse_cover_depth > 0) {
        uint32_t depth = env->rse_cover_depth - 1;
        uint64_t cover_end =
            ia64_rse_mapped_bsp(
                env, ia64_rse_bsp_advance(env->rse_cover_bsp[depth],
                                          env->rse_cover_sof[depth]));

        if (cover_end > end) {
            end = cover_end;
        }
    }

    if (end < base) {
        uint64_t tmp = base;

        base = end;
        end = tmp;
    }
    return new_bsp >= base && new_bsp <= end;
}

static int ia64_rse_snapshot_nat_bit(const uint64_t nat[2], uint32_t index)
{
    uint32_t reg = IA64_STACKED_GR_BASE + index;

    return (nat[reg / 64] >> (reg % 64)) & 1;
}

static bool ia64_rse_snapshot_word_at(CPUIA64State *env, uint64_t addr,
                                      uint64_t *value, int *nat)
{
    uint32_t depth;

    for (depth = 0; depth < env->rse_frame_depth; depth++) {
        uint32_t sol = env->rse_frame_sol[depth];
        uint32_t index;

        if (sol == 0 ||
            !ia64_rse_bsp_distance(env, env->rse_frame_bsp[depth], addr,
                                   &index) ||
            index >= sol) {
            continue;
        }

        *value = env->rse_frame_gr[depth][index];
        *nat = ia64_rse_snapshot_nat_bit(env->rse_frame_nat[depth], index);
        return true;
    }
    for (depth = 0; depth < env->rse_cover_depth; depth++) {
        uint32_t sof = env->rse_cover_sof[depth];
        uint32_t index;

        if (sof == 0 ||
            !ia64_rse_bsp_distance(env, env->rse_cover_bsp[depth], addr,
                                   &index) ||
            index >= sof) {
            continue;
        }

        *value = env->rse_cover_gr[depth][index];
        *nat = ia64_rse_snapshot_nat_bit(env->rse_cover_nat[depth], index);
        return true;
    }

    return false;
}

static bool ia64_rse_read_backing_u64_if_mapped(CPUIA64State *env,
                                                uint64_t addr,
                                                uint64_t *value)
{
    uint64_t pa;
    uint8_t buf[8];

    if (!ia64_rse_address_to_phys(env, addr, &pa)) {
        return false;
    }

    cpu_physical_memory_read(pa, buf, sizeof(buf));
    *value = ldq_le_p(buf);
    return true;
}

static bool ia64_rse_write_backing_u64_if_mapped(CPUIA64State *env,
                                                 uint64_t addr,
                                                 uint64_t value)
{
    uint64_t pa;
    uint8_t buf[8];

    if (!ia64_rse_address_to_phys(env, addr, &pa)) {
        return false;
    }

    stq_le_p(buf, value);
    cpu_physical_memory_write(pa, buf, sizeof(buf));
    return true;
}

static bool ia64_rse_dirty_word_at(CPUIA64State *env, uint64_t addr,
                                   uint64_t *value, int *nat)
{
    if (ia64_rse_snapshot_word_at(env, addr, value, nat)) {
        return true;
    }

    *value = ia64_rse_read_u64(env, addr);
    *nat = 0;
    return false;
}

static bool ia64_rse_copy_dirty_partition(CPUIA64State *env,
                                          uint64_t old_bspstore,
                                          uint64_t new_bspstore,
                                          uint32_t dirty_words,
                                          uint64_t *new_rnat)
{
    uint64_t *values;
    uint8_t *nats;
    uint64_t old_ptr = old_bspstore;
    uint64_t new_ptr = new_bspstore;
    uint64_t rnat = 0;
    uint32_t i;

    values = g_new(uint64_t, dirty_words);
    nats = g_new(uint8_t, dirty_words);

    for (i = 0; i < dirty_words; i++) {
        int nat = 0;

        if (ia64_rse_is_rnat_slot(old_ptr)) {
            old_ptr += 8;
        }

        if (!ia64_rse_snapshot_word_at(env, old_ptr, &values[i], &nat) &&
            !ia64_rse_read_backing_u64_if_mapped(env, old_ptr, &values[i])) {
            g_free(nats);
            g_free(values);
            return false;
        }
        nats[i] = nat != 0;
        old_ptr += 8;
    }

    for (i = 0; i < dirty_words; i++) {
        if (ia64_rse_is_rnat_slot(new_ptr)) {
            if (!ia64_rse_write_backing_u64_if_mapped(env, new_ptr, rnat)) {
                g_free(nats);
                g_free(values);
                return false;
            }
            new_ptr += 8;
            rnat = 0;
        }

        if (nats[i]) {
            rnat |= 1ULL << ((new_ptr >> 3) & 0x3f);
        } else {
            rnat &= ~(1ULL << ((new_ptr >> 3) & 0x3f));
        }

        if (!ia64_rse_write_backing_u64_if_mapped(env, new_ptr, values[i])) {
            g_free(nats);
            g_free(values);
            return false;
        }
        new_ptr += 8;
    }

    g_free(nats);
    g_free(values);
    *new_rnat = rnat;
    return true;
}

static bool ia64_rse_exception_frame_word_at(CPUIA64State *env,
                                             const IA64ExceptionFrame *frame,
                                             uint64_t addr, uint64_t *value,
                                             int *nat)
{
    uint32_t depth;

    for (depth = 0; depth < frame->rse_frame_depth; depth++) {
        uint32_t sol = frame->rse_frame_sol[depth];
        uint32_t index;

        if (sol == 0 ||
            !ia64_rse_bsp_distance(env, frame->rse_frame_bsp[depth], addr,
                                   &index) ||
            index >= sol) {
            continue;
        }

        *value = frame->rse_frame_gr[depth][index];
        *nat = ia64_rse_snapshot_nat_bit(frame->rse_frame_nat[depth], index);
        return true;
    }
    for (depth = 0; depth < frame->rse_cover_depth; depth++) {
        uint32_t sof = frame->rse_cover_sof[depth];
        uint32_t index;

        if (sof == 0 ||
            !ia64_rse_bsp_distance(env, frame->rse_cover_bsp[depth], addr,
                                   &index) ||
            index >= sof) {
            continue;
        }

        *value = frame->rse_cover_gr[depth][index];
        *nat = ia64_rse_snapshot_nat_bit(frame->rse_cover_nat[depth], index);
        return true;
    }

    *value = ia64_rse_read_u64(env, addr);
    *nat = 0;
    return false;
}

static uint64_t ia64_rse_spill_exception_frame(CPUIA64State *env,
                                               const IA64ExceptionFrame *frame)
{
    uint32_t dirty;
    uint64_t bspstore;
    uint64_t rnat;
    uint32_t i;

    if (!ia64_rse_bsp_distance(env, frame->bspstore, frame->bsp, &dirty) ||
        dirty == 0) {
        return frame->rnat;
    }

    bspstore = frame->bspstore;
    rnat = frame->rnat & ~(1ULL << 63);

    for (i = 0; i < dirty; i++) {
        uint64_t value = 0;
        int nat_bit = 0;

        if (ia64_rse_is_rnat_slot(bspstore)) {
            ia64_rse_write_u64(env, bspstore, rnat);
            bspstore += 8;
            rnat = 0;
        }

        ia64_rse_exception_frame_word_at(env, frame, bspstore, &value,
                                         &nat_bit);
        if (nat_bit) {
            rnat |= 1ULL << ((bspstore >> 3) & 0x3f);
        }
        rnat &= ~(1ULL << 63);

        ia64_rse_write_u64(env, bspstore, value);
        bspstore += 8;
    }

    return rnat;
}

static void ia64_rse_restore_current_frame_from_bsp(CPUIA64State *env,
                                                    uint32_t sof)
{
    uint32_t count = MIN(sof, IA64_STACKED_GR_COUNT);
    uint64_t load_base = ia64_rse_bsp_retreat(env->ar_bsp, count);
    uint64_t load_ptr = load_base;
    uint64_t rnat_collection = env->ar_rnat & ~(1ULL << 63);
    uint32_t i;

    for (i = 0; i < count; i++) {
        uint32_t reg = IA64_STACKED_GR_BASE + i;
        uint8_t bit;

        if (ia64_rse_is_rnat_slot(load_ptr)) {
            rnat_collection = ia64_rse_read_u64(env, load_ptr);
            rnat_collection &= ~(1ULL << 63);
            load_ptr += 8;
        }

        bit = (load_ptr >> 3) & 0x3f;
        env->gr[reg] = ia64_rse_read_u64(env, load_ptr);
        ia64_gr_nat_set(env, reg, (rnat_collection >> bit) & 1);
        load_ptr += 8;
    }

    env->ar_bsp = load_base;
    env->ar_bspstore = load_base;
    env->ar_rnat = rnat_collection;
    env->rse_spill_base = load_base;
    env->rse_spill_words = 0;
    env->rse_cumulative_words = env->cfm_sof;
    env->rse_bspstore_switched = false;
    env->rse_flushed = false;
    ia64_invalidate_stacked_alat(env);
}

void helper_write_pr(CPUIA64State *env, uint64_t value, uint64_t mask)
{
    for (uint32_t i = 1; i < IA64_PR_COUNT; i++) {
        if (mask & (1ULL << i)) {
            env->pr[i] = (value >> i) & 1;
        }
    }
    env->pr[0] = 1;
}

uint64_t helper_read_ar(CPUIA64State *env, uint32_t ar_num)
{
    if (ar_num >= IA64_AR_COUNT) {
        return 0;
    }
    if (ar_num == 17) {
        return env->ar_bsp;
    }
    if (ar_num == 44) {
        return ia64_itc_read(env);
    }
    return env->ar[ar_num];
}

void helper_write_ar(CPUIA64State *env, uint32_t ar_num, uint64_t value)
{
    uint64_t old_bspstore;
    uint32_t dirty_words;

    if (ar_num >= IA64_AR_COUNT) {
        return;
    }
    if (ar_num == 44) {
        bool match = env->cr[1] == value;

        ia64_itc_write(env, value);
        env->itm_last_match_valid = false;
        if (match) {
            env->itm_armed = true;
            env->itm_armed_value = value;
        }
        ia64_itm_update(env, env->cr[1]);
        return;
    }
    old_bspstore = env->ar_bspstore;
    dirty_words = ia64_rse_dirty_words(env);
    env->ar[ar_num] = value;
    if (ar_num == 18) {
        uint64_t rebased_rnat = env->ar_rnat;
        bool copied_dirty_partition = false;
        bool bspstore_changed =
            ia64_rse_mapped_bsp(env, value) !=
            ia64_rse_mapped_bsp(env, old_bspstore);
        bool bspstore_rebased = value != old_bspstore;
        bool bspstore_context_switch =
            !(env->ar_rsc & IA64_RSC_MODE) &&
            env->rse_flushed &&
            bspstore_changed;

        if (dirty_words > 0 && bspstore_rebased) {
            uint32_t i;

            copied_dirty_partition =
                ia64_rse_copy_dirty_partition(env, old_bspstore, value,
                                              dirty_words, &rebased_rnat);
            ia64_rse_rebase_dirty_snapshots(env, old_bspstore, value,
                                            dirty_words);
            for (i = 0; i < env->excp_frame_depth; i++) {
                ia64_rse_rebase_exception_frame(env, &env->excp_frames[i],
                                                old_bspstore, value,
                                                dirty_words);
            }
            if (copied_dirty_partition) {
                env->ar_rnat = rebased_rnat;
            }
            env->rse_bspstore_switched = true;
        } else if (env->rse_spill_words > 0) {
            if (ia64_rse_bsp_in_spill_range(env, value, old_bspstore)) {
                ia64_rse_trim_frames_to_bsp(env, value);
                if (bspstore_rebased) {
                    ia64_rse_rebase_spilled_snapshots(env, old_bspstore,
                                                      value);
                }
                env->rse_bspstore_switched = false;
            } else {
                ia64_rse_drop_snapshots(env);
                env->rse_bspstore_switched = true;
            }
        } else if (bspstore_context_switch) {
            ia64_rse_drop_snapshots(env);
            env->rse_bspstore_switched = true;
        }
        env->rse_spill_words = 0;
        env->rse_spill_base = value;
        env->ar_bsp = ia64_rse_bsp_advance(value, dirty_words);
        env->rse_cumulative_words = dirty_words + env->cfm_sof;
        env->rse_flushed = false;
    }
}

uint64_t helper_read_cr(CPUIA64State *env, uint32_t cr_num)
{
    if (cr_num >= IA64_CR_COUNT) {
        return 0;
    }
    switch (cr_num) {
    case IA64_CR_SAPIC_IVR:
        return (uint64_t)ia64_sapic_get_ivr(env) & 0xFF;
    case IA64_CR_SAPIC_IRR0:
        return env->sapic_irr[0];
    case IA64_CR_SAPIC_IRR1:
        return env->sapic_irr[1];
    case IA64_CR_SAPIC_IRR2:
        return env->sapic_irr[2];
    case IA64_CR_SAPIC_IRR3:
        return env->sapic_irr[3];
    default:
        return env->cr[cr_num];
    }
}

uint64_t helper_read_cpuid(CPUIA64State *env, uint64_t index)
{
    static const uint64_t cpuid[] = {
        IA64_CPUID_VENDOR0,
        IA64_CPUID_VENDOR1,
        IA64_CPUID_SERIAL,
        IA64_CPUID_VERSION_ITANIUM2,
        IA64_CPUID_FEATURES,
    };

    (void)env;
    if (index < ARRAY_SIZE(cpuid)) {
        return cpuid[index];
    }
    return 0;
}

uint64_t helper_read_dahr_indexed(CPUIA64State *env, uint64_t index)
{
    return env->dahr[index & 7] & 0x7ff;
}

uint64_t helper_read_msr(CPUIA64State *env, uint64_t index)
{
    if (index < IA64_MSR_COUNT) {
        return env->msr[index];
    }
    return 0;
}

void helper_write_msr(CPUIA64State *env, uint64_t index, uint64_t value)
{
    if (index < IA64_MSR_COUNT) {
        env->msr[index] = value;
    }
}

uint64_t helper_read_dbr(CPUIA64State *env, uint32_t index)
{
    if (index >= IA64_DBR_COUNT) {
        return 0;
    }
    return env->dbr[index];
}

void helper_write_dbr(CPUIA64State *env, uint32_t index, uint64_t value)
{
    if (index < IA64_DBR_COUNT) {
        env->dbr[index] = value;
    }
}

uint64_t helper_read_ibr(CPUIA64State *env, uint32_t index)
{
    if (index >= IA64_IBR_COUNT) {
        return 0;
    }
    return env->ibr[index];
}

void helper_write_ibr(CPUIA64State *env, uint32_t index, uint64_t value)
{
    if (index < IA64_IBR_COUNT) {
        env->ibr[index] = value;
    }
}

void helper_write_cr(CPUIA64State *env, uint32_t cr_num, uint64_t value)
{
    if (cr_num >= IA64_CR_COUNT) {
        return;
    }
    switch (cr_num) {
    case 1:
        if (env->cr[1] != value) {
            env->itm_last_match_valid = false;
        }
        env->cr[1] = value;
        ia64_itm_update(env, value);
        break;
    case 8:
        env->cr[8] = value;
        tlb_flush(env_cpu(env));
        break;
    case IA64_CR_SAPIC_TPR:
        env->cr[cr_num] = value & IA64_TPR_WRITABLE_MASK;
        ia64_sapic_update_interrupt(env);
        break;
    case IA64_CR_SAPIC_EOI:
        ia64_sapic_eoi(env);
        break;
    case IA64_CR_SAPIC_IVR:
        break;
    case IA64_CR_SAPIC_IRR0:
    case IA64_CR_SAPIC_IRR1:
    case IA64_CR_SAPIC_IRR2:
    case IA64_CR_SAPIC_IRR3:
        break;
    case IA64_CR_ITV:
        env->cr[cr_num] = value;
        ia64_itm_update(env, env->cr[1]);
        break;
    default:
        env->cr[cr_num] = value;
        break;
    }
}

uint64_t helper_read_pmc(CPUIA64State *env, uint32_t index)
{
    if (index >= IA64_PMC_COUNT) {
        return 0;
    }
    return env->pmc[index];
}

void helper_write_pmc(CPUIA64State *env, uint32_t index, uint64_t value)
{
    if (index >= IA64_PMC_COUNT) {
        return;
    }
    env->pmc[index] = value;
}

uint64_t helper_read_pmc_indexed(CPUIA64State *env, uint64_t index)
{
    if (index >= IA64_PMC_COUNT) {
        return 0;
    }
    return env->pmc[index];
}

void helper_write_pmc_indexed(CPUIA64State *env, uint64_t index,
                              uint64_t value)
{
    if (index >= IA64_PMC_COUNT) {
        return;
    }
    env->pmc[index] = value;
}

uint64_t helper_read_pmd(CPUIA64State *env, uint32_t index)
{
    if (index >= IA64_PMD_COUNT) {
        return 0;
    }
    return env->pmd[index];
}

void helper_write_pmd(CPUIA64State *env, uint32_t index, uint64_t value)
{
    if (index >= IA64_PMD_COUNT) {
        return;
    }
    env->pmd[index] = value;
}

uint64_t helper_read_pmd_indexed(CPUIA64State *env, uint64_t index)
{
    if (index >= IA64_PMD_COUNT) {
        return 0;
    }
    return env->pmd[index];
}

void helper_write_pmd_indexed(CPUIA64State *env, uint64_t index,
                              uint64_t value)
{
    if (index >= IA64_PMD_COUNT) {
        return;
    }
    env->pmd[index] = value;
}

static void pal_get_version(CPUIA64State *env)
{
    if (pal_reserved_args_are_zero(env)) {
        env->gr[8] = PAL_STATUS_SUCCESS;
        env->gr[9] = (2ULL << 40) | (0x23ULL << 32) | (1ULL << 24) |
                     (2ULL << 8) | 0x23ULL;
        env->gr[10] = env->gr[9];
    } else {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
        env->gr[10] = 0;
    }
    env->gr[11] = 0;
}

static void pal_rse_info(CPUIA64State *env)
{
    if (pal_reserved_args_are_zero(env)) {
        env->gr[8] = PAL_STATUS_SUCCESS;
        env->gr[9] = 96;
        env->gr[10] = 16;
    } else {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
        env->gr[10] = 0;
    }
    env->gr[11] = 0;
}

static void pal_vm_summary(CPUIA64State *env)
{
    if (pal_reserved_args_are_zero(env)) {
        env->gr[8] = PAL_STATUS_SUCCESS;
        env->gr[9] = 1ULL |
                     ((uint64_t)IA64_IMPL_PA_BITS << 1) |
                     ((uint64_t)IA64_IMPL_RID_BITS << 8) |
                     (((uint64_t)IA64_PKR_COUNT - 1ULL) << 16) |
                     (8ULL << 24) |
                     (((uint64_t)IA64_TLB_MAX - 1ULL) << 32) |
                     (((uint64_t)IA64_TLB_MAX - 1ULL) << 40) |
                     (4ULL << 48) | (3ULL << 56);
        env->gr[10] = IA64_IMPL_VA_MSB |
                      ((uint64_t)IA64_IMPL_RID_BITS << 8);
    } else {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
        env->gr[10] = 0;
    }
    env->gr[11] = 0;
}

static bool pal_halt_light(CPUIA64State *env)
{
    CPUState *cs = env_cpu(env);

    env->gr[8] = PAL_STATUS_SUCCESS;
    cs->halted = 1;
    return true;
}

static void pal_prefetch_vis(CPUIA64State *env)
{
    if (pal_reserved_args_are_zero(env)) {
        env->gr[8] = PAL_STATUS_SUCCESS;
        env->gr[9] = (1ULL << 0) | (1ULL << 1);
    } else {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
    }
    env->gr[10] = 0;
    env->gr[11] = 0;
}

static bool pal_cache_flush(CPUIA64State *env)
{
    uint64_t cache_type = env->gr[29];
    uint64_t operation = env->gr[30];

    if (cache_type < 1 || cache_type > 4 ||
        (operation & ~PAL_CACHE_FLUSH_OPERATION_MASK) != 0) {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
    } else {
        env->gr[8] = PAL_STATUS_SUCCESS;
        if (cache_type == 1 || cache_type == 3 || cache_type == 4) {
            queue_tb_flush(env_cpu(env));
            env->gr[9] = 0;
            env->gr[10] = 0;
            env->gr[11] = 0;
            return true;
        }
    }
    env->gr[9] = 0;
    env->gr[10] = 0;
    env->gr[11] = 0;
    return false;
}

static void pal_cache_init(CPUIA64State *env)
{
    uint64_t level = env->gr[29];
    uint64_t cache_type = env->gr[30];
    uint64_t restrict_side_effects = env->gr[31];

    if (level != UINT64_MAX &&
        (level >= 3 || cache_type < 1 || cache_type > 3 ||
         restrict_side_effects > 1)) {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
    } else {
        env->gr[8] = PAL_STATUS_SUCCESS;
    }
    env->gr[9] = 0;
    env->gr[10] = 0;
    env->gr[11] = 0;
}

static void pal_mem_attrib(CPUIA64State *env)
{
    if (pal_reserved_args_are_zero(env)) {
        env->gr[8] = PAL_STATUS_SUCCESS;
        env->gr[9] = (1ULL << 0) | (1ULL << 4); /* WB and UC */
    } else {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
    }
    env->gr[10] = 0;
    env->gr[11] = 0;
}

static uint64_t pal_page_size_mask(void)
{
    return (1ULL << 12) | (1ULL << 13) | (1ULL << 14) |
           (1ULL << 16) | (1ULL << 18) | (1ULL << 20) |
           (1ULL << 22) | (1ULL << 24) | (1ULL << 26) |
           (1ULL << 28) | (1ULL << 32);
}

static void pal_vm_page_size(CPUIA64State *env)
{
    if (pal_reserved_args_are_zero(env)) {
        env->gr[8] = PAL_STATUS_SUCCESS;
        env->gr[9] = pal_page_size_mask();
        env->gr[10] = pal_page_size_mask();
    } else {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
        env->gr[10] = 0;
    }
    env->gr[11] = 0;
}

static void pal_cache_summary(CPUIA64State *env)
{
    if (pal_reserved_args_are_zero(env)) {
        env->gr[8] = PAL_STATUS_SUCCESS;
        env->gr[9] = 3;
        env->gr[10] = 4;
    } else {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
        env->gr[10] = 0;
    }
    env->gr[11] = 0;
}

static void pal_copy_info(CPUIA64State *env)
{
    uint64_t copy_type = env->gr[29];
    uint64_t platform_info = env->gr[30];

    if (copy_type == 0 && platform_info == 0) {
        env->gr[8] = PAL_STATUS_SUCCESS;
        env->gr[9] = PAL_COPY_BUFFER_SIZE;
        env->gr[10] = PAL_COPY_BUFFER_ALIGN;
    } else if (copy_type == 1) {
        env->gr[8] = PAL_STATUS_ERROR;
        env->gr[9] = 0;
        env->gr[10] = 0;
    } else {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
        env->gr[10] = 0;
    }
    env->gr[11] = 0;
}

static void pal_copy_pal(CPUIA64State *env)
{
    static const uint64_t pal_proc_words[] = {
        0x000002000000000aULL,
        0x0004000000000200ULL,
        0x0000000100000010ULL,
        0x0084000080000200ULL,
    };
    uint64_t target_addr = pal_stacked_arg(env, 0);
    uint64_t alloc_size = pal_stacked_arg(env, 1);
    uint64_t processor = pal_stacked_arg(env, 2);
    uint64_t target_pa = target_addr & ~PAL_COPY_TARGET_CACHE_ATTR;

    if (processor > 1 ||
        alloc_size < PAL_COPY_BUFFER_SIZE ||
        (target_pa & (PAL_COPY_BUFFER_ALIGN - 1)) != 0 ||
        target_pa > UINT64_MAX - PAL_COPY_CODE_SIZE) {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
        env->gr[10] = 0;
        env->gr[11] = 0;
        return;
    }

    if (processor == 0) {
        uint64_t le_words[ARRAY_SIZE(pal_proc_words)];
        int i;

        for (i = 0; i < ARRAY_SIZE(pal_proc_words); i++) {
            le_words[i] = cpu_to_le64(pal_proc_words[i]);
        }
        cpu_physical_memory_write(target_pa, le_words, sizeof(le_words));
        tb_invalidate_phys_range(env_cpu(env), target_pa,
                                 target_pa + PAL_COPY_CODE_SIZE - 1);
        env->pal_proc_copy_addr = target_pa + PAL_COPY_PROC_OFFSET;
        env->pal_proc_copy_valid = true;
        env->pal_pmi_entry = target_pa + PAL_COPY_PROC_OFFSET;
    }

    env->gr[8] = PAL_STATUS_SUCCESS;
    env->gr[9] = PAL_COPY_PROC_OFFSET;
    env->gr[10] = 0;
    env->gr[11] = 0;
}

static void pal_halt_info(CPUIA64State *env)
{
    uint64_t power_buffer = pal_stacked_arg(env, 0);
    uint64_t reserved1 = pal_stacked_arg(env, 1);
    uint64_t reserved2 = pal_stacked_arg(env, 2);
    uint64_t power_states[PAL_HALT_STATE_COUNT] = { 0 };
    uintptr_t ra = GETPC();
    int i;

    if ((power_buffer & 7) != 0 || reserved1 != 0 || reserved2 != 0) {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
        env->gr[10] = 0;
        env->gr[11] = 0;
        return;
    }

    power_states[0] = PAL_HALT_STATE_IMPLEMENTED | PAL_HALT_STATE_COHERENT |
                      (1000ULL << 32) | (1ULL << 16) | 1ULL;

    for (i = 0; i < PAL_HALT_STATE_COUNT; i++) {
        cpu_stq_data_ra(env, power_buffer + i * 8, power_states[i], ra);
    }

    env->gr[8] = PAL_STATUS_SUCCESS;
    env->gr[9] = 0;
    env->gr[10] = 0;
    env->gr[11] = 0;
}

static void pal_mc_drain(CPUIA64State *env)
{
    env->gr[8] = pal_reserved_args_are_zero(env) ?
        PAL_STATUS_SUCCESS : PAL_STATUS_INVALID_ARGUMENT;
    env->gr[9] = 0;
    env->gr[10] = 0;
    env->gr[11] = 0;
}

static bool pal_reserved_args_are_zero(CPUIA64State *env)
{
    return env->gr[29] == 0 && env->gr[30] == 0 && env->gr[31] == 0;
}

static void pal_mc_clear_log(CPUIA64State *env)
{
    env->gr[8] = pal_reserved_args_are_zero(env) ?
        PAL_STATUS_SUCCESS : PAL_STATUS_INVALID_ARGUMENT;
    env->gr[9] = 0;
    env->gr[10] = 0;
    env->gr[11] = 0;
}

static void pal_mc_expected(CPUIA64State *env)
{
    uint64_t expected = env->gr[29];

    if (expected > 1 || env->gr[30] != 0 || env->gr[31] != 0) {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
    } else {
        env->gr[8] = PAL_STATUS_SUCCESS;
        env->gr[9] = env->pal_mc_expected ? 1 : 0;
        env->pal_mc_expected = expected != 0;
    }
    env->gr[10] = 0;
    env->gr[11] = 0;
}

static void pal_mc_dynamic_state(CPUIA64State *env)
{
    uint64_t offset = env->gr[29];

    if ((offset & 7) != 0 || env->gr[30] != 0 || env->gr[31] != 0) {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
    } else {
        env->gr[8] = PAL_STATUS_SUCCESS;
    }
    env->gr[9] = 0;
    env->gr[10] = 0;
    env->gr[11] = 0;
}

static bool pal_mc_level_index_valid(uint64_t level_index)
{
    uint64_t structure_bits = (level_index >> 8) & ((1ULL << 40) - 1);

    if ((level_index >> 48) != 0 || (level_index & 0xff) != 0) {
        return false;
    }

    return structure_bits != 0 && (structure_bits & (structure_bits - 1)) == 0;
}

static void pal_mc_error_info(CPUIA64State *env)
{
    uint64_t info_index = env->gr[29];
    uint64_t level_index = env->gr[30];
    uint64_t err_type_index = env->gr[31];
    bool valid = false;

    switch (info_index) {
    case 0:
    case 1:
        valid = true;
        break;
    case 2:
        valid = pal_mc_level_index_valid(level_index) &&
                (err_type_index & 7) <= 4;
        break;
    default:
        valid = false;
        break;
    }

    env->gr[8] = valid ? PAL_STATUS_NO_INFORMATION :
        PAL_STATUS_INVALID_ARGUMENT;
    env->gr[9] = 0;
    env->gr[10] = 0;
    env->gr[11] = 0;
}

static void pal_mc_resume(CPUIA64State *env)
{
    uint64_t set_cmci = env->gr[29];
    uint64_t save_ptr = env->gr[30];
    uint64_t new_context = env->gr[31];

    if (set_cmci > 1 || new_context > 1 ||
        (save_ptr >> 63) != 0 || (save_ptr & 0x1ff) != 0) {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
    } else {
        env->gr[8] = PAL_STATUS_ERROR;
    }
    env->gr[9] = 0;
    env->gr[10] = 0;
    env->gr[11] = 0;
}

static void pal_mc_register_mem(CPUIA64State *env)
{
    uint64_t address = env->gr[29];

    if ((address >> 63) != 0 || (address & 0x1ff) != 0 ||
        env->gr[30] != 0 || env->gr[31] != 0) {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
    } else {
        env->gr[8] = PAL_STATUS_SUCCESS;
        env->pal_mc_save_addr = address;
    }
    env->gr[9] = 0;
    env->gr[10] = 0;
    env->gr[11] = 0;
}

static void pal_cache_line_init(CPUIA64State *env)
{
    uint64_t address = env->gr[29];

    if ((address >> 63) != 0 || env->gr[31] != 0) {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
    } else {
        env->gr[8] = PAL_STATUS_SUCCESS;
    }
    env->gr[9] = 0;
    env->gr[10] = 0;
    env->gr[11] = 0;
}

static void pal_pmi_entrypoint(CPUIA64State *env)
{
    uint64_t entry = env->gr[29];

    if ((entry >> 63) != 0 || (entry & 0xff) != 0 ||
        env->gr[30] != 0 || env->gr[31] != 0) {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
    } else {
        env->gr[8] = PAL_STATUS_SUCCESS;
        env->pal_pmi_entry = entry;
    }
    env->gr[9] = 0;
    env->gr[10] = 0;
    env->gr[11] = 0;
}

static void pal_mem_for_test(CPUIA64State *env)
{
    env->gr[8] = pal_reserved_args_are_zero(env) ?
        PAL_STATUS_SUCCESS : PAL_STATUS_INVALID_ARGUMENT;
    env->gr[9] = 0;
    env->gr[10] = env->gr[8] == PAL_STATUS_SUCCESS ? 1 : 0;
    env->gr[11] = 0;
}

static void pal_proc_get_features(CPUIA64State *env)
{
    if (pal_reserved_args_are_zero(env)) {
        env->gr[8] = PAL_STATUS_SUCCESS;
        env->gr[9] = (1ULL << 0)  | (1ULL << 1)  | (1ULL << 2)  |
                     (1ULL << 8)  | (1ULL << 9)  | (1ULL << 10) |
                     (1ULL << 16) | (1ULL << 17) | (1ULL << 20) |
                     (1ULL << 32) | (1ULL << 33) | (1ULL << 48) |
                     (1ULL << 49);
        env->gr[10] = (1ULL << 0) | (1ULL << 2) | (1ULL << 4) |
                      (1ULL << 8);
        env->gr[11] = 0;
    } else {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
        env->gr[10] = 0;
        env->gr[11] = 0;
    }
}

static void pal_cache_info(CPUIA64State *env)
{
    uint64_t level = env->gr[29];
    uint64_t cache_type = env->gr[30];
    bool unified = level != 0;
    uint64_t associativity;
    uint64_t line_size;
    uint64_t line_shift = 0;
    uint64_t cache_size;
    uint64_t tag_msb;
    uint64_t store_latency;

    env->gr[8] = PAL_STATUS_SUCCESS;

    if (level >= 3 || env->gr[31] != 0 ||
        cache_type < 1 || cache_type > 2 ||
        (level != 0 && cache_type != 2)) {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
        env->gr[10] = 0;
        env->gr[11] = 0;
        return;
    }

    switch (level) {
    case 0:
        associativity = 4;
        line_size = IA64_L0_CACHE_LINE_SIZE;
        cache_size = 16 * 1024;
        tag_msb = 31;
        break;
    case 1:
        associativity = 8;
        line_size = IA64_L1_CACHE_LINE_SIZE;
        cache_size = 256 * 1024;
        tag_msb = 35;
        break;
    case 2:
        associativity = 12;
        line_size = IA64_L2_CACHE_LINE_SIZE;
        cache_size = 3 * 1024 * 1024;
        tag_msb = 39;
        break;
    default:
        g_assert_not_reached();
    }

    while ((1ULL << line_shift) < line_size) {
        line_shift++;
    }
    store_latency = cache_type == 1 ? 0xff : 1;

    env->gr[9] = (unified ? 1ULL : 0ULL) | (1ULL << 1) |
                 (associativity << 8) | (line_shift << 16) |
                 (line_shift << 24) | (store_latency << 32) |
                 (1ULL << 40);
    env->gr[10] = cache_size | (line_shift << 32) | (12ULL << 40) |
                  (tag_msb << 48);
    env->gr[11] = 0;
}

static uint32_t pal_cache_tag_msb(uint64_t level)
{
    switch (level) {
    case 0:
        return 31;
    case 1:
        return 35;
    case 2:
        return 39;
    default:
        g_assert_not_reached();
    }
}

static void pal_cache_prot_info(CPUIA64State *env)
{
    uint64_t level = env->gr[29];
    uint64_t cache_type = env->gr[30];
    uint64_t reserved = env->gr[31];
    uint32_t data_none = 64;
    uint32_t tag_none;

    if (level >= 3 || cache_type < 1 || cache_type > 2 ||
        (level != 0 && cache_type != 2) || reserved != 0) {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
        env->gr[10] = 0;
        env->gr[11] = 0;
        return;
    }

    tag_none = (1U << 30) | (12U << 8) | (pal_cache_tag_msb(level) << 14);
    env->gr[8] = PAL_STATUS_SUCCESS;
    env->gr[9] = data_none | ((uint64_t)tag_none << 32);
    env->gr[10] = 0;
    env->gr[11] = 0;
}

static void pal_vm_info(CPUIA64State *env)
{
    uint64_t level = env->gr[29];
    uint64_t tc_type = env->gr[30];
    bool unified = level != 0;

    env->gr[8] = PAL_STATUS_SUCCESS;

    if (level >= 3 || env->gr[31] != 0 ||
        tc_type < 1 || tc_type > 2 ||
        (level != 0 && tc_type != 2)) {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
        env->gr[10] = 0;
        env->gr[11] = 0;
        return;
    }

    switch (level) {
    case 0:
        env->gr[9] = 64ULL | (4ULL << 8) | (256ULL << 16) |
                     (1ULL << 32);
        break;
    case 1:
        env->gr[9] = 128ULL | (4ULL << 8) | (512ULL << 16) |
                     (1ULL << 32) | (unified ? (1ULL << 33) : 0);
        break;
    case 2:
        env->gr[9] = 256ULL | (8ULL << 8) | (2048ULL << 16) |
                     (1ULL << 32) | (unified ? (1ULL << 33) : 0);
        break;
    default:
        g_assert_not_reached();
    }
    env->gr[10] = pal_page_size_mask();
    env->gr[11] = 0;
}

static uint64_t pal_page_shift(uint64_t page_size)
{
    uint64_t shift = 0;

    while ((1ULL << shift) < page_size && shift < 63) {
        shift++;
    }
    return shift;
}

static void pal_vm_tr_read(CPUIA64State *env)
{
    uint64_t reg_num = pal_stacked_arg(env, 0);
    uint64_t tr_type = pal_stacked_arg(env, 1);
    uint64_t tr_buffer = pal_stacked_arg(env, 2);
    const IA64TlbEntry *tlb;
    const IA64TlbEntry *entry;
    uint64_t pte = 0;
    uint64_t itir = 0;
    uint64_t ifa = 0;
    uint64_t rr = 0;
    uint64_t tr_valid = 0;
    uint64_t ps_shift;
    uintptr_t ra = GETPC();

    if (reg_num >= IA64_TLB_MAX || tr_type > 1 || (tr_buffer & 7) != 0) {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
        env->gr[10] = 0;
        env->gr[11] = 0;
        return;
    }

    tlb = tr_type == 0 ? env->tlb_inst : env->tlb_data;
    entry = &tlb[reg_num];
    if (entry->valid && entry->is_tr) {
        ps_shift = pal_page_shift(entry->ps);
        pte = entry->pte;
        itir = (ps_shift << IA64_ITIR_PS_SHIFT) |
               ((uint64_t)entry->key << IA64_ITIR_KEY_SHIFT);
        ifa = entry->va | 1;
        rr = ((uint64_t)entry->rid << IA64_RR_RID_SHIFT) |
             (ps_shift << IA64_ITIR_PS_SHIFT);
        tr_valid = 0xf;
    }

    cpu_stq_data_ra(env, tr_buffer, pte, ra);
    cpu_stq_data_ra(env, tr_buffer + 8, itir, ra);
    cpu_stq_data_ra(env, tr_buffer + 16, ifa, ra);
    cpu_stq_data_ra(env, tr_buffer + 24, rr, ra);

    env->gr[8] = PAL_STATUS_SUCCESS;
    env->gr[9] = tr_valid;
    env->gr[10] = 0;
    env->gr[11] = 0;
}

static void pal_freq_base(CPUIA64State *env)
{
    if (pal_reserved_args_are_zero(env)) {
        env->gr[8] = PAL_STATUS_SUCCESS;
        env->gr[9] = 100000000ULL;
    } else {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
    }
    env->gr[10] = 0;
    env->gr[11] = 0;
}

static void pal_freq_ratios(CPUIA64State *env)
{
    if (pal_reserved_args_are_zero(env)) {
        env->gr[8] = PAL_STATUS_SUCCESS;
        env->gr[9] = (16ULL << 32) | 1ULL; /* processor: 1.6 GHz */
        env->gr[10] = (4ULL << 32) | 1ULL; /* bus: 400 MHz */
        env->gr[11] = (2ULL << 32) | 1ULL; /* ITC: 200 MHz */
    } else {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
        env->gr[10] = 0;
        env->gr[11] = 0;
    }
}

static void pal_ptce_info(CPUIA64State *env)
{
    if (pal_reserved_args_are_zero(env)) {
        env->gr[8] = PAL_STATUS_SUCCESS;
        env->gr[9] = (1ULL << 32) | (1ULL << 0);
        env->gr[10] = (1ULL) | (1ULL << 8) | (64ULL << 16);
    } else {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
        env->gr[10] = 0;
    }
    env->gr[11] = 0;
}

static void pal_bus_get_features(CPUIA64State *env)
{
    if (pal_reserved_args_are_zero(env)) {
        env->gr[8] = PAL_STATUS_SUCCESS;
        env->gr[9] = (1ULL << 0) | (1ULL << 1) | (1ULL << 2) |
                     (1ULL << 4) | (1ULL << 8) | (1ULL << 16);
        env->gr[10] = 0;
        env->gr[11] = 0;
    } else {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
        env->gr[10] = 0;
        env->gr[11] = 0;
    }
}

static void pal_set_features(CPUIA64State *env)
{
    if (env->gr[30] != 0 || env->gr[31] != 0) {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
    } else {
        env->gr[8] = PAL_STATUS_SUCCESS;
    }
    env->gr[9] = 0;
    env->gr[10] = 0;
    env->gr[11] = 0;
}

static void pal_register_info(CPUIA64State *env)
{
    uint64_t info_type = env->gr[29];

    if (env->gr[30] != 0 || env->gr[31] != 0 || info_type > 3) {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
        env->gr[10] = 0;
        env->gr[11] = 0;
        return;
    }

    env->gr[8] = PAL_STATUS_SUCCESS;
    switch (info_type) {
    case 0:
        env->gr[9] = 0x000011117f2f00ffULL;
        env->gr[10] = 0x7;
        break;
    case 1:
        env->gr[9] = 0;
        env->gr[10] = 0;
        break;
    case 2:
        env->gr[9] = 0x0000000003fb0107ULL;
        env->gr[10] = 0x307ff;
        break;
    case 3:
        env->gr[9] = 0;
        env->gr[10] = 0x2;
        break;
    default:
        g_assert_not_reached();
        break;
    }
    env->gr[11] = 0;
}

static void pal_perf_mon_info(CPUIA64State *env)
{
    uint64_t pm_buffer = env->gr[29];
    uintptr_t ra = GETPC();
    int i;

    if (pm_buffer == 0 || (pm_buffer & 7) != 0 ||
        env->gr[30] != 0 || env->gr[31] != 0) {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
        env->gr[10] = 0;
        env->gr[11] = 0;
        return;
    }

    for (i = 0; i < 16; i++) {
        cpu_stq_data_ra(env, pm_buffer + i * 8, 0, ra);
    }

    env->gr[8] = PAL_STATUS_SUCCESS;
    env->gr[9] = 0;
    env->gr[10] = 0;
    env->gr[11] = 0;
}

static bool pal_addr_overlaps_fw_update(uint64_t address, uint64_t alignment)
{
    uint64_t fw_base = 0xff000000ULL;
    uint64_t fw_limit = 0x100000000ULL;
    uint64_t block_end;

    if (address >= fw_limit) {
        return false;
    }

    block_end = address + alignment;
    return block_end > fw_base && address < fw_limit;
}

static void pal_platform_addr(CPUIA64State *env)
{
    uint64_t block_type = env->gr[29];
    uint64_t address = env->gr[30] & ~(1ULL << 63);
    uint64_t alignment;
    uint64_t supported;

    if (env->gr[31] != 0 || block_type > 1) {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
        env->gr[10] = 0;
        env->gr[11] = 0;
        return;
    }

    if (block_type == 0) {
        alignment = 2ULL << 20;
        supported = IA64_LOCAL_SAPIC_PA;
    } else {
        alignment = 64ULL << 20;
        supported = IA64_PAL_IO_BLOCK_PA;
    }

    if ((address & (alignment - 1)) != 0 ||
        pal_addr_overlaps_fw_update(address, alignment)) {
        env->gr[8] = PAL_STATUS_ERROR;
    } else if (address != supported) {
        env->gr[8] = PAL_STATUS_ERROR;
    } else {
        env->gr[8] = PAL_STATUS_SUCCESS;
        if (block_type == 0) {
            env->pal_interrupt_block_addr = address;
        } else {
            env->pal_io_block_addr = address;
        }
    }
    env->gr[9] = 0;
    env->gr[10] = 0;
    env->gr[11] = 0;
}

static void pal_test_proc(CPUIA64State *env)
{
    uint64_t test_address = pal_stacked_arg(env, 0);
    uint64_t attributes = pal_stacked_arg(env, 2);

    if ((test_address >> 63) != 0 ||
        (attributes & ~PAL_MEM_ATTR_VALID_MASK) != 0 ||
        (attributes & PAL_MEM_ATTR_WB) == 0) {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
    } else {
        env->gr[8] = PAL_STATUS_SUCCESS;
        env->gr[9] = PAL_SELF_TEST_STATE_TESTED;
    }
    env->gr[10] = 0;
    env->gr[11] = 0;
}

static void pal_debug_info(CPUIA64State *env)
{
    if (pal_reserved_args_are_zero(env)) {
        env->gr[8] = PAL_STATUS_SUCCESS;
        env->gr[9] = 4;
        env->gr[10] = 4;
    } else {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
        env->gr[10] = 0;
    }
    env->gr[11] = 0;
}

static void pal_fixed_addr(CPUIA64State *env)
{
    CPUState *cs = env_cpu(env);

    if (pal_reserved_args_are_zero(env)) {
        env->gr[8] = PAL_STATUS_SUCCESS;
        env->gr[9] = cs->cpu_index & 0xffff;
    } else {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
    }
    env->gr[10] = 0;
    env->gr[11] = 0;
}

uint32_t helper_pal_dispatch(CPUIA64State *env)
{
    uint64_t index = env->gr[28];
    uint32_t flags = 0;

    switch (index) {
    case PAL_VERSION:
        pal_get_version(env);
        break;
    case PAL_RSE_INFO:
        pal_rse_info(env);
        break;
    case PAL_VM_SUMMARY:
        pal_vm_summary(env);
        break;
    case PAL_HALT_LIGHT:
        if (pal_halt_light(env)) {
            flags |= IA64_PAL_DISPATCH_HALTED;
        }
        break;
    case PAL_PREFETCH_VIS:
        pal_prefetch_vis(env);
        break;
    case PAL_CACHE_FLUSH:
        if (pal_cache_flush(env)) {
            flags |= IA64_PAL_DISPATCH_EXIT_TB;
        }
        break;
    case PAL_CACHE_INIT:
        pal_cache_init(env);
        break;
    case PAL_CACHE_LINE_INIT:
        pal_cache_line_init(env);
        break;
    case PAL_CACHE_SUMMARY:
        pal_cache_summary(env);
        break;
    case PAL_MEM_ATTRIB:
        pal_mem_attrib(env);
        break;
    case PAL_PROC_GET_FEATURES:
        pal_proc_get_features(env);
        break;
    case PAL_PROC_SET_FEATURES:
        pal_set_features(env);
        break;
    case PAL_CACHE_INFO:
        pal_cache_info(env);
        break;
    case PAL_CACHE_PROT_INFO:
        pal_cache_prot_info(env);
        break;
    case PAL_VM_INFO:
        pal_vm_info(env);
        break;
    case PAL_VM_PAGE_SIZE:
        pal_vm_page_size(env);
        break;
    case PAL_VM_TR_READ:
        pal_vm_tr_read(env);
        break;
    case PAL_FREQ_BASE:
        pal_freq_base(env);
        break;
    case PAL_FREQ_RATIOS:
        pal_freq_ratios(env);
        break;
    case PAL_PTCE_INFO:
        pal_ptce_info(env);
        break;
    case PAL_BUS_GET_FEATURES:
        pal_bus_get_features(env);
        break;
    case PAL_BUS_SET_FEATURES:
        pal_set_features(env);
        break;
    case PAL_REGISTER_INFO:
        pal_register_info(env);
        break;
    case PAL_PERF_MON_INFO:
        pal_perf_mon_info(env);
        break;
    case PAL_PLATFORM_ADDR:
        pal_platform_addr(env);
        break;
    case PAL_TEST_PROC:
        pal_test_proc(env);
        break;
    case PAL_DEBUG_INFO:
        pal_debug_info(env);
        break;
    case PAL_FIXED_ADDR:
        pal_fixed_addr(env);
        break;
    case PAL_MC_CLEAR_LOG:
        pal_mc_clear_log(env);
        break;
    case PAL_COPY_INFO:
        pal_copy_info(env);
        break;
    case PAL_COPY_PAL:
        pal_copy_pal(env);
        break;
    case PAL_HALT_INFO:
        pal_halt_info(env);
        break;
    case PAL_MC_DRAIN:
        pal_mc_drain(env);
        break;
    case PAL_MC_EXPECTED:
        pal_mc_expected(env);
        break;
    case PAL_MC_DYNAMIC_STATE:
        pal_mc_dynamic_state(env);
        break;
    case PAL_MC_ERROR_INFO:
        pal_mc_error_info(env);
        break;
    case PAL_MC_RESUME:
        pal_mc_resume(env);
        break;
    case PAL_MC_REGISTER_MEM:
        pal_mc_register_mem(env);
        break;
    case PAL_MEM_FOR_TEST:
        pal_mem_for_test(env);
        break;
    case PAL_PMI_ENTRYPOINT:
        pal_pmi_entrypoint(env);
        break;
    default:
        env->gr[8] = PAL_STATUS_NOT_IMPLEMENTED;
        env->gr[9] = 0;
        env->gr[10] = 0;
        env->gr[11] = 0;
        break;
    }

    /*
     * PAL_PROC is a firmware portal, not a normal C function.  Linux enters
     * it both with a plain branch (static calls) and with br.call (stacked
     * calls).  The PAL trampoline returns with a plain branch to b0; when the
     * caller used br.call, complete that call's RSE frame here before the
     * trampoline branches back.
     */
    if (env->rse_frame_depth > 0 &&
        env->rse_frame_return_ip[env->rse_frame_depth - 1] == env->br[0]) {
        ia64_rse_pop_return_frame(env, env->ar_pfs, false);
    }

    return flags;
}

static bool ia64_data_address_to_mapped_phys(CPUIA64State *env, uint64_t va,
                                             uint64_t *pa)
{
    uint8_t perm;
    uint32_t rid;

    if (ia64_firmware_identity_pa(va, pa)) {
        return true;
    }

    if (ia64_sal_boot_virtual_pa(env, va, pa)) {
        return true;
    }

    rid = ia64_region_rid(env, va);
    if (ia64_tlb_lookup(env->tlb_data, env->tlb_data_count,
                        va, rid, ia64_psr_cpl(env->psr), false, pa, &perm)) {
        return (perm & IA64_TLB_R) != 0;
    }

    if (ia64_kernel_direct_data_pa(env->psr, env->rr[ia64_rr_index(va)],
                                   va, pa)) {
        return true;
    }

    if (ia64_vhpt_walk(env, va, rid, false, pa, &perm)) {
        return (perm & IA64_TLB_R) != 0;
    }

    return ia64_sal_boot_identity_pa(env, va, pa);
}

static bool ia64_data_address_to_phys(CPUIA64State *env, uint64_t va,
                                      uint64_t *pa)
{
    if (!(env->psr & IA64_PSR_DT)) {
        *pa = va;
        return true;
    }

    return ia64_data_address_to_mapped_phys(env, va, pa);
}

static bool ia64_rse_address_to_phys(CPUIA64State *env, uint64_t va,
                                     uint64_t *pa)
{
    if (!(env->psr & IA64_PSR_RT)) {
        *pa = va;
        return true;
    }

    return ia64_data_address_to_mapped_phys(env, va, pa);
}

void helper_fc(CPUIA64State *env, uint64_t addr)
{
    uint64_t pa;

    if (ia64_data_address_to_phys(env, addr, &pa)) {
        uint64_t start = pa & ~(IA64_L0_CACHE_LINE_SIZE - 1);
        uint64_t end = start + IA64_L0_CACHE_LINE_SIZE - 1;

        if (end < start) {
            end = UINT64_MAX;
        }
        tb_invalidate_phys_range(env_cpu(env), start, end);
    }
}

static bool ia64_gr_nat_get(const CPUIA64State *env, uint32_t reg)
{
    if (reg == 0) {
        return false;
    }

    return (env->nat[reg / 64] >> (reg % 64)) & 1;
}

static void ia64_gr_nat_set(CPUIA64State *env, uint32_t reg, bool nat)
{
    if (reg == 0) {
        return;
    }

    if (nat) {
        env->nat[reg / 64] |= (1ULL << (reg % 64));
    } else {
        env->nat[reg / 64] &= ~(1ULL << (reg % 64));
    }
}

void helper_st_spill_unat(CPUIA64State *env, uint32_t reg, uint64_t addr)
{
    uint32_t bit_pos = (addr >> 3) & 0x3f;

    if (ia64_gr_nat_get(env, reg)) {
        env->ar_unat |= 1ULL << bit_pos;
    } else {
        env->ar_unat &= ~(1ULL << bit_pos);
    }
}

static void ia64_swap_banked_gr(CPUIA64State *env)
{
    uint32_t i;

    for (i = 0; i < 16; i++) {
        uint32_t reg = 16 + i;
        uint64_t value = env->gr[reg];
        bool nat = ia64_gr_nat_get(env, reg);

        env->gr[reg] = env->banked_gr[i];
        ia64_gr_nat_set(env, reg, (env->banked_nat >> i) & 1);
        env->banked_gr[i] = value;
        if (nat) {
            env->banked_nat |= (uint16_t)(1U << i);
        } else {
            env->banked_nat &= (uint16_t)~(1U << i);
        }
    }
}

void ia64_set_psr(CPUIA64State *env, uint64_t value)
{
    if ((env->psr ^ value) & IA64_PSR_IC) {
        env->psr_ic_inflight = true;
    }
    if ((env->psr ^ value) & IA64_PSR_BN) {
        ia64_swap_banked_gr(env);
    }
    env->psr = value;
}

void helper_clear_psr_fault_suppression(CPUIA64State *env)
{
    uint64_t old_mask = env->psr_suppression_before_insn &
                        IA64_PSR_FAULT_SUPPRESS_MASK;
    uint64_t clear_mask = env->psr & old_mask;
    bool flush_translation = old_mask & (IA64_PSR_DA | IA64_PSR_IA);

    if (clear_mask) {
        ia64_set_psr(env, env->psr & ~clear_mask);
    }
    if (flush_translation) {
        /*
         * A one-instruction A/D-bit suppression may have installed a QEMU
         * host TLB entry for a page whose architectural access or dirty bit is
         * still clear.  Drop cached translations when the suppression window
         * closes so the next reference rechecks the architectural PTE bits.
         */
        tlb_flush(env_cpu(env));
    }
    env->psr_suppression_before_insn = 0;
}

void ia64_set_psr_bn(CPUIA64State *env, bool bank1)
{
    uint64_t value = bank1 ? (env->psr | IA64_PSR_BN) :
                             (env->psr & ~IA64_PSR_BN);

    ia64_set_psr(env, value);
}

void helper_set_psr_bn(CPUIA64State *env, uint32_t bank1)
{
    ia64_set_psr_bn(env, bank1 != 0);
}

/*
 * Rotate stacked GR window (r32-r127) so br.call can present caller out
 * registers as callee input registers without changing translator-side
 * register numbering.
 */
static void ia64_rotate_stacked_gr_left(CPUIA64State *env, uint32_t shift)
{
    uint64_t gr_tmp[IA64_STACKED_GR_COUNT];
    uint8_t nat_tmp[IA64_STACKED_GR_COUNT];
    uint32_t i;

    shift %= IA64_STACKED_GR_COUNT;
    if (shift == 0) {
        return;
    }

    for (i = 0; i < IA64_STACKED_GR_COUNT; i++) {
        uint32_t src = (i + shift) % IA64_STACKED_GR_COUNT;
        uint32_t src_reg = IA64_STACKED_GR_BASE + src;
        gr_tmp[i] = env->gr[src_reg];
        nat_tmp[i] = ia64_gr_nat_get(env, src_reg);
    }

    for (i = 0; i < IA64_STACKED_GR_COUNT; i++) {
        uint32_t dst_reg = IA64_STACKED_GR_BASE + i;
        env->gr[dst_reg] = gr_tmp[i];
        ia64_gr_nat_set(env, dst_reg, nat_tmp[i]);
    }
    ia64_invalidate_stacked_alat(env);
}

static void ia64_rotate_rotating_gr_right(CPUIA64State *env)
{
    uint64_t gr_tmp[IA64_STACKED_GR_COUNT];
    uint8_t nat_tmp[IA64_STACKED_GR_COUNT];
    uint32_t count = env->cfm_sor * 8;
    uint32_t i;

    if (count == 0) {
        return;
    }
    if (count > env->cfm_sof) {
        count = env->cfm_sof;
    }
    if (count > IA64_STACKED_GR_COUNT) {
        count = IA64_STACKED_GR_COUNT;
    }

    for (i = 0; i < count; i++) {
        uint32_t src = (i + count - 1) % count;
        uint32_t src_reg = IA64_STACKED_GR_BASE + src;

        gr_tmp[i] = env->gr[src_reg];
        nat_tmp[i] = ia64_gr_nat_get(env, src_reg);
    }

    for (i = 0; i < count; i++) {
        uint32_t dst_reg = IA64_STACKED_GR_BASE + i;

        env->gr[dst_reg] = gr_tmp[i];
        ia64_gr_nat_set(env, dst_reg, nat_tmp[i]);
    }
    ia64_invalidate_alat_reg_range(env, IA64_STACKED_GR_BASE,
                                   IA64_STACKED_GR_BASE + count, false);
}

static void ia64_rotate_rotating_fr_right(CPUIA64State *env)
{
    uint64_t fr_tmp[IA64_ROTATING_FR_COUNT];
    uint8_t nat_tmp[IA64_ROTATING_FR_COUNT];
    uint8_t sig_tmp[IA64_ROTATING_FR_COUNT];
    uint32_t i;

    for (i = 0; i < IA64_ROTATING_FR_COUNT; i++) {
        uint32_t src = (i + IA64_ROTATING_FR_COUNT - 1) %
                       IA64_ROTATING_FR_COUNT;
        uint32_t src_reg = IA64_ROTATING_FR_BASE + src;

        fr_tmp[i] = env->fr[src_reg];
        nat_tmp[i] = ia64_fr_nat_get(env, src_reg);
        sig_tmp[i] = ia64_fr_sig_get(env, src_reg);
    }

    for (i = 0; i < IA64_ROTATING_FR_COUNT; i++) {
        uint32_t dst_reg = IA64_ROTATING_FR_BASE + i;

        env->fr[dst_reg] = fr_tmp[i];
        ia64_fr_nat_set(env, dst_reg, nat_tmp[i]);
        if (sig_tmp[i] && !nat_tmp[i]) {
            env->fr_sig[dst_reg / 64] |= 1ULL << (dst_reg % 64);
        } else {
            env->fr_sig[dst_reg / 64] &= ~(1ULL << (dst_reg % 64));
        }
    }
    ia64_invalidate_rotating_fp_alat(env);
}

static void ia64_rotate_predicates_right(CPUIA64State *env)
{
    uint8_t last = env->pr[63] & 1;
    uint32_t i;

    for (i = 63; i > 16; i--) {
        env->pr[i] = env->pr[i - 1] & 1;
    }
    env->pr[16] = last;
    env->pr[0] = 1;
}

static void ia64_rotate_loop_regs(CPUIA64State *env)
{
    ia64_rotate_rotating_gr_right(env);
    ia64_rotate_rotating_fr_right(env);
    ia64_rotate_predicates_right(env);
}

void helper_br_call_rse(CPUIA64State *env, uint32_t b_reg,
                         uint64_t next_ip, uint64_t target)
{
    uint64_t pfs = ia64_current_pfs(env);
    uint32_t caller_sof = env->cfm_sof;
    uint32_t caller_sol = env->cfm_sol;
    uint32_t callee_sof =
        caller_sof > caller_sol ? caller_sof - caller_sol : 0;
    uint32_t depth = env->rse_frame_depth;
    uint32_t i;

    ia64_rse_redirty_current_frame(env);
    if (depth == IA64_RSE_FRAME_MAX) {
        ia64_rse_evict_parent_frames(env);
        depth = env->rse_frame_depth;
    }

    if (depth < IA64_RSE_FRAME_MAX) {
        for (i = 0; i < IA64_STACKED_GR_COUNT; i++) {
            env->rse_frame_gr[depth][i] = env->gr[IA64_STACKED_GR_BASE + i];
        }
        env->rse_frame_nat[depth][0] = env->nat[0];
        env->rse_frame_nat[depth][1] = env->nat[1];
        env->rse_frame_sof[depth] = env->cfm_sof;
        env->rse_frame_sol[depth] = env->cfm_sol;
        env->rse_frame_sor[depth] = env->cfm_sor;
        env->rse_frame_rrb_gr[depth] = env->cfm_rrb_gr;
        /*
         * AR.BSP is architecturally visible.  Keep the guest-visible address
         * here; helpers that compare backing-store locations canonicalize on
         * demand without changing the value that a later br.ret restores.
         */
        env->rse_frame_bsp[depth] = env->ar_bsp;
        env->rse_frame_return_ip[depth] = next_ip;
        env->rse_frame_cumulative_words[depth] = env->rse_cumulative_words;
        env->rse_frame_depth = depth + 1;

        if (caller_sol < IA64_STACKED_GR_COUNT) {
            uint32_t outputs = callee_sof;

            if (outputs > IA64_STACKED_GR_COUNT - caller_sol) {
                outputs = IA64_STACKED_GR_COUNT - caller_sol;
            }
            for (i = 0; i < outputs; i++) {
                uint32_t src = IA64_STACKED_GR_BASE + caller_sol + i;
                uint32_t dst = IA64_STACKED_GR_BASE + i;

                env->gr[dst] = env->rse_frame_gr[depth][caller_sol + i];
                ia64_gr_nat_set(env, dst, ia64_gr_nat_get(env, src));
            }
        }
    } else {
        ia64_rotate_stacked_gr_left(env, caller_sol);
    }

    env->ar_pfs = pfs;
    env->ar_bsp = ia64_rse_bsp_advance(env->ar_bsp, caller_sol);
    env->cfm_sof = callee_sof;
    env->cfm_sol = 0;
    env->cfm_sor = 0;
    env->cfm_rrb_gr = 0;
    ia64_rse_refresh_cumulative(env);
    ia64_invalidate_stacked_alat(env);
    env->br[b_reg] = next_ip;
    env->ip = ia64_ip_bundle_addr(target);
}

void helper_br_ia_diag(CPUIA64State *env, uint32_t b_reg)
{
    static unsigned br_ia_zero_logs;
    uint64_t target = env->br[b_reg];

    if (target == 0 && br_ia_zero_logs++ < 16) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "ia64 br.ia target zero ip=0x%016" PRIx64
                      " b%u pfs=0x%016" PRIx64 " depth=%u"
                      " b0=0x%016" PRIx64 " b6=0x%016" PRIx64
                      " r1=0x%016" PRIx64 " r10=0x%016" PRIx64
                      " r11=0x%016" PRIx64 " r14=0x%016" PRIx64
                      " r16=0x%016" PRIx64 " r17=0x%016" PRIx64
                      " r18=0x%016" PRIx64 "\n",
                      env->ip, b_reg, env->ar_pfs, env->rse_frame_depth,
                      env->br[0], env->br[6], env->gr[1], env->gr[10],
                      env->gr[11], env->gr[14], env->gr[16], env->gr[17],
                      env->gr[18]);
    }
    env->ip = target;
}

static void ia64_rse_reload_spilled_words(CPUIA64State *env)
{
    uint32_t count = env->rse_spill_words;
    uint64_t load_ptr = env->rse_spill_base;
    uint64_t rnat_collection = env->ar_rnat & ~(1ULL << 63);
    uint32_t i;

    for (i = 0; i < count; i++) {
        uint8_t bit;
        uint64_t value;
        int nat;

        if (ia64_rse_is_rnat_slot(load_ptr)) {
            rnat_collection = ia64_rse_read_u64(env, load_ptr);
            rnat_collection &= ~(1ULL << 63);
            load_ptr += 8;
        }

        bit = (load_ptr >> 3) & 0x3f;
        nat = (rnat_collection >> bit) & 1;
        value = ia64_rse_read_u64(env, load_ptr);
        load_ptr += 8;

        if (i < IA64_STACKED_GR_COUNT) {
            uint32_t reg = IA64_STACKED_GR_BASE + i;

            env->gr[reg] = value;
            ia64_gr_nat_set(env, reg, nat);
        }
    }

    env->ar_bspstore = env->rse_spill_base;
    env->ar_rnat = rnat_collection;
    env->rse_cumulative_words += count;
    env->rse_spill_words = 0;
}

static int ia64_rse_find_cover_frame_ending_at_bsp(CPUIA64State *env,
                                                   uint32_t words,
                                                   uint64_t *frame_bsp,
                                                   uint32_t *cover_index)
{
    uint64_t base;
    int depth;

    if (words == 0) {
        return -1;
    }

    base = ia64_rse_bsp_retreat(env->ar_bsp, words);
    for (depth = env->rse_cover_depth - 1; depth >= 0; depth--) {
        uint32_t index;

        if (!ia64_rse_bsp_distance(env, env->rse_cover_bsp[depth],
                                   base, &index) ||
            index > env->rse_cover_sof[depth] ||
            env->rse_cover_sof[depth] - index < words) {
            continue;
        }

        *frame_bsp = base;
        *cover_index = index;
        return depth;
    }

    return -1;
}

static void ia64_rse_pop_return_frame(CPUIA64State *env, uint64_t pfs,
                                      bool restore_untracked_frame)
{
    uint32_t saved_sof = pfs & IA64_CFM_SOF_MASK;
    uint32_t sol = (pfs & IA64_CFM_SOL_MASK) >> IA64_CFM_SOL_SHIFT;
    uint32_t i;

    if (sol > IA64_STACKED_GR_COUNT) {
        sol = IA64_STACKED_GR_COUNT;
    }

    if (env->rse_spill_words > 0) {
        ia64_rse_reload_spilled_words(env);
    }

    if (env->rse_cumulative_words >= env->cfm_sof) {
        env->rse_cumulative_words -= env->cfm_sof;
    }

    if (env->rse_frame_depth > 0) {
        uint32_t depth = --env->rse_frame_depth;
        uint32_t saved_sol = env->rse_frame_sol[depth];
        uint32_t tracked_sof = env->rse_frame_sof[depth];
        uint32_t outputs =
            tracked_sof > saved_sol ? tracked_sof - saved_sol : 0;

        if (saved_sol < IA64_STACKED_GR_COUNT &&
            outputs > IA64_STACKED_GR_COUNT - saved_sol) {
            outputs = IA64_STACKED_GR_COUNT - saved_sol;
        }
        for (i = 0; saved_sol < IA64_STACKED_GR_COUNT && i < outputs; i++) {
            env->rse_frame_gr[depth][saved_sol + i] =
                env->gr[IA64_STACKED_GR_BASE + i];
            if (ia64_gr_nat_get(env, IA64_STACKED_GR_BASE + i)) {
                env->rse_frame_nat[depth][(IA64_STACKED_GR_BASE + saved_sol + i) / 64] |=
                    1ULL << ((IA64_STACKED_GR_BASE + saved_sol + i) % 64);
            } else {
                env->rse_frame_nat[depth][(IA64_STACKED_GR_BASE + saved_sol + i) / 64] &=
                    ~(1ULL << ((IA64_STACKED_GR_BASE + saved_sol + i) % 64));
            }
        }

        for (i = 0; i < IA64_STACKED_GR_COUNT; i++) {
            env->gr[IA64_STACKED_GR_BASE + i] = env->rse_frame_gr[depth][i];
        }
        env->nat[0] = (env->nat[0] & 0xffffffffULL) |
                      (env->rse_frame_nat[depth][0] & ~0xffffffffULL);
        env->nat[1] = env->rse_frame_nat[depth][1];
        env->cfm_sof = env->rse_frame_sof[depth];
        env->cfm_sol = env->rse_frame_sol[depth];
        env->cfm_sor = env->rse_frame_sor[depth];
        env->cfm_rrb_gr = env->rse_frame_rrb_gr[depth];
        env->rse_cumulative_words = env->rse_frame_cumulative_words[depth];
        env->ar_bsp = env->rse_frame_bsp[depth];
        ia64_rse_refresh_cumulative(env);
        ia64_invalidate_stacked_alat(env);
    } else if (restore_untracked_frame) {
        uint32_t outputs = saved_sof > sol ? saved_sof - sol : 0;
        uint64_t out_gr[IA64_STACKED_GR_COUNT];
        uint8_t out_nat[IA64_STACKED_GR_COUNT];
        uint64_t load_ptr;
        uint64_t load_base;
        uint64_t cover_base = 0;
        uint32_t cover_index = 0;
        int cover_depth;

        if (outputs > IA64_STACKED_GR_COUNT - sol) {
            outputs = IA64_STACKED_GR_COUNT - sol;
        }
        for (i = 0; i < outputs; i++) {
            uint32_t reg = IA64_STACKED_GR_BASE + i;

            out_gr[i] = env->gr[reg];
            out_nat[i] = ia64_gr_nat_get(env, reg);
        }

        cover_depth = -1;
        if (env->cfm_sof == saved_sof || sol == 0) {
            cover_depth =
                ia64_rse_find_cover_frame_ending_at_bsp(env, saved_sof,
                                                        &cover_base,
                                                        &cover_index);
        }
        if (cover_depth < 0) {
            cover_depth =
                ia64_rse_find_cover_frame_ending_at_bsp(env, sol,
                                                        &cover_base,
                                                        &cover_index);
        }
        if (cover_depth >= 0) {
            uint64_t retained_cover_base = env->rse_cover_bsp[cover_depth];

            for (i = 0; i < sol; i++) {
                uint32_t reg = IA64_STACKED_GR_BASE + i;
                uint32_t src = cover_index + i;
                uint32_t src_reg = IA64_STACKED_GR_BASE + src;

                env->gr[reg] = env->rse_cover_gr[cover_depth][src];
                ia64_gr_nat_set(env, reg,
                    (env->rse_cover_nat[cover_depth][src_reg / 64] >>
                     (src_reg % 64)) & 1);
            }
            env->ar_bsp = cover_base;
            if (cover_index > 0) {
                env->ar_bspstore = retained_cover_base;
                env->rse_spill_base = retained_cover_base;
                env->rse_cover_sof[cover_depth] = cover_index;
                env->rse_cover_depth = cover_depth + 1;
            } else {
                env->ar_bspstore = cover_base;
                env->rse_spill_base = cover_base;
                env->rse_cover_depth = cover_depth;
            }
            env->rse_spill_words = 0;
        } else if (sol <= IA64_STACKED_GR_COUNT) {
            load_ptr = ia64_rse_bsp_retreat(env->ar_bsp, sol);
            load_base = load_ptr;
            for (i = 0; i < sol; i++) {
                uint32_t reg = IA64_STACKED_GR_BASE + i;

                if (((load_ptr >> 3) & 0x3f) == 0x3f) {
                    load_ptr += 8;
                }
                env->gr[reg] = ia64_rse_read_u64(env, load_ptr);
                load_ptr += 8;
                ia64_gr_nat_set(env, reg, 0);
            }
            env->ar_bsp = load_base;
            /*
             * The tracked frame stack is gone, so the only registers we know
             * are present after this mandatory fill are the restored current
             * frame registers.  Reset the spill tear point to that frame base;
             * a later br.call will then move its locals into the dirty
             * partition again before flushrs writes them out.
             */
            env->ar_bspstore = load_base;
            env->rse_spill_base = load_base;
            env->rse_spill_words = 0;
        }
        for (i = 0; i < outputs; i++) {
            uint32_t reg = IA64_STACKED_GR_BASE + sol + i;

            env->gr[reg] = out_gr[i];
            ia64_gr_nat_set(env, reg, out_nat[i]);
        }

        env->cfm_sof = saved_sof;
        env->cfm_sol = (pfs & IA64_CFM_SOL_MASK) >> IA64_CFM_SOL_SHIFT;
        env->cfm_sor = (pfs & IA64_CFM_SOR_MASK) >> IA64_CFM_SOR_SHIFT;
        env->cfm_rrb_gr = (pfs & IA64_CFM_RRB_GR_MASK) >> IA64_CFM_RRB_GR_SHIFT;
        ia64_rse_refresh_cumulative(env);
        ia64_invalidate_stacked_alat(env);
    }
}

void helper_br_ret_rse(CPUIA64State *env, uint32_t b_reg)
{
    static unsigned br_ret_zero_logs;
    uint64_t pfs = env->ar_pfs;
    uint64_t target = env->br[b_reg];
    uint8_t ppl = (pfs & IA64_PFS_PPL_MASK) >> IA64_PFS_PPL_SHIFT;

    ia64_rse_pop_return_frame(env, pfs, true);
    env->ar_ec = (pfs & IA64_PFS_PEC_MASK) >> IA64_PFS_PEC_SHIFT;
    if (ia64_psr_cpl(env->psr) < ppl) {
        ia64_set_psr(env, (env->psr & ~IA64_PSR_CPL_MASK) |
                          ((uint64_t)ppl << IA64_PSR_CPL_SHIFT));
    }

    if (target == 0 && br_ret_zero_logs++ < 16) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "ia64 br.ret target zero ip=0x%016" PRIx64
                      " b%u pfs=0x%016" PRIx64 " depth=%u"
                      " b0=0x%016" PRIx64 " b6=0x%016" PRIx64 "\n",
                      env->ip, b_reg, pfs, env->rse_frame_depth,
                      env->br[0], env->br[6]);
    }
    env->ip = ia64_ip_bundle_addr(target);
}

static bool ia64_purge_tc_entries(CPUIA64State *env, IA64TlbEntry *tlb,
                                  uint8_t *count, uint64_t va, uint64_t ps,
                                  uint32_t rid, bool is_data)
{
    uint8_t i;
    bool purged = false;

    for (i = 0; i < *count; i++) {
        if (!tlb[i].is_tr && ia64_tlb_entry_overlaps(&tlb[i], va, rid, ps)) {
            if (is_data) {
                ia64_invalidate_alat_tlb_entry(env, &tlb[i]);
            }
            ia64_qemu_tlb_flush_entry(env, &tlb[i]);
            tlb[i].valid = 0;
            purged = true;
        }
    }

    while (*count > 0 && !tlb[*count - 1].valid) {
        (*count)--;
    }

    return purged;
}

static bool ia64_mark_pending_purge_entries(IA64TlbEntry *tlb, uint8_t count,
                                            uint64_t va, uint64_t ps,
                                            uint32_t rid, bool tc_only,
                                            char kind)
{
    uint8_t i;
    bool marked = false;

    for (i = 0; i < count; i++) {
        if ((!tc_only || !tlb[i].is_tr) &&
            ia64_tlb_entry_overlaps(&tlb[i], va, rid, ps)) {
            qemu_log_mask(CPU_LOG_MMU,
                          "ia64 pending purge.%c slot=%u %s"
                          " va=0x%016" PRIx64 " rid=0x%06" PRIx32
                          " pa=0x%016" PRIx64 " ps=0x%016" PRIx64
                          " purge_va=0x%016" PRIx64
                          " purge_ps=0x%016" PRIx64 "\n",
                          kind, i, tlb[i].is_tr ? "TR" : "TC",
                          tlb[i].va, tlb[i].rid, tlb[i].pa, tlb[i].ps,
                          va, ps);
            tlb[i].pending_purge = 1;
            marked = true;
        }
    }

    return marked;
}

static bool ia64_mark_pending_purge_all_tc(IA64TlbEntry *tlb, uint8_t count,
                                           char kind)
{
    uint8_t i;
    bool marked = false;

    for (i = 0; i < count; i++) {
        if (!tlb[i].is_tr && tlb[i].valid) {
            qemu_log_mask(CPU_LOG_MMU,
                          "ia64 pending purge.%c slot=%u TC"
                          " va=0x%016" PRIx64 " rid=0x%06" PRIx32
                          " pa=0x%016" PRIx64 " ps=0x%016" PRIx64
                          " purge=all-tc\n",
                          kind, i, tlb[i].va, tlb[i].rid,
                          tlb[i].pa, tlb[i].ps);
            tlb[i].pending_purge = 1;
            marked = true;
        }
    }

    return marked;
}

static bool ia64_complete_pending_purges(CPUIA64State *env,
                                         IA64TlbEntry *tlb, uint8_t *count,
                                         char kind)
{
    uint8_t i;
    bool purged = false;

    for (i = 0; i < *count; i++) {
        if (tlb[i].valid && tlb[i].pending_purge) {
            qemu_log_mask(CPU_LOG_MMU,
                          "ia64 complete purge.%c slot=%u %s"
                          " va=0x%016" PRIx64 " rid=0x%06" PRIx32
                          " pa=0x%016" PRIx64 " ps=0x%016" PRIx64 "\n",
                          kind, i, tlb[i].is_tr ? "TR" : "TC",
                          tlb[i].va, tlb[i].rid, tlb[i].pa, tlb[i].ps);
            if (kind == 'd') {
                ia64_invalidate_alat_tlb_entry(env, &tlb[i]);
            }
            tlb[i].pending_purge = 0;
            tlb[i].valid = 0;
            purged = true;
        }
    }

    while (*count > 0 && !tlb[*count - 1].valid) {
        (*count)--;
    }

    return purged;
}

void helper_tlb_serialize(CPUIA64State *env, uint32_t serialize_data,
                          uint32_t serialize_inst)
{
    bool data_purged = false;
    bool inst_purged = false;

    if (serialize_data) {
        env->psr_ic_inflight = false;
        data_purged = ia64_complete_pending_purges(env, env->tlb_data,
                                                   &env->tlb_data_count, 'd');
    }
    if (serialize_inst) {
        inst_purged = ia64_complete_pending_purges(env, env->tlb_inst,
                                                   &env->tlb_inst_count, 'i');
    }
    if (data_purged || inst_purged) {
        tlb_flush(env_cpu(env));
    }
    /*
     * srlz.i and rfi re-initiate later instruction fetches.  QEMU must also
     * process any pending full TB flush queued by prior instruction-side
     * translation or cache maintenance before fetching the next TB.
     */
    if (serialize_inst) {
        ia64_queue_itlb_tb_flush(env);
    }
}

void helper_ssm(CPUIA64State *env, uint64_t imm)
{
    ia64_set_psr(env, env->psr | imm);
}

void helper_rsm(CPUIA64State *env, uint64_t imm)
{
    ia64_set_psr(env, env->psr & ~imm);
}

static int ia64_tlb_select_tc_slot(IA64TlbEntry *tlb, uint8_t *next_replace,
                                   uint64_t va, uint32_t rid, bool *matched)
{
    int empty = -1;
    uint8_t i;

    *matched = false;
    for (i = 0; i < IA64_TLB_MAX; i++) {
        if (!tlb[i].valid) {
            if (empty < 0) {
                empty = i;
            }
            continue;
        }
        if (tlb[i].is_tr) {
            continue;
        }
        if (tlb[i].va == va && tlb[i].rid == rid) {
            *matched = true;
            return i;
        }
    }

    if (empty >= 0) {
        *next_replace = (empty + 1) % IA64_TLB_MAX;
        return empty;
    }

    /*
     * TC replacement is implementation-specific, but it must not
     * consistently evict the same software-required entry and defeat forward
     * progress.  Use a small round-robin policy over non-TR entries.
     */
    for (i = 0; i < IA64_TLB_MAX; i++) {
        uint8_t slot = (*next_replace + i) % IA64_TLB_MAX;

        if (!tlb[slot].is_tr) {
            *next_replace = (slot + 1) % IA64_TLB_MAX;
            return slot;
        }
    }

    return -1;
}

static bool ia64_cache_replaced_tr(IA64TlbEntry *tlb, uint8_t *cnt,
                                   uint8_t *next_replace,
                                   const IA64TlbEntry *old_tr)
{
    bool matched;
    int slot;

    if (!old_tr->valid || !old_tr->is_tr) {
        return false;
    }

    /*
     * Replacing a TR slot does not purge the previous translation from the
     * processor TLBs.  Model that architected behavior as a TC copy, which
     * remains until normal TC replacement or an explicit ptr purge.
     */
    slot = ia64_tlb_select_tc_slot(tlb, next_replace, old_tr->va,
                                   old_tr->rid, &matched);
    if (slot < 0) {
        qemu_log_mask(CPU_LOG_MMU,
                      "ia64 cache replaced tr failed va=0x%016" PRIx64
                      " rid=0x%06" PRIx32 " ps=0x%016" PRIx64 "\n",
                      old_tr->va, old_tr->rid, old_tr->ps);
        return false;
    }

    qemu_log_mask(CPU_LOG_MMU,
                  "ia64 cache replaced tr slot=%d va=0x%016" PRIx64
                  " rid=0x%06" PRIx32 " pa=0x%016" PRIx64
                  " ps=0x%016" PRIx64 "\n",
                  slot, old_tr->va, old_tr->rid, old_tr->pa, old_tr->ps);
    tlb[slot] = *old_tr;
    tlb[slot].is_tr = 0;
    tlb[slot].slot = slot;
    if (slot >= *cnt) {
        *cnt = slot + 1;
    }
    return true;
}

void helper_itr_insert(CPUIA64State *env, uint64_t pte, uint64_t slot_reg,
                       uint32_t is_data)
{
    IA64TlbEntry *tlb;
    uint8_t *cnt;
    uint64_t ps = ia64_itir_page_size(env);
    uint64_t va = env->cr_ifa & ~(ps - 1);
    uint64_t pa = (pte & IA64_PTE_PPN_MASK) & ~(ps - 1);
    uint32_t key = (env->cr_itir & IA64_ITIR_KEY_MASK) >>
                   IA64_ITIR_KEY_SHIFT;
    uint8_t ar = ia64_pte_ar(pte);
    uint8_t pl = ia64_pte_pl(pte);
    uint8_t perm = ia64_pte_perm(pte, 0);
    uint32_t rid = ia64_region_rid(env, env->cr_ifa);
    uint32_t slot = slot_reg;
    uint8_t *next_replace;

    CPUState *cs = env_cpu(env);

    if ((pte & IA64_PTE_PRESENT) && perm == 0) {
        return;
    }

    if (is_data) {
        tlb = env->tlb_data;
        cnt = &env->tlb_data_count;
        next_replace = &env->tlb_data_replace;
    } else {
        tlb = env->tlb_inst;
        cnt = &env->tlb_inst_count;
        next_replace = &env->tlb_inst_replace;
    }

    if (slot < IA64_TLB_MAX) {
        IA64TlbEntry old_tr = tlb[slot];

        ia64_purge_tc_entries(env, tlb, cnt, va, ps, rid, is_data);
        ia64_cache_replaced_tr(tlb, cnt, next_replace, &old_tr);

        tlb[slot].va = va;
        tlb[slot].pa = pa;
        tlb[slot].ps = ps;
        tlb[slot].pte = pte;
        tlb[slot].perm = perm;
        tlb[slot].ar = ar;
        tlb[slot].pl = pl;
        tlb[slot].valid = 1;
        tlb[slot].is_tr = 1;
        tlb[slot].pending_purge = 0;
        tlb[slot].rid = rid;
        tlb[slot].key = key;
        tlb[slot].slot = slot;
        if (slot >= *cnt) {
            *cnt = slot + 1;
        }
        qemu_log_mask(CPU_LOG_MMU,
                      "ia64 itr.%c slot=%u va=0x%016" PRIx64
                      " rid=0x%06" PRIx32 " pa=0x%016" PRIx64
                      " ps=0x%016" PRIx64 " pte=0x%016" PRIx64 "\n",
                      is_data ? 'd' : 'i', slot, va, rid, pa, ps, pte);
        tlb_flush(cs);
        if (!is_data) {
            ia64_queue_itlb_tb_flush(env);
        }
    }
}

void helper_ptr_purge(CPUIA64State *env, uint64_t ifa, uint64_t size_reg,
                      uint32_t is_data)
{
    IA64TlbEntry *tlb;
    uint64_t ps = ia64_gr_page_size(size_reg);
    uint64_t va = ifa & ~(ps - 1);
    uint32_t rid = ia64_region_rid(env, ifa);
    uint8_t count;

    if (is_data) {
        tlb = env->tlb_data;
        count = env->tlb_data_count;
    } else {
        tlb = env->tlb_inst;
        count = env->tlb_inst_count;
    }

    ia64_mark_pending_purge_entries(tlb, count, va, ps, rid, false,
                                    is_data ? 'd' : 'i');
}

void helper_ptc_purge(CPUIA64State *env, uint64_t va, uint64_t size_reg,
                      uint32_t mode)
{
    uint32_t rid = ia64_region_rid(env, va);

    if (mode == 2) {
        ia64_mark_pending_purge_all_tc(env->tlb_data,
                                       env->tlb_data_count, 'd');
        ia64_mark_pending_purge_all_tc(env->tlb_inst,
                                       env->tlb_inst_count, 'i');
    } else {
        uint64_t ps = ia64_gr_page_size(size_reg);

        ia64_mark_pending_purge_entries(env->tlb_data, env->tlb_data_count,
                                        va, ps, rid, true, 'd');
        ia64_mark_pending_purge_entries(env->tlb_inst, env->tlb_inst_count,
                                        va, ps, rid, true, 'i');
    }
}

uint64_t helper_tpa(CPUIA64State *env, uint64_t va)
{
    CPUState *cs = env_cpu(env);
    uint64_t pa;
    uint8_t perm;
    uint32_t rid = ia64_region_rid(env, va);
    IA64Exception excp;
    uint8_t vhpt_size;
    bool vhpt_long_format;
    bool vhpt_enabled;
    static unsigned tpa_logs;
    uint64_t pte;
    const IA64TlbEntry *entry;

    if (env->psr & IA64_PSR_DT) {
        entry = ia64_tlb_find(env->tlb_data, env->tlb_data_count, va, rid,
                              false);
        if (entry) {
            ia64_tlb_entry_translate(entry, va, ia64_psr_cpl(env->psr), &pa,
                                     &perm);
            if (!ia64_tlb_entry_present(entry)) {
                excp = IA64_EXCP_PAGE_NOT_PRESENT;
                goto tpa_fault;
            }
            if (!(perm & IA64_TLB_R)) {
                excp = IA64_EXCP_DATA_ACCESS;
                goto tpa_fault;
            }
            if (tpa_logs++ < 128) {
                qemu_log_mask(CPU_LOG_MMU,
                              "ia64 tpa va=0x%016" PRIx64
                              " pa=0x%016" PRIx64
                              " dtlb psr=0x%016" PRIx64
                              " ip=0x%016" PRIx64 "\n",
                              va, pa, env->psr, env->ip);
            }
            return pa;
        }
        if (ia64_kernel_direct_data_pa(env->psr, env->rr[ia64_rr_index(va)],
                                       va, &pa)) {
            if (tpa_logs++ < 128) {
                qemu_log_mask(CPU_LOG_MMU,
                              "ia64 tpa va=0x%016" PRIx64
                              " pa=0x%016" PRIx64
                              " direct psr=0x%016" PRIx64
                              " ip=0x%016" PRIx64 "\n",
                              va, pa, env->psr, env->ip);
            }
            return pa;
        }
        pte = 0;
        if (ia64_vhpt_walk_full(env, va, rid, false, &pa, &perm, &pte)) {
            if (!(pte & IA64_PTE_PRESENT)) {
                excp = IA64_EXCP_PAGE_NOT_PRESENT;
                goto tpa_fault;
            }
            if (!(perm & IA64_TLB_R)) {
                excp = IA64_EXCP_DATA_ACCESS;
                goto tpa_fault;
            }
            if (tpa_logs++ < 128) {
                qemu_log_mask(CPU_LOG_MMU,
                              "ia64 tpa va=0x%016" PRIx64
                              " pa=0x%016" PRIx64
                              " vhpt psr=0x%016" PRIx64
                              " ip=0x%016" PRIx64 "\n",
                              va, pa, env->psr, env->ip);
            }
            return pa;
        }
        if (ia64_sal_boot_identity_pa(env, va, &pa)) {
            if (tpa_logs++ < 128) {
                qemu_log_mask(CPU_LOG_MMU,
                              "ia64 tpa va=0x%016" PRIx64
                              " pa=0x%016" PRIx64
                              " sal-identity psr=0x%016" PRIx64
                              " ip=0x%016" PRIx64 "\n",
                              va, pa, env->psr, env->ip);
            }
            return pa;
        }
        vhpt_enabled = ia64_vhpt_walker_enabled(env, va, false,
                                                &vhpt_size,
                                                &vhpt_long_format);
        if (ia64_data_nested_tlb_active(env)) {
            excp = IA64_EXCP_DATA_NESTED_TLB;
        } else if (!ia64_vhpt_entry_accessible(env, va, false,
                                               &env->cr_iha)) {
            excp = IA64_EXCP_VHPT_FAULT;
        } else if (vhpt_enabled) {
            excp = IA64_EXCP_DTLB_FAULT;
        } else {
            excp = IA64_EXCP_ALT_DTLB;
        }
    } else if (ia64_kernel_direct_data_pa(env->psr,
                                          env->rr[ia64_rr_index(va)],
                                          va, &pa)) {
        if (tpa_logs++ < 128) {
            qemu_log_mask(CPU_LOG_MMU,
                          "ia64 tpa va=0x%016" PRIx64
                          " pa=0x%016" PRIx64 " direct psr=0x%016" PRIx64
                          " ip=0x%016" PRIx64 "\n",
                          va, pa, env->psr, env->ip);
        }
        return pa;
    } else if ((entry = ia64_tlb_find(env->tlb_data, env->tlb_data_count,
                                      va, rid, false)) != NULL &&
               ia64_tlb_entry_present(entry)) {
        ia64_tlb_entry_translate(entry, va, ia64_psr_cpl(env->psr), &pa,
                                 &perm);
        if (!(perm & IA64_TLB_R)) {
            excp = IA64_EXCP_DATA_ACCESS;
            goto tpa_fault;
        }
        if (tpa_logs++ < 128) {
            qemu_log_mask(CPU_LOG_MMU,
                          "ia64 tpa va=0x%016" PRIx64
                          " pa=0x%016" PRIx64
                          " phys-dtlb psr=0x%016" PRIx64
                          " ip=0x%016" PRIx64 "\n",
                          va, pa, env->psr, env->ip);
        }
        return pa;
    } else {
        excp = IA64_EXCP_ALT_DTLB;
    }

tpa_fault:
    if (env->psr & IA64_PSR_IC) {
        env->cr_ifa = va;
        if (ia64_exception_initializes_iha(excp)) {
            env->cr_iha = ia64_vhpt_hash_address(env, va);
        }
        env->cr_itir = ia64_region_itir(
            env, excp == IA64_EXCP_VHPT_FAULT ? env->cr_iha : va);
    }
    if (excp != IA64_EXCP_DATA_NESTED_TLB) {
        env->cr_isr = IA64_ISR_NA;
    }
    cs->exception_index = excp;
    cpu_loop_exit(cs);
}

void helper_fadd(CPUIA64State *env, uint32_t r1, uint32_t r2, uint32_t r3)
{
    if (ia64_fr_write_nat_if_any2(env, r1, r2, r3)) {
        return;
    }
    ia64_fr_write(env, r1,
                  float64_add(env->fr[r2], env->fr[r3], &env->fp_status));
}

void helper_fsub(CPUIA64State *env, uint32_t r1, uint32_t r2, uint32_t r3)
{
    if (ia64_fr_write_nat_if_any2(env, r1, r2, r3)) {
        return;
    }
    ia64_fr_write(env, r1,
                  float64_sub(env->fr[r2], env->fr[r3], &env->fp_status));
}

void helper_fmpy(CPUIA64State *env, uint32_t r1, uint32_t r2, uint32_t r3)
{
    if (ia64_fr_write_nat_if_any2(env, r1, r2, r3)) {
        return;
    }
    ia64_fr_write(env, r1,
                  float64_mul(env->fr[r2], env->fr[r3], &env->fp_status));
}

void helper_fma(CPUIA64State *env, uint32_t r1, uint32_t r2, uint32_t r3)
{
    if (ia64_fr_write_nat_if_any2(env, r1, r2, r3)) {
        return;
    }
    ia64_fr_write(env, r1,
                  float64_muladd(env->fr[r2], env->fr[r3],
                                 float64_zero, 0, &env->fp_status));
}

void helper_fma4(CPUIA64State *env, uint32_t r1, uint32_t r2,
                 uint32_t r3, uint32_t r4)
{
    if (ia64_fr_write_nat_if_any3(env, r1, r2, r3, r4)) {
        return;
    }
    ia64_fr_write(env, r1,
                  float64_muladd(env->fr[r3], env->fr[r4],
                                 env->fr[r2], 0, &env->fp_status));
}

void helper_fcmp(CPUIA64State *env, uint32_t p1, uint32_t p2,
                 uint32_t r2, uint32_t r3, uint32_t cond_code)
{
    FloatRelation rel;
    bool cond;

    if (ia64_fr_nat_get(env, r2) || ia64_fr_nat_get(env, r3)) {
        ia64_pr_write(env, p1, false);
        ia64_pr_write(env, p2, false);
        return;
    }

    rel = float64_compare(env->fr[r2], env->fr[r3], &env->fp_status);

    switch (cond_code & 3) {
    case 0:
        cond = rel == float_relation_equal;
        break;
    case 1:
        cond = rel == float_relation_less;
        break;
    case 2:
        cond = rel == float_relation_less || rel == float_relation_equal;
        break;
    default:
        cond = rel == float_relation_unordered;
        break;
    }

    if (p1) {
        env->pr[p1] = cond ? 1 : 0;
    }
    if (p2) {
        env->pr[p2] = cond ? 0 : 1;
    }
    env->pr[0] = 1;
}

/* ---- FP min/max (F8 forms select f3 on equality or NaN) ---- */

static void ia64_fminmax(CPUIA64State *env, uint32_t r1, uint32_t r2,
                         uint32_t r3, bool is_max, bool is_abs)
{
    float64 left;
    float64 right;
    FloatRelation rel;
    bool take_left;

    if (ia64_fr_write_nat_if_any2(env, r1, r2, r3)) {
        return;
    }

    left = env->fr[r2];
    right = env->fr[r3];
    rel = float64_compare(is_abs ? float64_abs(left) : left,
                          is_abs ? float64_abs(right) : right,
                          &env->fp_status);
    take_left = is_max ? rel == float_relation_greater :
                         rel == float_relation_less;
    ia64_fr_write(env, r1, take_left ? left : right);
}

void helper_fmin(CPUIA64State *env, uint32_t r1, uint32_t r2, uint32_t r3)
{
    ia64_fminmax(env, r1, r2, r3, false, false);
}

void helper_fmax(CPUIA64State *env, uint32_t r1, uint32_t r2, uint32_t r3)
{
    ia64_fminmax(env, r1, r2, r3, true, false);
}

void helper_famin(CPUIA64State *env, uint32_t r1, uint32_t r2, uint32_t r3)
{
    ia64_fminmax(env, r1, r2, r3, false, true);
}

void helper_famax(CPUIA64State *env, uint32_t r1, uint32_t r2, uint32_t r3)
{
    ia64_fminmax(env, r1, r2, r3, true, true);
}

/* ---- FP reciprocal approximation (frcpa: ~1/x in table index 0) ---- */

static bool ia64_fr_looks_like_setf_sig_payload(uint64_t value)
{
    uint64_t exponent = (value >> 52) & 0x7ff;
    uint64_t fraction = value & 0x000fffffffffffffULL;

    return exponent == 0 && fraction != 0;
}

static bool ia64_float64_rcpa_predicate(float64 num, float64 den)
{
    return !float64_is_zero(num) &&
           !float64_is_infinity(num) &&
           !float64_is_any_nan(num) &&
           !float64_is_zero(den) &&
           !float64_is_infinity(den) &&
           !float64_is_any_nan(den);
}

static float64 ia64_float64_rcpa(float64 num, float64 den,
                                 bool approximate, float_status *status)
{
    return float64_div(approximate ? float64_one : num, den, status);
}

void helper_frcpa(CPUIA64State *env, uint32_t r1, uint32_t p2,
                  uint32_t r2, uint32_t r3)
{
    uint64_t num_bits = env->fr[r2];
    uint64_t den_bits = env->fr[r3];
    float64 num;
    float64 den;
    bool predicate;

    if (ia64_fr_nat_get(env, r2) || ia64_fr_nat_get(env, r3)) {
        ia64_fr_write_nat(env, r1);
        ia64_pr_write(env, p2, false);
        return;
    }

    /*
     * setf.sig places an integer significand into the FP register format.
     * When both operands are in that form, compute the quotient exactly and
     * clear the refinement predicate; this is the architected software-assist
     * completion path for reciprocal approximation.
     */
    if ((ia64_fr_sig_get(env, r2) ||
         ia64_fr_looks_like_setf_sig_payload(num_bits)) &&
        (ia64_fr_sig_get(env, r3) ||
         ia64_fr_looks_like_setf_sig_payload(den_bits))) {
        ia64_fr_write_sig(env, r1, den_bits == 0 ? 0 : num_bits / den_bits);
        ia64_pr_write(env, p2, false);
        return;
    }

    num = num_bits;
    den = den_bits;
    predicate = ia64_float64_rcpa_predicate(num, den);
    ia64_fr_write(env, r1,
                  ia64_float64_rcpa(num, den, predicate, &env->fp_status));
    ia64_pr_write(env, p2, predicate);
}

static bool ia64_float32_rcpa_predicate(float32 num, float32 den)
{
    return !float32_is_zero(num) &&
           !float32_is_infinity(num) &&
           !float32_is_any_nan(num) &&
           !float32_is_zero(den) &&
           !float32_is_infinity(den) &&
           !float32_is_any_nan(den);
}

static float32 ia64_float32_rcpa(float32 num, float32 den,
                                 bool approximate, float_status *status)
{
    return float32_div(approximate ? float32_one : num, den, status);
}

void helper_fprcpa(CPUIA64State *env, uint32_t r1, uint32_t p2,
                   uint32_t r2, uint32_t r3)
{
    uint64_t num = env->fr[r2];
    uint64_t den = env->fr[r3];
    float32 num_hi = make_float32(num >> 32);
    float32 num_lo = make_float32(num);
    float32 den_hi = make_float32(den >> 32);
    float32 den_lo = make_float32(den);
    bool hi_pred;
    bool lo_pred;
    float32 hi_result;
    float32 lo_result;

    if (ia64_fr_nat_get(env, r2) || ia64_fr_nat_get(env, r3)) {
        ia64_fr_write_nat(env, r1);
        ia64_pr_write(env, p2, false);
        return;
    }

    hi_pred = ia64_float32_rcpa_predicate(num_hi, den_hi);
    lo_pred = ia64_float32_rcpa_predicate(num_lo, den_lo);
    hi_result = ia64_float32_rcpa(num_hi, den_hi, hi_pred, &env->fp_status);
    lo_result = ia64_float32_rcpa(num_lo, den_lo, lo_pred, &env->fp_status);

    ia64_fr_write(env, r1,
                  ((uint64_t)float32_val(hi_result) << 32) |
                  float32_val(lo_result));
    ia64_pr_write(env, p2, hi_pred && lo_pred);
}

/* ---- FP classify ---- */

void helper_fclass(CPUIA64State *env, uint32_t p1, uint32_t p2,
                   uint32_t f2, uint32_t fclass9)
{
    uint64_t val = env->fr[f2];
    bool is_neg = (val >> 63) & 1;
    uint64_t exp = (val >> 52) & 0x7FF;
    uint64_t mant = val & 0xFFFFFFFFFFFFFULL;
    bool is_nat = (env->fr_nat[f2 / 64] >> (f2 % 64)) & 1;
    bool is_zero = exp == 0 && mant == 0;
    bool is_unorm = exp == 0 && mant != 0;
    bool is_inf = exp == 0x7ff && mant == 0;
    bool is_nan = exp == 0x7ff && mant != 0;
    bool is_qnan = is_nan && (mant & 0x8000000000000ULL);
    bool is_snan = is_nan && !is_qnan;
    bool is_normal = !is_zero && !is_unorm && !is_inf && !is_nan;
    bool sign_match = ((fclass9 & 0x001) && !is_neg) ||
                      ((fclass9 & 0x002) && is_neg);
    bool type_match = ((fclass9 & 0x004) && is_zero) ||
                      ((fclass9 & 0x008) && is_unorm) ||
                      ((fclass9 & 0x010) && is_normal) ||
                      ((fclass9 & 0x020) && is_inf);
    bool member = (sign_match && type_match) ||
                  ((fclass9 & 0x040) && is_snan) ||
                  ((fclass9 & 0x080) && is_qnan) ||
                  ((fclass9 & 0x100) && is_nat);

    if (is_nat && !(fclass9 & 0x100)) {
        if (p1) {
            env->pr[p1] = 0;
        }
        if (p2) {
            env->pr[p2] = 0;
        }
    } else {
        if (p1) {
            env->pr[p1] = member ? 1 : 0;
        }
        if (p2) {
            env->pr[p2] = member ? 0 : 1;
        }
    }
    env->pr[0] = 1;
}

#define IA64_FP_SIGN_MASK 0x8000000000000000ULL
#define IA64_FP_EXP_MASK  0x7ff0000000000000ULL
#define IA64_FP_FRAC_MASK 0x000fffffffffffffULL

/* ---- FP merge ---- */

void helper_fmerge_ns(CPUIA64State *env, uint32_t r1,
                      uint32_t r2, uint32_t r3)
{
    if (ia64_fr_nat_get(env, r2) || ia64_fr_nat_get(env, r3)) {
        ia64_fr_write_nat(env, r1);
        return;
    }

    ia64_fr_write_sig(env, r1,
                      ((~env->fr[r2]) & IA64_FP_SIGN_MASK) |
                      (env->fr[r3] & ~IA64_FP_SIGN_MASK));
}

void helper_fmerge_s(CPUIA64State *env, uint32_t r1, uint32_t r2, uint32_t r3)
{
    if (ia64_fr_nat_get(env, r2) || ia64_fr_nat_get(env, r3)) {
        ia64_fr_write_nat(env, r1);
        return;
    }

    ia64_fr_write_sig(env, r1,
                      (env->fr[r2] & IA64_FP_SIGN_MASK) |
                      (env->fr[r3] & ~IA64_FP_SIGN_MASK));
}

void helper_fmerge_se(CPUIA64State *env, uint32_t r1, uint32_t r2, uint32_t r3)
{
    if (ia64_fr_nat_get(env, r2) || ia64_fr_nat_get(env, r3)) {
        ia64_fr_write_nat(env, r1);
        return;
    }

    ia64_fr_write_sig(env, r1,
                      (env->fr[r2] & (IA64_FP_SIGN_MASK |
                                      IA64_FP_EXP_MASK)) |
                      (env->fr[r3] & IA64_FP_FRAC_MASK));
}

/* ---- FP logical/swap ---- */

void helper_flogical_and(CPUIA64State *env, uint32_t r1,
                         uint32_t r2, uint32_t r3)
{
    if (ia64_fr_write_nat_if_any2(env, r1, r2, r3)) {
        return;
    }

    ia64_fr_write_sig(env, r1, env->fr[r2] & env->fr[r3]);
}

void helper_flogical_andcm(CPUIA64State *env, uint32_t r1,
                           uint32_t r2, uint32_t r3)
{
    if (ia64_fr_write_nat_if_any2(env, r1, r2, r3)) {
        return;
    }

    ia64_fr_write_sig(env, r1, env->fr[r2] & ~env->fr[r3]);
}

void helper_flogical_or(CPUIA64State *env, uint32_t r1,
                        uint32_t r2, uint32_t r3)
{
    if (ia64_fr_write_nat_if_any2(env, r1, r2, r3)) {
        return;
    }

    ia64_fr_write_sig(env, r1, env->fr[r2] | env->fr[r3]);
}

void helper_flogical_xor(CPUIA64State *env, uint32_t r1,
                         uint32_t r2, uint32_t r3)
{
    if (ia64_fr_write_nat_if_any2(env, r1, r2, r3)) {
        return;
    }

    ia64_fr_write_sig(env, r1, env->fr[r2] ^ env->fr[r3]);
}

void helper_fswap(CPUIA64State *env, uint32_t r1, uint32_t r2,
                  uint32_t r3, uint32_t form)
{
    uint32_t hi;
    uint32_t lo;

    if (ia64_fr_write_nat_if_any2(env, r1, r2, r3)) {
        return;
    }

    hi = env->fr[r3];
    lo = env->fr[r2] >> 32;
    if (form == 1) {
        hi ^= 0x80000000U;
    } else if (form == 2) {
        lo ^= 0x80000000U;
    }

    ia64_fr_write(env, r1, ((uint64_t)hi << 32) | lo);
}

void helper_fmix(CPUIA64State *env, uint32_t r1, uint32_t r2,
                 uint32_t r3, uint32_t form)
{
    uint32_t hi;
    uint32_t lo;

    if (ia64_fr_write_nat_if_any2(env, r1, r2, r3)) {
        return;
    }

    if (form == 1) {
        hi = env->fr[r2];
        lo = env->fr[r3];
    } else {
        hi = env->fr[r2] >> 32;
        lo = form == 2 ? env->fr[r3] >> 32 : env->fr[r3];
    }

    ia64_fr_write(env, r1, ((uint64_t)hi << 32) | lo);
}

void helper_fsxt(CPUIA64State *env, uint32_t r1, uint32_t r2,
                 uint32_t r3, uint32_t form)
{
    uint32_t hi;
    uint32_t lo;

    if (ia64_fr_write_nat_if_any2(env, r1, r2, r3)) {
        return;
    }

    if (form == 1) {
        hi = (env->fr[r2] >> 63) ? UINT32_MAX : 0;
        lo = env->fr[r3] >> 32;
    } else {
        hi = ((env->fr[r2] >> 31) & 1) ? UINT32_MAX : 0;
        lo = env->fr[r3];
    }

    ia64_fr_write(env, r1, ((uint64_t)hi << 32) | lo);
}

/* ---- Parallel FP merge/min/max/compare ---- */

static uint64_t ia64_pack_fp32_lanes(uint32_t hi, uint32_t lo)
{
    return ((uint64_t)hi << 32) | lo;
}

void helper_fpmerge(CPUIA64State *env, uint32_t r1, uint32_t r2,
                    uint32_t r3, uint32_t form)
{
    uint32_t f2_hi;
    uint32_t f2_lo;
    uint32_t f3_hi;
    uint32_t f3_lo;
    uint32_t hi;
    uint32_t lo;

    if (ia64_fr_write_nat_if_any2(env, r1, r2, r3)) {
        return;
    }

    f2_hi = env->fr[r2] >> 32;
    f2_lo = env->fr[r2];
    f3_hi = env->fr[r3] >> 32;
    f3_lo = env->fr[r3];

    if (form == 0) {
        hi = ((f2_hi ^ 0x80000000U) & 0x80000000U) |
             (f3_hi & 0x7fffffffU);
        lo = ((f2_lo ^ 0x80000000U) & 0x80000000U) |
             (f3_lo & 0x7fffffffU);
    } else if (form == 1) {
        hi = (f2_hi & 0x80000000U) | (f3_hi & 0x7fffffffU);
        lo = (f2_lo & 0x80000000U) | (f3_lo & 0x7fffffffU);
    } else {
        hi = (f2_hi & 0xff800000U) | (f3_hi & 0x007fffffU);
        lo = (f2_lo & 0xff800000U) | (f3_lo & 0x007fffffU);
    }

    ia64_fr_write(env, r1, ia64_pack_fp32_lanes(hi, lo));
}

static uint32_t ia64_fpminmax_lane(CPUIA64State *env, uint32_t a_bits,
                                   uint32_t b_bits, bool is_max,
                                   bool is_abs)
{
    float32 a = make_float32(a_bits);
    float32 b = make_float32(b_bits);
    float32 cmp_a = is_abs ? float32_abs(a) : a;
    float32 cmp_b = is_abs ? float32_abs(b) : b;
    FloatRelation rel;

    if (float32_is_any_nan(a) || float32_is_any_nan(b)) {
        return b_bits;
    }

    rel = float32_compare(cmp_a, cmp_b, &env->fp_status);
    if (is_max) {
        return rel == float_relation_greater ? a_bits : b_bits;
    }
    return rel == float_relation_less ? a_bits : b_bits;
}

void helper_fpminmax(CPUIA64State *env, uint32_t r1, uint32_t r2,
                     uint32_t r3, uint32_t is_max, uint32_t is_abs)
{
    uint32_t f2_hi;
    uint32_t f2_lo;
    uint32_t f3_hi;
    uint32_t f3_lo;
    uint32_t hi;
    uint32_t lo;

    if (ia64_fr_write_nat_if_any2(env, r1, r2, r3)) {
        return;
    }

    f2_hi = env->fr[r2] >> 32;
    f2_lo = env->fr[r2];
    f3_hi = env->fr[r3] >> 32;
    f3_lo = env->fr[r3];
    hi = ia64_fpminmax_lane(env, f2_hi, f3_hi, is_max != 0, is_abs != 0);
    lo = ia64_fpminmax_lane(env, f2_lo, f3_lo, is_max != 0, is_abs != 0);

    ia64_fr_write(env, r1, ia64_pack_fp32_lanes(hi, lo));
}

static bool ia64_fpcmp_lane(CPUIA64State *env, uint32_t a_bits,
                            uint32_t b_bits, uint32_t frel)
{
    FloatRelation rel = float32_compare(make_float32(a_bits),
                                        make_float32(b_bits),
                                        &env->fp_status);

    switch (frel & 7) {
    case 0:
        return rel == float_relation_equal;
    case 1:
        return rel == float_relation_less;
    case 2:
        return rel == float_relation_less || rel == float_relation_equal;
    case 3:
        return rel == float_relation_unordered;
    case 4:
        return rel != float_relation_equal;
    case 5:
        return rel != float_relation_less;
    case 6:
        return rel != float_relation_less && rel != float_relation_equal;
    default:
        return rel != float_relation_unordered;
    }
}

void helper_fpcmp(CPUIA64State *env, uint32_t r1, uint32_t r2,
                  uint32_t r3, uint32_t frel)
{
    uint32_t hi;
    uint32_t lo;

    if (ia64_fr_write_nat_if_any2(env, r1, r2, r3)) {
        return;
    }

    hi = ia64_fpcmp_lane(env, env->fr[r2] >> 32, env->fr[r3] >> 32,
                         frel) ? UINT32_MAX : 0;
    lo = ia64_fpcmp_lane(env, env->fr[r2], env->fr[r3], frel) ?
         UINT32_MAX : 0;

    ia64_fr_write(env, r1, ia64_pack_fp32_lanes(hi, lo));
}

static uint32_t ia64_fpcvt_lane(CPUIA64State *env, uint32_t value,
                                bool is_unsigned, bool is_trunc)
{
    float32 f = make_float32(value);

    if (is_unsigned) {
        return is_trunc ?
            float32_to_uint32_round_to_zero(f, &env->fp_status) :
            float32_to_uint32(f, &env->fp_status);
    }
    return is_trunc ?
        (uint32_t)float32_to_int32_round_to_zero(f, &env->fp_status) :
        (uint32_t)float32_to_int32(f, &env->fp_status);
}

void helper_fpcvt(CPUIA64State *env, uint32_t r1, uint32_t r2,
                  uint32_t is_unsigned, uint32_t is_trunc)
{
    uint32_t hi;
    uint32_t lo;

    if (ia64_fr_nat_get(env, r2)) {
        ia64_fr_write_nat(env, r1);
        return;
    }

    hi = ia64_fpcvt_lane(env, env->fr[r2] >> 32,
                         is_unsigned != 0, is_trunc != 0);
    lo = ia64_fpcvt_lane(env, env->fr[r2],
                         is_unsigned != 0, is_trunc != 0);

    ia64_fr_write(env, r1, ia64_pack_fp32_lanes(hi, lo));
}

static uint32_t ia64_fpma_lane(CPUIA64State *env, uint32_t addend_bits,
                               uint32_t multiplicand_bits,
                               uint32_t multiplier_bits, uint32_t form)
{
    float32 addend = make_float32(addend_bits);
    float32 multiplicand = make_float32(multiplicand_bits);
    float32 multiplier = make_float32(multiplier_bits);

    if (form == 1) {
        addend = float32_chs(addend);
    } else if (form == 2) {
        multiplicand = float32_chs(multiplicand);
    }

    return float32_val(float32_muladd(multiplicand, multiplier, addend,
                                      0, &env->fp_status));
}

void helper_fpma(CPUIA64State *env, uint32_t r1, uint32_t r2,
                 uint32_t r3, uint32_t r4, uint32_t form)
{
    uint32_t hi;
    uint32_t lo;

    if (ia64_fr_write_nat_if_any3(env, r1, r2, r3, r4)) {
        return;
    }

    hi = ia64_fpma_lane(env, env->fr[r2] >> 32, env->fr[r3] >> 32,
                        env->fr[r4] >> 32, form);
    lo = ia64_fpma_lane(env, env->fr[r2], env->fr[r3], env->fr[r4], form);

    ia64_fr_write(env, r1, ia64_pack_fp32_lanes(hi, lo));
}

/* ---- FP status field controls ---- */

#define IA64_FPSR_TRAPS_MASK        0x3fULL
#define IA64_FPSR_SF_BITS           13
#define IA64_FPSR_SF0_SHIFT         6
#define IA64_FPSR_SF_CONTROLS_MASK  0x7fULL
#define IA64_FPSR_SF_FLAGS_MASK     0x3fULL
#define IA64_FPSR_SF_FLAGS_SHIFT    7
#define IA64_FPSR_SF_TD             (1U << 6)

static uint32_t ia64_fpsr_sf_shift(uint32_t sf)
{
    return IA64_FPSR_SF0_SHIFT + (sf & 3) * IA64_FPSR_SF_BITS;
}

static uint64_t ia64_fpsr_sf_controls(const CPUIA64State *env, uint32_t sf)
{
    return (env->ar_fpsr >> ia64_fpsr_sf_shift(sf)) &
           IA64_FPSR_SF_CONTROLS_MASK;
}

static uint64_t ia64_fpsr_sf_flags(const CPUIA64State *env, uint32_t sf)
{
    return (env->ar_fpsr >>
            (ia64_fpsr_sf_shift(sf) + IA64_FPSR_SF_FLAGS_SHIFT)) &
           IA64_FPSR_SF_FLAGS_MASK;
}

void helper_fsetc(CPUIA64State *env, uint32_t sf,
                  uint32_t amask7, uint32_t omask7)
{
    uint64_t controls = (ia64_fpsr_sf_controls(env, 0) & (amask7 & 0x7f)) |
                        (omask7 & 0x7f);
    uint64_t shift = ia64_fpsr_sf_shift(sf);

    if ((sf & 3) == 0 && (controls & IA64_FPSR_SF_TD)) {
        CPUState *cs = env_cpu(env);
        cs->exception_index = IA64_EXCP_GENERAL;
        cpu_loop_exit(cs);
    }

    env->ar_fpsr &= ~(IA64_FPSR_SF_CONTROLS_MASK << shift);
    env->ar_fpsr |= controls << shift;
}

void helper_fclrf(CPUIA64State *env, uint32_t sf)
{
    uint64_t mask = IA64_FPSR_SF_FLAGS_MASK <<
                    (ia64_fpsr_sf_shift(sf) + IA64_FPSR_SF_FLAGS_SHIFT);

    env->ar_fpsr &= ~mask;
}

uint64_t helper_fchkf(CPUIA64State *env, uint32_t sf)
{
    uint64_t traps = env->ar_fpsr & IA64_FPSR_TRAPS_MASK;
    uint64_t sf0_flags = ia64_fpsr_sf_flags(env, 0);
    uint64_t flags = ia64_fpsr_sf_flags(env, sf);

    return (flags & ~traps) || (flags & ~sf0_flags);
}

/* ---- FP check flags ---- */

void helper_fchkfs(CPUIA64State *env, uint32_t r1)
{
    uint8_t fpsr_traps = env->ar_fpsr & 0x1F;
    if (fpsr_traps) {
        CPUState *cs = env_cpu(env);
        cs->exception_index = IA64_EXCP_GENERAL;
        cpu_loop_exit(cs);
    }
}

/* ---- FP multiply-subtract (fms: r1 = r2 * r3 - r4; fma with negated addend) ---- */

void helper_fms(CPUIA64State *env, uint32_t r1, uint32_t r2,
                uint32_t r3, uint32_t r4)
{
    float64 neg;

    if (ia64_fr_write_nat_if_any3(env, r1, r2, r3, r4)) {
        return;
    }
    neg = float64_chs(env->fr[r2]);

    ia64_fr_write(env, r1,
                  float64_muladd(env->fr[r3], env->fr[r4], neg,
                                 0, &env->fp_status));
}

void helper_fnma(CPUIA64State *env, uint32_t r1, uint32_t r2, uint32_t r3)
{
    float64 neg;

    if (ia64_fr_write_nat_if_any2(env, r1, r2, r3)) {
        return;
    }
    neg = float64_chs(env->fr[r2]);

    ia64_fr_write(env, r1,
                  float64_muladd(neg, env->fr[r3], float64_zero,
                                 0, &env->fp_status));
}

void helper_fnma4(CPUIA64State *env, uint32_t r1, uint32_t r2,
                  uint32_t r3, uint32_t r4)
{
    float64 neg;

    if (ia64_fr_write_nat_if_any3(env, r1, r2, r3, r4)) {
        return;
    }
    neg = float64_chs(env->fr[r3]);

    ia64_fr_write(env, r1,
                  float64_muladd(neg, env->fr[r4], env->fr[r2],
                                 0, &env->fp_status));
}

/* ---- FP bitwise select ---- */

void helper_fselect(CPUIA64State *env, uint32_t r1,
                     uint32_t r2, uint32_t r3, uint32_t r4)
{
    uint64_t mask;

    /*
     * IA-64 fselect: f1 = (f3 AND f2) OR (f4 AND NOT f2)
     * For each bit position, if f2 bit is 1, select from f3; else from f4.
     */
    if (ia64_fr_write_nat_if_any3(env, r1, r2, r3, r4)) {
        return;
    }
    mask = env->fr[r2];
    ia64_fr_write_sig(env, r1, (env->fr[r3] & mask) | (env->fr[r4] & ~mask));
}

/* ---- FP normalize ---- */

void helper_fnorm(CPUIA64State *env, uint32_t r1, uint32_t r2, uint32_t r3)
{
    (void)r2;
    if (ia64_fr_nat_get(env, r3)) {
        ia64_fr_write_nat(env, r1);
        return;
    }
    if (ia64_fr_sig_get(env, r3)) {
        ia64_fr_write_sig(env, r1, env->fr[r3]);
    } else {
        ia64_fr_write(env, r1, env->fr[r3]);
    }
}

/* ---- FP absolute / negate / negate-absolute ---- */

void helper_fpabs(CPUIA64State *env, uint32_t r1, uint32_t r2)
{
    if (ia64_fr_nat_get(env, r2)) {
        ia64_fr_write_nat(env, r1);
        return;
    }
    ia64_fr_write(env, r1, env->fr[r2] & 0x7FFFFFFFFFFFFFFFULL);
}

void helper_fpneg(CPUIA64State *env, uint32_t r1, uint32_t r2)
{
    if (ia64_fr_nat_get(env, r2)) {
        ia64_fr_write_nat(env, r1);
        return;
    }
    ia64_fr_write(env, r1, env->fr[r2] ^ 0x8000000000000000ULL);
}

void helper_fpnegabs(CPUIA64State *env, uint32_t r1, uint32_t r2)
{
    if (ia64_fr_nat_get(env, r2)) {
        ia64_fr_write_nat(env, r1);
        return;
    }
    ia64_fr_write(env, r1, env->fr[r2] | 0x8000000000000000ULL);
}

void helper_fcvt_xf(CPUIA64State *env, uint32_t r1, uint32_t r2)
{
    if (ia64_fr_nat_get(env, r2)) {
        ia64_fr_write_nat(env, r1);
        return;
    }

    ia64_fr_write(env, r1,
                  int64_to_float64((int64_t)env->fr[r2], &env->fp_status));
}

void helper_fcvt_fx(CPUIA64State *env, uint32_t r1, uint32_t r2,
                    uint32_t is_unsigned, uint32_t is_trunc)
{
    uint64_t value = env->fr[r2];
    uint64_t result;

    if (ia64_fr_nat_get(env, r2)) {
        ia64_fr_write_nat(env, r1);
        return;
    }

    /*
     * fcvt.fx[u] writes an integer significand result.  Preserve operands
     * that are already tracked in significand form through the conversion.
     */
    if (ia64_fr_sig_get(env, r2) ||
        ia64_fr_looks_like_setf_sig_payload(value)) {
        ia64_fr_write_sig(env, r1, value);
        return;
    }

    if (is_unsigned) {
        result = is_trunc ?
            float64_to_uint64_round_to_zero(value, &env->fp_status) :
            float64_to_uint64(value, &env->fp_status);
    } else {
        result = is_trunc ?
            (uint64_t)float64_to_int64_round_to_zero(value, &env->fp_status) :
            (uint64_t)float64_to_int64(value, &env->fp_status);
    }
    ia64_fr_write_sig(env, r1, result);
}

/* ---- FP reciprocal sqrt approx ---- */

static bool ia64_float64_rsqrta_predicate(float64 val)
{
    return !float64_is_zero(val) &&
           !float64_is_neg(val) &&
           !float64_is_infinity(val) &&
           !float64_is_any_nan(val);
}

static float64 ia64_float64_rsqrta(float64 val, float_status *status)
{
    float64 one = float64_one;
    float64 sqrtv = float64_sqrt(val, status);

    if (float64_is_zero(sqrtv)) {
        return float64_set_sign(float64_infinity, float64_is_neg(val));
    }
    return float64_div(one, sqrtv, status);
}

static bool ia64_float32_rsqrta_predicate(float32 val)
{
    return !float32_is_zero(val) &&
           !float32_is_neg(val) &&
           !float32_is_infinity(val) &&
           !float32_is_any_nan(val);
}

static float32 ia64_float32_rsqrta(float32 val, float_status *status)
{
    float32 sqrtv = float32_sqrt(val, status);

    if (float32_is_zero(sqrtv)) {
        return float32_set_sign(float32_infinity, float32_is_neg(val));
    }
    return float32_div(float32_one, sqrtv, status);
}

void helper_fprsqrta(CPUIA64State *env, uint32_t r1, uint32_t p2,
                     uint32_t r3)
{
    uint64_t val = env->fr[r3];
    float32 hi = make_float32(val >> 32);
    float32 lo = make_float32(val);
    bool hi_pred;
    bool lo_pred;
    float32 hi_result;
    float32 lo_result;

    if (ia64_fr_nat_get(env, r3)) {
        ia64_fr_write_nat(env, r1);
        ia64_pr_write(env, p2, false);
        return;
    }

    hi_pred = ia64_float32_rsqrta_predicate(hi);
    lo_pred = ia64_float32_rsqrta_predicate(lo);
    hi_result = ia64_float32_rsqrta(hi, &env->fp_status);
    lo_result = ia64_float32_rsqrta(lo, &env->fp_status);

    ia64_fr_write(env, r1,
                  ((uint64_t)float32_val(hi_result) << 32) |
                  float32_val(lo_result));
    ia64_pr_write(env, p2, hi_pred && lo_pred);
}

void helper_frsqrta(CPUIA64State *env, uint32_t r1, uint32_t p2,
                    uint32_t r3)
{
    float64 val = env->fr[r3];

    if (ia64_fr_nat_get(env, r3)) {
        ia64_fr_write_nat(env, r1);
        ia64_pr_write(env, p2, false);
        return;
    }

    if (float64_is_zero(val) ||
        (!float64_is_neg(val) && float64_is_infinity(val))) {
        ia64_fr_write(env, r1, val);
        ia64_pr_write(env, p2, false);
        return;
    }

    ia64_fr_write(env, r1, ia64_float64_rsqrta(val, &env->fp_status));
    ia64_pr_write(env, p2, ia64_float64_rsqrta_predicate(val));
}

/* ---- FP pack ---- */

void helper_fpack(CPUIA64State *env, uint32_t r1, uint32_t r2, uint32_t r3)
{
    float_status status = env->fp_status;
    float32 hi;
    float32 lo;

    if (ia64_fr_nat_get(env, r2) || ia64_fr_nat_get(env, r3)) {
        ia64_fr_write_nat(env, r1);
        return;
    }

    hi = float64_to_float32(env->fr[r2], &status);
    status = env->fp_status;
    lo = float64_to_float32(env->fr[r3], &status);
    ia64_fr_write(env, r1, ((uint64_t)hi << 32) | lo);
}

void helper_alloc_rse(CPUIA64State *env, uint32_t r1,
                       uint32_t sof, uint32_t sol, uint32_t sor,
                       uint32_t rrb)
{
    uint32_t new_sof = sof & 0x7f;

    if (r1 != 0) {
        env->gr[r1] = env->ar_pfs;
    }

    ia64_rse_resize_current_frame(env, new_sof);

    env->cfm_sof = new_sof;
    env->cfm_sol = sol & 0x7f;
    env->cfm_sor = sor & 0x1f;
    env->cfm_rrb_gr = rrb & 0x1f;
    ia64_rse_refresh_cumulative(env);
    ia64_invalidate_stacked_alat(env);
    if (env->rse_cumulative_words > IA64_STACKED_GR_COUNT) {
        ia64_rse_evict_parent_frames(env);
    }
}

void helper_cover_rse(CPUIA64State *env)
{
    uint32_t depth = env->rse_cover_depth;

    if (!(env->psr & IA64_PSR_IC)) {
        env->cr_ifs = IA64_IFS_V | ia64_current_cfm(env);
    }

    ia64_rse_redirty_current_frame(env);
    if (depth == IA64_RSE_FRAME_MAX) {
        ia64_rse_evict_parent_frames(env);
        depth = env->rse_cover_depth;
    }

    if (depth < IA64_RSE_FRAME_MAX && env->cfm_sof > 0) {
        memcpy(env->rse_cover_gr[depth], &env->gr[IA64_STACKED_GR_BASE],
               sizeof(env->rse_cover_gr[depth]));
        env->rse_cover_nat[depth][0] = env->nat[0];
        env->rse_cover_nat[depth][1] = env->nat[1];
        env->rse_cover_sof[depth] = env->cfm_sof;
        env->rse_cover_bsp[depth] = env->ar_bsp;
        env->rse_cover_depth = depth + 1;
    }

    env->ar_bsp = ia64_rse_bsp_advance(env->ar_bsp, env->cfm_sof);
    env->cfm_sof = 0;
    env->cfm_sol = 0;
    env->cfm_sor = 0;
    env->cfm_rrb_gr = 0;
    ia64_rse_refresh_cumulative(env);
    ia64_invalidate_stacked_alat(env);
}

void helper_flushrs_rse(CPUIA64State *env)
{
    uint32_t dirty;
    uint64_t bspstore;
    uint64_t rnat;
    uint32_t i;

    dirty = ia64_rse_dirty_words(env);
    if (dirty == 0) {
        env->ar_bspstore = env->ar_bsp;
        env->rse_cumulative_words = env->cfm_sof;
        env->rse_spill_words = 0;
        env->rse_spill_base = env->ar_bspstore;
        env->rse_cover_depth = 0;
        env->rse_flushed = true;
        return;
    }

    bspstore = env->ar_bspstore;
    rnat = env->ar_rnat & ~(1ULL << 63);

    env->rse_spill_base = bspstore;

    for (i = 0; i < dirty; i++) {
        uint64_t value = 0;
        int nat_bit = 0;

        if (((bspstore >> 3) & 0x3f) == 0x3f) {
            ia64_rse_write_u64(env, bspstore, rnat);
            bspstore += 8;
            rnat = 0;
        }

        ia64_rse_dirty_word_at(env, bspstore, &value, &nat_bit);
        if (nat_bit) {
            rnat |= (1ULL << ((bspstore >> 3) & 0x3f));
        }
        rnat &= ~(1ULL << 63);

        ia64_rse_write_u64(env, bspstore, value);
        bspstore += 8;
    }

    env->ar_bspstore = env->ar_bsp;
    env->ar_rnat = rnat;
    env->rse_spill_words = dirty;
    env->rse_cumulative_words = env->cfm_sof;
    env->rse_cover_depth = 0;
    env->rse_flushed = true;
}

void helper_loadrs_rse(CPUIA64State *env)
{
    uint64_t loadrs_bytes;
    uint64_t tear;
    uint64_t addr;
    uint64_t values[IA64_STACKED_GR_COUNT];
    uint8_t nats[IA64_STACKED_GR_COUNT];
    uint32_t count = 0;
    uint32_t i;

    loadrs_bytes = ((env->ar_rsc >> IA64_RSC_LOADRS_SHIFT) &
                    IA64_RSC_LOADRS_MASK) & ~7ULL;

    /*
     * The translator currently admits only valid loadrs placements.  Keep the
     * helper side conservative: invalid architectural uses leave RSE state
     * unchanged rather than manufacturing backing-store contents.
     */
    if ((env->ar_rsc & IA64_RSC_MODE) != 0 ||
        (env->cfm_sof != 0 && loadrs_bytes != 0)) {
        return;
    }
    if (env->cfm_sof != 0 && loadrs_bytes == 0) {
        return;
    }

    tear = (env->ar_bsp - loadrs_bytes) & ~7ULL;
    addr = tear;

    while (addr < (env->ar_bsp & ~7ULL) &&
           count < IA64_STACKED_GR_COUNT) {
        uint64_t value;
        int nat = 0;

        if (ia64_rse_is_rnat_slot(addr)) {
            addr += 8;
            continue;
        }
        ia64_rse_dirty_word_at(env, addr, &value, &nat);
        values[count] = value;
        nats[count] = nat != 0;
        count++;
        addr += 8;
    }

    ia64_rse_drop_snapshots(env);
    for (i = 0; i < count; i++) {
        uint32_t reg = IA64_STACKED_GR_BASE + i;

        env->gr[reg] = values[i];
        ia64_gr_nat_set(env, reg, nats[i]);
        env->rse_cover_gr[0][i] = values[i];
    }
    if (count > 0) {
        env->rse_cover_nat[0][0] = env->nat[0];
        env->rse_cover_nat[0][1] = env->nat[1];
        env->rse_cover_sof[0] = count;
        env->rse_cover_bsp[0] = tear;
        env->rse_cover_depth = 1;
    }

    env->ar_bspstore = tear;
    env->rse_spill_base = tear;
    env->rse_spill_words = 0;
    env->rse_cumulative_words =
        ia64_rse_count_register_slots(tear, env->ar_bsp) + env->cfm_sof;
    env->rse_bspstore_switched = false;
    env->rse_flushed = false;
    ia64_invalidate_stacked_alat(env);
}

/* ---- Loop branch helpers ---- */

uint64_t helper_br_cloop(CPUIA64State *env, uint64_t target, uint32_t b_reg)
{
    uint64_t lc = env->ar_lc;
    if (lc == 0) {
        return 0;
    }
    env->ar_lc = lc - 1;
    return (b_reg == 0) ? target : env->br[b_reg];
}

uint64_t helper_br_cexit(CPUIA64State *env, uint64_t target, uint32_t b_reg)
{
    uint64_t lc = env->ar_lc;
    uint64_t ec = env->ar_ec;
    bool active = lc != 0 || ec > 1;

    if (lc != 0) {
        env->ar_lc = lc - 1;
        env->pr[63] = 1;
        ia64_rotate_loop_regs(env);
    } else if (ec != 0) {
        env->ar_ec = ec - 1;
        env->pr[63] = 0;
        ia64_rotate_loop_regs(env);
    } else {
        env->pr[63] = 0;
    }

    return active ? 0 : ((b_reg == 0) ? target : env->br[b_reg]);
}

uint64_t helper_br_ctop(CPUIA64State *env, uint64_t target, uint32_t b_reg)
{
    uint64_t lc = env->ar_lc;
    uint64_t ec = env->ar_ec;
    bool active = lc != 0 || ec > 1;

    if (lc != 0) {
        env->ar_lc = lc - 1;
        env->pr[63] = 1;
        ia64_rotate_loop_regs(env);
    } else if (ec != 0) {
        env->ar_ec = ec - 1;
        env->pr[63] = 0;
        ia64_rotate_loop_regs(env);
    } else {
        env->pr[63] = 0;
    }

    return active ? ((b_reg == 0) ? target : env->br[b_reg]) : 0;
}

uint64_t helper_br_wexit(CPUIA64State *env, uint64_t target, uint32_t qp)
{
    bool active = env->pr[qp & 63] || env->ar_ec > 1;

    if (env->pr[qp & 63]) {
        env->pr[63] = 0;
        ia64_rotate_loop_regs(env);
    } else if (env->ar_ec != 0) {
        env->ar_ec--;
        env->pr[63] = 0;
        ia64_rotate_loop_regs(env);
    } else {
        env->pr[63] = 0;
    }

    return active ? 0 : target;
}

uint64_t helper_br_wtop(CPUIA64State *env, uint64_t target, uint32_t qp)
{
    bool active = env->pr[qp & 63] || env->ar_ec > 1;

    if (env->pr[qp & 63]) {
        env->pr[63] = 0;
        ia64_rotate_loop_regs(env);
    } else if (env->ar_ec != 0) {
        env->ar_ec--;
        env->pr[63] = 0;
        ia64_rotate_loop_regs(env);
    } else {
        env->pr[63] = 0;
    }

    return active ? target : 0;
}

/* ---- Advanced Load Address Table check ---- */

uint64_t helper_chk_a(CPUIA64State *env, uint64_t va, uint32_t reg)
{
    int i;
    for (i = 0; i < IA64_ALAT_ENTRIES; i++) {
        if (env->alat[i].valid && env->alat[i].reg == reg) {
            return 0;
        }
    }
    env->cr_ifa = va;
    CPUState *cs = env_cpu(env);
    cs->exception_index = IA64_EXCP_GENERAL;
    cpu_loop_exit(cs);
    return 1;
}

/* ---- Probe helper (r1 != 0 => write result to r1; returns probe result) ---- */

static uint64_t ia64_probe_address(CPUIA64State *env, uint64_t va,
                                   uint32_t is_write, uint32_t is_ifetch,
                                   uint8_t access_level, bool walk_vhpt)
{
    uint64_t pa;
    uint8_t perm;
    uint32_t rid = ia64_region_rid(env, va);
    const IA64TlbEntry *tlb;
    uint8_t tlb_count;
    uint8_t needed;

    needed = is_write ? IA64_TLB_W :
             (is_ifetch ? IA64_TLB_X : IA64_TLB_R);

    if (!(env->psr & (is_ifetch ? IA64_PSR_IT : IA64_PSR_DT))) {
        return 1;
    }

    if (ia64_firmware_identity_pa(va, &pa)) {
        return 1;
    }

    if (ia64_sal_boot_virtual_pa(env, va, &pa)) {
        return 1;
    }

    if (is_ifetch) {
        tlb = env->tlb_inst;
        tlb_count = env->tlb_inst_count;
    } else {
        tlb = env->tlb_data;
        tlb_count = env->tlb_data_count;
    }

    if (ia64_tlb_probe(tlb, tlb_count, va, rid, access_level, is_ifetch,
                       &pa, &perm)) {
        return (perm & needed) ? 1 : 0;
    }

    if (!is_ifetch && !walk_vhpt &&
        ia64_vhpt_pte_not_present(env, va, false, NULL)) {
        /*
         * Speculative loads suppress the memory reference when the data
         * translation has a deferrable fault.  A region-6 direct physical
         * alias is only a fallback for a true miss; an explicit VHPT
         * not-present PTE must make the speculative load produce NaT instead
         * of falling through to a normal load that raises Page Not Present.
         */
        return 0;
    }

    if (!is_ifetch &&
        ia64_kernel_direct_data_pa(env->psr, env->rr[ia64_rr_index(va)],
                                   va, &pa)) {
        return 1;
    }

    if (!(walk_vhpt &&
          ia64_vhpt_walk(env, va, rid, is_ifetch, &pa, &perm))) {
        if (ia64_sal_boot_identity_pa(env, va, &pa)) {
            return 1;
        }
        return 0;
    }
    return (perm & needed) ? 1 : 0;
}

static IA64Exception ia64_data_reference_exception(CPUIA64State *env,
                                                   uint64_t va,
                                                   uint32_t is_write,
                                                   uint32_t is_rw,
                                                   uint8_t access_level,
                                                   bool walk_vhpt)
{
    uint64_t pa;
    uint8_t perm;
    uint8_t needed = is_rw ? (IA64_TLB_R | IA64_TLB_W) :
                     (is_write ? IA64_TLB_W : IA64_TLB_R);
    uint32_t rid = ia64_region_rid(env, va);
    uint8_t vhpt_size;
    bool vhpt_long_format;
    bool vhpt_enabled;
    uint64_t pte = IA64_PTE_PRESENT;
    const IA64TlbEntry *entry;
    bool found = false;

    if (!(env->psr & IA64_PSR_DT) ||
        ia64_firmware_identity_pa(va, &pa) ||
        ia64_sal_boot_virtual_pa(env, va, &pa)) {
        return IA64_EXCP_NONE;
    }

    entry = ia64_tlb_find(env->tlb_data, env->tlb_data_count, va, rid, false);
    if (entry) {
        ia64_tlb_entry_translate(entry, va, access_level, &pa, &perm);
        pte = entry->pte;
        found = true;
    } else if (ia64_kernel_direct_data_pa(env->psr,
                                          env->rr[ia64_rr_index(va)],
                                          va, &pa)) {
        return IA64_EXCP_NONE;
    } else if (walk_vhpt) {
        found = ia64_vhpt_walk_full(env, va, rid, false, &pa, &perm, &pte);
    }

    if (found) {
        return ia64_pte_exception_for_access(pte, perm, needed, false,
                                             is_write || is_rw, env->psr);
    }
    if (ia64_sal_boot_identity_pa(env, va, &pa)) {
        return IA64_EXCP_NONE;
    }
    if (ia64_data_nested_tlb_active(env)) {
        return IA64_EXCP_DATA_NESTED_TLB;
    }
    if (ia64_vhpt_pte_not_present(env, va, false, NULL)) {
        return IA64_EXCP_PAGE_NOT_PRESENT;
    }
    if (!ia64_vhpt_entry_accessible(env, va, false, &pa)) {
        return IA64_EXCP_VHPT_FAULT;
    }

    vhpt_enabled = ia64_vhpt_walker_enabled(env, va, false, &vhpt_size,
                                            &vhpt_long_format);
    return vhpt_enabled ? IA64_EXCP_DTLB_FAULT : IA64_EXCP_ALT_DTLB;
}

static uint64_t ia64_speculative_deferral_dcr_mask(IA64Exception excp)
{
    switch (excp) {
    case IA64_EXCP_ALT_DTLB:
    case IA64_EXCP_VHPT_FAULT:
    case IA64_EXCP_DTLB_FAULT:
        return IA64_DCR_DM;
    case IA64_EXCP_PAGE_NOT_PRESENT:
        return IA64_DCR_DP;
    case IA64_EXCP_DATA_ACCESS:
        return IA64_DCR_DR;
    case IA64_EXCP_DATA_ACCESS_BIT:
        return IA64_DCR_DA;
    default:
        return 0;
    }
}

static bool ia64_speculative_exception_deferrable(CPUIA64State *env,
                                                  IA64Exception excp,
                                                  bool itlb_ed)
{
    uint64_t dcr_mask;

    if (!(env->psr & IA64_PSR_IC)) {
        return true;
    }

    if (excp == IA64_EXCP_NAT_CONSUMPTION) {
        return true;
    }

    if (excp == IA64_EXCP_UNALIGNED) {
        return (env->psr & IA64_PSR_IT) && itlb_ed;
    }

    dcr_mask = ia64_speculative_deferral_dcr_mask(excp);
    return dcr_mask != 0 &&
           (env->psr & IA64_PSR_IT) &&
           itlb_ed &&
           (env->cr_dcr & dcr_mask);
}

static bool ia64_speculative_alignment_fault(CPUIA64State *env,
                                             uint64_t va, uint32_t size)
{
    if (size <= 1 || (va & (size - 1)) == 0) {
        return false;
    }

    return (env->psr & IA64_PSR_AC) ||
           ((va & 0xfff) + size - 1 > 0xfff);
}

static void ia64_raise_data_reference_exception(CPUIA64State *env,
                                                uint64_t va,
                                                uint32_t is_write,
                                                uint32_t is_rw,
                                                bool is_non_access,
                                                IA64Exception excp,
                                                bool is_speculative,
                                                bool itlb_ed)
{
    CPUState *cs = env_cpu(env);

    if (env->psr & IA64_PSR_IC) {
        env->cr_ifa = va;
        if (ia64_exception_initializes_iha(excp)) {
            env->cr_iha = ia64_vhpt_hash_address(env, va);
        }
        env->cr_itir = ia64_region_itir(
            env, excp == IA64_EXCP_VHPT_FAULT ? env->cr_iha : va);
    }
    if (excp != IA64_EXCP_DATA_NESTED_TLB) {
        env->cr_isr = (is_non_access ? IA64_ISR_NA : 0) |
                      (is_rw ? (IA64_ISR_R | IA64_ISR_W) :
                       (is_write ? IA64_ISR_W : IA64_ISR_R));
        if (is_speculative) {
            env->cr_isr |= IA64_ISR_SP;
        }
        if (itlb_ed) {
            env->cr_isr |= IA64_ISR_ED;
        }
    }
    cs->exception_index = excp;
    cpu_loop_exit(cs);
}

static uint8_t ia64_probe_access_level(CPUIA64State *env,
                                       uint64_t access_level)
{
    uint8_t requested_pl = access_level & 3;
    uint8_t current_cpl = ia64_psr_cpl(env->psr);

    return requested_pl < current_cpl ? current_cpl : requested_pl;
}

uint64_t helper_probe(CPUIA64State *env, uint64_t va, uint32_t is_write,
                      uint32_t is_ifetch, uint64_t access_level)
{
    return ia64_probe_address(env, va, is_write, is_ifetch,
                              ia64_probe_access_level(env, access_level),
                              true);
}

static void ia64_raise_data_reference_fault_if_needed(CPUIA64State *env,
                                                      uint64_t va,
                                                      uint32_t is_write,
                                                      uint32_t is_rw,
                                                      uint8_t access_level,
                                                      bool is_non_access)
{
    IA64Exception excp = ia64_data_reference_exception(
        env, va, is_write, is_rw, access_level, true);

    if (excp == IA64_EXCP_NONE) {
        return;
    }
    ia64_raise_data_reference_exception(env, va, is_write, is_rw,
                                        is_non_access, excp, false,
                                        ia64_current_code_tlb_ed(env));
}

void helper_probe_fault(CPUIA64State *env, uint64_t va, uint32_t is_write,
                        uint32_t is_rw, uint64_t access_level)
{
    uint8_t effective_pl = ia64_probe_access_level(env, access_level);

    ia64_raise_data_reference_fault_if_needed(env, va, is_write, is_rw,
                                              effective_pl, true);
}

void helper_check_semaphore_access(CPUIA64State *env, uint64_t va)
{
    ia64_raise_data_reference_fault_if_needed(env, va, true, true,
                                              ia64_psr_cpl(env->psr), false);
}

uint64_t helper_speculative_probe(CPUIA64State *env, uint64_t va,
                                  uint32_t is_write, uint32_t is_ifetch,
                                  uint32_t size)
{
    bool itlb_ed;
    IA64Exception excp;

    if (env->psr & IA64_PSR_ED) {
        return 0;
    }

    itlb_ed = ia64_current_code_tlb_ed(env);
    if (ia64_speculative_alignment_fault(env, va, size)) {
        excp = IA64_EXCP_UNALIGNED;
    } else if (is_ifetch) {
        return ia64_probe_address(env, va, is_write, is_ifetch,
                                  ia64_psr_cpl(env->psr), false);
    } else {
        if (!(env->psr & IA64_PSR_IC) &&
            ia64_vhpt_pte_not_present(env, va, false, NULL)) {
            return 0;
        }
        excp = ia64_data_reference_exception(
            env, va, is_write, false, ia64_psr_cpl(env->psr),
            (env->psr & IA64_PSR_IC) != 0);
    }

    if (excp == IA64_EXCP_NONE) {
        return 1;
    }
    if (ia64_speculative_exception_deferrable(env, excp, itlb_ed)) {
        return 0;
    }

    ia64_raise_data_reference_exception(env, va, is_write, false, false,
                                        excp, true, itlb_ed);
    g_assert_not_reached();
}

void helper_ldfe(CPUIA64State *env, uint32_t r1, uint64_t addr)
{
    uintptr_t ra = GETPC();
    uint64_t low = cpu_ldq_data_ra(env, addr, ra);
    uint16_t high = cpu_lduw_data_ra(env, addr + 8, ra);
    floatx80 value = make_floatx80(high, low);

    ia64_fr_write(env, r1, floatx80_to_float64(value, &env->fp_status));
}

void helper_stfe(CPUIA64State *env, uint64_t addr, uint32_t r2)
{
    uintptr_t ra = GETPC();
    floatx80 value = float64_to_floatx80(env->fr[r2], &env->fp_status);

    cpu_stq_data_ra(env, addr, value.low, ra);
    cpu_stw_data_ra(env, addr + 8, value.high, ra);
}

/* ---- ITC read helper ---- */

uint64_t helper_itc_read(CPUIA64State *env, uint32_t unused)
{
    return ia64_itc_read(env);
}

/* ---- tak / thash / ttag helpers ---- */

uint64_t helper_tak(CPUIA64State *env, uint64_t va)
{
    uint32_t rid = ia64_region_rid(env, va);
    uint8_t i;

    for (i = 0; i < env->tlb_data_count; i++) {
        if (ia64_tlb_match(&env->tlb_data[i], va, rid, false)) {
            return env->tlb_data[i].key;
        }
    }
    return 0;
}

uint64_t helper_thash(CPUIA64State *env, uint64_t va)
{
    return ia64_vhpt_hash_address(env, va);
}

static uint64_t ia64_implemented_va_payload(uint64_t va)
{
    return va & ((1ULL << (IA64_IMPL_VA_MSB + 1)) - 1);
}

static uint8_t ia64_region_preferred_ps(CPUIA64State *env, uint64_t va)
{
    uint8_t rr_ps = (env->rr[ia64_rr_index(va)] >> IA64_ITIR_PS_SHIFT) &
                    IA64_ITIR_PS_MASK;

    return rr_ps < 12 ? 12 : rr_ps;
}

static uint64_t ia64_vhpt_hpn(CPUIA64State *env, uint64_t va)
{
    return ia64_implemented_va_payload(va) >>
           ia64_region_preferred_ps(env, va);
}

static uint64_t ia64_vhpt_long_tag(CPUIA64State *env, uint64_t va)
{
    uint8_t rr_ps = ia64_region_preferred_ps(env, va);
    uint8_t hpn_bits = rr_ps > IA64_IMPL_VA_MSB ? 0 :
                       IA64_IMPL_VA_MSB + 1 - rr_ps;
    uint64_t hpn = ia64_vhpt_hpn(env, va);
    uint64_t rid = ia64_region_rid(env, va);

    if (hpn_bits == 0) {
        return rid;
    }
    return (rid << hpn_bits) | (hpn & ((1ULL << hpn_bits) - 1));
}

static uint64_t ia64_vhpt_short_hash_address(CPUIA64State *env, uint64_t va,
                                             uint8_t size)
{
    uint64_t region = va & (IA64_REGION_MASK << IA64_REGION_SHIFT);
    uint64_t offset;
    uint64_t mask;
    uint64_t base;

    offset = ia64_vhpt_hpn(env, va) << 3;
    mask = (1ULL << size) - 1;
    base = env->cr_pta & (((1ULL << IA64_REGION_SHIFT) - 1) & ~0x7fffULL);
    return region | ((base & ~mask) | (offset & mask));
}

static uint64_t ia64_vhpt_long_hash_address(CPUIA64State *env, uint64_t va,
                                            uint8_t size)
{
    uint64_t base = env->cr_pta & IA64_PTA_BASE_MASK;
    uint64_t entries = 1ULL << (size - 5);
    uint64_t hpn = ia64_vhpt_hpn(env, va);
    uint64_t hash = (hpn ^ (hpn >> 7) ^ ia64_region_rid(env, va)) &
                    (entries - 1);
    uint64_t offset = hash << 5;
    uint64_t mask = (1ULL << size) - 1;

    return (base & ~mask) | (offset & mask);
}

uint64_t ia64_vhpt_hash_address(CPUIA64State *env, uint64_t va)
{
    uint8_t size;
    bool long_format;

    if (!ia64_vhpt_config_valid(env, &size, &long_format)) {
        return va;
    }

    if (!long_format) {
        return ia64_vhpt_short_hash_address(env, va, size);
    }

    return ia64_vhpt_long_hash_address(env, va, size);
}

uint64_t helper_ttag(CPUIA64State *env, uint64_t va)
{
    return ia64_vhpt_long_tag(env, va);
}

static bool ia64_vhpt_entry_phys(CPUIA64State *env, uint64_t entry_va,
                                 uint64_t *entry_pa)
{
    uint8_t perm;
    uint32_t rid;

    if (ia64_firmware_identity_pa(entry_va, entry_pa)) {
        return true;
    }

    rid = ia64_region_rid(env, entry_va);
    /*
     * VHPT walker references to the VHPT itself are performed at
     * privilege level 0 regardless of PSR.cpl.
     */
    if (ia64_tlb_lookup(env->tlb_data, env->tlb_data_count, entry_va,
                        rid, 0, false, entry_pa, &perm) &&
        (perm & IA64_TLB_R)) {
        return true;
    }

    return ia64_region6_uncached_pa(entry_va, entry_pa) ||
           ia64_region7_identity_pa(entry_va, entry_pa);
}

bool ia64_vhpt_entry_accessible(CPUIA64State *env, uint64_t va,
                                bool is_ifetch, uint64_t *entry_va)
{
    uint64_t entry_pa;
    bool long_format;
    uint8_t size;

    if (!ia64_vhpt_walker_enabled(env, va, is_ifetch, &size, &long_format)) {
        return true;
    }
    *entry_va = long_format ? ia64_vhpt_long_hash_address(env, va, size) :
                ia64_vhpt_short_hash_address(env, va, size);
    return ia64_vhpt_entry_phys(env, *entry_va, &entry_pa);
}

static bool ia64_vhpt_lookup_pte(CPUIA64State *env, uint64_t va,
                                 bool is_ifetch, uint64_t *pte,
                                 uint64_t *entry_va)
{
    uint8_t size;
    bool long_format;
    uint64_t entry_pa;
    uint32_t rid = ia64_region_rid(env, va);

    if (!ia64_vhpt_walker_enabled(env, va, is_ifetch, &size, &long_format)) {
        return false;
    }

    if (!long_format) {
        *entry_va = ia64_vhpt_short_hash_address(env, va, size);
        if (!ia64_vhpt_entry_phys(env, *entry_va, &entry_pa)) {
            return false;
        }
        cpu_physical_memory_read(entry_pa, pte, 8);
        return true;
    }

    {
        uint64_t entries = 1ULL << (size - 5);
        uint64_t hpn = ia64_vhpt_hpn(env, va);
        uint64_t hash = (hpn ^ (hpn >> 7) ^ rid) & (entries - 1);
        uint64_t expected_tag = ia64_vhpt_long_tag(env, va);
        uint64_t base = env->cr_pta & IA64_PTA_BASE_MASK;
        uint64_t table_mask = (1ULL << size) - 1;

        for (uint32_t i = 0; i < 4; i++) {
            uint64_t tag;
            uint64_t entry_index = (hash + i) & (entries - 1);
            uint64_t entry_offset = entry_index << 5;

            *entry_va = (base & ~table_mask) | (entry_offset & table_mask);
            if (!ia64_vhpt_entry_phys(env, *entry_va, &entry_pa)) {
                return false;
            }
            cpu_physical_memory_read(entry_pa + 16, &tag, 8);
            if ((tag & (1ULL << 63)) || tag != expected_tag) {
                continue;
            }
            cpu_physical_memory_read(entry_pa, pte, 8);
            return true;
        }
    }

    return false;
}

bool ia64_vhpt_pte_not_present(CPUIA64State *env, uint64_t va,
                               bool is_ifetch, uint64_t *entry_va)
{
    uint64_t local_entry_va;
    uint64_t pte;

    if (!entry_va) {
        entry_va = &local_entry_va;
    }

    return ia64_vhpt_lookup_pte(env, va, is_ifetch, &pte, entry_va) &&
           !(pte & IA64_PTE_PRESENT);
}

static void ia64_vhpt_install_tc(CPUIA64State *env, uint64_t va, uint32_t rid,
                                 bool is_ifetch, uint64_t pa,
                                 uint64_t page_size, uint8_t ar, uint8_t pl,
                                 uint8_t perm, uint32_t key, uint64_t pte)
{
    IA64TlbEntry *tlb = is_ifetch ? env->tlb_inst : env->tlb_data;
    uint8_t *cnt = is_ifetch ? &env->tlb_inst_count : &env->tlb_data_count;
    uint8_t *next_replace = is_ifetch ? &env->tlb_inst_replace :
                                       &env->tlb_data_replace;
    uint64_t base_va = va & ~(page_size - 1);
    uint64_t base_pa = pa & ~(page_size - 1);
    int slot;
    bool matched;

    ia64_purge_tc_entries(env, tlb, cnt, base_va, page_size, rid,
                          !is_ifetch);

    slot = ia64_tlb_select_tc_slot(tlb, next_replace, base_va, rid, &matched);
    if (slot < 0) {
        return;
    }

    ia64_qemu_tlb_flush_entry(env, &tlb[slot]);
    tlb[slot].va = base_va;
    tlb[slot].pa = base_pa;
    tlb[slot].ps = page_size;
    tlb[slot].pte = pte;
    tlb[slot].perm = perm;
    tlb[slot].ar = ar;
    tlb[slot].pl = pl;
    tlb[slot].valid = 1;
    tlb[slot].is_tr = 0;
    tlb[slot].pending_purge = 0;
    tlb[slot].rid = rid;
    tlb[slot].key = key;
    tlb[slot].slot = slot;
    if (slot >= *cnt) {
        *cnt = slot + 1;
    }
    qemu_log_mask(CPU_LOG_MMU,
                  "ia64 vhpt install tc.%c slot=%d va=0x%016" PRIx64
                  " rid=0x%06" PRIx32 " pa=0x%016" PRIx64
                  " ps=0x%016" PRIx64 " perm=0x%x key=0x%x"
                  " pte=0x%016" PRIx64 "\n",
                  is_ifetch ? 'i' : 'd', slot, base_va, rid, base_pa,
                  page_size, perm, key, pte);
}

/* ---- VHPT walker ---- */

bool ia64_vhpt_walk_full(CPUIA64State *env, uint64_t va, uint32_t rid,
                         bool is_ifetch, uint64_t *pa, uint8_t *perm,
                         uint64_t *pte)
{
    uint64_t vhpt_base;
    uint64_t vhpt_entries;
    uint64_t hash;
    uint64_t hpn;
    uint32_t i;
    uint64_t tag;
    uint64_t expected_tag;
    uint64_t translation;
    uint64_t itir;
    uint64_t entry_pa;
    uint64_t entry_va;
    uint8_t page_shift;
    uint8_t size;
    bool long_format;

    if (!ia64_vhpt_walker_enabled(env, va, is_ifetch, &size, &long_format)) {
        qemu_log_mask(CPU_LOG_MMU,
                      "ia64 vhpt disabled %c va=0x%016" PRIx64
                      " rid=0x%06" PRIx32 " pta=0x%016" PRIx64
                      " rr=0x%016" PRIx64 " psr=0x%016" PRIx64 "\n",
                      is_ifetch ? 'i' : 'd', va, rid, env->cr_pta,
                      env->rr[ia64_rr_index(va)], env->psr);
        return false;
    }

    if (!long_format) {
        uint64_t page_mask;

        entry_va = ia64_vhpt_short_hash_address(env, va, size);
        page_shift = ia64_region_preferred_ps(env, va);
        if (!ia64_vhpt_entry_phys(env, entry_va, &entry_pa)) {
            qemu_log_mask(CPU_LOG_MMU,
                          "ia64 vhpt short entry miss %c va=0x%016" PRIx64
                          " rid=0x%06" PRIx32
                          " entry_va=0x%016" PRIx64 "\n",
                          is_ifetch ? 'i' : 'd', va, rid, entry_va);
            return false;
        }

        cpu_physical_memory_read(entry_pa, &translation, 8);
        if (pte) {
            *pte = translation;
        }
        {
            uint8_t ar = ia64_pte_ar(translation);
            uint8_t pl = ia64_pte_pl(translation);

            *perm = ia64_pte_perm(translation, ia64_psr_cpl(env->psr));
            page_mask = (1ULL << page_shift) - 1;
            *pa = ((translation & IA64_PTE_PPN_MASK) & ~page_mask) |
                  (va & page_mask);
            ia64_vhpt_install_tc(env, va, rid, is_ifetch, *pa,
                                 1ULL << page_shift, ar, pl, *perm, rid,
                                 translation);
        }
        if (!(translation & IA64_PTE_PRESENT)) {
            qemu_log_mask(CPU_LOG_MMU,
                          "ia64 vhpt short not-present %c va=0x%016" PRIx64
                          " rid=0x%06" PRIx32
                          " entry_va=0x%016" PRIx64
                          " entry_pa=0x%016" PRIx64
                          " pte=0x%016" PRIx64 "\n",
                          is_ifetch ? 'i' : 'd', va, rid, entry_va, entry_pa,
                          translation);
            return true;
        }
        if (*perm == 0) {
            qemu_log_mask(CPU_LOG_MMU,
                          "ia64 vhpt short access denied %c va=0x%016" PRIx64
                          " rid=0x%06" PRIx32
                          " entry_va=0x%016" PRIx64
                          " entry_pa=0x%016" PRIx64
                          " pte=0x%016" PRIx64 "\n",
                          is_ifetch ? 'i' : 'd', va, rid, entry_va,
                          entry_pa, translation);
            return true;
        }

        qemu_log_mask(CPU_LOG_MMU,
                      "ia64 vhpt short walk %c va=0x%016" PRIx64
                      " rid=0x%06" PRIx32
                      " entry_va=0x%016" PRIx64
                      " entry_pa=0x%016" PRIx64
                      " pte=0x%016" PRIx64
                      " pa=0x%016" PRIx64 " perm=0x%x\n",
                      is_ifetch ? 'i' : 'd', va, rid, entry_va, entry_pa,
                      translation, *pa, *perm);
        return true;
    }

    {
        vhpt_entries = 1ULL << (size - 5);
        vhpt_base = env->cr_pta & IA64_PTA_BASE_MASK;
    }

    hpn = ia64_vhpt_hpn(env, va);
    hash = (hpn ^ (hpn >> 7) ^ rid) & (vhpt_entries - 1);
    expected_tag = ia64_vhpt_long_tag(env, va);
    for (i = 0; i < 4; i++) {
        uint64_t entry_index = (hash + i) & (vhpt_entries - 1);
        uint64_t entry_offset = entry_index << 5;
        uint64_t table_mask = (1ULL << size) - 1;

        entry_va = (vhpt_base & ~table_mask) | (entry_offset & table_mask);
        if (!ia64_vhpt_entry_phys(env, entry_va, &entry_pa)) {
            qemu_log_mask(CPU_LOG_MMU,
                          "ia64 vhpt long entry miss %c va=0x%016" PRIx64
                          " rid=0x%06" PRIx32
                          " entry_va=0x%016" PRIx64 "\n",
                          is_ifetch ? 'i' : 'd', va, rid, entry_va);
            return false;
        }

        cpu_physical_memory_read(entry_pa, &translation, 8);
        cpu_physical_memory_read(entry_pa + 8, &itir, 8);
        cpu_physical_memory_read(entry_pa + 16, &tag, 8);
        if (tag & (1ULL << 63)) {
            continue;
        }
        if (tag != expected_tag) {
            continue;
        }
        if (pte) {
            *pte = translation;
        }

        {
            uint64_t page_mask;
            uint8_t long_page_shift =
                (itir >> IA64_ITIR_PS_SHIFT) & IA64_ITIR_PS_MASK;

            if (long_page_shift < 12) {
                long_page_shift = 12;
            }
            page_mask = (1ULL << long_page_shift) - 1;
            {
                uint8_t ar = ia64_pte_ar(translation);
                uint8_t pl = ia64_pte_pl(translation);
                uint32_t key = (itir & IA64_ITIR_KEY_MASK) >>
                               IA64_ITIR_KEY_SHIFT;

                *perm = ia64_pte_perm(translation, ia64_psr_cpl(env->psr));
                *pa = ((translation & IA64_PTE_PPN_MASK) & ~page_mask) |
                      (va & page_mask);
                ia64_vhpt_install_tc(env, va, rid, is_ifetch, *pa,
                                     1ULL << long_page_shift, ar, pl, *perm,
                                     key, translation);
            }
            if (!(translation & IA64_PTE_PRESENT)) {
                qemu_log_mask(CPU_LOG_MMU,
                              "ia64 vhpt not-present %c va=0x%016" PRIx64
                              " rid=0x%06" PRIx32
                              " entry_va=0x%016" PRIx64
                              " entry_pa=0x%016" PRIx64
                              " tag=0x%016" PRIx64
                              " pte=0x%016" PRIx64 "\n",
                              is_ifetch ? 'i' : 'd', va, rid, entry_va,
                              entry_pa, tag, translation);
                return true;
            }
            if (*perm == 0) {
                qemu_log_mask(CPU_LOG_MMU,
                              "ia64 vhpt access denied %c va=0x%016" PRIx64
                              " rid=0x%06" PRIx32
                              " entry_va=0x%016" PRIx64
                              " entry_pa=0x%016" PRIx64
                              " tag=0x%016" PRIx64
                              " pte=0x%016" PRIx64 "\n",
                              is_ifetch ? 'i' : 'd', va, rid, entry_va,
                              entry_pa, tag, translation);
                return true;
            }

            qemu_log_mask(CPU_LOG_MMU,
                          "ia64 vhpt walk %c va=0x%016" PRIx64
                          " rid=0x%06" PRIx32
                          " entry_va=0x%016" PRIx64
                          " entry_pa=0x%016" PRIx64
                          " tag=0x%016" PRIx64 " pte=0x%016" PRIx64
                          " pa=0x%016" PRIx64 " perm=0x%x\n",
                          is_ifetch ? 'i' : 'd', va, rid, entry_va, entry_pa,
                          tag, translation, *pa, *perm);
            return true;
        }
    }
    qemu_log_mask(CPU_LOG_MMU,
                  "ia64 vhpt miss %c va=0x%016" PRIx64
                  " rid=0x%06" PRIx32 " base=0x%016" PRIx64
                  " hash=0x%016" PRIx64 "\n",
                  is_ifetch ? 'i' : 'd', va, rid, vhpt_base, hash);
    return false;
}

bool ia64_vhpt_walk(CPUIA64State *env, uint64_t va, uint32_t rid,
                    bool is_ifetch, uint64_t *pa, uint8_t *perm)
{
    return ia64_vhpt_walk_full(env, va, rid, is_ifetch, pa, perm, NULL);
}

bool ia64_tlb_probe(const IA64TlbEntry *tlb, uint8_t tlb_count,
                     uint64_t va, uint32_t rid, uint8_t access_level,
                     bool is_ifetch, uint64_t *pa, uint8_t *perm)
{
    const IA64TlbEntry *entry = ia64_tlb_find(tlb, tlb_count, va, rid,
                                              is_ifetch);

    if (!entry) {
        return false;
    }
    ia64_tlb_entry_translate(entry, va, access_level, pa, perm);
    return true;
}

/* ---- ITC insert helper (software-managed TLB insert) ---- */

void helper_itc_insert(CPUIA64State *env, uint64_t pte, uint32_t is_data)
{
    IA64TlbEntry *tlb;
    uint8_t *cnt;
    uint8_t *next_replace;
    uint64_t ps = ia64_itir_page_size(env);
    uint64_t va = env->cr_ifa & ~(ps - 1);
    uint64_t pa = (pte & IA64_PTE_PPN_MASK) & ~(ps - 1);
    uint32_t key = (env->cr_itir & IA64_ITIR_KEY_MASK) >>
                   IA64_ITIR_KEY_SHIFT;
    uint32_t rid = ia64_region_rid(env, env->cr_ifa);
    uint8_t ar = ia64_pte_ar(pte);
    uint8_t pl = ia64_pte_pl(pte);
    uint8_t perm = ia64_pte_perm(pte, 0);
    CPUState *cs = env_cpu(env);
    bool matched;
    int slot;

    if ((pte & IA64_PTE_PRESENT) && perm == 0) {
        return;
    }

    if (is_data) {
        tlb = env->tlb_data;
        cnt = &env->tlb_data_count;
        next_replace = &env->tlb_data_replace;
    } else {
        tlb = env->tlb_inst;
        cnt = &env->tlb_inst_count;
        next_replace = &env->tlb_inst_replace;
    }

    ia64_purge_tc_entries(env, tlb, cnt, va, ps, rid, is_data);

    slot = ia64_tlb_select_tc_slot(tlb, next_replace, va, rid, &matched);
    if (slot < 0) {
        return;
    }

    tlb[slot].va = va;
    tlb[slot].pa = pa;
    tlb[slot].ps = ps;
    tlb[slot].pte = pte;
    tlb[slot].perm = perm;
    tlb[slot].ar = ar;
    tlb[slot].pl = pl;
    tlb[slot].valid = 1;
    tlb[slot].is_tr = 0;
    tlb[slot].pending_purge = 0;
    tlb[slot].rid = rid;
    tlb[slot].key = key;
    tlb[slot].slot = slot;
    if (slot >= *cnt) {
        *cnt = slot + 1;
    }
    qemu_log_mask(CPU_LOG_MMU,
                  "ia64 itc.%c %s slot=%u va=0x%016" PRIx64
                  " rid=0x%06" PRIx32 " pa=0x%016" PRIx64
                  " ps=0x%016" PRIx64 " perm=0x%x"
                  " pte=0x%016" PRIx64 "\n",
                  is_data ? 'd' : 'i', matched ? "update" : "slot",
                  slot, va, rid, pa, ps, perm, pte);
    tlb_flush(cs);
    if (!is_data) {
        ia64_queue_itlb_tb_flush(env);
    }
}

/* ---- mov from PSR helper ---- */

uint64_t helper_mov_psrgr_read(CPUIA64State *env, uint32_t unused)
{
    (void)unused;
    return env->psr;
}

/* ---- mov to PSR helper ---- */

void helper_mov_psr_write(CPUIA64State *env, uint64_t value, uint32_t unused)
{
    if (unused) {
        ia64_set_psr(env, (env->psr & ~0xffffffffULL) |
                     (value & 0xffffffffULL));
    } else {
        ia64_set_psr(env, value);
    }
    tlb_flush(env_cpu(env));
}

/* ---- mov from Region Register helper ---- */

uint64_t helper_mov_rrgr_read(CPUIA64State *env, uint64_t rr_addr)
{
    uint32_t rr_num = (rr_addr >> 61) & 7;

    if (rr_num < 8) {
        return env->rr[rr_num];
    }
    return 0;
}

/* ---- mov to Region Register helper ---- */

void helper_mov_grrr_write(CPUIA64State *env, uint64_t rr_addr, uint64_t value)
{
    uint32_t rr_num = (rr_addr >> 61) & 7;

    if (rr_num < 8) {
        bool inst_purged = false;
        env->rr[rr_num] = value;
        uint8_t i;
        for (i = 0; i < env->tlb_data_count; i++) {
            if (!env->tlb_data[i].is_tr &&
                ia64_rr_index(env->tlb_data[i].va) == rr_num) {
                env->tlb_data[i].valid = 0;
            }
        }
        for (i = 0; i < env->tlb_inst_count; i++) {
            if (!env->tlb_inst[i].is_tr &&
                ia64_rr_index(env->tlb_inst[i].va) == rr_num) {
                env->tlb_inst[i].valid = 0;
                inst_purged = true;
            }
        }
        tlb_flush(env_cpu(env));
        if (inst_purged) {
            ia64_queue_itlb_tb_flush(env);
        }
    }
}

/* ---- mov from PKR helper ---- */

uint64_t helper_mov_pkrgr_read(CPUIA64State *env, uint32_t pkr_num)
{
    if (pkr_num < IA64_PKR_COUNT) {
        return env->pkr[pkr_num];
    }
    return 0;
}

uint64_t helper_mov_pkrgr_indexed_read(CPUIA64State *env, uint64_t pkr_num)
{
    pkr_num &= 0xff;
    if (pkr_num < IA64_PKR_COUNT) {
        return env->pkr[pkr_num];
    }
    return 0;
}

/* ---- mov to PKR helper ---- */

static void ia64_pkr_write(CPUIA64State *env, uint32_t pkr_num,
                           uint64_t value)
{
    uint64_t masked = value & IA64_PKR_MASK;
    uint64_t key = masked & IA64_PKR_KEY_MASK;

    if (pkr_num >= IA64_PKR_COUNT) {
        return;
    }

    if (masked & IA64_PKR_VALID) {
        for (uint32_t i = 0; i < IA64_PKR_COUNT; i++) {
            if ((env->pkr[i] & IA64_PKR_VALID) &&
                (env->pkr[i] & IA64_PKR_KEY_MASK) == key) {
                env->pkr[i] &= ~IA64_PKR_VALID;
            }
        }
    }
    env->pkr[pkr_num] = masked;
    tlb_flush(env_cpu(env));
}

void helper_mov_grpkr_write(CPUIA64State *env, uint32_t pkr_num, uint64_t value)
{
    ia64_pkr_write(env, pkr_num, value);
}

void helper_mov_grpkr_indexed_write(CPUIA64State *env, uint64_t pkr_num,
                                    uint64_t value)
{
    pkr_num &= 0xff;
    ia64_pkr_write(env, pkr_num, value);
}

void helper_invala(CPUIA64State *env)
{
    int i;
    for (i = 0; i < IA64_ALAT_ENTRIES; i++) {
        env->alat[i].valid = false;
    }
}

void helper_clrrrb_rse(CPUIA64State *env)
{
    env->cfm_rrb_gr = 0;
    ia64_invalidate_stacked_alat(env);
}

void helper_vmsw(CPUIA64State *env, uint64_t value)
{
    if (value & 1) {
        env->psr |= IA64_PSR_VM;
    } else {
        env->psr &= ~IA64_PSR_VM;
    }
    tlb_flush(env_cpu(env));
}

static void ia64_set_alat(CPUIA64State *env, uint32_t reg, uint64_t addr,
                          uint32_t size, bool fp)
{
    uint64_t pa;
    int i;

    if (!ia64_data_address_to_phys(env, addr, &pa)) {
        return;
    }

    for (i = 0; i < IA64_ALAT_ENTRIES; i++) {
        if (!env->alat[i].valid ||
            (env->alat[i].reg == reg && env->alat[i].fp == fp)) {
            env->alat[i].phys_addr = pa;
            env->alat[i].size = size;
            env->alat[i].reg = reg;
            env->alat[i].fp = fp;
            env->alat[i].valid = true;
            return;
        }
    }
}

void helper_set_alat(CPUIA64State *env, uint32_t reg, uint64_t addr,
                     uint32_t size)
{
    ia64_set_alat(env, reg, addr, size, false);
}

void helper_set_alat_fp(CPUIA64State *env, uint32_t reg, uint64_t addr,
                        uint32_t size)
{
    if (reg > 1) {
        ia64_set_alat(env, reg, addr, size, true);
    }
}

static int ia64_find_alat_reg(CPUIA64State *env, uint32_t reg, bool fp)
{
    int i;

    for (i = 0; i < IA64_ALAT_ENTRIES; i++) {
        if (env->alat[i].valid &&
            env->alat[i].reg == reg && env->alat[i].fp == fp) {
            return i;
        }
    }

    return -1;
}

static bool ia64_alat_matches_addr(CPUIA64State *env,
                                   const IA64AlatEntry *entry,
                                   uint64_t addr, uint32_t size)
{
    uint64_t pa;

    if (entry->size != size) {
        return false;
    }
    if (!ia64_data_address_to_phys(env, addr, &pa)) {
        return false;
    }
    return entry->phys_addr == pa;
}

static uint64_t ia64_check_load_alat(CPUIA64State *env, uint32_t reg,
                                     bool fp, bool verify_addr,
                                     uint64_t addr, uint32_t size,
                                     uint32_t clear)
{
    int i;

    if (fp && reg <= 1) {
        return 0;
    }

    i = ia64_find_alat_reg(env, reg, fp);
    if (i < 0) {
        return 0;
    }
    if (verify_addr && !ia64_alat_matches_addr(env, &env->alat[i],
                                               addr, size)) {
        if (clear) {
            env->alat[i].valid = false;
        }
        return 0;
    }
    if (clear) {
        env->alat[i].valid = false;
    }
    return 1;
}

void helper_invalidate_alat_reg(CPUIA64State *env, uint32_t reg)
{
    int i = ia64_find_alat_reg(env, reg, false);

    if (i >= 0) {
        env->alat[i].valid = false;
    }
}

void helper_invalidate_alat_fp_reg(CPUIA64State *env, uint32_t reg)
{
    int i = ia64_find_alat_reg(env, reg, true);

    if (i >= 0) {
        env->alat[i].valid = false;
    }
}

uint64_t helper_check_load_alat(CPUIA64State *env, uint32_t reg,
                                uint32_t clear)
{
    return ia64_check_load_alat(env, reg, false, false, 0, 0, clear);
}

uint64_t helper_check_load_alat_addr(CPUIA64State *env, uint32_t reg,
                                     uint64_t addr, uint32_t size,
                                     uint32_t clear)
{
    return ia64_check_load_alat(env, reg, false, true, addr, size, clear);
}

uint64_t helper_check_load_alat_fp(CPUIA64State *env, uint32_t reg,
                                   uint32_t clear)
{
    return ia64_check_load_alat(env, reg, true, false, 0, 0, clear);
}

uint64_t helper_check_load_alat_fp_addr(CPUIA64State *env, uint32_t reg,
                                        uint64_t addr, uint32_t size,
                                        uint32_t clear)
{
    return ia64_check_load_alat(env, reg, true, true, addr, size, clear);
}

static void ia64_invalidate_alat_store(CPUIA64State *env, uint64_t addr,
                                       uint32_t size)
{
    uint64_t pa;

    if (!ia64_data_address_to_phys(env, addr, &pa)) {
        return;
    }

    ia64_invalidate_alat_phys_range(env, pa, size);
}

void helper_invalidate_alat_store(CPUIA64State *env, uint64_t addr,
                                  uint32_t size)
{
    ia64_invalidate_alat_store(env, addr, size);
}

void helper_rum(CPUIA64State *env, uint64_t imm)
{
    env->psr &= ~(imm & IA64_PSR_UM_MASK);
    tlb_flush(env_cpu(env));
}

void helper_sum_um(CPUIA64State *env, uint64_t imm)
{
    env->psr |= imm & IA64_PSR_UM_MASK;
    tlb_flush(env_cpu(env));
}

static inline uint64_t simd_lane(uint64_t val, int idx, int bits)
{
    return (val >> (idx * bits)) & (((uint64_t)1 << bits) - 1);
}

static inline int64_t simd_signed_lane(uint64_t val, int idx, int bits)
{
    uint64_t lane = simd_lane(val, idx, bits);

    return (int64_t)(lane << (64 - bits)) >> (64 - bits);
}

#define SIMD_SEL_ARG uint32_t r1, uint32_t r2, uint32_t r3, uint32_t op_sel

void helper_simd_pavg(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                       uint32_t r2, uint32_t r3)
{
    bool sub = op_sel == 2 || op_sel == 3;
    bool raz = op_sel == 4 || op_sel == 5;
    int bits = (op_sel == 0 || op_sel == 2 || op_sel == 4) ? 8 : 16;
    int lanes = 64 / bits;
    uint64_t mask = ((uint64_t)1 << bits) - 1;
    uint64_t ext_mask = ((uint64_t)1 << (bits + 1)) - 1;
    uint64_t a = env->gr[r2], b = env->gr[r3], result = 0;

    for (int i = 0; i < lanes; i++) {
        uint64_t la = simd_lane(a, i, bits), lb = simd_lane(b, i, bits);
        uint64_t temp;
        uint64_t lane;

        if (sub) {
            temp = (la - lb) & ext_mask;
            lane = ((temp >> 1) | (temp & 1)) & mask;
        } else if (raz) {
            lane = ((la + lb + 1) >> 1) & mask;
        } else {
            temp = la + lb;
            lane = ((temp >> 1) | (temp & 1)) & mask;
        }
        result |= lane << (i * bits);
    }
    env->gr[r1] = result;
}

void helper_simd_pcmp(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                       uint32_t r2, uint32_t r3)
{
    int bits;
    switch (op_sel) {
    case 0: case 1: bits = 8; break;
    case 2: case 3: bits = 16; break;
    default: bits = 32; break;
    }
    int lanes = 64 / bits;
    uint64_t mask = ((uint64_t)1 << bits) - 1;
    bool is_gt = (op_sel & 1) != 0;
    uint64_t a = env->gr[r2], b = env->gr[r3], result = 0;
    for (int i = 0; i < lanes; i++) {
        uint64_t la = simd_lane(a, i, bits), lb = simd_lane(b, i, bits);
        uint64_t lane;

        if (is_gt) {
            lane = simd_signed_lane(a, i, bits) >
                   simd_signed_lane(b, i, bits) ? mask : 0;
        } else {
            lane = la == lb ? mask : 0;
        }
        result |= lane << (i * bits);
    }
    env->gr[r1] = result;
}

void helper_simd_pminmax(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                          uint32_t r2, uint32_t r3)
{
    int bits = (op_sel <= 1) ? 8 : 16;
    int lanes = 64 / bits;
    bool is_max = (op_sel == 0 || op_sel == 2);
    uint64_t a = env->gr[r2], b = env->gr[r3], result = 0;

    for (int i = 0; i < lanes; i++) {
        uint64_t la = simd_lane(a, i, bits), lb = simd_lane(b, i, bits);
        uint64_t lane;

        if (bits == 16) {
            int64_t sa = simd_signed_lane(a, i, bits);
            int64_t sb = simd_signed_lane(b, i, bits);

            lane = is_max ? (sa > sb ? la : lb) : (sa < sb ? la : lb);
        } else {
            lane = is_max ? (la > lb ? la : lb) : (la < lb ? la : lb);
        }
        result |= lane << (i * bits);
    }
    env->gr[r1] = result;
}

static uint64_t simd_pmpy2_result(uint64_t a, uint64_t b, bool right_form)
{
    int first_lane = right_form ? 0 : 1;
    uint64_t result = 0;

    for (int out = 0; out < 2; out++) {
        int lane = first_lane + out * 2;
        int32_t prod = (int16_t)simd_lane(a, lane, 16) *
                       (int16_t)simd_lane(b, lane, 16);

        result |= (uint64_t)(uint32_t)prod << (out * 32);
    }

    return result;
}

void helper_simd_pmpy(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                       uint32_t r2, uint32_t r3, uint32_t shift)
{
    int bits = 16, lanes = 4;
    uint64_t mask = 0xffff;
    uint64_t a = env->gr[r2], b = env->gr[r3], result = 0;

    if (r1 == 0) {
        return;
    }

    if (op_sel <= 1) {
        env->gr[r1] = simd_pmpy2_result(a, b, op_sel == 1);
        return;
    }

    for (int i = 0; i < lanes; i++) {
        uint64_t la = simd_lane(a, i, bits), lb = simd_lane(b, i, bits);
        uint64_t prod;
        if (op_sel == 2) {
            int64_t signed_prod = (int64_t)(int16_t)la * (int16_t)lb;
            prod = (uint64_t)(signed_prod >> shift);
        } else {
            prod = (la * lb) >> shift;
        }
        result |= (prod & mask) << (i * bits);
    }
    env->gr[r1] = result;
}

void helper_simd_psad1(CPUIA64State *env, uint32_t r1, uint32_t r2, uint32_t r3)
{
    uint64_t a = env->gr[r2], b = env->gr[r3], sum = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t la = simd_lane(a, i, 8), lb = simd_lane(b, i, 8);
        sum += (la > lb) ? (la - lb) : (lb - la);
    }
    env->gr[r1] = sum;
}

void helper_simd_mux(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                      uint32_t r2, uint32_t imm)
{
    static const uint8_t mux1_perms[16][8] = {
        [0x0] = { 0, 0, 0, 0, 0, 0, 0, 0 }, /* @brcst */
        [0x8] = { 0, 4, 2, 6, 1, 5, 3, 7 }, /* @mix */
        [0x9] = { 0, 4, 1, 5, 2, 6, 3, 7 }, /* @shuf */
        [0xa] = { 0, 2, 4, 6, 1, 3, 5, 7 }, /* @alt */
        [0xb] = { 7, 6, 5, 4, 3, 2, 1, 0 }, /* @rev */
    };
    const uint64_t a = env->gr[r2];
    uint64_t result = 0;

    if (r1 == 0) {
        return;
    }

    if (op_sel == 0) {
        const uint8_t *perm = mux1_perms[imm & 0xf];

        for (int i = 0; i < 8; i++) {
            result |= simd_lane(a, perm[i], 8) << (i * 8);
        }
    } else {
        for (int i = 0; i < 4; i++) {
            int lane = (imm >> (i * 2)) & 3;

            result |= simd_lane(a, lane, 16) << (i * 16);
        }
    }
    env->gr[r1] = result;
}

void helper_simd_mix(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                      uint32_t r2, uint32_t r3)
{
    int bits;
    bool left;
    switch (op_sel) {
    case 0: case 1: bits = 8; left = (op_sel == 0); break;
    case 2: case 3: bits = 16; left = (op_sel == 2); break;
    default: bits = 32; left = (op_sel == 4); break;
    }
    int lanes = 64 / bits;
    int half = lanes / 2;
    uint64_t a = env->gr[r2], b = env->gr[r3], result = 0;
    for (int i = 0; i < half; i++) {
        int lane = 2 * i + (left ? 1 : 0);

        result |= simd_lane(a, lane, bits) << ((2 * i + 1) * bits);
        result |= simd_lane(b, lane, bits) << ((2 * i) * bits);
    }
    env->gr[r1] = result;
}

void helper_simd_unpack(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                         uint32_t r2, uint32_t r3)
{
    int bits;
    bool lo;
    switch (op_sel) {
    case 0: case 1: bits = 8; lo = (op_sel == 1); break;
    case 2: case 3: bits = 16; lo = (op_sel == 3); break;
    default: bits = 32; lo = (op_sel == 5); break;
    }
    int lanes = 64 / bits;
    int half = lanes / 2;
    int base = lo ? 0 : half;
    uint64_t a = env->gr[r2], b = env->gr[r3], result = 0;
    for (int i = 0; i < half; i++) {
        uint64_t pa = simd_lane(a, base + i, bits);
        uint64_t pb = simd_lane(b, base + i, bits);
        result |= pb << ((2 * i) * bits);
        result |= pa << ((2 * i + 1) * bits);
    }
    env->gr[r1] = result;
}

void helper_simd_pack(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                       uint32_t r2, uint32_t r3)
{
    int in_bits, out_bits;
    bool uss;
    switch (op_sel) {
    case 0: in_bits = 16; out_bits = 8; uss = false; break;
    case 1: in_bits = 16; out_bits = 8; uss = true; break;
    default: in_bits = 32; out_bits = 16; uss = false; break;
    }
    int64_t out_max = (1LL << (out_bits - 1)) - 1;
    int64_t out_min = -(1LL << (out_bits - 1));
    uint64_t out_umax = (1ULL << out_bits) - 1;
    uint64_t src[2] = { env->gr[r2], env->gr[r3] };
    uint64_t result = 0;
    int out_lane = 0;

    for (int src_index = 0; src_index < 2; src_index++) {
        int lanes = 64 / in_bits;

        for (int i = 0; i < lanes; i++, out_lane++) {
            int64_t value = simd_signed_lane(src[src_index], i, in_bits);
            uint64_t lane;

            if (uss) {
                if (value < 0) {
                    value = 0;
                } else if ((uint64_t)value > out_umax) {
                    value = out_umax;
                }
            } else {
                if (value > out_max) {
                    value = out_max;
                } else if (value < out_min) {
                    value = out_min;
                }
            }
            lane = (uint64_t)value & ((1ULL << out_bits) - 1);
            result |= lane << (out_lane * out_bits);
        }
    }
    env->gr[r1] = result;
}

void helper_simd_czx(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                      uint32_t r2, uint32_t r3)
{
    uint64_t val = env->gr[r2];
    int bits = (op_sel <= 1) ? 8 : 16;
    int max_count = 64 / bits;
    int index = max_count;

    if (op_sel == 0 || op_sel == 2) {
        for (int i = max_count - 1; i >= 0; i--) {
            if (simd_lane(val, i, bits) == 0) {
                index = max_count - 1 - i;
                break;
            }
        }
    } else {
        for (int i = 0; i < max_count; i++) {
            if (simd_lane(val, i, bits) == 0) {
                index = i;
                break;
            }
        }
    }
    env->gr[r1] = index;
}

void helper_simd_sum(CPUIA64State *env, uint32_t r1, uint32_t r2, uint32_t r3)
{
    uint64_t a = env->gr[r2], b = env->gr[r3], result = 0;
    for (int i = 0; i < 2; i++) {
        uint64_t la = simd_lane(a, 2 * i, 16) + simd_lane(a, 2 * i + 1, 16);
        uint64_t lb = simd_lane(b, 2 * i, 16) + simd_lane(b, 2 * i + 1, 16);
        result |= la << ((2 + i) * 16);
        result |= lb << (i * 16);
    }
    env->gr[r1] = result;
}
