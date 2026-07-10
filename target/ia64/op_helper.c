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
#define IA64_PTE_MA_SHIFT 2
#define IA64_PTE_MA_MASK  (7ULL << IA64_PTE_MA_SHIFT)
#define IA64_PTE_MA_WB 0
#define IA64_PTE_MA_UC 4
#define IA64_PTE_MA_UCE 5
#define IA64_PTE_MA_WC 6
#define IA64_PTE_MA_NATPAGE 7
#define IA64_PTE_RESERVED_MASK ((1ULL << 1) | (3ULL << 50))
#define IA64_ITIR_RESERVED_MASK (3ULL | (0xffffffffULL << 32))
typedef enum IA64MemorySpeculation {
    IA64_MEM_NON_SPECULATIVE,
    IA64_MEM_LIMITED_SPECULATION,
    IA64_MEM_SPECULATIVE,
} IA64MemorySpeculation;

#define IA64_FP_REG_INTEGER_EXP 0x1003e
#define IA64_FP_REG_NATVAL_EXP  0x1fffe
#define IA64_FP_REG_SPECIAL_EXP 0x1ffff
#define IA64_FP_WRE_BIAS        0x0ffff
#define IA64_FP_WRE_EXP_MASK    0x1ffff
#define IA64_FP_SINGLE_BIAS     127
#define IA64_FP_SINGLE_MANT_WIDTH 24
#define IA64_FP_DOUBLE_EXP_BASE 0x0fc00
#define IA64_FP_DOUBLE_FRAC_MASK ((1ULL << 52) - 1)
#define IA64_FP_SIGNIFICAND_INTEGER_BIT (1ULL << 63)
#define IA64_FP_SPILL_EXP_SIGN_MASK 0x3ffffULL
#define IA64_FP_ISR_SWA 0x8ULL

#define IA64_CPUID_VENDOR0           0x49656e69756e6547ULL /* "GenuineI" */
#define IA64_CPUID_VENDOR1           0x000000006c65746eULL /* "ntel" */
#define IA64_CPUID_SERIAL            0x0000000000000000ULL
#define IA64_CPUID_VERSION_ITANIUM2  0x000000001f010504ULL
#define IA64_CPUID_FEATURES          ((1ULL << 0) | (1ULL << 32) | (1ULL << 33))

static inline void ia64_fr_ext_clear(CPUIA64State *env, uint32_t reg)
{
    if (reg > 1) {
        env->fr_ext_valid[reg / 64] &= ~(1ULL << (reg % 64));
    }
}

static inline void ia64_fr_int_origin_clear(CPUIA64State *env, uint32_t reg)
{
    if (reg > 1) {
        env->fr_int_origin[reg / 64] &= ~(1ULL << (reg % 64));
    }
}

static inline void ia64_fr_write(CPUIA64State *env, uint32_t reg,
                                 uint64_t value)
{
    if (reg > 1) {
        env->fr[reg] = value;
        env->fr_nat[reg / 64] &= ~(1ULL << (reg % 64));
        env->fr_sig[reg / 64] &= ~(1ULL << (reg % 64));
        ia64_fr_ext_clear(env, reg);
        ia64_fr_int_origin_clear(env, reg);
    }
}

static inline void ia64_fr_write_sig(CPUIA64State *env, uint32_t reg,
                                     uint64_t value)
{
    if (reg > 1) {
        env->fr[reg] = value;
        env->fr_nat[reg / 64] &= ~(1ULL << (reg % 64));
        env->fr_sig[reg / 64] |= 1ULL << (reg % 64);
        ia64_fr_ext_clear(env, reg);
        env->fr_int_value[reg] = value;
        env->fr_int_origin[reg / 64] |= 1ULL << (reg % 64);
    }
}

static void ia64_fr_write_ext(CPUIA64State *env, uint32_t reg, bool sign,
                              uint32_t exp, uint64_t mant)
{
    uint16_t ext_exp;
    float_status status;

    if (reg <= 1) {
        return;
    }

    if (exp == IA64_FP_REG_SPECIAL_EXP) {
        ext_exp = 0x7fff;
    } else if (exp == 0) {
        ext_exp = 0;
    } else if (exp > 0xc000 && exp - 0xc000 < 0x7fff) {
        ext_exp = exp - 0xc000;
    } else {
        ext_exp = exp < 0xc000 ? 0 : 0x7fff;
    }

    status = env->fp_status;
    env->fr[reg] = floatx80_to_float64(
        make_floatx80(((uint16_t)sign << 15) | ext_exp, mant), &status);
    env->fr_nat[reg / 64] &= ~(1ULL << (reg % 64));
    env->fr_sig[reg / 64] &= ~(1ULL << (reg % 64));
    ia64_fr_int_origin_clear(env, reg);
    env->fr_ext_mant[reg] = mant;
    env->fr_ext_exp[reg] = exp;
    if (sign) {
        env->fr_ext_sign[reg / 64] |= 1ULL << (reg % 64);
    } else {
        env->fr_ext_sign[reg / 64] &= ~(1ULL << (reg % 64));
    }
    env->fr_ext_valid[reg / 64] |= 1ULL << (reg % 64);
}

static bool ia64_fr_ext_get(const CPUIA64State *env, uint32_t reg,
                            bool *sign, uint32_t *exp, uint64_t *mant)
{
    if (reg <= 1 ||
        !((env->fr_ext_valid[reg / 64] >> (reg % 64)) & 1)) {
        return false;
    }

    *sign = (env->fr_ext_sign[reg / 64] >> (reg % 64)) & 1;
    *exp = env->fr_ext_exp[reg];
    *mant = env->fr_ext_mant[reg];
    return true;
}

static bool ia64_fr_int_origin_get(const CPUIA64State *env, uint32_t reg)
{
    return reg > 1 &&
           ((env->fr_int_origin[reg / 64] >> (reg % 64)) & 1);
}

static bool ia64_fr_nat_get(const CPUIA64State *env, uint32_t reg);
static bool ia64_fr_sig_get(const CPUIA64State *env, uint32_t reg);
static void ia64_fr_write_nat(CPUIA64State *env, uint32_t reg);
static void ia64_raise_fp_fault(CPUIA64State *env, uint64_t isr);
static uint64_t ia64_fp_active_traps(CPUIA64State *env, uint32_t sf);
static uint64_t ia64_fp_soft_flags_to_ia64(int soft);
static void ia64_fp_simd_fault_end(CPUIA64State *env, uint32_t sf,
                                   int hi_soft, int lo_soft);

static floatx80 ia64_register_format_to_floatx80(CPUIA64State *env,
                                                  bool sign, uint32_t exp,
                                                  uint64_t mant)
{
    int shift;
    int32_t adjusted_exp;

    if (exp == IA64_FP_REG_SPECIAL_EXP) {
        return make_floatx80(((uint16_t)sign << 15) | 0x7fff, mant);
    }
    if (mant == 0) {
        return make_floatx80((uint16_t)sign << 15, 0);
    }
    if (exp == 0) {
        return make_floatx80((uint16_t)sign << 15, mant);
    }

    /*
     * setf.sig architecturally produces a positive integer significand
     * with exponent 0x1003e.  Normalize the raw dword before handing it
     * to SoftFloat's x87-style extended format.  The same normalization
     * is required for ldf.fill/ldfe values whose register significand
     * is architecturally unnormalized.
     */
    shift = clz64(mant);
    adjusted_exp = (int32_t)exp - shift;
    mant <<= shift;

    if (adjusted_exp > 0xc000 && adjusted_exp - 0xc000 < 0x7fff) {
        return make_floatx80(((uint16_t)sign << 15) |
                             (uint16_t)(adjusted_exp - 0xc000), mant);
    }

    /*
     * SoftFloat's floatx80 exponent is narrower than IA-64's 17-bit
     * wide-range exponent.  Preserve such values losslessly in the register
     * file, but report the narrowing when an arithmetic operation consumes
     * one.
     */
    if (adjusted_exp <= 0xc000) {
        float_raise(float_flag_underflow | float_flag_inexact,
                    &env->fp_status);
        return make_floatx80((uint16_t)sign << 15, 0);
    }
    float_raise(float_flag_overflow | float_flag_inexact, &env->fp_status);
    return floatx80_default_inf(sign, &env->fp_status);
}

static floatx80 ia64_sig_to_floatx80(CPUIA64State *env, uint64_t mant)
{
    return ia64_register_format_to_floatx80(
        env, false, IA64_FP_REG_INTEGER_EXP, mant);
}

static floatx80 ia64_fr_to_floatx80(CPUIA64State *env, uint32_t reg)
{
    bool sign;
    uint32_t exp;
    uint64_t mant;

    if (reg == 0) {
        return make_floatx80(0, 0);
    }
    if (reg == 1) {
        return make_floatx80(0x3fff, IA64_FP_SIGNIFICAND_INTEGER_BIT);
    }
    if (ia64_fr_sig_get(env, reg)) {
        return ia64_sig_to_floatx80(env, env->fr[reg]);
    }
    if (!ia64_fr_ext_get(env, reg, &sign, &exp, &mant)) {
        return float64_to_floatx80(env->fr[reg], &env->fp_status);
    }

    return ia64_register_format_to_floatx80(env, sign, exp, mant);
}

static void ia64_fr_write_floatx80(CPUIA64State *env, uint32_t reg,
                                   floatx80 value)
{
    uint32_t exp = value.high & 0x7fff;

    if (exp == 0x7fff) {
        exp = IA64_FP_REG_SPECIAL_EXP;
    } else if (exp != 0) {
        exp += 0xc000;
    }
    ia64_fr_write_ext(env, reg, value.high >> 15, exp, value.low);
}

static void ia64_fr_copy(CPUIA64State *env, uint32_t dst, uint32_t src,
                         int sign_mode)
{
    bool sign;
    uint32_t exp;
    uint64_t mant;
    uint64_t value;

    if (dst <= 1) {
        return;
    }
    if (ia64_fr_nat_get(env, src)) {
        ia64_fr_write_nat(env, dst);
        return;
    }
    if (ia64_fr_sig_get(env, src)) {
        value = src == 0 ? 0 : src == 1 ? IA64_FR_ONE : env->fr[src];
        if (sign_mode == 0 || sign_mode == 1) {
            ia64_fr_write_sig(env, dst, value);
        } else if (sign_mode < 0 || sign_mode == 2) {
            ia64_fr_write_ext(env, dst, true, IA64_FP_REG_INTEGER_EXP, value);
        } else {
            ia64_fr_write_sig(env, dst, value);
        }
        return;
    }
    if (ia64_fr_ext_get(env, src, &sign, &exp, &mant)) {
        if (sign_mode == 0) {
            sign = false;
        } else if (sign_mode < 0) {
            sign = !sign;
        } else if (sign_mode == 2) {
            sign = true;
        }
        ia64_fr_write_ext(env, dst, sign, exp, mant);
        if (ia64_fr_int_origin_get(env, src)) {
            env->fr_int_value[dst] = env->fr_int_value[src];
            env->fr_int_origin[dst / 64] |= 1ULL << (dst % 64);
        }
        return;
    }

    value = src == 0 ? 0 : src == 1 ? IA64_FR_ONE : env->fr[src];
    if (sign_mode == 0) {
        value &= INT64_MAX;
    } else if (sign_mode < 0) {
        value ^= 1ULL << 63;
    } else if (sign_mode == 2) {
        value |= 1ULL << 63;
    }
    ia64_fr_write(env, dst, value);
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

static void ia64_float64_to_register_format(uint64_t value, uint64_t *sig,
                                            uint32_t *exp, bool *sign)
{
    uint64_t frac = value & IA64_FP_DOUBLE_FRAC_MASK;
    uint32_t double_exp = (value >> 52) & 0x7ff;

    *sign = (value >> 63) & 1;
    if (double_exp == 0) {
        if (frac == 0) {
            *exp = 0;
            *sig = 0;
        } else {
            *exp = IA64_FP_DOUBLE_EXP_BASE + 1;
            *sig = frac << 11;
        }
    } else if (double_exp == 0x7ff) {
        *exp = IA64_FP_REG_SPECIAL_EXP;
        *sig = IA64_FP_SIGNIFICAND_INTEGER_BIT | (frac << 11);
    } else {
        *exp = IA64_FP_DOUBLE_EXP_BASE + double_exp;
        *sig = IA64_FP_SIGNIFICAND_INTEGER_BIT | (frac << 11);
    }
}

static void ia64_fr_spill_words(const CPUIA64State *env, uint32_t reg,
                                uint64_t *low, uint64_t *high)
{
    uint32_t exp;
    bool sign;

    if (ia64_fr_nat_get(env, reg)) {
        *low = 0;
        exp = IA64_FP_REG_NATVAL_EXP;
        sign = false;
    } else if (ia64_fr_ext_get(env, reg, &sign, &exp, low)) {
        /* Exact register-format value was retained by ldf.fill/ldfe. */
    } else if (ia64_fr_sig_get(env, reg)) {
        *low = env->fr[reg];
        exp = IA64_FP_REG_INTEGER_EXP;
        sign = false;
    } else {
        ia64_float64_to_register_format(reg == 0 ? 0 :
                                        reg == 1 ? IA64_FR_ONE : env->fr[reg],
                                        low, &exp, &sign);
    }

    *high = (exp & 0xffff) |
            (((uint64_t)exp >> 16) << 16) |
            ((uint64_t)sign << 17);
}

static void ia64_fr_fill_spill_words(CPUIA64State *env, uint32_t reg,
                                     uint64_t low, uint64_t high)
{
    uint32_t exp;
    bool sign;

    if (reg <= 1) {
        return;
    }

    high &= IA64_FP_SPILL_EXP_SIGN_MASK;
    exp = (high & 0xffff) | (((high >> 16) & 1) << 16);
    sign = (high >> 17) & 1;

    if (!sign && exp == IA64_FP_REG_NATVAL_EXP && low == 0) {
        ia64_fr_write_nat(env, reg);
    } else if (!sign && exp == IA64_FP_REG_INTEGER_EXP) {
        ia64_fr_write_sig(env, reg, low);
    } else {
        ia64_fr_write_ext(env, reg, sign, exp, low);
    }
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
        ia64_fr_ext_clear(env, reg);
        ia64_fr_int_origin_clear(env, reg);
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

    start = ia64_va_page_base(va, ps);
    end = start + ps - 1;
    if (end < start || end > IA64_REGION7_PHYS_MASK) {
        end = IA64_REGION7_PHYS_MASK;
    }

    entry_start = ia64_va_page_base(entry->va, entry->ps);
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
    uint8_t region;

    if (!entry->valid || entry->ps < TARGET_PAGE_SIZE) {
        return;
    }

    base = ia64_va_page_base(entry->va, entry->ps);
    for (region = 0; region <= IA64_REGION_MASK; region++) {
        uint64_t va = ((uint64_t)region << IA64_REGION_SHIFT) | base;

        tlb_flush_range_by_mmuidx(env_cpu(env), va, entry->ps,
                                  (1u << MMU_IDX_VIRT) | (1u << MMU_IDX_RSE),
                                  TARGET_LONG_BITS);
    }
}

static bool ia64_data_address_to_phys(CPUIA64State *env, uint64_t va,
                                      uint64_t *pa);
static bool ia64_data_address_to_phys_attr(CPUIA64State *env, uint64_t va,
                                           uint64_t *pa,
                                           IA64MemorySpeculation *spec);
static void ia64_raise_data_reference_fault_if_needed(CPUIA64State *env,
                                                      uint64_t va,
                                                      uint32_t is_write,
                                                      uint32_t is_rw,
                                                      uint8_t access_level,
                                                      bool is_non_access,
                                                      uint8_t non_access_code);
static void ia64_rse_pop_return_frame(CPUIA64State *env, uint64_t pfs);
static void ia64_rse_check(CPUIA64State *env, const char *site);
static void ia64_swap_banked_gr(CPUIA64State *env);
static void ia64_invalidate_alat_store(CPUIA64State *env, uint64_t addr,
                                       uint32_t size);
static bool ia64_gr_nat_get(const CPUIA64State *env, uint32_t reg);
static void ia64_gr_nat_set(CPUIA64State *env, uint32_t reg, bool nat);

static void ia64_alat_invalidate_entry(CPUIA64State *env,
                                       IA64AlatEntry *entry)
{
    if (!entry->valid) {
        return;
    }

    entry->valid = false;
    if (env->alat_active_count > 0) {
        env->alat_active_count--;
    }
}

static int ia64_rse_mmu_index(CPUIA64State *env)
{
    return env->psr & IA64_PSR_RT ? MMU_IDX_RSE : MMU_PHYS_IDX;
}

/*
 * RSE backing-store accesses.  The retaddr is threaded from the helper
 * entry point: a non-zero value unwinds to the issuing instruction
 * (alloc/flushrs/loadrs mandatory operations fault on the issuing
 * instruction), while 0 delivers the fault with the already-committed
 * env state (br.ret/rfi mandatory loads fault on the target
 * instruction, SDM Vol.2 6.6).
 */
static void ia64_rse_write_u64(CPUIA64State *env, uint64_t addr,
                               uint64_t value, uintptr_t ra)
{
    int mmu_idx = ia64_rse_mmu_index(env);

    if (env->ar_rsc & IA64_RSC_BE) {
        cpu_stq_be_mmuidx_ra(env, addr, value, mmu_idx, ra);
    } else {
        cpu_stq_le_mmuidx_ra(env, addr, value, mmu_idx, ra);
    }
}

static uint64_t ia64_rse_read_u64(CPUIA64State *env, uint64_t addr,
                                  uintptr_t ra)
{
    int mmu_idx = ia64_rse_mmu_index(env);

    return env->ar_rsc & IA64_RSC_BE ?
           cpu_ldq_be_mmuidx_ra(env, addr, mmu_idx, ra) :
           cpu_ldq_le_mmuidx_ra(env, addr, mmu_idx, ra);
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
#define PAL_HALT            0x001C
#define PAL_HALT_LIGHT      0x001D
#define PAL_COPY_INFO       0x001E
#define PAL_CACHE_LINE_INIT 0x001F
#define PAL_PMI_ENTRYPOINT  0x0020
#define PAL_VM_PAGE_SIZE    0x0022
#define PAL_MEM_FOR_TEST    0x0025
#define PAL_CACHE_PROT_INFO 0x0026
#define PAL_REGISTER_INFO   0x0027
#define PAL_PREFETCH_VIS    0x0029

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
#define PAL_HALT_IO_TYPE_NONE      0
#define PAL_HALT_IO_TYPE_LOAD      1
#define PAL_HALT_IO_TYPE_STORE     2
#define PAL_HALT_IO_PHYS_ADDR_MASK (~(1ULL << 63))
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

    if (env->alat_active_count == 0) {
        return;
    }

    for (i = 0; i < IA64_ALAT_ENTRIES; i++) {
        if (env->alat[i].valid &&
            env->alat[i].fp == fp &&
            env->alat[i].reg >= first && env->alat[i].reg < last) {
            ia64_alat_invalidate_entry(env, &env->alat[i]);
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

    if (env->alat_active_count == 0) {
        return;
    }

    for (i = 0; i < IA64_ALAT_ENTRIES; i++) {
        if (env->alat[i].valid &&
            ia64_ranges_overlap(pa, size, env->alat[i].phys_addr,
                                env->alat[i].size)) {
            ia64_alat_invalidate_entry(env, &env->alat[i]);
        }
    }
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
        | ((uint64_t)env->cfm_rrb_gr << IA64_CFM_RRB_GR_SHIFT)
        | ((uint64_t)env->cfm_rrb_fr << IA64_CFM_RRB_FR_SHIFT)
        | ((uint64_t)env->cfm_rrb_pr << IA64_CFM_RRB_PR_SHIFT);
}

static uint64_t ia64_current_pfs(const CPUIA64State *env)
{
    return ia64_current_cfm(env)
        | ((env->ar_ec & 0x3fULL) << IA64_PFS_PEC_SHIFT)
        | ((uint64_t)ia64_psr_cpl(env->psr) << IA64_PFS_PPL_SHIFT);
}

/*
 * ---- Register Stack Engine core ----
 *
 * Direct implementation of the architected register stack model of
 * SDM Vol.2 chapter 6: a circular physical stacked register file
 * partitioned into current frame, dirty, clean and invalid regions,
 * with the register stack backing store in guest memory as the
 * authoritative home of spilled values.  See cpu.h for the state
 * layout and partition invariants.
 */

static inline uint32_t ia64_rse_wrap_phys(int32_t idx)
{
    idx %= (int32_t)IA64_STACKED_GR_COUNT;
    if (idx < 0) {
        idx += IA64_STACKED_GR_COUNT;
    }
    return idx;
}

/* BSPSTORE{8:3}: the RNAT bit that collects the register spilled there. */
static inline uint32_t ia64_rse_collect_bit(uint64_t addr)
{
    return (addr >> 3) & 0x3f;
}

/*
 * NaT collection words emitted when a backing-store pointer advances
 * over nregs registers: (addr{8:3} + nregs) / 63 (SDM Vol.2 table 6-2,
 * e.g. the br.call row's AR[BSP] update).
 */
static inline uint32_t ia64_rse_nat_words_grow(uint64_t addr, uint32_t nregs)
{
    return (ia64_rse_collect_bit(addr) + nregs) / 63;
}

/*
 * NaT collection words crossed when a backing-store pointer retreats
 * over nregs registers: (62 - addr{8:3} + nregs) / 63 (SDM Vol.2
 * table 6-2, e.g. the br.ret row's AR[BSP] update).
 */
static inline uint32_t ia64_rse_nat_words_shrink(uint64_t addr, uint32_t nregs)
{
    return (62 - ia64_rse_collect_bit(addr) + nregs) / 63;
}

/*
 * Map a virtual stacked register index [0, sof) to its physical index:
 * registers inside the rotating region are renamed by CFM.rrb.gr
 * modulo the region size before the bottom-of-frame bias is applied
 * (register rotation, SDM Vol.1 4.5.3).
 */
static uint32_t ia64_rse_virt_to_phys(const CPUIA64State *env, uint32_t v)
{
    uint32_t sor_regs = (uint32_t)env->cfm_sor << 3;
    uint32_t p;

    if (v < sor_regs) {
        v += env->cfm_rrb_gr;
        if (v >= sor_regs) {
            v -= sor_regs;
        }
    }
    p = env->rse_bol + v;
    return p < IA64_STACKED_GR_COUNT ? p : p - IA64_STACKED_GR_COUNT;
}

/* Inverse of ia64_rse_virt_to_phys. */
static uint32_t ia64_rse_phys_to_virt(const CPUIA64State *env, uint32_t p)
{
    uint32_t off = p >= env->rse_bol ?
                   p - env->rse_bol :
                   p + IA64_STACKED_GR_COUNT - env->rse_bol;
    uint32_t sor_regs = (uint32_t)env->cfm_sor << 3;

    if (off < sor_regs) {
        off += sor_regs - env->cfm_rrb_gr;
        if (off >= sor_regs) {
            off -= sor_regs;
        }
    }
    return off;
}

/* Copy the current frame from the virtual view into the physical file. */
static void ia64_rse_sync_frame_out(CPUIA64State *env)
{
    uint32_t i;

    for (i = 0; i < env->cfm_sof; i++) {
        uint32_t p = ia64_rse_virt_to_phys(env, i);

        env->rse_pgr[p] = env->gr[IA64_STACKED_GR_BASE + i];
        env->rse_pgr_nat[p] = ia64_gr_nat_get(env, IA64_STACKED_GR_BASE + i);
    }
}

/* Load the virtual view of the current frame from the physical file. */
static void ia64_rse_sync_frame_in(CPUIA64State *env)
{
    uint32_t i;

    for (i = 0; i < env->cfm_sof; i++) {
        uint32_t p = ia64_rse_virt_to_phys(env, i);

        env->gr[IA64_STACKED_GR_BASE + i] = env->rse_pgr[p];
        ia64_gr_nat_set(env, IA64_STACKED_GR_BASE + i, env->rse_pgr_nat[p]);
    }
}

/*
 * Perform one mandatory RSE store at AR.BSPSTORE, spilling either the
 * oldest dirty register or, when BSPSTORE{8:3} is all ones, the RNAT
 * collection (SDM Vol.2 6.5.2).  Returns 1 when a register was stored,
 * 0 for a NaT collection word.
 */
static int ia64_rse_store_one(CPUIA64State *env, uintptr_t ra)
{
    uint64_t bspstore = env->ar_bspstore;
    uint32_t ncb = ia64_rse_collect_bit(bspstore);

    if (ncb == 63) {
        /*
         * SDM Vol.2 6.5: whenever BSPSTORE{8:3} are all ones the RSE
         * stores RNAT; bit 63 is always written as zero, and the spill
         * leaves RNAT undefined (cleared here).
         */
        ia64_rse_write_u64(env, bspstore, env->ar_rnat & INT64_MAX, ra);
        env->ar_rnat = 0;
        env->ar_bspstore = bspstore + 8;
        env->rse_dirty_nat--;
        env->rse_clean_nat++;
        env->psr &= ~(IA64_PSR_DA | IA64_PSR_DD);
        return 0;
    } else {
        uint32_t p = ia64_rse_wrap_phys((int32_t)env->rse_bol -
                                        env->rse_dirty);

        ia64_rse_write_u64(env, bspstore, env->rse_pgr[p], ra);
        if (env->rse_pgr_nat[p]) {
            env->ar_rnat |= 1ULL << ncb;
        } else {
            env->ar_rnat &= ~(1ULL << ncb);
        }
        env->ar_bspstore = bspstore + 8;
        env->rse_dirty--;
        env->rse_clean++;
        env->psr &= ~(IA64_PSR_DA | IA64_PSR_DD);
        return 1;
    }
}

/*
 * Perform one mandatory RSE load from the first backing-store word
 * below the clean partition, filling either an invalid physical
 * register or reloading the RNAT collection when the load pointer sits
 * on a NaT collection word (SDM Vol.2 6.5.2).  Returns 1 when a
 * register was loaded, 0 for a NaT collection word.  When the load
 * targets the current frame (only possible while the frame is
 * incomplete) the virtual view is updated alongside the physical file
 * so that a fault on a later load leaves a consistent frame.
 */
static int ia64_rse_load_one(CPUIA64State *env, uintptr_t ra)
{
    int64_t live = (int64_t)env->rse_clean + env->rse_clean_nat +
                   env->rse_dirty + env->rse_dirty_nat;
    uint64_t bspload = env->ar_bsp - (live + 1) * 8;
    uint32_t ncb = ia64_rse_collect_bit(bspload);

    if (ncb == 63) {
        env->ar_rnat = ia64_rse_read_u64(env, bspload, ra) & INT64_MAX;
        env->rse_clean_nat++;
        env->psr &= ~(IA64_PSR_DA | IA64_PSR_DD);
        return 0;
    } else {
        uint64_t value = ia64_rse_read_u64(env, bspload, ra);
        uint32_t p = ia64_rse_wrap_phys(
            (int32_t)env->rse_bol -
            (env->rse_clean + env->rse_dirty + 1));
        uint32_t v;

        env->rse_pgr[p] = value;
        env->rse_pgr_nat[p] = (env->ar_rnat >> ncb) & 1;
        env->rse_clean++;
        env->rse_invalid--;

        v = ia64_rse_phys_to_virt(env, p);
        if (v < env->cfm_sof) {
            env->gr[IA64_STACKED_GR_BASE + v] = value;
            ia64_gr_nat_set(env, IA64_STACKED_GR_BASE + v,
                            env->rse_pgr_nat[p]);
        }
        env->psr &= ~(IA64_PSR_DA | IA64_PSR_DD);
        return 1;
    }
}

/*
 * Complete an incomplete frame with mandatory RSE loads after br.ret
 * or rfi (SDM Vol.2 6.8).  env must already be committed to the
 * post-branch state: faults are delivered on the target instruction
 * (ra == 0) with the partitions describing exactly the loads that
 * remain.
 *
 * RSE.CFLE (SDM Vol.2 6.6) is set for the duration of the sequence:
 * br.ret and rfi set it when the frame being returned to is not
 * entirely contained in the physical stacked register file, and it is
 * cleared when the sequence completes.  A load that faults leaves the
 * frame incomplete; interruption delivery then clears CFLE and the
 * handler runs with the incomplete frame until it executes cover or
 * an rfi resumes the sequence.
 */
static void ia64_rse_complete_frame_loads(CPUIA64State *env, uintptr_t ra)
{
    if (env->rse_dirty >= 0 && env->rse_dirty_nat >= 0) {
        return;
    }

    env->rse_cfle = true;
    while (env->rse_dirty < 0 || env->rse_dirty_nat < 0) {
        if (ia64_rse_load_one(env, ra)) {
            env->rse_clean--;
            env->rse_dirty++;
        } else {
            env->rse_clean_nat--;
            env->rse_dirty_nat++;
        }
        env->ar_bspstore -= 8;
    }
    env->rse_cfle = false;
}

/* br.call/cover: the current frame joins the dirty partition. */
static void ia64_rse_preserve_frame(CPUIA64State *env, uint32_t nregs)
{
    uint32_t nats = ia64_rse_nat_words_grow(env->ar_bsp, nregs);

    env->rse_bol = ia64_rse_wrap_phys(env->rse_bol + nregs);
    env->ar_bsp += (uint64_t)(nregs + nats) * 8;
    env->rse_dirty += nregs;
    env->rse_dirty_nat += nats;
}

/*
 * Grow the current frame for alloc.  New registers come from the
 * invalid partition first; once that is exhausted the oldest clean
 * registers are reused (their backing-store copies remain valid), and
 * only when the whole file is occupied does the RSE issue mandatory
 * stores to make room (SDM Vol.2 6.4).  Restartable: a faulting store
 * leaves the partitions describing the completed portion and the
 * alloc re-executes.
 */
static void ia64_rse_new_frame(CPUIA64State *env, int32_t growth,
                               uintptr_t ra)
{
    if (growth <= env->rse_invalid) {
        env->rse_invalid -= growth;
        return;
    }
    growth -= env->rse_invalid;

    if (growth <= env->rse_clean) {
        env->rse_invalid = 0;
        env->rse_clean -= growth;
        env->rse_clean_nat =
            ia64_rse_nat_words_shrink(env->ar_bsp,
                                      env->rse_clean + env->rse_dirty + 1) -
            env->rse_dirty_nat;
        return;
    }
    growth -= env->rse_clean;

    /*
     * Mandatory stores make room for the remainder.  The invalid and
     * clean partitions are consumed only after the last store
     * completes: a store that faults must leave every register still
     * owned by its partition so that the re-executed alloc recomputes
     * exactly the work that remains.
     */
    while (growth > 0) {
        growth -= ia64_rse_store_one(env, ra);
    }
    env->rse_invalid = 0;
    env->rse_clean = 0;
    env->rse_clean_nat = 0;
}

/*
 * Partition bookkeeping for the frame restored by br.ret or rfi.
 * "preserved" is the number of new-frame registers that lie below the
 * old bottom-of-frame (AR.PFS.pfm.sol for br.ret, CR.IFS.ifm.sof for
 * rfi, per the AR[BSP] rows of SDM Vol.2 table 6-2); "growth" is how
 * far the new frame's top extends beyond the old frame's top;
 * "old_sof" is the returned-from frame's size.  rse_bol must already
 * have been moved down by "preserved" and CFM set to the restored
 * frame marker.
 */
static void ia64_rse_restore_frame(CPUIA64State *env, uint32_t preserved,
                                   int32_t growth, uint32_t old_sof)
{
    int32_t preserved_nats =
        ia64_rse_nat_words_shrink(env->ar_bsp, preserved);
    int32_t missing;
    int32_t missing_nats;

    env->ar_bsp -= (uint64_t)(preserved + preserved_nats) * 8;

    if (growth > env->rse_invalid + env->rse_clean) {
        /*
         * Bad PFS used by branch return (SDM Vol.2 6.5.5): the output
         * area of the frame being returned to does not fit in the
         * physical file.  CFM is forced to zero, the preserved and
         * returned-from registers all join the invalid partition, and
         * the dirty partition shrinks by the preserved registers; the
         * clean partition is left unchanged.
         */
        env->rse_invalid += preserved + old_sof;
        env->rse_dirty -= preserved;
        env->rse_dirty_nat -= preserved_nats;
        env->cfm_sof = 0;
        env->cfm_sol = 0;
        env->cfm_sor = 0;
        env->cfm_rrb_gr = 0;
        env->cfm_rrb_fr = 0;
        env->cfm_rrb_pr = 0;
        return;
    }

    /*
     * Any growth of the frame's top consumes invalid registers first
     * and then the oldest clean registers, whose backing-store copies
     * remain valid.
     */
    if (growth > env->rse_invalid) {
        env->rse_clean -= growth - env->rse_invalid;
        env->rse_clean_nat =
            ia64_rse_nat_words_shrink(env->ar_bsp,
                                      env->rse_clean + env->rse_dirty + 1) -
            env->rse_dirty_nat;
        env->rse_invalid = 0;
    } else {
        env->rse_invalid -= growth;
    }

    /*
     * The preserved registers re-enter the frame from the top of the
     * dirty partition.  Anything beyond it is taken from the clean
     * partition, and anything older than that is no longer in the
     * physical file: the frame becomes incomplete (negative dirty
     * counts, BSPSTORE above BSP) until mandatory loads bring the
     * missing registers back from the backing store (SDM Vol.2 6.8).
     */
    missing = (int32_t)preserved - env->rse_dirty;
    missing_nats = preserved_nats - env->rse_dirty_nat;
    if (missing <= 0) {
        env->rse_dirty -= preserved;
        env->rse_dirty_nat -= preserved_nats;
        return;
    }

    if (missing <= env->rse_clean) {
        env->rse_clean -= missing;
        env->rse_clean_nat -= missing_nats;
        env->rse_dirty = 0;
        env->rse_dirty_nat = 0;
        env->ar_bspstore = env->ar_bsp;
        return;
    }

    env->rse_dirty = -(missing - env->rse_clean);
    env->rse_dirty_nat = -(missing_nats - env->rse_clean_nat);
    env->rse_clean = 0;
    env->rse_clean_nat = 0;
    env->ar_bspstore = env->ar_bsp -
        (int64_t)(env->rse_dirty + env->rse_dirty_nat) * 8;
}

/* br.ia and rfi-to-IA-32: only the current frame stays valid. */
static void ia64_rse_invalidate_non_current(CPUIA64State *env)
{
    env->rse_dirty = 0;
    env->rse_dirty_nat = 0;
    env->rse_clean = 0;
    env->rse_clean_nat = 0;
    env->rse_invalid = IA64_STACKED_GR_COUNT - env->cfm_sof;
}

/*
 * Common CFM/BOF update for br.ret and rfi.  Writes the restored frame
 * marker, moves BOF down by "preserved", adjusts the partitions, and
 * performs any mandatory loads.  The caller must have committed PSR
 * and IP to the post-branch state first (mandatory load faults are
 * delivered on the target instruction).
 */
static void ia64_rse_return_to_frame(CPUIA64State *env, uint64_t pfm,
                                     uint32_t preserved)
{
    uint32_t old_sof = env->cfm_sof;
    uint32_t new_sof = pfm & IA64_CFM_SOF_MASK;
    uint32_t new_sol = (pfm & IA64_CFM_SOL_MASK) >> IA64_CFM_SOL_SHIFT;
    int32_t growth = (int32_t)new_sof - (int32_t)preserved -
                     (int32_t)old_sof;

    ia64_rse_sync_frame_out(env);

    env->cfm_sof = new_sof;
    env->cfm_sol = new_sol;
    env->cfm_sor = (pfm & IA64_CFM_SOR_MASK) >> IA64_CFM_SOR_SHIFT;
    env->cfm_rrb_gr = (pfm & IA64_CFM_RRB_GR_MASK) >> IA64_CFM_RRB_GR_SHIFT;
    env->cfm_rrb_fr = (pfm & IA64_CFM_RRB_FR_MASK) >> IA64_CFM_RRB_FR_SHIFT;
    env->cfm_rrb_pr = (pfm & IA64_CFM_RRB_PR_MASK) >> IA64_CFM_RRB_PR_SHIFT;
    env->rse_bol = ia64_rse_wrap_phys((int32_t)env->rse_bol -
                                      (int32_t)preserved);

    ia64_rse_restore_frame(env, preserved, growth, old_sof);
    ia64_rse_sync_frame_in(env);
    ia64_invalidate_stacked_alat(env);
    ia64_rse_complete_frame_loads(env, 0);
    ia64_rse_check(env, "return");
}

void ia64_rse_delivery_check(CPUIA64State *env, int excp)
{
    char site[32];

    snprintf(site, sizeof(site), "delivery excp=%d", excp);
    ia64_rse_check(env, site);
}

/*
 * Internal consistency checks for the register stack model.  Each RSE
 * operation must leave the four partitions covering the physical file
 * exactly once, the backing-store pointers in their architected
 * relationship, and the NaT-collection word counts matching the
 * partition boundaries.  A violation indicates an emulator bug; log it
 * once with enough state to reconstruct the failure.
 */
static void ia64_rse_check(CPUIA64State *env, const char *site)
{
    static int reported;
    int64_t total = (int64_t)env->cfm_sof + env->rse_dirty +
                    env->rse_clean + env->rse_invalid;
    uint64_t expected_bspstore = env->ar_bsp -
        (int64_t)(env->rse_dirty + env->rse_dirty_nat) * 8;
    bool bad = total != IA64_STACKED_GR_COUNT ||
               env->ar_bspstore != expected_bspstore ||
               env->rse_clean < 0 || env->rse_invalid < 0 ||
               env->rse_bol >= IA64_STACKED_GR_COUNT;

    if (!bad && env->rse_dirty >= 0) {
        /* NaT collection words live at addresses 0x1f8 mod 0x200. */
        bad |= env->rse_dirty_nat !=
               (int32_t)((int64_t)(env->ar_bsp >> 9) -
                         (int64_t)(env->ar_bspstore >> 9));
    }
    if (!bad && env->rse_clean >= 0 && env->rse_dirty >= 0) {
        uint64_t bspload = env->ar_bspstore -
            (int64_t)(env->rse_clean + env->rse_clean_nat) * 8;

        bad |= env->rse_clean_nat !=
               (int32_t)((int64_t)(env->ar_bspstore >> 9) -
                         (int64_t)(bspload >> 9));
    }

    if (bad && reported < 8) {
        reported++;
        qemu_log_mask(LOG_GUEST_ERROR,
                      "ia64 rse inconsistency at %s: excp=%u ip=%016" PRIx64
                      " sof=%u sol=%u sor=%u rrb=%u bol=%u dirty=%d/%d"
                      " clean=%d/%d invalid=%d bsp=%016" PRIx64
                      " bspstore=%016" PRIx64 " rnat=%016" PRIx64
                      " cfle=%d\n",
                      site, env->exception, env->ip, env->cfm_sof,
                      env->cfm_sol,
                      env->cfm_sor, env->cfm_rrb_gr, env->rse_bol,
                      env->rse_dirty, env->rse_dirty_nat, env->rse_clean,
                      env->rse_clean_nat, env->rse_invalid, env->ar_bsp,
                      env->ar_bspstore, env->ar_rnat, env->rse_cfle);
    }
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

    if (exception == IA64_EXCP_RESERVED_REG_FIELD) {
        qemu_log_mask(CPU_LOG_INT,
                      "ia64 reserved-field exception ip=%016" PRIx64
                      " imm=%016" PRIx64 " slot=%u isr=%016" PRIx64
                      " cfm=%016" PRIx64 "\n",
                      fault_ip, fault_imm, fault_slot, env->cr_isr,
                      ia64_current_cfm(env));
    }
    env->ip = fault_ip;
    env->fault_ip = fault_ip;
    env->fault_imm = fault_imm;
    env->fault_slot = fault_slot;
    env->exception = exception;
    cs->exception_index = exception;
    cpu_loop_exit(cs);
}

void helper_ia32_unsupported(CPUIA64State *env)
{
    cpu_abort(env_cpu(env),
              "IA-32 instruction set execution is not implemented "
              "(IP=0x%016" PRIx64 " PSR=0x%016" PRIx64 ")\n",
              env->ip, env->psr);
}

void helper_raise_unaligned(CPUIA64State *env, uint64_t addr,
                            uint64_t isr_access, uint64_t fault_ip,
                            uint32_t fault_slot)
{
    env->cr_ifa = addr;
    env->cr_isr = isr_access;
    if (ia64_current_code_tlb_ed(env)) {
        env->cr_isr |= IA64_ISR_ED;
    }
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

static void ia64_raise_unimplemented_data_address(CPUIA64State *env,
                                                  uint64_t va,
                                                  uint64_t access,
                                                  bool is_non_access,
                                                  bool is_speculative,
                                                  bool itlb_ed)
{
    uint64_t isr = IA64_GENEX_UNIMPL_DATA_ADDR | access;

    if (is_non_access) {
        isr |= IA64_ISR_NA;
    }
    if (is_speculative) {
        isr |= IA64_ISR_SP;
    }
    if (itlb_ed) {
        isr |= IA64_ISR_ED;
    }

    env->cr_ifa = va;
    env->cr_isr = isr;
    helper_raise_exception(env, IA64_EXCP_UNIMPL_DATA_ADDR,
                           ia64_ip_bundle_addr(env->ip), 0,
                           (env->psr & IA64_PSR_RI_MASK) >>
                           IA64_PSR_RI_SHIFT);
}


static bool ia64_cmpxchg_compare_representable(uint64_t cmp, uint32_t size)
{
    switch (size) {
    case 1:
        return cmp <= UINT8_MAX;
    case 2:
        return cmp <= UINT16_MAX;
    case 4:
        return cmp <= UINT32_MAX;
    case 8:
        return true;
    default:
        g_assert_not_reached();
    }
}

static bool ia64_data_big_endian(CPUIA64State *env)
{
    return (env->psr & IA64_PSR_BE) != 0;
}

static MemOp ia64_data_memop(CPUIA64State *env, MemOp memop)
{
    if ((memop & MO_SIZE) == MO_8) {
        return memop & ~MO_BSWAP;
    }
    return (memop & ~MO_BSWAP) |
           (ia64_data_big_endian(env) ? MO_BE : MO_LE);
}

static uint32_t ia64_lduw_data_ra(CPUIA64State *env, uint64_t addr,
                                  uintptr_t ra)
{
    return ia64_data_big_endian(env) ?
           cpu_lduw_be_data_ra(env, addr, ra) :
           cpu_lduw_le_data_ra(env, addr, ra);
}

static uint32_t ia64_ldl_data_ra(CPUIA64State *env, uint64_t addr,
                                 uintptr_t ra)
{
    return ia64_data_big_endian(env) ?
           cpu_ldl_be_data_ra(env, addr, ra) :
           cpu_ldl_le_data_ra(env, addr, ra);
}

static uint64_t ia64_ldq_data_ra(CPUIA64State *env, uint64_t addr,
                                 uintptr_t ra)
{
    return ia64_data_big_endian(env) ?
           cpu_ldq_be_data_ra(env, addr, ra) :
           cpu_ldq_le_data_ra(env, addr, ra);
}

static void ia64_stq_data_ra(CPUIA64State *env, uint64_t addr, uint64_t val,
                             uintptr_t ra)
{
    if (ia64_data_big_endian(env)) {
        cpu_stq_be_data_ra(env, addr, val, ra);
    } else {
        cpu_stq_le_data_ra(env, addr, val, ra);
    }
}

uint64_t helper_cmpxchg(CPUIA64State *env, uint64_t addr, uint64_t cmp,
                        uint64_t val, uint32_t size)
{
    uintptr_t ra = GETPC();
    int mmu_idx = cpu_mmu_index(env_cpu(env), false);
    uint64_t old;
    bool cmp_representable = ia64_cmpxchg_compare_representable(cmp, size);

    switch (size) {
    case 1:
        if (cmp_representable) {
            old = cpu_atomic_cmpxchgb_mmu(env, addr, cmp, val,
                                          make_memop_idx(MO_UB, mmu_idx), ra);
        } else {
            old = cpu_ldub_data_ra(env, addr, ra);
        }
        if (old == cmp) {
            ia64_invalidate_alat_store(env, addr, size);
        }
        return old;
    case 2:
        if (cmp_representable) {
            MemOpIdx oi = make_memop_idx(ia64_data_memop(env, MO_LEUW),
                                         mmu_idx);

            old = ia64_data_big_endian(env) ?
                  cpu_atomic_cmpxchgw_be_mmu(env, addr, cmp, val, oi, ra) :
                  cpu_atomic_cmpxchgw_le_mmu(env, addr, cmp, val, oi, ra);
        } else {
            old = ia64_lduw_data_ra(env, addr, ra);
        }
        if (old == cmp) {
            ia64_invalidate_alat_store(env, addr, size);
        }
        return old;
    case 4:
        if (cmp_representable) {
            MemOpIdx oi = make_memop_idx(ia64_data_memop(env, MO_LEUL),
                                         mmu_idx);

            old = ia64_data_big_endian(env) ?
                  cpu_atomic_cmpxchgl_be_mmu(env, addr, cmp, val, oi, ra) :
                  cpu_atomic_cmpxchgl_le_mmu(env, addr, cmp, val, oi, ra);
        } else {
            old = ia64_ldl_data_ra(env, addr, ra);
        }
        if (old == cmp) {
            ia64_invalidate_alat_store(env, addr, size);
        }
        return old;
    case 8: {
        MemOpIdx oi = make_memop_idx(ia64_data_memop(env, MO_LEUQ), mmu_idx);

        old = ia64_data_big_endian(env) ?
              cpu_atomic_cmpxchgq_be_mmu(env, addr, cmp, val, oi, ra) :
              cpu_atomic_cmpxchgq_le_mmu(env, addr, cmp, val, oi, ra);
        if (old == cmp) {
            ia64_invalidate_alat_store(env, addr, size);
        }
        return old;
    }
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
    old = ia64_ldq_data_ra(env, addr, ra);
    if (old == cmp) {
        ia64_stq_data_ra(env, base, val, ra);
        ia64_stq_data_ra(env, base + 8, csd, ra);
        ia64_invalidate_alat_store(env, base, 16);
    }
    return old;
}








void helper_rfi(CPUIA64State *env)
{
    uint64_t ipsr = env->cr_ipsr;
    uint64_t iip = (ipsr & IA64_PSR_IS) ?
                   (env->cr_iip & UINT32_MAX) :
                   ia64_ip_bundle_addr(env->cr_iip);
    uint64_t ifs = env->cr_ifs;

    env->exception = IA64_EXCP_NONE;
    env->fault_ip = 0;
    env->fault_imm = 0;
    env->fault_slot = 0;
    env->instruction_group_start = true;

    /*
     * rfi restores PSR and IP before the RSE moves the frame: mandatory
     * RSE loads are delivered on the target instruction and use the
     * restored PSR state (SDM Vol.2 6.6).  CR[IPSR], CR[IIP] and
     * CR[IFS] are consumed, not modified.
     */
    ia64_set_psr(env, ipsr);
    env->ip = iip;
    helper_tlb_serialize(env, 1, 1);
    tlb_flush(env_cpu(env));

    if (ipsr & IA64_PSR_IS) {
        /* Return to IA-32: the register stack is left empty. */
        ia64_rse_sync_frame_out(env);
        env->cfm_sof = 0;
        env->cfm_sol = 0;
        env->cfm_sor = 0;
        env->cfm_rrb_gr = 0;
        env->cfm_rrb_fr = 0;
        env->cfm_rrb_pr = 0;
        ia64_rse_invalidate_non_current(env);
        ia64_invalidate_stacked_alat(env);
        return;
    }

    if (ifs & IA64_IFS_V) {
        ia64_rse_return_to_frame(env, ifs & IA64_IFS_IFM_MASK,
                                 ifs & IA64_CFM_SOF_MASK);
    } else if (env->rse_dirty < 0 || env->rse_dirty_nat < 0) {
        /*
         * SDM Vol.2 6.8: an interruption taken during the mandatory
         * loads of a br.ret/rfi leaves the current frame incomplete.
         * Returning with IFS.v = 0 resumes the original sequence of
         * mandatory loads for the still-incomplete frame.
         */
        ia64_rse_complete_frame_loads(env, 0);
        ia64_rse_check(env, "rfi-resume");
    }
}

uint64_t helper_read_pr(CPUIA64State *env)
{
    uint64_t value = 0;

    for (uint32_t i = 0; i < IA64_PR_COUNT; i++) {
        value |= (env->pr[i] & 1) << i;
    }

    return value;
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

        for (uint16_t i = 0; i < env->tlb_inst_count; i++) {
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

static bool ia64_reserved_rsc_field(uint64_t value)
{
    return value & ~(0x1fULL | (0x3fffULL << IA64_RSC_LOADRS_SHIFT));
}

static bool ia64_reserved_fpsr_field(uint64_t value)
{
    return (value >> 58) != 0 ||
           ((value >> 12) & 1) != 0 ||
           ((value >> 47) & 3) == 1 ||
           ((value >> 34) & 3) == 1 ||
           ((value >> 21) & 3) == 1 ||
           ((value >> 8) & 3) == 1;
}

static bool ia64_reserved_pfs_field(uint64_t value)
{
    uint32_t sof = value & 0x7f;
    uint32_t sol = (value >> 7) & 0x7f;
    uint32_t sor = ((value >> 14) & 0xf) << 3;
    uint32_t rrb_gr = (value >> 18) & 0x7f;
    uint32_t rrb_fr = (value >> 25) & 0x7f;
    uint32_t rrb_pr = (value >> 32) & 0x3f;

    if ((value & (0xfULL << 58)) ||
        (value & (0x3fffULL << 38))) {
        return true;
    }
    return sof > IA64_STACKED_GR_COUNT || sol > sof || sor > sof ||
           (sor ? rrb_gr >= sor : rrb_gr != 0) ||
           rrb_fr >= 96 || rrb_pr >= 48;
}

void helper_validate_ar_access(CPUIA64State *env, uint64_t value,
                               uint32_t ar_num, uint32_t write,
                               uint64_t fault_ip, uint64_t raw,
                               uint32_t slot)
{
    if ((ar_num == 18 || ar_num == 19) &&
        (env->ar_rsc & IA64_RSC_MODE)) {
        env->cr_isr = 0;
        helper_raise_exception(env, IA64_EXCP_ILLEGAL, fault_ip, raw, slot);
    }

    if (!write) {
        if (ar_num == 44 && (env->psr & IA64_PSR_SI) &&
            ia64_psr_cpl(env->psr) != 0) {
            env->cr_isr = 0x20;
            helper_raise_exception(env, IA64_EXCP_PRIVILEGED_REG,
                                   fault_ip, raw, slot);
        }
        return;
    }

    if ((ar_num == 16 && ia64_reserved_rsc_field(value)) ||
        (ar_num == 40 && ia64_reserved_fpsr_field(value)) ||
        (ar_num == 64 && ia64_reserved_pfs_field(value))) {
        qemu_log_mask(CPU_LOG_INT,
                      "ia64 reserved AR field ip=%016" PRIx64
                      " ar=%u value=%016" PRIx64 " raw=%011" PRIx64
                      " slot=%u\n",
                      fault_ip, ar_num, value, raw, slot);
        env->cr_isr = 0x30;
        helper_raise_exception(env, IA64_EXCP_RESERVED_REG_FIELD,
                               fault_ip, raw, slot);
    }
    if ((ar_num <= 7 || ar_num == 44) && ia64_psr_cpl(env->psr) != 0) {
        env->cr_isr = 0x20;
        helper_raise_exception(env, IA64_EXCP_PRIVILEGED_REG,
                               fault_ip, raw, slot);
    }
}

void helper_write_ar(CPUIA64State *env, uint32_t ar_num, uint64_t value)
{
    if (ar_num >= IA64_AR_COUNT) {
        return;
    }
    if ((ar_num >= 48 && ar_num <= 63) || ar_num >= 112) {
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
    if (ar_num == 16) {
        uint8_t pl = MAX(ia64_rsc_pl(value), ia64_psr_cpl(env->psr));
        uint64_t old_rsc = env->ar_rsc;

        env->ar_rsc = (value & ~IA64_RSC_PL) |
                      ((uint64_t)pl << IA64_RSC_PL_SHIFT);
        if ((old_rsc ^ env->ar_rsc) & IA64_RSC_PL) {
            tlb_flush_by_mmuidx(env_cpu(env), 1u << MMU_IDX_RSE);
        }
        return;
    }
    if (ar_num == 19) {
        value &= INT64_MAX;
    } else if (ar_num == 18) {
        value &= ~7ULL;
    } else if (ar_num == 66) {
        value &= 0x3f;
    }
    env->ar[ar_num] = value;
    if (ar_num == 18) {
        /*
         * mov-to-BSPSTORE (SDM Vol.2 6.5.3): the clean partition
         * empties and the dirty partition is preserved by rebasing
         * AR.BSP to the new address plus the dirty registers and their
         * intervening NaT collections.  No memory traffic occurs.
         * RNAT becomes architecturally undefined; this implementation
         * keeps its previous contents.
         */
        int32_t dirty = MAX(env->rse_dirty, 0);

        env->rse_dirty_nat = ia64_rse_nat_words_grow(value, dirty);
        env->ar_bsp = value +
            (uint64_t)(env->rse_dirty + env->rse_dirty_nat) * 8;
        env->rse_invalid += env->rse_clean;
        env->rse_clean = 0;
        env->rse_clean_nat = 0;
        ia64_rse_check(env, "bspstore");
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

static bool ia64_reserved_ipsr_field(uint64_t value)
{
    return (value >> 46) != 0 ||
           ((value >> 41) & 3) == 3 ||
           ((value >> 28) & 0xf) != 0 ||
           ((value >> 16) & 1) != 0 ||
           ((value >> 6) & 0x7f) != 0 ||
           (value & 1) != 0;
}

static bool ia64_reserved_ifs_field(uint64_t value)
{
    if (value & (0x1ffffffULL << 38)) {
        return true;
    }
    return (value >> 63) && ia64_reserved_pfs_field(value);
}

static bool ia64_reserved_cr_field(uint32_t cr_num, uint64_t value)
{
    switch (cr_num) {
    case 0:
        return (value >> 15) != 0 || (value & (0x1fULL << 3));
    case 8: {
        uint8_t ps = (value >> 2) & 0x3f;

        return (value & (0x3fULL << 9)) || (value & 2) ||
               ps < 15;
    }
    case 16:
        return ia64_reserved_ipsr_field(value);
    case 17:
        return (value >> 44) != 0 ||
               ((value >> 41) & 3) == 3 ||
               ((value >> 24) & 0xff) != 0;
    case 23:
        return ia64_reserved_ifs_field(value);
    case IA64_CR_SAPIC_LID:
        return (value & 0xffff) != 0;
    case IA64_CR_SAPIC_IVR:
        return (value & 0xff) != 0;
    case IA64_CR_SAPIC_TPR:
        return (value & 0xff00) != 0;
    case IA64_CR_ITV:
    case 73:
    case 74:
        return (value & (7ULL << 13)) ||
               (value & (0xfULL << 8));
    case 80:
    case 81: {
        uint8_t delivery_mode = (value >> 8) & 7;

        return (value & (1ULL << 14)) ||
               (value & (1ULL << 11)) ||
               delivery_mode == 1 || delivery_mode == 3 ||
               delivery_mode == 6;
    }
    default:
        return false;
    }
}

uint64_t helper_validate_cr_access(CPUIA64State *env, uint64_t value,
                                   uint32_t cr_num, uint32_t write,
                                   uint64_t fault_ip, uint64_t raw,
                                   uint32_t slot)
{
    if ((env->psr & IA64_PSR_IC) && cr_num >= 16 && cr_num <= 25) {
        env->cr_isr = 0;
        helper_raise_exception(env, IA64_EXCP_ILLEGAL, fault_ip, raw, slot);
    }
    if (write && ia64_reserved_cr_field(cr_num, value)) {
        qemu_log_mask(CPU_LOG_INT | LOG_GUEST_ERROR,
                      "ia64 reserved cr write cr%u value=%016" PRIx64
                      " ip=%016" PRIx64 " raw=%016" PRIx64
                      " slot=%u psr=%016" PRIx64 "\n",
                      cr_num, value, fault_ip, raw, slot, env->psr);
        env->cr_isr = 0x30;
        helper_raise_exception(env, IA64_EXCP_RESERVED_REG_FIELD,
                               fault_ip, raw, slot);
    }

    switch (cr_num) {
    case 2:
        return value & ~0x7fffULL;
    case 25:
        return value & ~3ULL;
    case IA64_CR_SAPIC_TPR:
        return value & 0x100f0;
    case IA64_CR_SAPIC_EOI:
        return 0;
    case IA64_CR_ITV:
    case 73:
    case 74:
    case 80:
    case 81:
        return value & 0x1efff;
    default:
        return value;
    }
}

uint64_t helper_read_cpuid(CPUIA64State *env, uint64_t index)
{
    index &= 0xff;
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
    index &= 0xff;
    if (index >= IA64_DBR_COUNT) {
        return 0;
    }
    return env->dbr[index];
}

void helper_write_dbr(CPUIA64State *env, uint32_t index, uint64_t value)
{
    index &= 0xff;
    if (index < IA64_DBR_COUNT) {
        if (index & 1) {
            value &= ~(3ULL << 60);
        }
        env->dbr[index] = value;
    }
}

uint64_t helper_read_ibr(CPUIA64State *env, uint32_t index)
{
    index &= 0xff;
    if (index >= IA64_IBR_COUNT) {
        return 0;
    }
    return env->ibr[index];
}

void helper_write_ibr(CPUIA64State *env, uint32_t index, uint64_t value)
{
    index &= 0xff;
    if (index < IA64_IBR_COUNT) {
        if (index & 1) {
            value &= ~(7ULL << 60);
        }
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
        env->cr[1] = value;
        ia64_itm_update(env, value);
        break;
    case 2:
        if (ia64_firmware_owns_iva(env->cr[2]) !=
            ia64_firmware_owns_iva(value)) {
            /*
             * The firmware identity window is an emulator boot facility,
             * not an architectural translation.  Drop cached mappings when
             * IVA ownership passes between firmware and the operating
             * system.
             */
            tlb_flush(env_cpu(env));
            queue_tb_flush(env_cpu(env));
        }
        env->cr[2] = value;
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
    index &= 0xff;
    if (index >= IA64_PMC_COUNT) {
        return 0;
    }
    return env->pmc[index];
}

void helper_write_pmc_indexed(CPUIA64State *env, uint64_t index,
                              uint64_t value)
{
    index &= 0xff;
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

uint64_t helper_read_pmd_checked(CPUIA64State *env, uint64_t index,
                                 uint64_t fault_ip, uint64_t raw,
                                 uint32_t slot)
{
    index &= 0xff;
    if (index >= IA64_PMD_COUNT) {
        env->cr_isr = 0x30;
        helper_raise_exception(env, IA64_EXCP_RESERVED_REG_FIELD,
                               fault_ip, raw, slot);
    }
    if ((env->pmc[index] & (1ULL << 6)) &&
        ia64_psr_cpl(env->psr) != 0) {
        env->cr_isr = 0x20;
        helper_raise_exception(env, IA64_EXCP_PRIVILEGED_REG,
                               fault_ip, raw, slot);
    }
    return (env->psr & IA64_PSR_SP) ? 0 : env->pmd[index];
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
    index &= 0xff;
    if (index >= IA64_PMD_COUNT) {
        return 0;
    }
    return env->pmd[index];
}

void helper_write_pmd_indexed(CPUIA64State *env, uint64_t index,
                              uint64_t value)
{
    index &= 0xff;
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
                     ((uint64_t)IA64_IMPL_KEY_BITS << 8) |
                     (((uint64_t)IA64_PKR_COUNT - 1ULL) << 16) |
                     (8ULL << 24) |
                     (((uint64_t)IA64_TR_COUNT - 1ULL) << 32) |
                     (((uint64_t)IA64_TR_COUNT - 1ULL) << 40) |
                     (4ULL << 48) | (2ULL << 56);
        env->gr[10] = IA64_PAL_IMPL_VA_MSB |
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
    ia64_itc_enter_halt(env);
    return true;
}

static bool pal_halt_valid_io_size(uint64_t io_size)
{
    return io_size == 1 || io_size == 2 || io_size == 4 || io_size == 8;
}

static bool pal_halt_io_transaction(uint64_t io_detail_ptr,
                                    uint64_t *load_return)
{
    uint64_t info;
    uint64_t io_type;
    uint64_t io_size;
    uint64_t addr;
    uint64_t data;
    uint64_t phys_addr;

    *load_return = 0;
    if (io_detail_ptr == 0) {
        return true;
    }
    if ((io_detail_ptr & 7) != 0) {
        return false;
    }

    cpu_physical_memory_read(io_detail_ptr, &info, sizeof(info));
    info = le64_to_cpu(info);
    io_type = info & 0xff;
    io_size = (info >> 8) & 0xff;
    if (io_type == PAL_HALT_IO_TYPE_NONE) {
        return io_size == 0;
    }
    if ((io_type != PAL_HALT_IO_TYPE_LOAD &&
         io_type != PAL_HALT_IO_TYPE_STORE) ||
        !pal_halt_valid_io_size(io_size)) {
        return false;
    }

    cpu_physical_memory_read(io_detail_ptr + 8, &addr, sizeof(addr));
    addr = le64_to_cpu(addr);
    phys_addr = addr & PAL_HALT_IO_PHYS_ADDR_MASK;
    if ((phys_addr & (io_size - 1)) != 0) {
        return false;
    }

    if (io_type == PAL_HALT_IO_TYPE_LOAD) {
        uint8_t buf[8] = { 0 };
        uint64_t value = 0;
        int i;

        cpu_physical_memory_read(phys_addr, buf, io_size);
        for (i = 0; i < io_size; i++) {
            value |= (uint64_t)buf[i] << (i * 8);
        }
        *load_return = value;
    } else {
        uint8_t buf[8];
        uint64_t store_value;
        int i;

        cpu_physical_memory_read(io_detail_ptr + 16, &data, sizeof(data));
        store_value = le64_to_cpu(data);
        for (i = 0; i < io_size; i++) {
            buf[i] = store_value >> (i * 8);
        }
        cpu_physical_memory_write(phys_addr, buf, io_size);
    }
    return true;
}

static bool pal_halt(CPUIA64State *env)
{
    CPUState *cs = env_cpu(env);
    uint64_t halt_state = env->gr[29];
    uint64_t io_detail_ptr = env->gr[30];
    uint64_t load_return = 0;

    if (halt_state != 1 || env->gr[31] != 0 ||
        !pal_halt_io_transaction(io_detail_ptr, &load_return)) {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
        env->gr[10] = 0;
        env->gr[11] = 0;
        return false;
    }

    env->gr[8] = PAL_STATUS_SUCCESS;
    env->gr[9] = load_return;
    env->gr[10] = 0;
    env->gr[11] = 0;
    cs->halted = 1;
    ia64_itc_enter_halt(env);
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

static void pal_vm_page_size(CPUIA64State *env)
{
    if (pal_reserved_args_are_zero(env)) {
        env->gr[8] = PAL_STATUS_SUCCESS;
        env->gr[9] = IA64_INSERTABLE_PAGE_SIZE_MASK;
        env->gr[10] = IA64_PURGEABLE_PAGE_SIZE_MASK;
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
    power_states[1] = PAL_HALT_STATE_IMPLEMENTED |
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
        env->gr[9] = 0;
        env->gr[10] = 0;
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

    if (level > 1 || env->gr[31] != 0 || tc_type < 1 || tc_type > 2) {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
        env->gr[10] = 0;
        env->gr[11] = 0;
        return;
    }

    env->gr[8] = PAL_STATUS_SUCCESS;
    if (level == 0) {
        env->gr[9] = 1ULL | (32ULL << 8) | (32ULL << 16);
        env->gr[10] = 1ULL << 12;
    } else {
        env->gr[9] = 1ULL | (128ULL << 8) | (128ULL << 16) |
                     (1ULL << 32) | (1ULL << 34);
        env->gr[10] = IA64_INSERTABLE_PAGE_SIZE_MASK;
    }
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

    if (reg_num >= IA64_TR_COUNT || tr_type > 1 || (tr_buffer & 7) != 0) {
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
        env->gr[9] = 0;
        env->gr[10] = (1ULL << 32) | 1ULL;
        env->gr[11] = 0;
    } else {
        env->gr[8] = PAL_STATUS_INVALID_ARGUMENT;
        env->gr[9] = 0;
        env->gr[10] = 0;
        env->gr[11] = 0;
    }
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
    case PAL_HALT:
        if (pal_halt(env)) {
            flags |= IA64_PAL_DISPATCH_HALTED;
        }
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
     * PAL_PROC is a firmware portal, not a normal C function.  Static
     * calls arrive with a plain branch, stacked calls with br.call; the
     * PAL trampoline returns with a plain branch to b0 in both cases.
     * Stacked-convention indices are exactly those with bit 8 set
     * (256-511 and 768-1023, SDM Vol.2 table 11-11); complete such a
     * call's frame here before the trampoline branches back.
     */
    if (index & 0x100) {
        ia64_rse_pop_return_frame(env, env->ar_pfs);
    }

    return flags;
}

static IA64MemorySpeculation ia64_pte_memory_speculation(uint64_t pte)
{
    switch ((pte & IA64_PTE_MA_MASK) >> IA64_PTE_MA_SHIFT) {
    case IA64_PTE_MA_WB:
    case IA64_PTE_MA_WC:
    case IA64_PTE_MA_NATPAGE:
        return IA64_MEM_SPECULATIVE;
    case IA64_PTE_MA_UC:
    case IA64_PTE_MA_UCE:
    default:
        return IA64_MEM_NON_SPECULATIVE;
    }
}

static bool ia64_memory_allows_advanced_load(IA64MemorySpeculation spec)
{
    return spec != IA64_MEM_NON_SPECULATIVE;
}

static bool ia64_memory_allows_control_speculation(IA64MemorySpeculation spec)
{
    return spec == IA64_MEM_SPECULATIVE;
}

static bool ia64_data_address_to_mapped_phys_attr(CPUIA64State *env,
                                                  uint64_t va, bool is_rse,
                                                  uint8_t access_level,
                                                  uint64_t *pa,
                                                  IA64MemorySpeculation *spec)
{
    uint8_t perm;
    uint32_t rid;
    const IA64TlbEntry *entry;

    if (ia64_firmware_identity_pa(env->cr_iva, env->ip, va, pa)) {
        if (spec) {
            *spec = IA64_MEM_SPECULATIVE;
        }
        return true;
    }

    if (ia64_sal_boot_virtual_pa(env, va, pa)) {
        if (spec) {
            *spec = IA64_MEM_SPECULATIVE;
        }
        return true;
    }

    rid = ia64_region_rid(env, va);
    entry = ia64_tlb_find(env->tlb_data, env->tlb_data_count, va, rid,
                          false);
    if (entry) {
        ia64_tlb_entry_translate(entry, va, access_level, pa, &perm);
        if (spec) {
            *spec = ia64_pte_memory_speculation(entry->pte);
        }
        return (perm & IA64_TLB_R) != 0;
    }

    {
        uint64_t pte = 0;

        if (ia64_vhpt_walk_full(env, va, rid, false, is_rse, access_level,
                                pa, &perm, &pte, NULL)) {
            if (spec) {
                *spec = ia64_pte_memory_speculation(pte);
            }
            return (perm & IA64_TLB_R) != 0;
        }
    }

    if (ia64_sal_boot_identity_pa(env, va, pa)) {
        if (spec) {
            *spec = IA64_MEM_SPECULATIVE;
        }
        return true;
    }

    return false;
}


static bool ia64_data_address_to_phys_attr(CPUIA64State *env, uint64_t va,
                                           uint64_t *pa,
                                           IA64MemorySpeculation *spec)
{
    if (!(env->psr & IA64_PSR_DT)) {
        *pa = ia64_physical_address(va);
        if (spec) {
            *spec = (va & IA64_PHYS_UC_BIT) ?
                    IA64_MEM_NON_SPECULATIVE :
                    IA64_MEM_LIMITED_SPECULATION;
        }
        return true;
    }

    return ia64_data_address_to_mapped_phys_attr(
        env, va, false, ia64_psr_cpl(env->psr), pa, spec);
}

static bool ia64_data_address_to_phys(CPUIA64State *env, uint64_t va,
                                      uint64_t *pa)
{
    return ia64_data_address_to_phys_attr(env, va, pa, NULL);
}


void helper_fc(CPUIA64State *env, uint64_t addr)
{
    uint64_t pa;

    if ((env->psr & IA64_PSR_DT) && !ia64_va_is_implemented(addr)) {
        ia64_raise_unimplemented_data_address(
            env, addr, IA64_ISR_R, true, false, ia64_current_code_tlb_ed(env));
    }

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

static void ia64_rotate_rotating_fr_u64_right(uint64_t values[IA64_FR_COUNT])
{
    uint64_t last = values[IA64_FR_COUNT - 1];

    memmove(&values[IA64_ROTATING_FR_BASE + 1],
            &values[IA64_ROTATING_FR_BASE],
            (IA64_ROTATING_FR_COUNT - 1) * sizeof(values[0]));
    values[IA64_ROTATING_FR_BASE] = last;
}

static void ia64_rotate_rotating_fr_u32_right(uint32_t values[IA64_FR_COUNT])
{
    uint32_t last = values[IA64_FR_COUNT - 1];

    memmove(&values[IA64_ROTATING_FR_BASE + 1],
            &values[IA64_ROTATING_FR_BASE],
            (IA64_ROTATING_FR_COUNT - 1) * sizeof(values[0]));
    values[IA64_ROTATING_FR_BASE] = last;
}

static void ia64_rotate_rotating_fr_bits_right(uint64_t bits[2])
{
    const uint64_t rotating_word0_mask = UINT64_MAX << IA64_ROTATING_FR_BASE;
    uint64_t word0 = bits[0];
    uint64_t word1 = bits[1];
    uint64_t wrap_to_base = word1 >> 63;
    uint64_t carry_to_word1 = word0 >> 63;

    bits[0] = (word0 & ~rotating_word0_mask) |
              ((word0 << 1) & rotating_word0_mask) |
              (wrap_to_base << IA64_ROTATING_FR_BASE);
    bits[1] = (word1 << 1) | carry_to_word1;
}

static void ia64_rotate_rotating_fr_right(CPUIA64State *env)
{
    const uint64_t rotating_word0_mask = UINT64_MAX << IA64_ROTATING_FR_BASE;

    ia64_rotate_rotating_fr_u64_right(env->fr);
    ia64_rotate_rotating_fr_u64_right(env->fr_int_value);
    ia64_rotate_rotating_fr_u64_right(env->fr_ext_mant);
    ia64_rotate_rotating_fr_u32_right(env->fr_ext_exp);

    ia64_rotate_rotating_fr_bits_right(env->fr_nat);
    ia64_rotate_rotating_fr_bits_right(env->fr_sig);
    ia64_rotate_rotating_fr_bits_right(env->fr_ext_sign);
    ia64_rotate_rotating_fr_bits_right(env->fr_ext_valid);
    ia64_rotate_rotating_fr_bits_right(env->fr_int_origin);

    env->fr_sig[0] &= ~(env->fr_nat[0] & rotating_word0_mask);
    env->fr_sig[1] &= ~env->fr_nat[1];
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
    ia64_rse_check(env, "ctop");
    ia64_rotate_rotating_gr_right(env);
    ia64_rotate_rotating_fr_right(env);
    ia64_rotate_predicates_right(env);
    if (env->cfm_sor != 0) {
        uint8_t count = env->cfm_sor << 3;

        env->cfm_rrb_gr = env->cfm_rrb_gr ?
                          env->cfm_rrb_gr - 1 : count - 1;
    }
    env->cfm_rrb_fr = env->cfm_rrb_fr ?
                      env->cfm_rrb_fr - 1 : IA64_ROTATING_FR_COUNT - 1;
    env->cfm_rrb_pr = env->cfm_rrb_pr ?
                      env->cfm_rrb_pr - 1 : 47;
}

void helper_br_call_rse(CPUIA64State *env, uint32_t b_reg,
                         uint64_t next_ip, uint64_t target)
{
    uint64_t pfs = ia64_current_pfs(env);
    uint32_t sol = env->cfm_sol;

    ia64_rse_sync_frame_out(env);
    ia64_rse_preserve_frame(env, sol);
    env->cfm_sof = env->cfm_sof > sol ? env->cfm_sof - sol : 0;
    env->cfm_sol = 0;
    env->cfm_sor = 0;
    env->cfm_rrb_gr = 0;
    env->cfm_rrb_fr = 0;
    env->cfm_rrb_pr = 0;
    ia64_rse_sync_frame_in(env);
    ia64_invalidate_stacked_alat(env);

    env->ar_pfs = pfs;
    env->br[b_reg] = next_ip;
    env->ip = ia64_ip_bundle_addr(target);
    env->psr &= ~IA64_PSR_RI_MASK;
    ia64_rse_check(env, "br.call");
}

void helper_br_ia(CPUIA64State *env, uint32_t b_reg,
                  uint64_t fault_ip, uint32_t fault_slot)
{
    if (env->ar_bspstore != env->ar_bsp) {
        helper_raise_exception(env, IA64_EXCP_ILLEGAL, fault_ip, 0,
                               fault_slot);
        return;
    }

    if (env->psr & IA64_PSR_DI) {
        env->cr_isr = 4 << 4;
        helper_raise_exception(env, IA64_EXCP_DISABLED_ISA_TRANSITION,
                               fault_ip, 0, fault_slot);
        return;
    }

    /*
     * Perform the architectural IA-64 to IA-32 transition: IP takes
     * BR[b1]{31:0} with byte granularity, PSR.is is set, and only the
     * current (zero-size) frame stays valid.  This CPU model has no
     * IA-32 execution engine, so report the abort with the
     * transitioned state visible.
     */
    env->ip = env->br[b_reg] & UINT32_MAX;
    env->psr |= IA64_PSR_IS;
    env->psr &= ~(IA64_PSR_DA | IA64_PSR_DD | IA64_PSR_IA | IA64_PSR_ED |
                  IA64_PSR_RI_MASK);
    ia64_rse_sync_frame_out(env);
    env->cfm_sof = 0;
    env->cfm_sol = 0;
    env->cfm_sor = 0;
    env->cfm_rrb_gr = 0;
    env->cfm_rrb_fr = 0;
    env->cfm_rrb_pr = 0;
    ia64_rse_invalidate_non_current(env);
    ia64_invalidate_stacked_alat(env);
    helper_ia32_unsupported(env);
}





static void ia64_rse_pop_return_frame(CPUIA64State *env, uint64_t pfs)
{
    ia64_rse_return_to_frame(env, pfs & IA64_PFS_PFM_MASK,
                             (pfs & IA64_CFM_SOL_MASK) >>
                             IA64_CFM_SOL_SHIFT);
    env->ar_ec = (pfs & IA64_PFS_PEC_MASK) >> IA64_PFS_PEC_SHIFT;
}

void helper_br_ret_rse(CPUIA64State *env, uint32_t b_reg)
{
    uint64_t pfs = env->ar_pfs;
    uint64_t target = env->br[b_reg];
    uint8_t ppl = (pfs & IA64_PFS_PPL_MASK) >> IA64_PFS_PPL_SHIFT;

    /*
     * Commit the branch target (slot 0) and demoted privilege level
     * before the frame restore: mandatory RSE load faults are
     * delivered on the target instruction (SDM Vol.2 6.6).
     */
    env->ip = ia64_ip_bundle_addr(target);
    env->psr &= ~IA64_PSR_RI_MASK;
    if (ia64_psr_cpl(env->psr) < ppl) {
        ia64_set_psr(env, (env->psr & ~IA64_PSR_CPL_MASK) |
                          ((uint64_t)ppl << IA64_PSR_CPL_SHIFT));
    }
    ia64_rse_pop_return_frame(env, pfs);
}

static bool ia64_purge_tc_entries(CPUIA64State *env, IA64TlbEntry *tlb,
                                  uint16_t *count, uint64_t va, uint64_t ps,
                                  uint32_t rid, bool is_data)
{
    uint16_t i;
    bool purged = false;

    for (i = 0; i < *count; i++) {
        if (!tlb[i].is_tr && ia64_tlb_entry_overlaps(&tlb[i], va, rid, ps)) {
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

static bool ia64_mark_pending_purge_entries(IA64TlbEntry *tlb, uint16_t count,
                                            uint64_t va, uint64_t ps,
                                            uint32_t rid, bool tc_only,
                                            char kind)
{
    uint16_t i;
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

static bool ia64_mark_pending_purge_all_tc(IA64TlbEntry *tlb, uint16_t count,
                                           char kind)
{
    uint16_t i;
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
                                         IA64TlbEntry *tlb, uint16_t *count,
                                         char kind)
{
    uint16_t i;
    bool purged = false;

    for (i = 0; i < *count; i++) {
        if (tlb[i].valid && tlb[i].pending_purge) {
            qemu_log_mask(CPU_LOG_MMU,
                          "ia64 complete purge.%c slot=%u %s"
                          " va=0x%016" PRIx64 " rid=0x%06" PRIx32
                          " pa=0x%016" PRIx64 " ps=0x%016" PRIx64 "\n",
                          kind, i, tlb[i].is_tr ? "TR" : "TC",
                          tlb[i].va, tlb[i].rid, tlb[i].pa, tlb[i].ps);
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
     * An instruction translation change does not change guest code.  The
     * softmmu flush also clears the virtual-PC jump cache, and the next
     * global TB lookup resolves the new physical page before matching a TB.
     * Keep the physical-page-keyed TBs so they can be reused when a mapping
     * becomes current again.
     */
}

void helper_ssm(CPUIA64State *env, uint64_t imm)
{
    ia64_set_psr(env, env->psr | imm);
}

void helper_rsm(CPUIA64State *env, uint64_t imm)
{
    ia64_set_psr(env, env->psr & ~imm);
}

static int ia64_tlb_select_tc_slot(IA64TlbEntry *tlb, uint16_t *next_replace,
                                   uint64_t va, uint32_t rid, bool *matched)
{
    int empty = -1;
    uint16_t i;

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
        uint16_t slot = (*next_replace + i) % IA64_TLB_MAX;

        if (!tlb[slot].is_tr) {
            *next_replace = (slot + 1) % IA64_TLB_MAX;
            return slot;
        }
    }

    return -1;
}

static bool ia64_cache_replaced_tr(IA64TlbEntry *tlb, uint16_t *cnt,
                                   uint16_t *next_replace,
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
    uint16_t *cnt;
    uint64_t ps;
    uint64_t va;
    uint64_t pa;
    uint32_t key;
    uint8_t ar;
    uint8_t pl;
    uint8_t perm;
    uint32_t rid;
    uint32_t slot = slot_reg & 0xff;
    uint16_t *next_replace;
    CPUState *cs = env_cpu(env);

    if (slot >= IA64_TR_COUNT) {
        helper_raise_exception(env, IA64_EXCP_ILLEGAL,
                               ia64_ip_bundle_addr(env->ip), slot_reg,
                               (env->psr & IA64_PSR_RI_MASK) >>
                               IA64_PSR_RI_SHIFT);
        return;
    }

    ps = ia64_itir_page_size(env);
    va = env->cr_ifa & ~(ps - 1);
    pa = (pte & IA64_PTE_PPN_MASK) & ~(ps - 1);
    key = (env->cr_itir & IA64_ITIR_KEY_MASK) >> IA64_ITIR_KEY_SHIFT;
    ar = ia64_pte_ar(pte);
    pl = ia64_pte_pl(pte);
    perm = ia64_pte_perm(pte, 0);
    rid = ia64_region_rid(env, env->cr_ifa);

    if (!ia64_va_is_implemented(env->cr_ifa)) {
        ia64_raise_unimplemented_data_address(
            env, env->cr_ifa, 0, true, false, ia64_current_code_tlb_ed(env));
    }

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

    IA64TlbEntry old_tr = tlb[slot];

    ia64_purge_tc_entries(env, tlb, cnt, va, ps, rid, is_data);
    if (old_tr.valid && !old_tr.is_tr) {
        ia64_qemu_tlb_flush_entry(env, &old_tr);
    }
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
}

void helper_ptr_purge(CPUIA64State *env, uint64_t ifa, uint64_t size_reg,
                      uint32_t is_data)
{
    IA64TlbEntry *tlb;
    uint64_t ps = ia64_gr_page_size(size_reg);
    uint64_t va = ifa & ~(ps - 1);
    uint32_t rid = ia64_region_rid(env, ifa);
    uint16_t count;

    if (!ia64_va_is_implemented(ifa)) {
        ia64_raise_unimplemented_data_address(
            env, ifa, 0, true, false, ia64_current_code_tlb_ed(env));
    }

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

    if (!ia64_va_is_implemented(va)) {
        ia64_raise_unimplemented_data_address(
            env, va, 0, true, false, ia64_current_code_tlb_ed(env));
    }

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
    uint64_t pte;
    uint32_t key;
    const IA64TlbEntry *entry;

    if (env->psr & IA64_PSR_DT) {
        if (!ia64_va_is_implemented(va)) {
            excp = IA64_EXCP_UNIMPL_DATA_ADDR;
            goto tpa_fault;
        }

        entry = ia64_tlb_find(env->tlb_data, env->tlb_data_count, va, rid,
                              false);
        if (entry) {
            ia64_tlb_entry_translate(entry, va, ia64_psr_cpl(env->psr), &pa,
                                     &perm);
            excp = ia64_tlb_exception_for_access(env, entry, perm,
                                                 IA64_TLB_R, false, false,
                                                 false);
            if (excp != IA64_EXCP_NONE) {
                goto tpa_fault;
            }
            return pa;
        }
        pte = 0;
        key = 0;
        if (ia64_vhpt_walk_full(env, va, rid, false, false,
                                ia64_psr_cpl(env->psr), &pa, &perm, &pte,
                                &key)) {
            entry = ia64_tlb_find(env->tlb_data, env->tlb_data_count, va,
                                  rid, false);
            excp = entry ?
                ia64_tlb_exception_for_access(env, entry, perm, IA64_TLB_R,
                                              false, false, false) :
                ia64_translation_exception_for_access(env, pte, key, perm,
                                                      IA64_TLB_R, false,
                                                      false, false);
            if (excp != IA64_EXCP_NONE) {
                goto tpa_fault;
            }
            return pa;
        }
        if (ia64_sal_boot_identity_pa(env, va, &pa)) {
            return pa;
        }
        vhpt_enabled = ia64_vhpt_walker_enabled(env, va, false, false,
                                                &vhpt_size,
                                                &vhpt_long_format);
        if (ia64_data_nested_tlb_active(env)) {
            excp = IA64_EXCP_DATA_NESTED_TLB;
        } else if (ia64_vhpt_walk_miss_reports_data_tlb(env, vhpt_enabled)) {
            excp = IA64_EXCP_DTLB_FAULT;
        } else if (!ia64_vhpt_entry_accessible(env, va, false, false,
                                               &env->cr_iha)) {
            excp = IA64_EXCP_VHPT_FAULT;
        } else if (vhpt_enabled) {
            excp = IA64_EXCP_DTLB_FAULT;
        } else {
            excp = IA64_EXCP_ALT_DTLB;
        }
    } else if ((entry = ia64_tlb_find(env->tlb_data, env->tlb_data_count,
                                      va, rid, false)) != NULL) {
        ia64_tlb_entry_translate(entry, va, ia64_psr_cpl(env->psr), &pa,
                                 &perm);
        excp = ia64_tlb_exception_for_access(env, entry, perm, IA64_TLB_R,
                                             false, false, false);
        if (excp != IA64_EXCP_NONE) {
            goto tpa_fault;
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
        if (excp == IA64_EXCP_UNIMPL_DATA_ADDR) {
            env->cr_isr |= IA64_GENEX_UNIMPL_DATA_ADDR;
        }
    }
    cs->exception_index = excp;
    cpu_loop_exit(cs);
}

void helper_fadd(CPUIA64State *env, uint32_t r1, uint32_t r2, uint32_t r3)
{
    floatx80 result;

    if (ia64_fr_write_nat_if_any2(env, r1, r2, r3)) {
        return;
    }
    result = floatx80_add(ia64_fr_to_floatx80(env, r2),
                          ia64_fr_to_floatx80(env, r3), &env->fp_status);
    ia64_fr_write_floatx80(env, r1, result);
}

void helper_fsub(CPUIA64State *env, uint32_t r1, uint32_t r2, uint32_t r3)
{
    floatx80 result;

    if (ia64_fr_write_nat_if_any2(env, r1, r2, r3)) {
        return;
    }
    result = floatx80_sub(ia64_fr_to_floatx80(env, r2),
                          ia64_fr_to_floatx80(env, r3), &env->fp_status);
    ia64_fr_write_floatx80(env, r1, result);
}

void helper_fmpy(CPUIA64State *env, uint32_t r1, uint32_t r2, uint32_t r3)
{
    floatx80 result;

    if (ia64_fr_write_nat_if_any2(env, r1, r2, r3)) {
        return;
    }
    result = floatx80_mul(ia64_fr_to_floatx80(env, r2),
                          ia64_fr_to_floatx80(env, r3), &env->fp_status);
    ia64_fr_write_floatx80(env, r1, result);
}

static floatx80 ia64_floatx80_muladd(CPUIA64State *env, floatx80 a,
                                     floatx80 b, floatx80 c, int flags)
{
    float128 result = float128_muladd(
        floatx80_to_float128(a, &env->fp_status),
        floatx80_to_float128(b, &env->fp_status),
        floatx80_to_float128(c, &env->fp_status), flags, &env->fp_status);

    return float128_to_floatx80(result, &env->fp_status);
}

static uint64_t ia64_fr_significand(const CPUIA64State *env, uint32_t reg)
{
    bool sign;
    uint32_t exp;
    uint64_t mant;

    if (reg == 0) {
        return 0;
    }
    if (reg == 1) {
        return IA64_FP_SIGNIFICAND_INTEGER_BIT;
    }
    return ia64_fr_ext_get(env, reg, &sign, &exp, &mant) ?
           mant : env->fr[reg];
}

void helper_fma(CPUIA64State *env, uint32_t r1, uint32_t r2, uint32_t r3)
{
    floatx80 zero = make_floatx80(0, 0);

    if (ia64_fr_write_nat_if_any2(env, r1, r2, r3)) {
        return;
    }
    ia64_fr_write_floatx80(
        env, r1, ia64_floatx80_muladd(
            env, ia64_fr_to_floatx80(env, r2),
            ia64_fr_to_floatx80(env, r3), zero, 0));
}

void helper_fma4(CPUIA64State *env, uint32_t r1, uint32_t r2,
                 uint32_t r3, uint32_t r4)
{
    if (ia64_fr_write_nat_if_any3(env, r1, r2, r3, r4)) {
        return;
    }
    ia64_fr_write_floatx80(
        env, r1, ia64_floatx80_muladd(
            env, ia64_fr_to_floatx80(env, r3),
            ia64_fr_to_floatx80(env, r4),
            ia64_fr_to_floatx80(env, r2), 0));
}

void helper_xma(CPUIA64State *env, uint32_t r1, uint32_t r2,
                uint32_t r3, uint32_t r4, uint32_t mode)
{
    uint64_t a;
    uint64_t b;
    uint64_t addend;
    __uint128_t result;

    if (ia64_fr_write_nat_if_any3(env, r1, r2, r3, r4)) {
        return;
    }
    a = ia64_fr_significand(env, r3);
    b = ia64_fr_significand(env, r4);
    addend = ia64_fr_significand(env, r2);

    if (mode == 1) {
        result = (__int128)(int64_t)a * (__int128)(int64_t)b + addend;
        ia64_fr_write_sig(env, r1, result >> 64);
    } else {
        result = (__uint128_t)a * b;
        if (mode != 3) {
            result += addend;
        }
        ia64_fr_write_sig(env, r1, mode == 0 ?
                          (uint64_t)result : result >> 64);
    }
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

    rel = floatx80_compare(ia64_fr_to_floatx80(env, r2),
                           ia64_fr_to_floatx80(env, r3), &env->fp_status);

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
    floatx80 left;
    floatx80 right;
    FloatRelation rel;
    bool take_left;

    if (ia64_fr_write_nat_if_any2(env, r1, r2, r3)) {
        return;
    }

    left = ia64_fr_to_floatx80(env, r2);
    right = ia64_fr_to_floatx80(env, r3);
    rel = floatx80_compare(is_abs ? floatx80_abs(left) : left,
                           is_abs ? floatx80_abs(right) : right,
                           &env->fp_status);
    take_left = is_max ? rel == float_relation_greater :
                         rel == float_relation_less;
    ia64_fr_copy(env, r1, take_left ? r2 : r3, 1);
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

static bool ia64_floatx80_rcpa_predicate(floatx80 num, floatx80 den,
                                          float_status *status)
{
    return !floatx80_is_zero(num) &&
           !floatx80_is_infinity(num, status) &&
           !floatx80_is_any_nan(num) &&
           !floatx80_is_zero(den) &&
           !floatx80_is_infinity(den, status) &&
           !floatx80_is_any_nan(den);
}

typedef struct IA64FPRegisterFormat {
    bool sign;
    uint32_t exp;
    uint64_t mant;
} IA64FPRegisterFormat;

static void ia64_normalize_fp_register_format(IA64FPRegisterFormat *fmt)
{
    int shift;

    if (fmt->exp == 0 ||
        fmt->exp == IA64_FP_REG_SPECIAL_EXP ||
        fmt->mant == 0) {
        return;
    }

    shift = clz64(fmt->mant);
    fmt->mant <<= shift;
    fmt->exp = fmt->exp > (uint32_t)shift ? fmt->exp - shift : 0;
}

static IA64FPRegisterFormat ia64_fr_register_format(CPUIA64State *env,
                                                     uint32_t reg)
{
    uint64_t low;
    uint64_t high;
    IA64FPRegisterFormat fmt;

    ia64_fr_spill_words(env, reg, &low, &high);
    fmt.sign = (high >> 17) & 1;
    fmt.exp = (high & 0xffff) | (((high >> 16) & 1) << 16);
    fmt.mant = low;
    ia64_normalize_fp_register_format(&fmt);
    return fmt;
}

static bool ia64_fp_register_format_is_normal(
    const IA64FPRegisterFormat *fmt)
{
    return fmt->exp != 0 &&
           fmt->exp != IA64_FP_REG_SPECIAL_EXP &&
           fmt->mant != 0 &&
           (fmt->mant & IA64_FP_SIGNIFICAND_INTEGER_BIT);
}

static bool ia64_fp_register_format_is_zero(
    const IA64FPRegisterFormat *fmt)
{
    return fmt->mant == 0 && fmt->exp != IA64_FP_REG_SPECIAL_EXP;
}

static bool ia64_fp_register_format_is_infinity(
    const IA64FPRegisterFormat *fmt)
{
    return fmt->exp == IA64_FP_REG_SPECIAL_EXP &&
           fmt->mant == IA64_FP_SIGNIFICAND_INTEGER_BIT;
}

static bool ia64_fp_register_format_is_nan(
    const IA64FPRegisterFormat *fmt)
{
    return fmt->exp == IA64_FP_REG_SPECIAL_EXP &&
           fmt->mant != IA64_FP_SIGNIFICAND_INTEGER_BIT;
}

static bool ia64_frcpa_limits_swa_fault(
    const IA64FPRegisterFormat *num,
    const IA64FPRegisterFormat *den)
{
    int32_t est_exp;

    if (ia64_fp_register_format_is_nan(num) ||
        ia64_fp_register_format_is_nan(den) ||
        ia64_fp_register_format_is_infinity(num) ||
        ia64_fp_register_format_is_zero(num) ||
        ia64_fp_register_format_is_infinity(den) ||
        ia64_fp_register_format_is_zero(den)) {
        return false;
    }

    est_exp = (int32_t)num->exp - (int32_t)den->exp;
    return den->exp == 0 ||
           den->exp >= 2 * IA64_FP_WRE_BIAS - 2 ||
           est_exp <= 2 - (int32_t)IA64_FP_WRE_BIAS ||
           est_exp >= (int32_t)IA64_FP_WRE_BIAS ||
           num->exp <= 64;
}

static bool ia64_frsqrta_limits_swa_fault(
    const IA64FPRegisterFormat *val)
{
    if (val->sign ||
        ia64_fp_register_format_is_nan(val) ||
        ia64_fp_register_format_is_infinity(val) ||
        ia64_fp_register_format_is_zero(val)) {
        return false;
    }

    return val->exp <= 64;
}

static uint32_t ia64_recip_table_index(uint64_t mant)
{
    return (mant >> 55) & 0xff;
}

static uint32_t ia64_recip_sqrt_table_index(
    const IA64FPRegisterFormat *fmt)
{
    return ((fmt->exp & 1) << 7) | ((fmt->mant >> 56) & 0x7f);
}

static uint32_t ia64_fp_register_recip_exp(uint32_t exp)
{
    int32_t result = (int32_t)(2 * IA64_FP_WRE_BIAS - 1) - (int32_t)exp;

    return result > 0 ? (uint32_t)result : 0;
}

static uint32_t ia64_fp_register_rsqrt_exp(uint32_t exp)
{
    int32_t unbiased = (int32_t)exp - IA64_FP_WRE_BIAS;
    int32_t result = (IA64_FP_WRE_BIAS - 1) - (unbiased >> 1);

    return (uint32_t)result & IA64_FP_WRE_EXP_MASK;
}

static const uint16_t ia64_recip_table[256] = {
    0x7fc, 0x7f4, 0x7ec, 0x7e4, 0x7dd, 0x7d5, 0x7cd, 0x7c6,
    0x7be, 0x7b7, 0x7af, 0x7a8, 0x7a1, 0x799, 0x792, 0x78b,
    0x784, 0x77d, 0x776, 0x76f, 0x768, 0x761, 0x75b, 0x754,
    0x74d, 0x746, 0x740, 0x739, 0x733, 0x72c, 0x726, 0x720,
    0x719, 0x713, 0x70d, 0x707, 0x700, 0x6fa, 0x6f4, 0x6ee,
    0x6e8, 0x6e2, 0x6dc, 0x6d7, 0x6d1, 0x6cb, 0x6c5, 0x6bf,
    0x6ba, 0x6b4, 0x6af, 0x6a9, 0x6a3, 0x69e, 0x699, 0x693,
    0x68e, 0x688, 0x683, 0x67e, 0x679, 0x673, 0x66e, 0x669,
    0x664, 0x65f, 0x65a, 0x655, 0x650, 0x64b, 0x646, 0x641,
    0x63c, 0x637, 0x632, 0x62e, 0x629, 0x624, 0x61f, 0x61b,
    0x616, 0x611, 0x60d, 0x608, 0x604, 0x5ff, 0x5fb, 0x5f6,
    0x5f2, 0x5ed, 0x5e9, 0x5e5, 0x5e0, 0x5dc, 0x5d8, 0x5d4,
    0x5cf, 0x5cb, 0x5c7, 0x5c3, 0x5bf, 0x5bb, 0x5b6, 0x5b2,
    0x5ae, 0x5aa, 0x5a6, 0x5a2, 0x59e, 0x59a, 0x597, 0x593,
    0x58f, 0x58b, 0x587, 0x583, 0x57f, 0x57c, 0x578, 0x574,
    0x571, 0x56d, 0x569, 0x566, 0x562, 0x55e, 0x55b, 0x557,
    0x554, 0x550, 0x54d, 0x549, 0x546, 0x542, 0x53f, 0x53b,
    0x538, 0x534, 0x531, 0x52e, 0x52a, 0x527, 0x524, 0x520,
    0x51d, 0x51a, 0x517, 0x513, 0x510, 0x50d, 0x50a, 0x507,
    0x503, 0x500, 0x4fd, 0x4fa, 0x4f7, 0x4f4, 0x4f1, 0x4ee,
    0x4eb, 0x4e8, 0x4e5, 0x4e2, 0x4df, 0x4dc, 0x4d9, 0x4d6,
    0x4d3, 0x4d0, 0x4cd, 0x4ca, 0x4c8, 0x4c5, 0x4c2, 0x4bf,
    0x4bc, 0x4b9, 0x4b7, 0x4b4, 0x4b1, 0x4ae, 0x4ac, 0x4a9,
    0x4a6, 0x4a4, 0x4a1, 0x49e, 0x49c, 0x499, 0x496, 0x494,
    0x491, 0x48e, 0x48c, 0x489, 0x487, 0x484, 0x482, 0x47f,
    0x47c, 0x47a, 0x477, 0x475, 0x473, 0x470, 0x46e, 0x46b,
    0x469, 0x466, 0x464, 0x461, 0x45f, 0x45d, 0x45a, 0x458,
    0x456, 0x453, 0x451, 0x44f, 0x44c, 0x44a, 0x448, 0x445,
    0x443, 0x441, 0x43f, 0x43c, 0x43a, 0x438, 0x436, 0x433,
    0x431, 0x42f, 0x42d, 0x42b, 0x429, 0x426, 0x424, 0x422,
    0x420, 0x41e, 0x41c, 0x41a, 0x418, 0x415, 0x413, 0x411,
    0x40f, 0x40d, 0x40b, 0x409, 0x407, 0x405, 0x403, 0x401,
};

static const uint16_t ia64_recip_sqrt_table[256] = {
    0x5a5, 0x5a0, 0x59a, 0x595, 0x58f, 0x58a, 0x585, 0x580,
    0x57a, 0x575, 0x570, 0x56b, 0x566, 0x561, 0x55d, 0x558,
    0x553, 0x54e, 0x54a, 0x545, 0x540, 0x53c, 0x538, 0x533,
    0x52f, 0x52a, 0x526, 0x522, 0x51e, 0x51a, 0x515, 0x511,
    0x50d, 0x509, 0x505, 0x501, 0x4fd, 0x4fa, 0x4f6, 0x4f2,
    0x4ee, 0x4ea, 0x4e7, 0x4e3, 0x4df, 0x4dc, 0x4d8, 0x4d5,
    0x4d1, 0x4ce, 0x4ca, 0x4c7, 0x4c3, 0x4c0, 0x4bd, 0x4b9,
    0x4b6, 0x4b3, 0x4b0, 0x4ad, 0x4a9, 0x4a6, 0x4a3, 0x4a0,
    0x49d, 0x49a, 0x497, 0x494, 0x491, 0x48e, 0x48b, 0x488,
    0x485, 0x482, 0x47f, 0x47d, 0x47a, 0x477, 0x474, 0x471,
    0x46f, 0x46c, 0x469, 0x467, 0x464, 0x461, 0x45f, 0x45c,
    0x45a, 0x457, 0x454, 0x452, 0x44f, 0x44d, 0x44a, 0x448,
    0x445, 0x443, 0x441, 0x43e, 0x43c, 0x43a, 0x437, 0x435,
    0x433, 0x430, 0x42e, 0x42c, 0x429, 0x427, 0x425, 0x423,
    0x420, 0x41e, 0x41c, 0x41a, 0x418, 0x416, 0x414, 0x411,
    0x40f, 0x40d, 0x40b, 0x409, 0x407, 0x405, 0x403, 0x401,
    0x7fc, 0x7f4, 0x7ec, 0x7e5, 0x7dd, 0x7d5, 0x7ce, 0x7c7,
    0x7bf, 0x7b8, 0x7b1, 0x7aa, 0x7a3, 0x79c, 0x795, 0x78e,
    0x788, 0x781, 0x77a, 0x774, 0x76d, 0x767, 0x761, 0x75a,
    0x754, 0x74e, 0x748, 0x742, 0x73c, 0x736, 0x730, 0x72b,
    0x725, 0x71f, 0x71a, 0x714, 0x70f, 0x709, 0x704, 0x6fe,
    0x6f9, 0x6f4, 0x6ee, 0x6e9, 0x6e4, 0x6df, 0x6da, 0x6d5,
    0x6d0, 0x6cb, 0x6c6, 0x6c1, 0x6bd, 0x6b8, 0x6b3, 0x6ae,
    0x6aa, 0x6a5, 0x6a1, 0x69c, 0x698, 0x693, 0x68f, 0x68a,
    0x686, 0x682, 0x67d, 0x679, 0x675, 0x671, 0x66d, 0x668,
    0x664, 0x660, 0x65c, 0x658, 0x654, 0x650, 0x64c, 0x649,
    0x645, 0x641, 0x63d, 0x639, 0x635, 0x632, 0x62e, 0x62a,
    0x627, 0x623, 0x620, 0x61c, 0x618, 0x615, 0x611, 0x60e,
    0x60a, 0x607, 0x604, 0x600, 0x5fd, 0x5f9, 0x5f6, 0x5f3,
    0x5f0, 0x5ec, 0x5e9, 0x5e6, 0x5e3, 0x5df, 0x5dc, 0x5d9,
    0x5d6, 0x5d3, 0x5d0, 0x5cd, 0x5ca, 0x5c7, 0x5c4, 0x5c1,
    0x5be, 0x5bb, 0x5b8, 0x5b5, 0x5b2, 0x5af, 0x5ac, 0x5aa,
};

static floatx80 ia64_floatx80_rcpa_approx(CPUIA64State *env,
                                           uint32_t den_reg)
{
    IA64FPRegisterFormat den = ia64_fr_register_format(env, den_reg);

    return ia64_register_format_to_floatx80(
        env, den.sign, ia64_fp_register_recip_exp(den.exp),
        (uint64_t)ia64_recip_table[ia64_recip_table_index(den.mant)] << 53);
}

static floatx80 ia64_floatx80_rsqrta_approx(CPUIA64State *env,
                                            uint32_t reg)
{
    IA64FPRegisterFormat val = ia64_fr_register_format(env, reg);

    return ia64_register_format_to_floatx80(
        env, false, ia64_fp_register_rsqrt_exp(val.exp),
        (uint64_t)ia64_recip_sqrt_table[
            ia64_recip_sqrt_table_index(&val)] << 53);
}

static floatx80 ia64_floatx80_rcpa(floatx80 num, floatx80 den,
                                    bool approximate, float_status *status)
{
    floatx80 one = make_floatx80(
        0x3fff, IA64_FP_SIGNIFICAND_INTEGER_BIT);

    return floatx80_div(approximate ? one : num, den, status);
}

void helper_frcpa(CPUIA64State *env, uint32_t r1, uint32_t p2,
                  uint32_t r2, uint32_t r3)
{
    floatx80 num;
    floatx80 den;
    bool predicate;
    IA64FPRegisterFormat num_fmt;
    IA64FPRegisterFormat den_fmt;
    bool approximate;

    if (ia64_fr_nat_get(env, r2) || ia64_fr_nat_get(env, r3)) {
        ia64_fr_write_nat(env, r1);
        ia64_pr_write(env, p2, false);
        return;
    }

    num_fmt = ia64_fr_register_format(env, r2);
    den_fmt = ia64_fr_register_format(env, r3);
    if (ia64_frcpa_limits_swa_fault(&num_fmt, &den_fmt)) {
        ia64_raise_fp_fault(env, IA64_FP_ISR_SWA);
    }

    num = ia64_fr_to_floatx80(env, r2);
    den = ia64_fr_to_floatx80(env, r3);
    predicate = ia64_floatx80_rcpa_predicate(
        num, den, &env->fp_status);
    approximate = predicate &&
                  ia64_fp_register_format_is_normal(&den_fmt);
    ia64_fr_write_floatx80(
        env, r1, approximate ? ia64_floatx80_rcpa_approx(env, r3) :
        ia64_floatx80_rcpa(num, den, predicate, &env->fp_status));
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

static bool ia64_float32_register_format(float32 val,
                                         IA64FPRegisterFormat *fmt)
{
    uint32_t bits = float32_val(val);
    uint32_t exp = (bits >> 23) & 0xff;
    uint32_t frac = bits & 0x7fffff;

    if (exp == 0 || exp == 0xff) {
        return false;
    }

    fmt->sign = bits >> 31;
    fmt->exp = exp + IA64_FP_WRE_BIAS - IA64_FP_SINGLE_BIAS;
    fmt->mant = IA64_FP_SIGNIFICAND_INTEGER_BIT | ((uint64_t)frac << 40);
    return true;
}

static float32 ia64_float32_from_register_format(CPUIA64State *env,
                                                 const IA64FPRegisterFormat *fmt)
{
    float_status status = env->fp_status;

    return floatx80_to_float32(
        ia64_register_format_to_floatx80(env, fmt->sign, fmt->exp,
                                         fmt->mant),
        &status);
}

static float32 ia64_float32_rcpa_approx(CPUIA64State *env,
                                        const IA64FPRegisterFormat *den)
{
    IA64FPRegisterFormat result = {
        .sign = den->sign,
        .exp = ia64_fp_register_recip_exp(den->exp),
        .mant = (uint64_t)ia64_recip_table[
            ia64_recip_table_index(den->mant)] << 53,
    };

    return ia64_float32_from_register_format(env, &result);
}

static bool ia64_float32_fprcpa_predicate(const IA64FPRegisterFormat *num,
                                          const IA64FPRegisterFormat *den)
{
    int32_t est_exp = (int32_t)num->exp - (int32_t)den->exp;

    return est_exp < IA64_FP_SINGLE_BIAS &&
           est_exp > 2 - IA64_FP_SINGLE_BIAS &&
           num->exp > IA64_FP_WRE_BIAS - IA64_FP_SINGLE_BIAS +
                      IA64_FP_SINGLE_MANT_WIDTH;
}

void helper_fprcpa(CPUIA64State *env, uint32_t r1, uint32_t p2,
                   uint32_t r2, uint32_t r3, uint32_t sf)
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
    int hi_soft;
    int lo_soft;

    if (ia64_fr_nat_get(env, r2) || ia64_fr_nat_get(env, r3)) {
        ia64_fr_write_nat(env, r1);
        ia64_pr_write(env, p2, false);
        return;
    }

    {
        IA64FPRegisterFormat num_hi_fmt = { 0 };
        IA64FPRegisterFormat num_lo_fmt = { 0 };
        IA64FPRegisterFormat den_hi_fmt = { 0 };
        IA64FPRegisterFormat den_lo_fmt = { 0 };
        bool hi_normal = ia64_float32_register_format(num_hi, &num_hi_fmt) &&
                         ia64_float32_register_format(den_hi, &den_hi_fmt);
        bool lo_normal = ia64_float32_register_format(num_lo, &num_lo_fmt) &&
                         ia64_float32_register_format(den_lo, &den_lo_fmt);
        float_status hi_status = env->fp_status;
        float_status lo_status = env->fp_status;

        hi_pred = ia64_float32_rcpa_predicate(num_hi, den_hi);
        lo_pred = ia64_float32_rcpa_predicate(num_lo, den_lo);
        hi_result = hi_pred && hi_normal ?
                    ia64_float32_rcpa_approx(env, &den_hi_fmt) :
                    ia64_float32_rcpa(num_hi, den_hi, hi_pred,
                                      &hi_status);
        lo_result = lo_pred && lo_normal ?
                    ia64_float32_rcpa_approx(env, &den_lo_fmt) :
                    ia64_float32_rcpa(num_lo, den_lo, lo_pred,
                                      &lo_status);
        hi_soft = get_float_exception_flags(&hi_status);
        lo_soft = get_float_exception_flags(&lo_status);
        hi_pred = hi_pred && hi_normal &&
                  ia64_float32_fprcpa_predicate(&num_hi_fmt, &den_hi_fmt);
        lo_pred = lo_pred && lo_normal &&
                  ia64_float32_fprcpa_predicate(&num_lo_fmt, &den_lo_fmt);
    }

    {
        uint64_t traps = ia64_fp_active_traps(env, sf);
        uint64_t hi_fault = ia64_fp_soft_flags_to_ia64(hi_soft) & ~traps & 0x7;
        uint64_t lo_fault = ia64_fp_soft_flags_to_ia64(lo_soft) & ~traps & 0x7;

        set_float_exception_flags(hi_soft | lo_soft, &env->fp_status);
        if (hi_fault || lo_fault) {
            ia64_raise_fp_fault(env, lo_fault | (hi_fault << 4));
        }
    }

    ia64_fr_write_sig(env, r1,
                      ((uint64_t)float32_val(hi_result) << 32) |
                      float32_val(lo_result));
    ia64_pr_write(env, p2, hi_pred && lo_pred);
}

/* ---- FP classify ---- */

void helper_fclass(CPUIA64State *env, uint32_t p1, uint32_t p2,
                   uint32_t f2, uint32_t fclass9)
{
    uint64_t mant;
    uint64_t high;
    uint32_t exp;
    bool is_neg;
    bool is_nat = ia64_fr_nat_get(env, f2);
    bool is_zero;
    bool is_unorm;
    bool is_inf;
    bool is_qnan;
    bool is_snan;
    bool is_normal;
    bool sign_match;
    bool type_match;
    bool member;

    ia64_fr_spill_words(env, f2, &mant, &high);
    exp = (high & 0xffff) | (((high >> 16) & 1) << 16);
    is_neg = (high >> 17) & 1;
    is_zero = !is_nat && mant == 0 && exp != IA64_FP_REG_SPECIAL_EXP;
    is_inf = !is_nat && exp == IA64_FP_REG_SPECIAL_EXP &&
             mant == IA64_FP_SIGNIFICAND_INTEGER_BIT;
    is_qnan = !is_nat && exp == IA64_FP_REG_SPECIAL_EXP &&
              mant >= 0xc000000000000000ULL;
    is_snan = !is_nat && exp == IA64_FP_REG_SPECIAL_EXP &&
              mant > IA64_FP_SIGNIFICAND_INTEGER_BIT &&
              mant < 0xc000000000000000ULL;
    is_unorm = !is_nat && !is_zero &&
                exp != IA64_FP_REG_SPECIAL_EXP &&
                (!(mant & IA64_FP_SIGNIFICAND_INTEGER_BIT) || exp == 0);
    is_normal = !is_nat && !is_zero && !is_unorm && !is_inf &&
                !is_qnan && !is_snan;
    sign_match = ((fclass9 & 0x001) && !is_neg) ||
                 ((fclass9 & 0x002) && is_neg);
    type_match = ((fclass9 & 0x004) && is_zero) ||
                 ((fclass9 & 0x008) && is_unorm) ||
                 ((fclass9 & 0x010) && is_normal) ||
                 ((fclass9 & 0x020) && is_inf);
    member = (sign_match && type_match) ||
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
    uint64_t low2;
    uint64_t high2;
    uint64_t low3;
    uint64_t high3;

    if (ia64_fr_nat_get(env, r2) || ia64_fr_nat_get(env, r3)) {
        ia64_fr_write_nat(env, r1);
        return;
    }

    ia64_fr_spill_words(env, r2, &low2, &high2);
    ia64_fr_spill_words(env, r3, &low3, &high3);
    ia64_fr_fill_spill_words(env, r1, low3,
                             (high3 & ~(1ULL << 17)) |
                             ((~high2) & (1ULL << 17)));
}

void helper_fmerge_s(CPUIA64State *env, uint32_t r1, uint32_t r2, uint32_t r3)
{
    uint64_t low2;
    uint64_t high2;
    uint64_t low3;
    uint64_t high3;

    if (ia64_fr_nat_get(env, r2) || ia64_fr_nat_get(env, r3)) {
        ia64_fr_write_nat(env, r1);
        return;
    }

    ia64_fr_spill_words(env, r2, &low2, &high2);
    ia64_fr_spill_words(env, r3, &low3, &high3);
    ia64_fr_fill_spill_words(env, r1, low3,
                             (high3 & ~(1ULL << 17)) |
                             (high2 & (1ULL << 17)));
}

void helper_fmerge_se(CPUIA64State *env, uint32_t r1, uint32_t r2, uint32_t r3)
{
    uint64_t low2;
    uint64_t high2;
    uint64_t low3;
    uint64_t high3;

    if (ia64_fr_nat_get(env, r2) || ia64_fr_nat_get(env, r3)) {
        ia64_fr_write_nat(env, r1);
        return;
    }

    ia64_fr_spill_words(env, r2, &low2, &high2);
    ia64_fr_spill_words(env, r3, &low3, &high3);
    ia64_fr_fill_spill_words(env, r1, low3, high2);
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

    ia64_fr_write_sig(env, r1, ((uint64_t)hi << 32) | lo);
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

    ia64_fr_write_sig(env, r1, ((uint64_t)hi << 32) | lo);
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

    ia64_fr_write_sig(env, r1, ((uint64_t)hi << 32) | lo);
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

    ia64_fr_write_sig(env, r1, ia64_pack_fp32_lanes(hi, lo));
}

static uint32_t ia64_fpminmax_lane(uint32_t a_bits, uint32_t b_bits,
                                   bool is_max, bool is_abs,
                                   float_status *status)
{
    float32 a = make_float32(a_bits);
    float32 b = make_float32(b_bits);
    float32 cmp_a = is_abs ? float32_abs(a) : a;
    float32 cmp_b = is_abs ? float32_abs(b) : b;
    FloatRelation rel;

    if (float32_is_any_nan(a) || float32_is_any_nan(b)) {
        float_raise(float_flag_invalid, status);
        return b_bits;
    }

    rel = float32_compare(cmp_a, cmp_b, status);
    if (is_max) {
        return rel == float_relation_greater ? a_bits : b_bits;
    }
    return rel == float_relation_less ? a_bits : b_bits;
}

void helper_fpminmax(CPUIA64State *env, uint32_t r1, uint32_t r2,
                     uint32_t r3, uint32_t is_max, uint32_t is_abs,
                     uint32_t sf)
{
    float_status hi_status = env->fp_status;
    float_status lo_status = env->fp_status;
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
    hi = ia64_fpminmax_lane(f2_hi, f3_hi, is_max != 0, is_abs != 0,
                            &hi_status);
    lo = ia64_fpminmax_lane(f2_lo, f3_lo, is_max != 0, is_abs != 0,
                            &lo_status);
    ia64_fp_simd_fault_end(env, sf, get_float_exception_flags(&hi_status),
                           get_float_exception_flags(&lo_status));

    ia64_fr_write_sig(env, r1, ia64_pack_fp32_lanes(hi, lo));
}

static bool ia64_fpcmp_lane(uint32_t a_bits, uint32_t b_bits, uint32_t frel,
                            float_status *status)
{
    FloatRelation rel = float32_compare(make_float32(a_bits),
                                        make_float32(b_bits),
                                        status);

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
                  uint32_t r3, uint32_t frel, uint32_t sf)
{
    float_status hi_status = env->fp_status;
    float_status lo_status = env->fp_status;
    uint32_t hi;
    uint32_t lo;

    if (ia64_fr_write_nat_if_any2(env, r1, r2, r3)) {
        return;
    }

    hi = ia64_fpcmp_lane(env->fr[r2] >> 32, env->fr[r3] >> 32,
                         frel, &hi_status) ? UINT32_MAX : 0;
    lo = ia64_fpcmp_lane(env->fr[r2], env->fr[r3], frel, &lo_status) ?
         UINT32_MAX : 0;
    ia64_fp_simd_fault_end(env, sf, get_float_exception_flags(&hi_status),
                           get_float_exception_flags(&lo_status));

    ia64_fr_write_sig(env, r1, ia64_pack_fp32_lanes(hi, lo));
}

static uint32_t ia64_fpcvt_lane(uint32_t value, bool is_unsigned,
                                bool is_trunc, float_status *status)
{
    float32 f = make_float32(value);

    if (is_unsigned) {
        return is_trunc ?
            float32_to_uint32_round_to_zero(f, status) :
            float32_to_uint32(f, status);
    }
    return is_trunc ?
        (uint32_t)float32_to_int32_round_to_zero(f, status) :
        (uint32_t)float32_to_int32(f, status);
}

void helper_fpcvt(CPUIA64State *env, uint32_t r1, uint32_t r2,
                  uint32_t is_unsigned, uint32_t is_trunc, uint32_t sf)
{
    float_status hi_status = env->fp_status;
    float_status lo_status = env->fp_status;
    uint32_t hi;
    uint32_t lo;
    int hi_soft;
    int lo_soft;

    if (ia64_fr_nat_get(env, r2)) {
        ia64_fr_write_nat(env, r1);
        return;
    }

    hi = ia64_fpcvt_lane(env->fr[r2] >> 32, is_unsigned != 0,
                         is_trunc != 0, &hi_status);
    lo = ia64_fpcvt_lane(env->fr[r2], is_unsigned != 0,
                         is_trunc != 0, &lo_status);
    hi_soft = get_float_exception_flags(&hi_status);
    lo_soft = get_float_exception_flags(&lo_status);

    {
        uint64_t traps = ia64_fp_active_traps(env, sf);
        uint64_t hi_fault = ia64_fp_soft_flags_to_ia64(hi_soft) & ~traps & 0x7;
        uint64_t lo_fault = ia64_fp_soft_flags_to_ia64(lo_soft) & ~traps & 0x7;

        set_float_exception_flags(hi_soft | lo_soft, &env->fp_status);
        if (hi_fault || lo_fault) {
            ia64_raise_fp_fault(env, lo_fault | (hi_fault << 4));
        }
    }

    ia64_fr_write_sig(env, r1, ia64_pack_fp32_lanes(hi, lo));
}

static uint32_t ia64_fpma_lane(uint32_t addend_bits, uint32_t multiplicand_bits,
                               uint32_t multiplier_bits, uint32_t form,
                               float_status *status)
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
                                      0, status));
}

void helper_fpma(CPUIA64State *env, uint32_t r1, uint32_t r2,
                 uint32_t r3, uint32_t r4, uint32_t form, uint32_t sf)
{
    float_status hi_status = env->fp_status;
    float_status lo_status = env->fp_status;
    uint32_t hi;
    uint32_t lo;

    if (ia64_fr_write_nat_if_any3(env, r1, r2, r3, r4)) {
        return;
    }

    hi = ia64_fpma_lane(env->fr[r2] >> 32, env->fr[r3] >> 32,
                        env->fr[r4] >> 32, form, &hi_status);
    lo = ia64_fpma_lane(env->fr[r2], env->fr[r3], env->fr[r4], form,
                        &lo_status);
    ia64_fp_simd_fault_end(env, sf, get_float_exception_flags(&hi_status),
                           get_float_exception_flags(&lo_status));

    ia64_fr_write_sig(env, r1, ia64_pack_fp32_lanes(hi, lo));
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

static uint64_t ia64_fp_active_traps(CPUIA64State *env, uint32_t sf)
{
    uint64_t controls = ia64_fpsr_sf_controls(env, sf);

    return (controls & IA64_FPSR_SF_TD) ?
           IA64_FPSR_TRAPS_MASK :
           (env->ar_fpsr & IA64_FPSR_TRAPS_MASK);
}

static uint64_t ia64_fp_soft_flags_to_ia64(int soft)
{
    uint64_t flags = 0;

    if (soft & float_flag_invalid) {
        flags |= 1U << 0;
    }
    if (soft & (float_flag_input_denormal_flushed |
                float_flag_input_denormal_used)) {
        flags |= 1U << 1;
    }
    if (soft & float_flag_divbyzero) {
        flags |= 1U << 2;
    }
    if (soft & float_flag_overflow) {
        flags |= 1U << 3;
    }
    if (soft & (float_flag_underflow |
                float_flag_output_denormal_flushed)) {
        flags |= 1U << 4;
    }
    if (soft & float_flag_inexact) {
        flags |= 1U << 5;
    }

    return flags;
}

static void ia64_fp_simd_fault_end(CPUIA64State *env, uint32_t sf,
                                   int hi_soft, int lo_soft)
{
    uint64_t traps = ia64_fp_active_traps(env, sf);
    uint64_t hi_fault = ia64_fp_soft_flags_to_ia64(hi_soft) & ~traps & 0x7;
    uint64_t lo_fault = ia64_fp_soft_flags_to_ia64(lo_soft) & ~traps & 0x7;

    set_float_exception_flags(hi_soft | lo_soft, &env->fp_status);
    if (hi_fault || lo_fault) {
        ia64_raise_fp_fault(env, lo_fault | (hi_fault << 4));
    }
}

static void ia64_fp_restore_state(CPUIA64State *env)
{
    memcpy(env->fr, env->fp_backup_fr, sizeof(env->fr));
    memcpy(env->fr_nat, env->fp_backup_fr_nat, sizeof(env->fr_nat));
    memcpy(env->fr_sig, env->fp_backup_fr_sig, sizeof(env->fr_sig));
    memcpy(env->fr_ext_mant, env->fp_backup_fr_ext_mant,
           sizeof(env->fr_ext_mant));
    memcpy(env->fr_ext_exp, env->fp_backup_fr_ext_exp,
           sizeof(env->fr_ext_exp));
    memcpy(env->fr_ext_sign, env->fp_backup_fr_ext_sign,
           sizeof(env->fr_ext_sign));
    memcpy(env->fr_ext_valid, env->fp_backup_fr_ext_valid,
           sizeof(env->fr_ext_valid));
    memcpy(env->fr_int_value, env->fp_backup_fr_int_value,
           sizeof(env->fr_int_value));
    memcpy(env->fr_int_origin, env->fp_backup_fr_int_origin,
           sizeof(env->fr_int_origin));
    memcpy(env->pr, env->fp_backup_pr, sizeof(env->pr));
}

static void ia64_raise_fp_fault(CPUIA64State *env, uint64_t isr)
{
    uint32_t slot = (env->psr & IA64_PSR_RI_MASK) >>
                    IA64_PSR_RI_SHIFT;

    ia64_fp_restore_state(env);
    env->cr_isr = isr;
    helper_raise_exception(env, IA64_EXCP_FP_FAULT, env->ip, 0, slot);
}

void helper_fp_begin(CPUIA64State *env, uint32_t sf, uint32_t precision)
{
    static const FloatRoundMode rounding[4] = {
        float_round_nearest_even,
        float_round_down,
        float_round_up,
        float_round_to_zero,
    };
    uint64_t controls = ia64_fpsr_sf_controls(env, sf);
    uint32_t pc = (controls >> 2) & 3;
    FloatX80RoundPrec round_precision;

    memcpy(env->fp_backup_fr, env->fr, sizeof(env->fr));
    memcpy(env->fp_backup_fr_nat, env->fr_nat, sizeof(env->fr_nat));
    memcpy(env->fp_backup_fr_sig, env->fr_sig, sizeof(env->fr_sig));
    memcpy(env->fp_backup_fr_ext_mant, env->fr_ext_mant,
           sizeof(env->fr_ext_mant));
    memcpy(env->fp_backup_fr_ext_exp, env->fr_ext_exp,
           sizeof(env->fr_ext_exp));
    memcpy(env->fp_backup_fr_ext_sign, env->fr_ext_sign,
           sizeof(env->fr_ext_sign));
    memcpy(env->fp_backup_fr_ext_valid, env->fr_ext_valid,
           sizeof(env->fr_ext_valid));
    memcpy(env->fp_backup_fr_int_value, env->fr_int_value,
           sizeof(env->fr_int_value));
    memcpy(env->fp_backup_fr_int_origin, env->fr_int_origin,
           sizeof(env->fr_int_origin));
    memcpy(env->fp_backup_pr, env->pr, sizeof(env->pr));

    set_float_rounding_mode(rounding[(controls >> 4) & 3],
                            &env->fp_status);
    if (precision == 1 || (precision == 0 && pc == 0)) {
        round_precision = floatx80_precision_s;
    } else if (precision == 2 || (precision == 0 && pc == 2)) {
        round_precision = floatx80_precision_d;
    } else {
        round_precision = floatx80_precision_x;
    }
    set_floatx80_rounding_precision(round_precision, &env->fp_status);
    set_flush_to_zero(controls & 1, &env->fp_status);
    set_flush_inputs_to_zero(false, &env->fp_status);
    set_float_exception_flags(0, &env->fp_status);
}

void helper_fp_end(CPUIA64State *env, uint32_t sf)
{
    int soft = get_float_exception_flags(&env->fp_status);
    uint64_t flags = ia64_fp_soft_flags_to_ia64(soft);
    uint64_t traps = ia64_fp_active_traps(env, sf);
    uint64_t enabled;
    uint32_t shift;

    enabled = flags & ~traps;
    if (enabled & 0x7) {
        ia64_raise_fp_fault(env, enabled & 0x7);
    }

    shift = ia64_fpsr_sf_shift(sf) + IA64_FPSR_SF_FLAGS_SHIFT;
    env->ar_fpsr |= flags << shift;

    if (enabled & 0x38) {
        uint32_t slot = (env->psr & IA64_PSR_RI_MASK) >>
                        IA64_PSR_RI_SHIFT;
        uint64_t trap_ip = env->ip;
        uint64_t next_ip = env->ip;
        uint32_t next_slot;

        if (slot < 2) {
            next_slot = slot + 1;
        } else {
            next_ip += 16;
            next_slot = 0;
        }
        env->psr = (env->psr & ~IA64_PSR_RI_MASK) |
                   ((uint64_t)next_slot << IA64_PSR_RI_SHIFT);
        env->cr_isr = ((enabled & 0x38) << 8) | 1;
        helper_raise_exception(env, IA64_EXCP_FP_TRAP, next_ip, trap_ip,
                               slot);
    }
}

void helper_fsetc(CPUIA64State *env, uint32_t sf,
                  uint32_t amask7, uint32_t omask7)
{
    uint64_t controls = (ia64_fpsr_sf_controls(env, 0) & (amask7 & 0x7f)) |
                        (omask7 & 0x7f);
    uint64_t shift = ia64_fpsr_sf_shift(sf);

    if (((sf & 3) == 0 && (controls & IA64_FPSR_SF_TD)) ||
        (((controls >> 2) & 3) == 1)) {
        uint32_t slot = (env->psr & IA64_PSR_RI_MASK) >>
                        IA64_PSR_RI_SHIFT;

        env->cr_isr = 0x30;
        helper_raise_exception(env, IA64_EXCP_RESERVED_REG_FIELD,
                               env->ip, 0, slot);
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

/* ---- FP multiply-subtract (fms: r1 = r2 * r3 - r4; fma with negated addend) ---- */

void helper_fms(CPUIA64State *env, uint32_t r1, uint32_t r2,
                uint32_t r3, uint32_t r4)
{
    if (ia64_fr_write_nat_if_any3(env, r1, r2, r3, r4)) {
        return;
    }
    ia64_fr_write_floatx80(
        env, r1, ia64_floatx80_muladd(
            env, ia64_fr_to_floatx80(env, r3),
            ia64_fr_to_floatx80(env, r4),
            ia64_fr_to_floatx80(env, r2), float_muladd_negate_c));
}

void helper_fnma(CPUIA64State *env, uint32_t r1, uint32_t r2, uint32_t r3)
{
    floatx80 zero = make_floatx80(0, 0);

    if (ia64_fr_write_nat_if_any2(env, r1, r2, r3)) {
        return;
    }
    ia64_fr_write_floatx80(
        env, r1, ia64_floatx80_muladd(
            env, ia64_fr_to_floatx80(env, r2),
            ia64_fr_to_floatx80(env, r3), zero,
            float_muladd_negate_product));
}

void helper_fnma4(CPUIA64State *env, uint32_t r1, uint32_t r2,
                  uint32_t r3, uint32_t r4)
{
    if (ia64_fr_write_nat_if_any3(env, r1, r2, r3, r4)) {
        return;
    }
    ia64_fr_write_floatx80(
        env, r1, ia64_floatx80_muladd(
            env, ia64_fr_to_floatx80(env, r3),
            ia64_fr_to_floatx80(env, r4),
            ia64_fr_to_floatx80(env, r2),
            float_muladd_negate_product));
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
    floatx80 value;

    (void)r2;
    if (ia64_fr_nat_get(env, r3)) {
        ia64_fr_write_nat(env, r1);
        return;
    }
    if (ia64_fr_sig_get(env, r3)) {
        uint64_t integer = env->fr[r3];

        value = float128_to_floatx80(
            uint64_to_float128(integer, &env->fp_status),
            &env->fp_status);
        ia64_fr_write_floatx80(env, r1, value);
        if (r1 > 1) {
            env->fr_int_value[r1] = integer;
            env->fr_int_origin[r1 / 64] |= 1ULL << (r1 % 64);
        }
    } else {
        value = floatx80_round(ia64_fr_to_floatx80(env, r3),
                               &env->fp_status);
        ia64_fr_write_floatx80(env, r1, value);
    }
}

/* ---- FP absolute / negate / negate-absolute ---- */

void helper_fpabs(CPUIA64State *env, uint32_t r1, uint32_t r2)
{
    if (ia64_fr_nat_get(env, r2)) {
        ia64_fr_write_nat(env, r1);
        return;
    }
    ia64_fr_copy(env, r1, r2, 0);
}

void helper_fpneg(CPUIA64State *env, uint32_t r1, uint32_t r2)
{
    if (ia64_fr_nat_get(env, r2)) {
        ia64_fr_write_nat(env, r1);
        return;
    }
    ia64_fr_copy(env, r1, r2, -1);
}

void helper_fpnegabs(CPUIA64State *env, uint32_t r1, uint32_t r2)
{
    if (ia64_fr_nat_get(env, r2)) {
        ia64_fr_write_nat(env, r1);
        return;
    }
    ia64_fr_copy(env, r1, r2, 2);
}

void helper_fcvt_xf(CPUIA64State *env, uint32_t r1, uint32_t r2)
{
    float128 value;

    if (ia64_fr_nat_get(env, r2)) {
        ia64_fr_write_nat(env, r1);
        return;
    }

    value = int64_to_float128((int64_t)env->fr[r2], &env->fp_status);
    ia64_fr_write_floatx80(
        env, r1, float128_to_floatx80(value, &env->fp_status));
}

void helper_fcvt_fx(CPUIA64State *env, uint32_t r1, uint32_t r2,
                    uint32_t is_unsigned, uint32_t is_trunc)
{
    uint64_t value = env->fr[r2];
    floatx80 fp_value;
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

    fp_value = ia64_fr_to_floatx80(env, r2);
    if (is_unsigned) {
        float128 fp128 = floatx80_to_float128(fp_value, &env->fp_status);

        result = is_trunc ?
            float128_to_uint64_round_to_zero(fp128, &env->fp_status) :
            float128_to_uint64(fp128, &env->fp_status);
    } else {
        result = is_trunc ?
            (uint64_t)floatx80_to_int64_round_to_zero(
                fp_value, &env->fp_status) :
            (uint64_t)floatx80_to_int64(fp_value, &env->fp_status);
    }
    ia64_fr_write_sig(env, r1, result);
}

uint64_t helper_getf(CPUIA64State *env, uint32_t reg, uint32_t kind)
{
    uint64_t low;
    uint64_t high;

    ia64_fr_spill_words(env, reg, &low, &high);
    if (kind == 0) {
        float_status status = env->fp_status;

        return float64_val(floatx80_to_float64(
            ia64_fr_to_floatx80(env, reg), &status));
    }
    if (kind == 1) {
        float_status status = env->fp_status;

        return float32_val(floatx80_to_float32(
            ia64_fr_to_floatx80(env, reg), &status));
    }
    return kind == 2 ? low : high;
}

void helper_setf_exp(CPUIA64State *env, uint32_t reg, uint64_t value)
{
    ia64_fr_write_ext(env, reg, (value >> 17) & 1,
                      value & 0x1ffff,
                      IA64_FP_SIGNIFICAND_INTEGER_BIT);
}

void helper_setf_s(CPUIA64State *env, uint32_t reg, uint64_t value)
{
    float_status status = env->fp_status;
    floatx80 fp_value = float32_to_floatx80(make_float32(value), &status);

    /* setf.s expands the single-precision encoding into register format. */
    ia64_fr_write_floatx80(env, reg, fp_value);
}

void helper_fmov(CPUIA64State *env, uint32_t dst, uint32_t src)
{
    ia64_fr_copy(env, dst, src, 1);
}

/* ---- FP reciprocal sqrt approx ---- */

static bool ia64_floatx80_rsqrta_predicate(floatx80 val,
                                            float_status *status)
{
    return !floatx80_is_zero(val) &&
           !floatx80_is_neg(val) &&
           !floatx80_is_infinity(val, status) &&
           !floatx80_is_any_nan(val);
}

static floatx80 ia64_floatx80_rsqrta(floatx80 val, float_status *status)
{
    floatx80 one = make_floatx80(
        0x3fff, IA64_FP_SIGNIFICAND_INTEGER_BIT);
    floatx80 sqrtv = floatx80_sqrt(val, status);

    if (floatx80_is_zero(sqrtv)) {
        return floatx80_default_inf(floatx80_is_neg(val), status);
    }
    return floatx80_div(one, sqrtv, status);
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

static float32 ia64_float32_rsqrta_approx(
    CPUIA64State *env, const IA64FPRegisterFormat *val)
{
    IA64FPRegisterFormat result = {
        .sign = false,
        .exp = ia64_fp_register_rsqrt_exp(val->exp),
        .mant = (uint64_t)ia64_recip_sqrt_table[
            ia64_recip_sqrt_table_index(val)] << 53,
    };

    return ia64_float32_from_register_format(env, &result);
}

static bool ia64_float32_fprsqrta_predicate(
    const IA64FPRegisterFormat *val)
{
    return val->exp >
           IA64_FP_WRE_BIAS - IA64_FP_SINGLE_BIAS +
           IA64_FP_SINGLE_MANT_WIDTH;
}

void helper_fprsqrta(CPUIA64State *env, uint32_t r1, uint32_t p2,
                     uint32_t r3, uint32_t sf)
{
    uint64_t val = env->fr[r3];
    float32 hi = make_float32(val >> 32);
    float32 lo = make_float32(val);
    bool hi_pred;
    bool lo_pred;
    float32 hi_result;
    float32 lo_result;
    int hi_soft;
    int lo_soft;

    if (ia64_fr_nat_get(env, r3)) {
        ia64_fr_write_nat(env, r1);
        ia64_pr_write(env, p2, false);
        return;
    }

    {
        IA64FPRegisterFormat hi_fmt = { 0 };
        IA64FPRegisterFormat lo_fmt = { 0 };
        bool hi_normal = ia64_float32_register_format(hi, &hi_fmt);
        bool lo_normal = ia64_float32_register_format(lo, &lo_fmt);
        float_status hi_status = env->fp_status;
        float_status lo_status = env->fp_status;

        hi_pred = ia64_float32_rsqrta_predicate(hi);
        lo_pred = ia64_float32_rsqrta_predicate(lo);
        hi_result = hi_pred && hi_normal ?
                    ia64_float32_rsqrta_approx(env, &hi_fmt) :
                    ia64_float32_rsqrta(hi, &hi_status);
        lo_result = lo_pred && lo_normal ?
                    ia64_float32_rsqrta_approx(env, &lo_fmt) :
                    ia64_float32_rsqrta(lo, &lo_status);
        hi_soft = get_float_exception_flags(&hi_status);
        lo_soft = get_float_exception_flags(&lo_status);
        hi_pred = hi_pred && hi_normal &&
                  ia64_float32_fprsqrta_predicate(&hi_fmt);
        lo_pred = lo_pred && lo_normal &&
                  ia64_float32_fprsqrta_predicate(&lo_fmt);
    }

    {
        uint64_t traps = ia64_fp_active_traps(env, sf);
        uint64_t hi_fault = ia64_fp_soft_flags_to_ia64(hi_soft) & ~traps & 0x7;
        uint64_t lo_fault = ia64_fp_soft_flags_to_ia64(lo_soft) & ~traps & 0x7;

        set_float_exception_flags(hi_soft | lo_soft, &env->fp_status);
        if (hi_fault || lo_fault) {
            ia64_raise_fp_fault(env, lo_fault | (hi_fault << 4));
        }
    }

    ia64_fr_write_sig(env, r1,
                      ((uint64_t)float32_val(hi_result) << 32) |
                      float32_val(lo_result));
    ia64_pr_write(env, p2, hi_pred && lo_pred);
}

void helper_frsqrta(CPUIA64State *env, uint32_t r1, uint32_t p2,
                    uint32_t r3)
{
    floatx80 val;
    IA64FPRegisterFormat fmt;
    bool predicate;

    if (ia64_fr_nat_get(env, r3)) {
        ia64_fr_write_nat(env, r1);
        ia64_pr_write(env, p2, false);
        return;
    }

    fmt = ia64_fr_register_format(env, r3);
    if (ia64_frsqrta_limits_swa_fault(&fmt)) {
        ia64_raise_fp_fault(env, IA64_FP_ISR_SWA);
    }

    val = ia64_fr_to_floatx80(env, r3);
    if (floatx80_is_zero(val) ||
        (!floatx80_is_neg(val) &&
         floatx80_is_infinity(val, &env->fp_status))) {
        ia64_fr_copy(env, r1, r3, 1);
        ia64_pr_write(env, p2, false);
        return;
    }

    predicate = ia64_floatx80_rsqrta_predicate(val, &env->fp_status);
    ia64_fr_write_floatx80(
        env, r1, predicate && ia64_fp_register_format_is_normal(&fmt) ?
        ia64_floatx80_rsqrta_approx(env, r3) :
        ia64_floatx80_rsqrta(val, &env->fp_status));
    ia64_pr_write(env, p2, predicate);
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

    hi = floatx80_to_float32(ia64_fr_to_floatx80(env, r2), &status);
    status = env->fp_status;
    lo = floatx80_to_float32(ia64_fr_to_floatx80(env, r3), &status);
    ia64_fr_write_sig(env, r1, ((uint64_t)hi << 32) | lo);
}

void helper_alloc_rse(CPUIA64State *env, uint32_t r1, uint32_t pfm,
                       uint64_t fault_ip, uint32_t slot)
{
    uint32_t new_sof = pfm & 0x7f;
    uint32_t new_sol = (pfm >> 7) & 0x7f;
    uint32_t new_sor = (pfm >> 14) & 0x0f;
    int32_t growth = (int32_t)new_sof - (int32_t)env->cfm_sof;
    uintptr_t ra = GETPC();

    /*
     * SDM Vol.2 6.6: alloc raises a Reserved Register/Field fault when
     * it changes the rotating-region size while any RRB is non-zero.
     * The RRBs themselves are not modified by alloc.
     */
    if (new_sor != env->cfm_sor &&
        (env->cfm_rrb_gr || env->cfm_rrb_fr || env->cfm_rrb_pr)) {
        env->cr_isr = 0x30;
        helper_raise_exception(env, IA64_EXCP_RESERVED_REG_FIELD,
                               fault_ip, 0, slot);
    }

    ia64_rse_sync_frame_out(env);
    ia64_rse_new_frame(env, growth, ra);
    env->cfm_sof = new_sof;
    env->cfm_sol = new_sol;
    env->cfm_sor = new_sor;
    ia64_rse_sync_frame_in(env);
    ia64_invalidate_stacked_alat(env);

    if (r1 != 0) {
        env->gr[r1] = env->ar_pfs;
        ia64_gr_nat_set(env, r1, false);
    }
    ia64_rse_check(env, "alloc");
}

void helper_cover_rse(CPUIA64State *env)
{
    if (!(env->psr & IA64_PSR_IC)) {
        env->cr_ifs = IA64_IFS_V | ia64_current_cfm(env);
    }
    ia64_rse_sync_frame_out(env);
    ia64_rse_preserve_frame(env, env->cfm_sof);
    env->cfm_sof = 0;
    env->cfm_sol = 0;
    env->cfm_sor = 0;
    env->cfm_rrb_gr = 0;
    env->cfm_rrb_fr = 0;
    env->cfm_rrb_pr = 0;
    ia64_invalidate_stacked_alat(env);
    ia64_rse_check(env, "cover");
}

void helper_flushrs_rse(CPUIA64State *env)
{
    uintptr_t ra = GETPC();

    /*
     * Spill every dirty register and intervening NaT collection
     * (SDM Vol.2 6.5.4).  Each completed store updates BSPSTORE and
     * the partitions, so a faulting store restarts cleanly on the
     * issuing instruction.
     */
    while (env->rse_dirty + env->rse_dirty_nat > 0) {
        ia64_rse_store_one(env, ra);
    }
    ia64_rse_check(env, "flushrs");
}

void helper_loadrs_rse(CPUIA64State *env, uint64_t fault_ip, uint64_t raw,
                       uint32_t slot)
{
    uintptr_t ra = GETPC();
    uint64_t loadrs_bytes = ((env->ar_rsc >> IA64_RSC_LOADRS_SHIFT) &
                             IA64_RSC_LOADRS_MASK) & ~7ULL;
    int32_t words = loadrs_bytes >> 3;
    int32_t words_to_load;

    if ((env->ar_rsc & IA64_RSC_MODE) != 0 ||
        (env->cfm_sof != 0 && loadrs_bytes != 0)) {
        helper_raise_exception(env, IA64_EXCP_ILLEGAL, fault_ip, raw, slot);
    }

    /*
     * SDM Vol.2 6.5.4: ensure the backing store between BSP and the
     * tear point is present and dirty in the physical file; everything
     * below the tear point becomes invalid.
     */
    words_to_load = words - (env->rse_clean + env->rse_clean_nat +
                             env->rse_dirty + env->rse_dirty_nat);
    if (words_to_load >= 0) {
        env->rse_dirty_nat += env->rse_clean_nat;
        env->rse_dirty += env->rse_clean;
        env->rse_clean = 0;
        env->rse_clean_nat = 0;
        env->ar_bspstore = env->ar_bsp -
            (int64_t)(env->rse_dirty + env->rse_dirty_nat) * 8;
        while (words_to_load > 0) {
            int64_t live = (int64_t)env->rse_clean + env->rse_clean_nat +
                           env->rse_dirty + env->rse_dirty_nat;
            uint64_t bspload = env->ar_bsp - (live + 1) * 8;

            if (env->rse_dirty == IA64_STACKED_GR_COUNT &&
                ia64_rse_collect_bit(bspload) != 63) {
                /* More registers than fit in the physical file. */
                helper_raise_exception(env, IA64_EXCP_ILLEGAL, fault_ip,
                                       raw, slot);
            }
            if (ia64_rse_load_one(env, ra)) {
                env->rse_dirty++;
                env->rse_clean--;
            } else {
                env->rse_dirty_nat++;
                env->rse_clean_nat--;
            }
            env->ar_bspstore = env->ar_bsp -
                (int64_t)(env->rse_dirty + env->rse_dirty_nat) * 8;
            words_to_load--;
        }
    } else {
        uint64_t tear = env->ar_bsp - loadrs_bytes;

        env->rse_dirty_nat = (int32_t)((int64_t)(env->ar_bsp >> 9) -
                                       (int64_t)(tear >> 9));
        env->rse_dirty = words - env->rse_dirty_nat;
        env->ar_bspstore = env->ar_bsp -
            (int64_t)(env->rse_dirty + env->rse_dirty_nat) * 8;
        env->rse_clean = 0;
        env->rse_clean_nat = 0;
        env->rse_invalid = IA64_STACKED_GR_COUNT -
                           (env->cfm_sof + env->rse_dirty);
    }
    /*
     * SDM Vol.2 6.5.4: loadrs causes the contents of the RNAT register
     * to become undefined; invalidate it so stale collection bits are
     * not applied to later mandatory loads.  (Software reloads RNAT
     * after loadrs when switching backing stores.)
     */
    env->ar_rnat = 0;
    ia64_rse_check(env, "loadrs");
}

/* ---- Loop branch helpers ---- */

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

static bool ia64_update_while_loop(CPUIA64State *env, uint32_t qp)
{
    bool kernel_active = env->pr[qp & 63];
    bool pipeline_active = kernel_active || env->ar_ec > 1;

    if (kernel_active) {
        env->pr[63] = 0;
        ia64_rotate_loop_regs(env);
    } else if (env->ar_ec != 0) {
        env->ar_ec--;
        env->pr[63] = 0;
        ia64_rotate_loop_regs(env);
    } else {
        env->pr[63] = 0;
    }

    return pipeline_active;
}

uint64_t helper_br_wexit(CPUIA64State *env, uint64_t target, uint32_t qp)
{
    return ia64_update_while_loop(env, qp) ? 0 : target;
}

uint64_t helper_br_wtop(CPUIA64State *env, uint64_t target, uint32_t qp)
{
    return ia64_update_while_loop(env, qp) ? target : 0;
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
    uint16_t tlb_count;
    uint8_t needed;
    const IA64TlbEntry *entry;

    needed = is_write ? IA64_TLB_W :
             (is_ifetch ? IA64_TLB_X : IA64_TLB_R);

    if (!(env->psr & (is_ifetch ? IA64_PSR_IT : IA64_PSR_DT))) {
        return 1;
    }

    if (!ia64_va_is_implemented(va)) {
        return 0;
    }

    if (ia64_firmware_identity_pa(env->cr_iva, env->ip, va, &pa)) {
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

    entry = ia64_tlb_find(tlb, tlb_count, va, rid, is_ifetch);
    if (entry) {
        IA64Exception excp;

        ia64_tlb_entry_translate(entry, va, access_level, &pa, &perm);
        excp = ia64_tlb_exception_for_access(env, entry, perm, needed,
                                             is_ifetch, is_write, false);
        return excp == IA64_EXCP_NONE ? 1 : 0;
    }

    if (!walk_vhpt) {
        if (ia64_sal_boot_identity_pa(env, va, &pa)) {
            return 1;
        }
        return 0;
    }

    {
        uint64_t pte = 0;
        uint32_t key = 0;

        if (!ia64_vhpt_walk_full(env, va, rid, is_ifetch, false,
                                 access_level, &pa, &perm, &pte, &key)) {
            if (ia64_sal_boot_identity_pa(env, va, &pa)) {
                return 1;
            }
            return 0;
        }

        if (is_ifetch) {
            entry = ia64_tlb_find(env->tlb_inst, env->tlb_inst_count, va,
                                  rid, true);
        } else {
            entry = ia64_tlb_find(env->tlb_data, env->tlb_data_count, va,
                                  rid, false);
        }
        return (entry ?
                ia64_tlb_exception_for_access(env, entry, perm, needed,
                                              is_ifetch, is_write, false) :
                ia64_translation_exception_for_access(env, pte, key, perm,
                                                      needed, is_ifetch,
                                                      is_write, false)) ==
               IA64_EXCP_NONE ? 1 : 0;
    }
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
    uint32_t key = 0;
    const IA64TlbEntry *entry;
    bool found = false;

    if (!(env->psr & IA64_PSR_DT) ||
        ia64_firmware_identity_pa(env->cr_iva, env->ip, va, &pa) ||
        ia64_sal_boot_virtual_pa(env, va, &pa)) {
        return IA64_EXCP_NONE;
    }

    if (!ia64_va_is_implemented(va)) {
        return IA64_EXCP_UNIMPL_DATA_ADDR;
    }

    entry = ia64_tlb_find(env->tlb_data, env->tlb_data_count, va, rid, false);
    if (entry) {
        ia64_tlb_entry_translate(entry, va, access_level, &pa, &perm);
        pte = entry->pte;
        found = true;
    } else if (walk_vhpt) {
        found = ia64_vhpt_walk_full(env, va, rid, false, false,
                                    access_level, &pa, &perm, &pte, &key);
        if (found) {
            entry = ia64_tlb_find(env->tlb_data, env->tlb_data_count, va,
                                  rid, false);
        }
    }

    if (found) {
        if (entry) {
            return ia64_tlb_exception_for_access(env, entry, perm, needed,
                                                false, is_write || is_rw,
                                                false);
        }
        return ia64_translation_exception_for_access(env, pte, key, perm,
                                                     needed, false,
                                                     is_write || is_rw,
                                                     false);
    }
    if (ia64_sal_boot_identity_pa(env, va, &pa)) {
        return IA64_EXCP_NONE;
    }
    if (ia64_data_nested_tlb_active(env)) {
        return IA64_EXCP_DATA_NESTED_TLB;
    }
    if (ia64_vhpt_pte_not_present(env, va, false, false, NULL)) {
        return IA64_EXCP_PAGE_NOT_PRESENT;
    }
    vhpt_enabled = ia64_vhpt_walker_enabled(env, va, false, false,
                                            &vhpt_size, &vhpt_long_format);
    if (ia64_vhpt_walk_miss_reports_data_tlb(env, vhpt_enabled)) {
        return IA64_EXCP_DTLB_FAULT;
    }
    if (!ia64_vhpt_entry_accessible(env, va, false, false, &pa)) {
        return IA64_EXCP_VHPT_FAULT;
    }

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
    case IA64_EXCP_DATA_KEY_MISS:
        return IA64_DCR_DK;
    case IA64_EXCP_KEY_PERMISSION:
        return IA64_DCR_DX;
    case IA64_EXCP_DATA_ACCESS:
        return IA64_DCR_DR;
    case IA64_EXCP_DATA_ACCESS_BIT:
        return IA64_DCR_DA;
    case IA64_EXCP_UNIMPL_DATA_ADDR:
        return UINT64_MAX;
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
    if (dcr_mask == UINT64_MAX) {
        return true;
    }

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

static void ia64_raise_data_reference_exception_at(CPUIA64State *env,
                                                   uint64_t va,
                                                   uint32_t is_write,
                                                   uint32_t is_rw,
                                                   bool is_non_access,
                                                   uint8_t non_access_code,
                                                   IA64Exception excp,
                                                   bool is_speculative,
                                                   bool itlb_ed,
                                                   uint64_t fault_ip,
                                                   uint8_t fault_slot)
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
        if (excp == IA64_EXCP_UNIMPL_DATA_ADDR) {
            env->cr_isr = IA64_GENEX_UNIMPL_DATA_ADDR |
                          (is_non_access ? IA64_ISR_NA : 0) |
                          (is_rw ? (IA64_ISR_R | IA64_ISR_W) :
                           (is_write ? IA64_ISR_W : IA64_ISR_R));
        } else {
            env->cr_isr = (is_non_access ?
                           IA64_ISR_NA | non_access_code : 0) |
                          (is_rw ? (IA64_ISR_R | IA64_ISR_W) :
                           (is_write ? IA64_ISR_W : IA64_ISR_R));
        }
        if (is_speculative) {
            env->cr_isr |= IA64_ISR_SP;
        }
        if (itlb_ed) {
            env->cr_isr |= IA64_ISR_ED;
        }
    }
    env->fault_ip = fault_ip;
    env->fault_imm = 0;
    env->fault_slot = fault_slot;
    env->exception = excp;
    cs->exception_index = excp;
    cpu_loop_exit(cs);
}

static void ia64_raise_data_reference_exception(CPUIA64State *env,
                                                uint64_t va,
                                                uint32_t is_write,
                                                uint32_t is_rw,
                                                bool is_non_access,
                                                uint8_t non_access_code,
                                                IA64Exception excp,
                                                bool is_speculative,
                                                bool itlb_ed)
{
    ia64_raise_data_reference_exception_at(
        env, va, is_write, is_rw, is_non_access, non_access_code, excp,
        is_speculative, itlb_ed, ia64_ip_bundle_addr(env->ip),
        (env->psr & IA64_PSR_RI_MASK) >> IA64_PSR_RI_SHIFT);
}

static uint8_t ia64_probe_access_level(CPUIA64State *env,
                                       uint64_t access_level)
{
    uint8_t requested_pl = access_level & 3;
    uint8_t current_cpl = ia64_psr_cpl(env->psr);

    return requested_pl < current_cpl ? current_cpl : requested_pl;
}

static uint64_t ia64_probe_dt_disabled(CPUIA64State *env, uint64_t va,
                                       uint32_t is_write,
                                       uint8_t access_level)
{
    uint64_t pa;
    uint8_t perm;
    uint8_t needed = is_write ? IA64_TLB_W : IA64_TLB_R;
    uint32_t rid = ia64_region_rid(env, va);
    const IA64TlbEntry *entry = ia64_tlb_find(env->tlb_data,
                                             env->tlb_data_count,
                                             va, rid, false);
    IA64Exception excp;

    if (!entry) {
        ia64_raise_data_reference_exception(
            env, va, is_write, false, true, 2, IA64_EXCP_ALT_DTLB, false,
            ia64_current_code_tlb_ed(env));
        g_assert_not_reached();
    }

    ia64_tlb_entry_translate(entry, va, access_level, &pa, &perm);
    excp = ia64_pte_exception_for_access(entry->pte, perm, needed, false,
                                         is_write, env->psr);
    switch (excp) {
    case IA64_EXCP_NONE:
        return 1;
    case IA64_EXCP_DATA_ACCESS:
    case IA64_EXCP_DATA_DIRTY:
    case IA64_EXCP_DATA_ACCESS_BIT:
        return 0;
    default:
        ia64_raise_data_reference_exception(
            env, va, is_write, false, true, 0, excp, false,
            ia64_current_code_tlb_ed(env));
        g_assert_not_reached();
    }
}

uint64_t helper_probe(CPUIA64State *env, uint64_t va, uint32_t is_write,
                      uint32_t is_ifetch, uint64_t access_level)
{
    uint8_t effective_pl = ia64_probe_access_level(env, access_level);

    if (!is_ifetch && !(env->psr & IA64_PSR_DT)) {
        return ia64_probe_dt_disabled(env, va, is_write, effective_pl);
    }

    return ia64_probe_address(env, va, is_write, is_ifetch,
                              effective_pl, true);
}

static void ia64_raise_data_reference_fault_if_needed(CPUIA64State *env,
                                                      uint64_t va,
                                                      uint32_t is_write,
                                                      uint32_t is_rw,
                                                      uint8_t access_level,
                                                      bool is_non_access,
                                                      uint8_t non_access_code)
{
    IA64Exception excp = ia64_data_reference_exception(
        env, va, is_write, is_rw, access_level, true);

    if (excp == IA64_EXCP_NONE) {
        return;
    }
    ia64_raise_data_reference_exception(env, va, is_write, is_rw,
                                        is_non_access, non_access_code,
                                        excp, false,
                                        ia64_current_code_tlb_ed(env));
}

void helper_probe_fault(CPUIA64State *env, uint64_t va, uint32_t is_write,
                        uint32_t is_rw, uint64_t access_level)
{
    uint8_t effective_pl = ia64_probe_access_level(env, access_level);

    ia64_raise_data_reference_fault_if_needed(env, va, is_write, is_rw,
                                              effective_pl, true, 5);
}

void helper_lfetch_fault(CPUIA64State *env, uint64_t va,
                         uint64_t fault_ip, uint32_t fault_slot)
{
    IA64Exception excp = ia64_data_reference_exception(
        env, va, false, false, ia64_psr_cpl(env->psr), true);

    if (excp == IA64_EXCP_NONE) {
        return;
    }
    ia64_raise_data_reference_exception_at(
        env, va, false, false, true, 4, excp, false,
        ia64_current_code_tlb_ed(env), fault_ip, fault_slot);
}

void helper_check_semaphore_access(CPUIA64State *env, uint64_t va)
{
    ia64_raise_data_reference_fault_if_needed(env, va, true, true,
                                              ia64_psr_cpl(env->psr), false,
                                              0);
}

uint64_t helper_speculative_probe(CPUIA64State *env, uint64_t va,
                                  uint32_t is_write, uint32_t is_ifetch,
                                  uint32_t size)
{
    bool itlb_ed;
    IA64Exception excp;
    uint64_t pa;
    IA64MemorySpeculation spec;

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
            ia64_vhpt_pte_not_present(env, va, false, false, NULL)) {
            return 0;
        }
        excp = ia64_data_reference_exception(
            env, va, is_write, false, ia64_psr_cpl(env->psr),
            (env->psr & IA64_PSR_IC) != 0);
    }

    if (excp == IA64_EXCP_NONE) {
        if (!is_ifetch &&
            ia64_data_address_to_phys_attr(env, va, &pa, &spec) &&
            !ia64_memory_allows_control_speculation(spec)) {
            return 0;
        }
        return 1;
    }
    if (ia64_speculative_exception_deferrable(env, excp, itlb_ed)) {
        return 0;
    }

    ia64_raise_data_reference_exception(env, va, is_write, false, false, 0,
                                        excp, true, itlb_ed);
    g_assert_not_reached();
}

uint64_t helper_advanced_load_allowed(CPUIA64State *env, uint64_t va)
{
    uint64_t pa;
    IA64MemorySpeculation spec;
    IA64Exception excp;

    excp = ia64_data_reference_exception(env, va, false, false,
                                         ia64_psr_cpl(env->psr), true);
    if (excp != IA64_EXCP_NONE) {
        return 1;
    }
    if (!ia64_data_address_to_phys_attr(env, va, &pa, &spec)) {
        return 1;
    }
    return ia64_memory_allows_advanced_load(spec) ? 1 : 0;
}

void helper_ldfe(CPUIA64State *env, uint32_t r1, uint64_t addr)
{
    uintptr_t ra = GETPC();
    uint64_t low;
    uint16_t high;
    uint32_t exp;
    bool sign;

    if (ia64_data_big_endian(env)) {
        high = cpu_lduw_be_data_ra(env, addr, ra);
        low = cpu_ldq_be_data_ra(env, addr + 2, ra);
    } else {
        low = cpu_ldq_le_data_ra(env, addr, ra);
        high = cpu_lduw_le_data_ra(env, addr + 8, ra);
    }
    sign = high >> 15;
    exp = high & 0x7fff;
    if (exp == 0x7fff) {
        exp = IA64_FP_REG_SPECIAL_EXP;
    } else if (exp != 0) {
        exp += 0xc000;
    }
    ia64_fr_write_ext(env, r1, sign, exp, low);
}

void helper_ldf_fill(CPUIA64State *env, uint32_t r1, uint64_t addr)
{
    uintptr_t ra = GETPC();
    uint64_t low;
    uint64_t high;

    if (ia64_data_big_endian(env)) {
        low = cpu_ldq_be_data_ra(env, addr + 8, ra);
        high = ((uint64_t)cpu_ldub_data_ra(env, addr + 7, ra)) |
               ((uint64_t)cpu_ldub_data_ra(env, addr + 6, ra) << 8) |
               ((uint64_t)cpu_ldub_data_ra(env, addr + 5, ra) << 16);
    } else {
        low = cpu_ldq_le_data_ra(env, addr, ra);
        high = cpu_ldq_le_data_ra(env, addr + 8, ra);
    }

    ia64_fr_fill_spill_words(env, r1, low, high);
}

void helper_stfe(CPUIA64State *env, uint64_t addr, uint32_t r2)
{
    uintptr_t ra = GETPC();
    floatx80 value;
    uint64_t mant;
    uint32_t exp;
    bool sign;

    if (ia64_fr_ext_get(env, r2, &sign, &exp, &mant)) {
        uint16_t ext_exp;

        if (exp == IA64_FP_REG_SPECIAL_EXP) {
            ext_exp = 0x7fff;
        } else if (exp == 0) {
            ext_exp = 0;
        } else if (exp > 0xc000 && exp - 0xc000 < 0x7fff) {
            ext_exp = exp - 0xc000;
        } else {
            ext_exp = exp < 0xc000 ? 0 : 0x7fff;
        }
        value = make_floatx80(((uint16_t)sign << 15) | ext_exp, mant);
    } else {
        value = float64_to_floatx80(env->fr[r2], &env->fp_status);
    }

    if (ia64_data_big_endian(env)) {
        cpu_stw_be_data_ra(env, addr, value.high, ra);
        cpu_stq_be_data_ra(env, addr + 2, value.low, ra);
    } else {
        cpu_stq_le_data_ra(env, addr, value.low, ra);
        cpu_stw_le_data_ra(env, addr + 8, value.high, ra);
    }
}

void helper_stf_spill(CPUIA64State *env, uint64_t addr, uint32_t r2)
{
    uintptr_t ra = GETPC();
    uint64_t low;
    uint64_t high;

    ia64_fr_spill_words(env, r2, &low, &high);
    if (ia64_data_big_endian(env)) {
        cpu_stb_data_ra(env, addr, 0, ra);
        cpu_stb_data_ra(env, addr + 1, 0, ra);
        cpu_stb_data_ra(env, addr + 2, 0, ra);
        cpu_stb_data_ra(env, addr + 3, 0, ra);
        cpu_stb_data_ra(env, addr + 4, 0, ra);
        cpu_stb_data_ra(env, addr + 5, (high >> 16) & 0xff, ra);
        cpu_stb_data_ra(env, addr + 6, (high >> 8) & 0xff, ra);
        cpu_stb_data_ra(env, addr + 7, high & 0xff, ra);
        cpu_stq_be_data_ra(env, addr + 8, low, ra);
    } else {
        cpu_stq_le_data_ra(env, addr, low, ra);
        cpu_stq_le_data_ra(env, addr + 8, high, ra);
    }
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
    const IA64TlbEntry *entry;
    uint64_t pa;
    uint8_t perm;
    uint64_t pte = 0;

    entry = ia64_tlb_find(env->tlb_data, env->tlb_data_count, va, rid,
                          false);
    if (entry && ia64_tlb_entry_present(entry)) {
        return entry->key;
    }

    if ((env->psr & IA64_PSR_DT) &&
        ia64_vhpt_walk_full(env, va, rid, false, false,
                            ia64_psr_cpl(env->psr), &pa, &perm, &pte, NULL) &&
        (pte & IA64_PTE_PRESENT)) {
        entry = ia64_tlb_find(env->tlb_data, env->tlb_data_count, va, rid,
                              false);
        if (entry && ia64_tlb_entry_present(entry)) {
            return entry->key;
        }
    }

    return 1;
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

static bool ia64_vhpt_preferred_page_size_supported(CPUIA64State *env,
                                                    uint64_t va)
{
    uint8_t rr_ps = (env->rr[ia64_rr_index(va)] >> IA64_ITIR_PS_SHIFT) &
                    IA64_ITIR_PS_MASK;

    return ia64_page_shift_insertable(rr_ps);
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
                                            uint8_t size, uint64_t *hash_out)
{
    uint64_t base = env->cr_pta & IA64_PTA_BASE_MASK;
    uint64_t entries = 1ULL << (size - 5);
    uint64_t hpn = ia64_vhpt_hpn(env, va);
    uint64_t hash = (hpn ^ (hpn >> 7) ^ ia64_region_rid(env, va)) &
                    (entries - 1);
    uint64_t offset = hash << 5;
    uint64_t mask = (1ULL << size) - 1;

    if (hash_out) {
        *hash_out = hash;
    }
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

    return ia64_vhpt_long_hash_address(env, va, size, NULL);
}

uint64_t helper_ttag(CPUIA64State *env, uint64_t va)
{
    return ia64_vhpt_long_tag(env, va);
}

typedef enum IA64VhptEntryStatus {
    IA64_VHPT_ENTRY_TRANSLATED,
    IA64_VHPT_ENTRY_TLB_MISS,
    IA64_VHPT_ENTRY_ABORT,
} IA64VhptEntryStatus;

static IA64VhptEntryStatus ia64_vhpt_entry_phys(CPUIA64State *env,
                                                uint64_t entry_va,
                                                uint64_t *entry_pa)
{
    const IA64TlbEntry *entry;
    uint8_t perm;
    uint32_t rid;

    if (ia64_firmware_identity_pa(env->cr_iva, env->ip, entry_va,
                                  entry_pa)) {
        return IA64_VHPT_ENTRY_TRANSLATED;
    }

    rid = ia64_region_rid(env, entry_va);
    /*
     * VHPT walker references to the VHPT itself are performed at
     * privilege level 0 regardless of PSR.cpl.
     */
    entry = ia64_tlb_find(env->tlb_data, env->tlb_data_count, entry_va,
                          rid, false);
    if (entry) {
        IA64Exception excp;
        uint8_t ma = (entry->pte & IA64_PTE_MA_MASK) >> IA64_PTE_MA_SHIFT;

        ia64_tlb_entry_translate(entry, entry_va, 0, entry_pa, &perm);
        excp = ia64_tlb_exception_for_access(env, entry, perm, IA64_TLB_R,
                                             false, false, false);
        if (excp == IA64_EXCP_NONE && ma == 0) {
            return IA64_VHPT_ENTRY_TRANSLATED;
        }
        qemu_log_mask(CPU_LOG_MMU,
                      "ia64 vhpt entry abort va=0x%016" PRIx64
                      " rid=0x%06" PRIx32
                      " pte=0x%016" PRIx64 " ma=%u excp=%u\n",
                      entry_va, rid, entry->pte, ma, excp);
        return IA64_VHPT_ENTRY_ABORT;
    }

    return IA64_VHPT_ENTRY_TLB_MISS;
}

bool ia64_vhpt_entry_accessible(CPUIA64State *env, uint64_t va,
                                bool is_ifetch, bool is_rse,
                                uint64_t *entry_va)
{
    uint64_t entry_pa;
    bool long_format;
    uint8_t size;

    if (!ia64_vhpt_walker_enabled(env, va, is_ifetch, is_rse,
                                  &size, &long_format)) {
        return true;
    }
    if (!ia64_vhpt_preferred_page_size_supported(env, va)) {
        return true;
    }
    *entry_va = long_format ? ia64_vhpt_long_hash_address(env, va, size,
                                                          NULL) :
                ia64_vhpt_short_hash_address(env, va, size);
    /*
     * A present-but-faulting translation for the VHPT entry makes the walker
     * abort to the original TLB miss.  Only a missing DTLB translation for
     * the VHPT entry raises a VHPT Translation fault.
     */
    return ia64_vhpt_entry_phys(env, *entry_va, &entry_pa) !=
           IA64_VHPT_ENTRY_TLB_MISS;
}

static uint64_t ia64_vhpt_load_u64(CPUIA64State *env, uint64_t pa)
{
    uint8_t buf[8];

    cpu_physical_memory_read(pa, buf, sizeof(buf));
    return env->cr_dcr & IA64_DCR_BE ? ldq_be_p(buf) : ldq_le_p(buf);
}

static void ia64_vhpt_load_long_entry(CPUIA64State *env, uint64_t pa,
                                      uint64_t *pte, uint64_t *itir,
                                      uint64_t *tag)
{
    *pte = ia64_vhpt_load_u64(env, pa);
    *itir = ia64_vhpt_load_u64(env, pa + 8);
    *tag = ia64_vhpt_load_u64(env, pa + 16);
}

static bool ia64_vhpt_pte_valid(uint64_t pte)
{
    uint8_t ma;

    if (!(pte & IA64_PTE_PRESENT)) {
        return true;
    }
    ma = (pte & IA64_PTE_MA_MASK) >> IA64_PTE_MA_SHIFT;
    return !(pte & IA64_PTE_RESERVED_MASK) && (ma == 0 || ma >= 4);
}

static bool ia64_vhpt_itir_valid(uint64_t pte, uint64_t itir)
{
    uint8_t page_shift = (itir >> IA64_ITIR_PS_SHIFT) & IA64_ITIR_PS_MASK;
    uint64_t reserved_mask = IA64_ITIR_RESERVED_MASK;

    if (!(pte & IA64_PTE_PRESENT)) {
        reserved_mask &= 3;
    }
    return !(itir & reserved_mask) &&
           ia64_page_shift_insertable(page_shift);
}

static bool ia64_vhpt_lookup_pte(CPUIA64State *env, uint64_t va,
                                 bool is_ifetch, bool is_rse, uint64_t *pte,
                                 uint64_t *entry_va)
{
    uint8_t size;
    bool long_format;
    uint64_t entry_pa;

    if (!ia64_vhpt_walker_enabled(env, va, is_ifetch, is_rse,
                                  &size, &long_format)) {
        return false;
    }
    if (!ia64_vhpt_preferred_page_size_supported(env, va)) {
        return false;
    }

    if (!long_format) {
        *entry_va = ia64_vhpt_short_hash_address(env, va, size);
        if (ia64_vhpt_entry_phys(env, *entry_va, &entry_pa) !=
            IA64_VHPT_ENTRY_TRANSLATED) {
            return false;
        }
        *pte = ia64_vhpt_load_u64(env, entry_pa);
        return ia64_vhpt_pte_valid(*pte);
    }

    {
        uint64_t expected_tag = ia64_vhpt_long_tag(env, va);
        uint64_t itir;
        uint64_t tag;

        *entry_va = ia64_vhpt_long_hash_address(env, va, size, NULL);
        if (ia64_vhpt_entry_phys(env, *entry_va, &entry_pa) !=
            IA64_VHPT_ENTRY_TRANSLATED) {
            return false;
        }
        ia64_vhpt_load_long_entry(env, entry_pa, pte, &itir, &tag);
        if ((tag & (1ULL << 63)) || tag != expected_tag) {
            return false;
        }
        return ia64_vhpt_pte_valid(*pte) &&
               ia64_vhpt_itir_valid(*pte, itir);
    }
}

bool ia64_vhpt_pte_not_present(CPUIA64State *env, uint64_t va,
                               bool is_ifetch, bool is_rse,
                               uint64_t *entry_va)
{
    uint64_t local_entry_va;
    uint64_t pte;

    if (!entry_va) {
        entry_va = &local_entry_va;
    }

    return ia64_vhpt_lookup_pte(env, va, is_ifetch, is_rse,
                                &pte, entry_va) &&
           !(pte & IA64_PTE_PRESENT);
}

static void ia64_vhpt_install_tc(CPUIA64State *env, uint64_t va, uint32_t rid,
                                 bool is_ifetch, uint64_t pa,
                                 uint64_t page_size, uint8_t ar, uint8_t pl,
                                 uint8_t perm, uint32_t key, uint64_t pte)
{
    IA64TlbEntry *tlb = is_ifetch ? env->tlb_inst : env->tlb_data;
    uint16_t *cnt = is_ifetch ? &env->tlb_inst_count : &env->tlb_data_count;
    uint16_t *next_replace = is_ifetch ? &env->tlb_inst_replace :
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
    /*
     * The QEMU softmmu TLB is indexed by guest virtual address and mmu_idx;
     * it does not carry IA-64 region IDs.  A VHPT walk can install a TC entry
     * for a different RID than a cached same-VA host entry, so discard the
     * host translation range covered by the installed TC.
     */
    ia64_qemu_tlb_flush_entry(env, &tlb[slot]);
}

/* ---- VHPT walker ---- */

bool ia64_vhpt_walk_full(CPUIA64State *env, uint64_t va, uint32_t rid,
                         bool is_ifetch, bool is_rse, uint8_t access_level,
                         uint64_t *pa, uint8_t *perm, uint64_t *pte,
                         uint32_t *access_key)
{
    uint64_t vhpt_base;
    uint64_t hash;
    uint64_t tag;
    uint64_t expected_tag;
    uint64_t translation;
    uint64_t itir;
    uint64_t entry_pa;
    uint64_t entry_va;
    uint8_t page_shift;
    uint8_t size;
    bool long_format;

    if (!ia64_vhpt_walker_enabled(env, va, is_ifetch, is_rse,
                                  &size, &long_format)) {
        qemu_log_mask(CPU_LOG_MMU,
                      "ia64 vhpt disabled %c va=0x%016" PRIx64
                      " rid=0x%06" PRIx32 " pta=0x%016" PRIx64
                      " rr=0x%016" PRIx64 " psr=0x%016" PRIx64 "\n",
                      is_ifetch ? 'i' : 'd', va, rid, env->cr_pta,
                      env->rr[ia64_rr_index(va)], env->psr);
        return false;
    }
    if (!ia64_vhpt_preferred_page_size_supported(env, va)) {
        qemu_log_mask(CPU_LOG_MMU,
                      "ia64 vhpt unsupported preferred page size %c"
                      " va=0x%016" PRIx64 " rid=0x%06" PRIx32 "\n",
                      is_ifetch ? 'i' : 'd', va, rid);
        return false;
    }

    if (!long_format) {
        uint64_t page_mask;

        entry_va = ia64_vhpt_short_hash_address(env, va, size);
        page_shift = ia64_region_preferred_ps(env, va);
        if (ia64_vhpt_entry_phys(env, entry_va, &entry_pa) !=
            IA64_VHPT_ENTRY_TRANSLATED) {
            qemu_log_mask(CPU_LOG_MMU,
                          "ia64 vhpt short entry miss %c va=0x%016" PRIx64
                          " rid=0x%06" PRIx32
                          " entry_va=0x%016" PRIx64 "\n",
                          is_ifetch ? 'i' : 'd', va, rid, entry_va);
            return false;
        }

        translation = ia64_vhpt_load_u64(env, entry_pa);
        if (!ia64_vhpt_pte_valid(translation)) {
            qemu_log_mask(CPU_LOG_MMU,
                          "ia64 vhpt short reserved translation %c"
                          " va=0x%016" PRIx64 " rid=0x%06" PRIx32
                          " pte=0x%016" PRIx64 "\n",
                          is_ifetch ? 'i' : 'd', va, rid, translation);
            return false;
        }
        if (pte) {
            *pte = translation;
        }
        if (access_key) {
            *access_key = rid;
        }
        {
            uint8_t ar = ia64_pte_ar(translation);
            uint8_t pl = ia64_pte_pl(translation);

            *perm = ia64_pte_perm(translation, access_level);
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

    vhpt_base = env->cr_pta & IA64_PTA_BASE_MASK;
    expected_tag = ia64_vhpt_long_tag(env, va);
    {
        entry_va = ia64_vhpt_long_hash_address(env, va, size, &hash);
        if (ia64_vhpt_entry_phys(env, entry_va, &entry_pa) !=
            IA64_VHPT_ENTRY_TRANSLATED) {
            qemu_log_mask(CPU_LOG_MMU,
                          "ia64 vhpt long entry miss %c va=0x%016" PRIx64
                          " rid=0x%06" PRIx32
                          " entry_va=0x%016" PRIx64 "\n",
                          is_ifetch ? 'i' : 'd', va, rid, entry_va);
            return false;
        }

        ia64_vhpt_load_long_entry(env, entry_pa, &translation, &itir, &tag);
        if (tag & (1ULL << 63)) {
            goto long_miss;
        }
        if (tag != expected_tag) {
            goto long_miss;
        }
        if (!ia64_vhpt_pte_valid(translation) ||
            !ia64_vhpt_itir_valid(translation, itir)) {
            qemu_log_mask(CPU_LOG_MMU,
                          "ia64 vhpt reserved translation %c"
                          " va=0x%016" PRIx64 " rid=0x%06" PRIx32
                          " pte=0x%016" PRIx64 " itir=0x%016" PRIx64 "\n",
                          is_ifetch ? 'i' : 'd', va, rid, translation, itir);
            return false;
        }
        if (pte) {
            *pte = translation;
        }

        {
            uint64_t page_mask;
            uint8_t long_page_shift =
                (itir >> IA64_ITIR_PS_SHIFT) & IA64_ITIR_PS_MASK;

            page_mask = (1ULL << long_page_shift) - 1;
            {
                uint8_t ar = ia64_pte_ar(translation);
                uint8_t pl = ia64_pte_pl(translation);
                uint32_t entry_key = (itir & IA64_ITIR_KEY_MASK) >>
                                     IA64_ITIR_KEY_SHIFT;

                if (access_key) {
                    *access_key = entry_key;
                }
                *perm = ia64_pte_perm(translation, access_level);
                *pa = ((translation & IA64_PTE_PPN_MASK) & ~page_mask) |
                      (va & page_mask);
                ia64_vhpt_install_tc(env, va, rid, is_ifetch, *pa,
                                     1ULL << long_page_shift, ar, pl, *perm,
                                     entry_key, translation);
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
long_miss:
    qemu_log_mask(CPU_LOG_MMU,
                  "ia64 vhpt miss %c va=0x%016" PRIx64
                  " rid=0x%06" PRIx32 " base=0x%016" PRIx64
                  " hash=0x%016" PRIx64 "\n",
                  is_ifetch ? 'i' : 'd', va, rid, vhpt_base, hash);
    return false;
}

bool ia64_vhpt_walk(CPUIA64State *env, uint64_t va, uint32_t rid,
                    bool is_ifetch, bool is_rse, uint8_t access_level,
                    uint64_t *pa, uint8_t *perm)
{
    return ia64_vhpt_walk_full(env, va, rid, is_ifetch, is_rse, access_level,
                               pa, perm, NULL, NULL);
}

/* ---- ITC insert helper (software-managed TLB insert) ---- */

void helper_itc_insert(CPUIA64State *env, uint64_t pte, uint32_t is_data)
{
    IA64TlbEntry *tlb;
    uint16_t *cnt;
    uint16_t *next_replace;
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

    if (!ia64_va_is_implemented(env->cr_ifa)) {
        ia64_raise_unimplemented_data_address(
            env, env->cr_ifa, 0, true, false, ia64_current_code_tlb_ed(env));
    }

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
}

/* ---- mov from PSR helper ---- */

uint64_t helper_mov_psrgr_read(CPUIA64State *env, uint32_t unused)
{
    (void)unused;
    /*
     * PSR.ri is only defined as an rfi restart selector and becomes
     * undefined after the restarted IA-64 instruction begins execution.
     * The translator keeps it live internally to select a nonzero TB entry
     * slot, so expose the chosen architectural undefined value of zero.
     */
    return env->psr & ~IA64_PSR_RI_MASK;
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

uint64_t helper_validate_rr_value(CPUIA64State *env, uint64_t value,
                                  uint64_t fault_ip, uint64_t raw,
                                  uint32_t slot)
{
    uint8_t ps = (value >> 2) & 0x3f;
    uint64_t allowed = 1ULL | (0x3fULL << 2) |
                       (((1ULL << IA64_IMPL_RID_BITS) - 1) << 8);

    if ((value & ~allowed) || !ia64_page_shift_insertable(ps)) {
        env->cr_isr = 0x30;
        helper_raise_exception(env, IA64_EXCP_RESERVED_REG_FIELD,
                               fault_ip, raw, slot);
    }
    return value;
}

/* ---- mov to Region Register helper ---- */

void helper_mov_grrr_write(CPUIA64State *env, uint64_t rr_addr, uint64_t value)
{
    uint32_t rr_num = (rr_addr >> 61) & 7;

    if (env->rr[rr_num] == value) {
        return;
    }

    env->rr[rr_num] = value;
    /*
     * The softmmu TLB and jump cache contain virtual-address state, so both
     * must be discarded when the RID changes.  tlb_flush() does both.  The
     * global TB hash is keyed by the translated physical page as well as the
     * virtual PC, so its TBs remain valid and can be reused when this address
     * space becomes current again.
     */
    tlb_flush(env_cpu(env));
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
    env->alat_active_count = 0;
}

void helper_clrrrb_rse(CPUIA64State *env, uint32_t predicate_only)
{
    /*
     * clrrrb resets the rename bases (SDM Vol.2 table 6-2 notes; Vol.3
     * clrrrb).  The stacked physical registers do not move, so the
     * virtual view is re-derived under the new mapping.
     */
    ia64_rse_sync_frame_out(env);
    if (predicate_only) {
        env->cfm_rrb_pr = 0;
    } else {
        env->cfm_rrb_gr = 0;
        env->cfm_rrb_fr = 0;
        env->cfm_rrb_pr = 0;
    }
    ia64_rse_sync_frame_in(env);
    ia64_invalidate_stacked_alat(env);
    ia64_rse_check(env, "clrrrb");
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
    IA64MemorySpeculation spec;
    int free_index = -1;
    int match_index = -1;
    int i;

    if (!ia64_data_address_to_phys_attr(env, addr, &pa, &spec) ||
        !ia64_memory_allows_advanced_load(spec)) {
        return;
    }

    for (i = 0; i < IA64_ALAT_ENTRIES; i++) {
        if (!env->alat[i].valid) {
            if (free_index < 0) {
                free_index = i;
            }
        } else if (env->alat[i].reg == reg && env->alat[i].fp == fp) {
            if (match_index < 0) {
                match_index = i;
            } else {
                /* A register can name at most one ALAT entry. */
                ia64_alat_invalidate_entry(env, &env->alat[i]);
            }
        }
    }

    i = match_index >= 0 ? match_index : free_index;
    if (i < 0) {
        return;
    }
    if (!env->alat[i].valid) {
        env->alat_active_count++;
    }
    env->alat[i].phys_addr = pa;
    env->alat[i].size = size;
    env->alat[i].reg = reg;
    env->alat[i].fp = fp;
    env->alat[i].valid = true;
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

    if (env->alat_active_count == 0) {
        return -1;
    }

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
            ia64_alat_invalidate_entry(env, &env->alat[i]);
        }
        return 0;
    }
    if (clear) {
        ia64_alat_invalidate_entry(env, &env->alat[i]);
    }
    return 1;
}

void helper_invalidate_alat_reg(CPUIA64State *env, uint32_t reg)
{
    int i = ia64_find_alat_reg(env, reg, false);

    if (i >= 0) {
        ia64_alat_invalidate_entry(env, &env->alat[i]);
    }
}

void helper_invalidate_alat_fp_reg(CPUIA64State *env, uint32_t reg)
{
    int i = ia64_find_alat_reg(env, reg, true);

    if (i >= 0) {
        ia64_alat_invalidate_entry(env, &env->alat[i]);
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

    if (env->alat_active_count == 0) {
        return;
    }

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

uint64_t helper_cloop_zero_st1(CPUIA64State *env, uint32_t base_reg,
                               uint32_t mmu_idx, uint32_t max_stores)
{
    uintptr_t ra = GETPC();
    uint64_t lc = env->ar[65];
    uint64_t done = 0;
    uint64_t limit = MIN(lc, (uint64_t)max_stores);

    if (lc == 0 || limit == 0) {
        return 0;
    }

    while (done < limit) {
        uint64_t addr = env->gr[base_reg];
        uint64_t page_left = TARGET_PAGE_SIZE - (addr & (TARGET_PAGE_SIZE - 1));
        uint64_t span = MIN(limit - done, page_left);
        void *host = NULL;
        int flags = -1;

        /*
         * The helper is called from br.cloop after the current loop-body store.
         * Each future store is reached by a taken branch first, so LC has
         * already been decremented before a faulting store is observed.
         */
        env->ar[65] = lc - done - 1;
        env->gr[base_reg] = addr;

        flags = probe_access_flags(env, addr, (int)span, MMU_DATA_STORE,
                                   mmu_idx, false, &host, ra);
        if (flags == 0 && host != NULL) {
            memset(host, 0, span);
            ia64_invalidate_alat_store(env, addr, (uint32_t)span);
            env->gr[base_reg] = addr + span;
            done += span;
            env->ar[65] = lc - done;
            continue;
        }

        cpu_stb_mmuidx_ra(env, addr, 0, mmu_idx, ra);
        ia64_invalidate_alat_store(env, addr, 1);
        env->gr[base_reg] = addr + 1;
        done++;
        env->ar[65] = lc - done;
    }

    if (done < lc) {
        env->ar[65] = lc - done - 1;
        return 1;
    }
    return 0;
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
