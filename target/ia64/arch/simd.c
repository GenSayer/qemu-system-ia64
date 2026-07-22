/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * IA-64 packed-integer CPU-state adapters.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "arch/arch.h"
#include "arch/simd-ops.h"

void ia64_simd_pavg(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                    uint32_t r2, uint32_t r3)
{
    env->gr[r1] = ia64_simd_pavg_value(op_sel, env->gr[r2], env->gr[r3]);
}

void ia64_simd_pcmp(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                    uint32_t r2, uint32_t r3)
{
    env->gr[r1] = ia64_simd_pcmp_value(op_sel, env->gr[r2], env->gr[r3]);
}

void ia64_simd_pminmax(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                       uint32_t r2, uint32_t r3)
{
    env->gr[r1] = ia64_simd_pminmax_value(op_sel, env->gr[r2], env->gr[r3]);
}

void ia64_simd_pmpy(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                    uint32_t r2, uint32_t r3, uint32_t shift)
{
    if (r1 != IA64_GR_ZERO) {
        env->gr[r1] = ia64_simd_pmpy_value(op_sel, env->gr[r2], env->gr[r3],
                                            shift);
    }
}

void ia64_simd_psad1(CPUIA64State *env, uint32_t r1, uint32_t r2,
                     uint32_t r3)
{
    env->gr[r1] = ia64_simd_psad1_value(env->gr[r2], env->gr[r3]);
}

void ia64_simd_mux(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                   uint32_t r2, uint32_t imm)
{
    if (r1 != IA64_GR_ZERO) {
        env->gr[r1] = ia64_simd_mux_value(op_sel, env->gr[r2], imm);
    }
}

void ia64_simd_mix(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                   uint32_t r2, uint32_t r3)
{
    env->gr[r1] = ia64_simd_mix_value(op_sel, env->gr[r2], env->gr[r3]);
}

void ia64_simd_unpack(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                      uint32_t r2, uint32_t r3)
{
    env->gr[r1] = ia64_simd_unpack_value(op_sel, env->gr[r2], env->gr[r3]);
}

void ia64_simd_pack(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                    uint32_t r2, uint32_t r3)
{
    env->gr[r1] = ia64_simd_pack_value(op_sel, env->gr[r2], env->gr[r3]);
}

void ia64_simd_czx(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                   uint32_t r2, uint32_t r3)
{
    env->gr[r1] = ia64_simd_czx_value(op_sel, env->gr[r2]);
}

void ia64_simd_sum(CPUIA64State *env, uint32_t r1, uint32_t r2, uint32_t r3)
{
    env->gr[r1] = ia64_simd_sum_value(env->gr[r2], env->gr[r3]);
}
