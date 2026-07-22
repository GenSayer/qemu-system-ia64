/*
 * IA-64 TCG helper ABI adapters for packed integer operations.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "arch/arch.h"

void helper_simd_pavg(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                      uint32_t r2, uint32_t r3)
{
    ia64_simd_pavg(env, op_sel, r1, r2, r3);
}

void helper_simd_pcmp(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                      uint32_t r2, uint32_t r3)
{
    ia64_simd_pcmp(env, op_sel, r1, r2, r3);
}

void helper_simd_pminmax(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                         uint32_t r2, uint32_t r3)
{
    ia64_simd_pminmax(env, op_sel, r1, r2, r3);
}

void helper_simd_pmpy(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                      uint32_t r2, uint32_t r3, uint32_t shift)
{
    ia64_simd_pmpy(env, op_sel, r1, r2, r3, shift);
}

void helper_simd_psad1(CPUIA64State *env, uint32_t r1, uint32_t r2,
                       uint32_t r3)
{
    ia64_simd_psad1(env, r1, r2, r3);
}

void helper_simd_mux(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                     uint32_t r2, uint32_t imm)
{
    ia64_simd_mux(env, op_sel, r1, r2, imm);
}

void helper_simd_mix(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                     uint32_t r2, uint32_t r3)
{
    ia64_simd_mix(env, op_sel, r1, r2, r3);
}

void helper_simd_unpack(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                        uint32_t r2, uint32_t r3)
{
    ia64_simd_unpack(env, op_sel, r1, r2, r3);
}

void helper_simd_pack(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                      uint32_t r2, uint32_t r3)
{
    ia64_simd_pack(env, op_sel, r1, r2, r3);
}

void helper_simd_czx(CPUIA64State *env, uint32_t op_sel, uint32_t r1,
                     uint32_t r2, uint32_t r3)
{
    ia64_simd_czx(env, op_sel, r1, r2, r3);
}

void helper_simd_sum(CPUIA64State *env, uint32_t r1, uint32_t r2,
                     uint32_t r3)
{
    ia64_simd_sum(env, r1, r2, r3);
}
