/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * TCG softmmu implementation of the IA-64 execution access boundary.
 */

#include "qemu/osdep.h"
#include "qemu/atomic128.h"
#include "cpu.h"
#include "exec-access.h"
#include "accel/tcg/cpu-ldst.h"
#include "accel/tcg/probe.h"
#include "exec/cpu-common.h"
#include "exec/tlb-flags.h"
#include "exec/translation-block.h"
#include "system/address-spaces.h"
#include "system/memory.h"

bool ia64_exec_is_parallel(CPUIA64State *env)
{
    return tcg_cflags_has(env_cpu(env), CF_PARALLEL);
}

int ia64_exec_mmu_index(CPUIA64State *env, bool ifetch)
{
    return cpu_mmu_index(env_cpu(env), ifetch);
}

void ia64_exec_exit_atomic(CPUIA64State *env, uintptr_t ra)
{
    cpu_loop_exit_atomic(env_cpu(env), ra);
}

uint64_t ia64_exec_load_data(CPUIA64State *env, uint64_t addr,
                             unsigned size, bool big_endian, uintptr_t ra)
{
    switch (size) {
    case 1:
        return cpu_ldub_data_ra(env, addr, ra);
    case 2:
        return big_endian ? cpu_lduw_be_data_ra(env, addr, ra) :
                            cpu_lduw_le_data_ra(env, addr, ra);
    case 4:
        return big_endian ? cpu_ldl_be_data_ra(env, addr, ra) :
                            cpu_ldl_le_data_ra(env, addr, ra);
    case 8:
        return big_endian ? cpu_ldq_be_data_ra(env, addr, ra) :
                            cpu_ldq_le_data_ra(env, addr, ra);
    default:
        g_assert_not_reached();
    }
}

void ia64_exec_store_data(CPUIA64State *env, uint64_t addr, uint64_t value,
                          unsigned size, bool big_endian, uintptr_t ra)
{
    switch (size) {
    case 1:
        cpu_stb_data_ra(env, addr, value, ra);
        return;
    case 2:
        if (big_endian) {
            cpu_stw_be_data_ra(env, addr, value, ra);
        } else {
            cpu_stw_le_data_ra(env, addr, value, ra);
        }
        return;
    case 4:
        if (big_endian) {
            cpu_stl_be_data_ra(env, addr, value, ra);
        } else {
            cpu_stl_le_data_ra(env, addr, value, ra);
        }
        return;
    case 8:
        if (big_endian) {
            cpu_stq_be_data_ra(env, addr, value, ra);
        } else {
            cpu_stq_le_data_ra(env, addr, value, ra);
        }
        return;
    default:
        g_assert_not_reached();
    }
}

uint64_t ia64_exec_load_mmuidx(CPUIA64State *env, uint64_t addr,
                               unsigned size, bool big_endian, int mmu_idx,
                               uintptr_t ra)
{
    switch (size) {
    case 1:
        return cpu_ldub_mmuidx_ra(env, addr, mmu_idx, ra);
    case 8:
        return big_endian ? cpu_ldq_be_mmuidx_ra(env, addr, mmu_idx, ra) :
                            cpu_ldq_le_mmuidx_ra(env, addr, mmu_idx, ra);
    default:
        g_assert_not_reached();
    }
}

void ia64_exec_store_mmuidx(CPUIA64State *env, uint64_t addr, uint64_t value,
                            unsigned size, bool big_endian, int mmu_idx,
                            uintptr_t ra)
{
    switch (size) {
    case 1:
        cpu_stb_mmuidx_ra(env, addr, value, mmu_idx, ra);
        return;
    case 8:
        if (big_endian) {
            cpu_stq_be_mmuidx_ra(env, addr, value, mmu_idx, ra);
        } else {
            cpu_stq_le_mmuidx_ra(env, addr, value, mmu_idx, ra);
        }
        return;
    default:
        g_assert_not_reached();
    }
}

Int128 ia64_exec_load_16(CPUIA64State *env, uint64_t addr, MemOpIdx oi,
                         uintptr_t ra)
{
    return cpu_ld16_mmu(env, addr, oi, ra);
}

void ia64_exec_store_16(CPUIA64State *env, uint64_t addr, Int128 value,
                        MemOpIdx oi, uintptr_t ra)
{
    cpu_st16_mmu(env, addr, value, oi, ra);
}

uint64_t ia64_exec_cmpxchg(CPUIA64State *env, uint64_t addr, uint64_t cmp,
                           uint64_t value, unsigned size, bool big_endian,
                           MemOpIdx oi, uintptr_t ra)
{
    switch (size) {
    case 1:
        return cpu_atomic_cmpxchgb_mmu(env, addr, cmp, value, oi, ra);
    case 2:
        return big_endian ?
            cpu_atomic_cmpxchgw_be_mmu(env, addr, cmp, value, oi, ra) :
            cpu_atomic_cmpxchgw_le_mmu(env, addr, cmp, value, oi, ra);
    case 4:
        return big_endian ?
            cpu_atomic_cmpxchgl_be_mmu(env, addr, cmp, value, oi, ra) :
            cpu_atomic_cmpxchgl_le_mmu(env, addr, cmp, value, oi, ra);
    case 8:
        return big_endian ?
            cpu_atomic_cmpxchgq_be_mmu(env, addr, cmp, value, oi, ra) :
            cpu_atomic_cmpxchgq_le_mmu(env, addr, cmp, value, oi, ra);
    default:
        g_assert_not_reached();
    }
}

Int128 ia64_exec_cmpxchg_16(CPUIA64State *env, uint64_t addr, Int128 cmp,
                            Int128 value, bool big_endian, MemOpIdx oi,
                            uintptr_t ra)
{
#if HAVE_CMPXCHG128
    return big_endian ?
        cpu_atomic_cmpxchgo_be_mmu(env, addr, cmp, value, oi, ra) :
        cpu_atomic_cmpxchgo_le_mmu(env, addr, cmp, value, oi, ra);
#else
    g_assert_not_reached();
#endif
}

void ia64_exec_probe_write(CPUIA64State *env, uint64_t addr, int size,
                           int mmu_idx, uintptr_t ra)
{
    probe_write(env, addr, size, mmu_idx, ra);
}

bool ia64_exec_probe_host(CPUIA64State *env, uint64_t addr, int size,
                          MMUAccessType access_type, int mmu_idx,
                          void **host, uintptr_t ra)
{
    int flags = probe_access_flags(env, addr, size, access_type, mmu_idx,
                                   false, host, ra);

    return flags == 0 && *host != NULL;
}

bool ia64_exec_probe_writeback_ram(CPUIA64State *env, uint64_t addr,
                                   int size, MMUAccessType access_type,
                                   bool *direct, uintptr_t ra)
{
    CPUTLBEntryFull *full;
    void *host;
    int mmu_idx = cpu_mmu_index(env_cpu(env), false);
    int flags = probe_access_full(env, addr, size, access_type, mmu_idx,
                                  false, &host, &full, ra);

    *direct = !(flags & (TLB_MMIO | TLB_WATCHPOINT));
    return full->extra.ia64.memory_attribute == IA64_PTE_MA_WB &&
           memory_region_is_ram(full->section->mr);
}

bool ia64_exec_probe_writeback(CPUIA64State *env, uint64_t addr,
                               int size, MMUAccessType access_type,
                               uintptr_t ra)
{
    CPUState *cs = env_cpu(env);
    int mmu_idx = cpu_mmu_index(cs, false);
    bool writeback = true;

    while (size > 0) {
        CPUTLBEntryFull *full;
        void *host;
        int page_offset = addr & ((1u << TARGET_PAGE_BITS) - 1);
        int page_left = (1u << TARGET_PAGE_BITS) - page_offset;
        int chunk = MIN(size, page_left);
        int flags = probe_access_full(env, addr, chunk, access_type,
                                      mmu_idx, false, &host, &full, ra);

        if (flags & TLB_WATCHPOINT) {
            cpu_check_watchpoint(cs, addr, chunk, full->attrs,
                                 BP_MEM_ACCESS, ra);
        }
        writeback &= full->extra.ia64.memory_attribute == IA64_PTE_MA_WB;
        addr += chunk;
        if (env->psr & IA64_PSR_IS) {
            addr = (uint32_t)addr;
        }
        size -= chunk;
    }
    return writeback;
}

bool ia64_exec_advanced_load_allowed(CPUIA64State *env, uint64_t addr,
                                     int mmu_idx)
{
    CPUTLBEntryFull *full;
    void *host;
    int flags = probe_access_full(env, addr, 1, MMU_DATA_LOAD, mmu_idx, true,
                                  &host, &full, 0);

    if (flags & TLB_INVALID_MASK) {
        return true;
    }
    return full->extra.ia64.speculation != IA64_MEM_NON_SPECULATIVE;
}

bool ia64_exec_debug_read(CPUState *cs, uint64_t addr, void *buffer,
                          size_t size)
{
    return cpu_memory_rw_debug(cs, addr, buffer, size, false) == 0;
}

bool ia64_exec_physical_rw(uint64_t addr, void *buffer, size_t size,
                           bool is_write)
{
    return address_space_rw(&address_space_memory, addr,
                            MEMTXATTRS_UNSPECIFIED, buffer, size,
                            is_write) == MEMTX_OK;
}
