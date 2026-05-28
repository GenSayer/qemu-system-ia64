#ifndef IA64_CPU_H
#define IA64_CPU_H

#include "cpu-qom.h"
#include "exec/cpu-common.h"
#include "exec/cpu-interrupt.h"
#include "fpu/softfloat.h"
#include "qemu/timer.h"

#ifdef CONFIG_USER_ONLY
#error "IA-64 target currently supports system mode only"
#endif

#define CPU_RESOLVING_TYPE TYPE_IA64_CPU

#undef NB_MMU_MODES
#define MMU_PHYS_IDX     0
#define MMU_IDX_VIRT     1
#define NB_MMU_MODES     2

#define IA64_GR_COUNT    128
#define IA64_PR_COUNT    64
#define IA64_BR_COUNT    8
#define IA64_AR_COUNT    128
#define IA64_CR_COUNT    128
#define IA64_DBR_COUNT   8
#define IA64_FR_COUNT    128
#define IA64_IBR_COUNT   8
#define IA64_PMC_COUNT   32
#define IA64_PMD_COUNT   64
#define IA64_PKR_COUNT   16
#define IA64_MSR_COUNT   1024
#define IA64_TLB_MAX     64
#define IA64_RSE_FRAME_MAX 128
#define IA64_EXCP_FRAME_MAX 8

#define IA64_IMPL_PA_BITS 50
#define IA64_IMPL_VA_MSB 60
#define IA64_IMPL_RID_BITS 24
#define IA64_IMPL_KEY_BITS 24

#define IA64_PAL_DISPATCH_HALTED  (1U << 0)
#define IA64_PAL_DISPATCH_EXIT_TB (1U << 1)

#define IA64_FR_ONE      0x3ff0000000000000ULL

/* ---- PSR bit definitions ---- */
#define IA64_PSR_IC      (1ULL << 13)
#define IA64_PSR_I       (1ULL << 14)
#define IA64_PSR_UM_MASK 0x7fULL
#define IA64_PSR_AC      (1ULL << 3)
#define IA64_PSR_DT      (1ULL << 17)
#define IA64_PSR_RT      (1ULL << 27)
#define IA64_PSR_IT      (1ULL << 36)
#define IA64_PSR_CPL_MASK (3ULL << 32)
#define IA64_PSR_CPL_SHIFT 32
#define IA64_PSR_BN      (1ULL << 44)
#define IA64_PSR_VM      (1ULL << 46)
#define IA64_PSR_ED      (1ULL << 43)
#define IA64_PSR_DA      (1ULL << 38)
#define IA64_PSR_DD      (1ULL << 39)
#define IA64_PSR_IA      (1ULL << 45)
#define IA64_PSR_RI_MASK (3ULL << 41)
#define IA64_PSR_RI_SHIFT  41
#define IA64_PSR_FAULT_SUPPRESS_MASK \
    (IA64_PSR_DA | IA64_PSR_DD | IA64_PSR_ED | IA64_PSR_IA)

#define IA64_REGION_SHIFT 61
#define IA64_REGION_MASK  7ULL
#define IA64_BUNDLE_SIZE  16ULL
#define IA64_IP_BUNDLE_MASK (~(IA64_BUNDLE_SIZE - 1))
#define IA64_REGION7_PHYS_MASK ((1ULL << IA64_REGION_SHIFT) - 1)
#define IA64_REGION7_IDENTITY_LIMIT 0x0000010000000000ULL
#define IA64_FW_IDENTITY_BASE 0x00100000ULL
#define IA64_FW_IDENTITY_SIZE 0x00100000ULL
#define IA64_FIRMWARE_IVT_BASE 0x10000ULL
#define IA64_FW_BOOT_IDENTITY_LIMIT IA64_REGION7_IDENTITY_LIMIT
#define IA64_LOCAL_SAPIC_VA   0xc0000000fee00000ULL
#define IA64_LOCAL_SAPIC_PA   0x00000000fee00000ULL
#define IA64_LOCAL_SAPIC_SIZE 0x00200000ULL
#define IA64_PAL_IO_BLOCK_PA  0x000080000c000000ULL

#define IA64_RR_RID_MASK   (0xffffffULL << 8)
#define IA64_RR_RID_SHIFT  8
#define IA64_RR_VE         (1ULL << 0)

static inline uint32_t ia64_rr_rid(uint64_t rr)
{
    return (rr & IA64_RR_RID_MASK) >> IA64_RR_RID_SHIFT;
}

static inline bool ia64_firmware_identity_pa(uint64_t va, uint64_t *pa)
{
    if (va >= IA64_FW_IDENTITY_BASE &&
        va < IA64_FW_IDENTITY_BASE + IA64_FW_IDENTITY_SIZE) {
        *pa = va;
        return true;
    }

    return false;
}

static inline bool ia64_region7_identity_pa(uint64_t va, uint64_t *pa)
{
    uint64_t phys = va & IA64_REGION7_PHYS_MASK;

    if (((va >> IA64_REGION_SHIFT) & IA64_REGION_MASK) != 7) {
        return false;
    }
    if (phys >= IA64_REGION7_IDENTITY_LIMIT) {
        return false;
    }

    *pa = phys;
    return true;
}

static inline bool ia64_region6_uncached_pa(uint64_t va, uint64_t *pa)
{
    uint64_t phys = va & IA64_REGION7_PHYS_MASK;

    if (((va >> IA64_REGION_SHIFT) & IA64_REGION_MASK) != 6) {
        return false;
    }

    *pa = phys;
    return true;
}

static inline bool ia64_psr_cpl0(uint64_t psr)
{
    return (psr & IA64_PSR_CPL_MASK) == 0;
}

static inline uint64_t ia64_ip_bundle_addr(uint64_t ip)
{
    return ip & IA64_IP_BUNDLE_MASK;
}

static inline uint8_t ia64_psr_cpl(uint64_t psr)
{
    return (psr & IA64_PSR_CPL_MASK) >> IA64_PSR_CPL_SHIFT;
}

static inline bool ia64_kernel_direct_data_pa(uint64_t psr, uint64_t rr,
                                              uint64_t va, uint64_t *pa)
{
    if (!ia64_psr_cpl0(psr)) {
        return false;
    }

    if (ia64_region6_uncached_pa(va, pa)) {
        return true;
    }

    return ia64_rr_rid(rr) == 0 && ia64_region7_identity_pa(va, pa);
}

static inline bool ia64_region6_local_sapic_pa(uint64_t va, uint64_t *pa)
{
    uint64_t phys;

    if (!ia64_region6_uncached_pa(va, &phys) ||
        phys < IA64_LOCAL_SAPIC_PA ||
        phys >= IA64_LOCAL_SAPIC_PA + IA64_LOCAL_SAPIC_SIZE) {
        return false;
    }

    *pa = phys;
    return true;
}

#define IA64_RI_0        (0ULL << 41)
#define IA64_RI_1        (1ULL << 41)
#define IA64_RI_2        (2ULL << 41)

/* ---- RSC bit definitions ---- */
#define IA64_RSC_MODE    0x3ULL
#define IA64_RSC_PL      0xcULL
#define IA64_RSC_LOADRS_SHIFT 16
#define IA64_RSC_LOADRS_MASK  0x3fffULL

/* ---- CFM mask definitions ---- */
#define IA64_CFM_SOF_MASK     0x7f
#define IA64_CFM_SOL_MASK     (0x7f << 7)
#define IA64_CFM_SOL_SHIFT    7
#define IA64_CFM_SOR_MASK     (0x1f << 14)
#define IA64_CFM_SOR_SHIFT    14
#define IA64_CFM_RRB_GR_MASK  (0x1f << 18)
#define IA64_CFM_RRB_GR_SHIFT 18
#define IA64_IFS_V            (1ULL << 63)
#define IA64_IFS_IFM_MASK     (IA64_CFM_SOF_MASK | IA64_CFM_SOL_MASK | \
                               IA64_CFM_SOR_MASK | IA64_CFM_RRB_GR_MASK)

/* ---- PFS field definitions ---- */
#define IA64_PFS_PFM_MASK     ((1ULL << 38) - 1)
#define IA64_PFS_PEC_SHIFT    52
#define IA64_PFS_PEC_MASK     (0x3fULL << IA64_PFS_PEC_SHIFT)
#define IA64_PFS_PPL_SHIFT    62
#define IA64_PFS_PPL_MASK     (0x3ULL << IA64_PFS_PPL_SHIFT)

/* ---- ISR fields ---- */
#define IA64_ISR_CODE_MASK   0xffff
#define IA64_ISR_VECTOR_MASK (0xffUL << 16)
#define IA64_ISR_VECTOR_SHIFT 16
#define IA64_ISR_X           (1ULL << 32)
#define IA64_ISR_W           (1ULL << 33)
#define IA64_ISR_R           (1ULL << 34)
#define IA64_ISR_NA          (1ULL << 35)
#define IA64_ISR_SP          (1ULL << 36)
#define IA64_ISR_RS          (1ULL << 37)
#define IA64_ISR_IR          (1ULL << 38)
#define IA64_ISR_NI          (1ULL << 39)
#define IA64_ISR_EI_MASK     (3ULL << 41)
#define IA64_ISR_EI_SHIFT    41
#define IA64_ISR_ED          (1ULL << 43)

/* ---- ITIR fields ---- */
#define IA64_ITIR_PS_MASK    0x3f
#define IA64_ITIR_PS_SHIFT   2
#define IA64_ITIR_KEY_MASK   (0xffffffULL << 8)
#define IA64_ITIR_KEY_SHIFT  8

/* ---- PTE fields ---- */
#define IA64_PTE_PRESENT  (1ULL << 0)
#define IA64_PTE_ACCESSED (1ULL << 5)
#define IA64_PTE_DIRTY    (1ULL << 6)
#define IA64_PTE_ED       (1ULL << 52)

/* ---- PTA fields ---- */
#define IA64_PTA_VE          (1ULL << 0)
#define IA64_PTA_SIZE_MASK   (0x3fULL << 2)
#define IA64_PTA_SIZE_SHIFT  2
#define IA64_PTA_VF          (1ULL << 8)
#define IA64_PTA_BASE_MASK   (~0x7fffULL)
#define IA64_PTA_BASE_SHIFT  15

/* ---- DCR fields ---- */
#define IA64_DCR_PP          (1ULL << 0)
#define IA64_DCR_LC          (1ULL << 2)
#define IA64_DCR_DM          (1ULL << 8)
#define IA64_DCR_DP          (1ULL << 9)
#define IA64_DCR_DK          (1ULL << 10)
#define IA64_DCR_DX          (1ULL << 11)
#define IA64_DCR_DR          (1ULL << 12)
#define IA64_DCR_DA          (1ULL << 13)
#define IA64_DCR_DD          (1ULL << 14)

/* ---- Local SAPIC CR register indices ---- */
#define IA64_CR_SAPIC_LID     64
#define IA64_CR_SAPIC_IVR     65
#define IA64_CR_SAPIC_TPR     66
#define IA64_CR_SAPIC_EOI     67
#define IA64_CR_SAPIC_IRR0    68
#define IA64_CR_SAPIC_IRR1    69
#define IA64_CR_SAPIC_IRR2    70
#define IA64_CR_SAPIC_IRR3    71
#define IA64_CR_ITV           72
#define IA64_CR_PMV           73
#define IA64_CR_CMCV          74
#define IA64_CR_LRR0          80
#define IA64_CR_LRR1          81

#define IA64_TIMER_VECTOR         239
#define IA64_SPURIOUS_VECTOR      0x0F
#define IA64_VECTOR_MASKED        (1ULL << 16)
#define IA64_TPR_MIC_MASK         0x00000000000000f0ULL
#define IA64_TPR_MMI              (1ULL << 16)
#define IA64_TPR_WRITABLE_MASK    (IA64_TPR_MIC_MASK | IA64_TPR_MMI)

/* ---- TLB permissions ---- */
#define IA64_TLB_R           1
#define IA64_TLB_W           2
#define IA64_TLB_X           4
#define IA64_TLB_ALL         7

static inline uint8_t ia64_tlb_effective_perm(uint8_t ar, uint8_t pl,
                                              uint8_t access_level)
{
    if (access_level > 3 || pl > 3) {
        return 0;
    }

    switch (ar & 7) {
    case 0:
        return access_level <= pl ? IA64_TLB_R : 0;
    case 1:
        return access_level <= pl ? (IA64_TLB_R | IA64_TLB_X) : 0;
    case 2:
        return access_level <= pl ? (IA64_TLB_R | IA64_TLB_W) : 0;
    case 3:
        return access_level <= pl ? IA64_TLB_ALL : 0;
    case 4:
        if (access_level > pl) {
            return 0;
        }
        return access_level < pl ? (IA64_TLB_R | IA64_TLB_W) : IA64_TLB_R;
    case 5:
        if (access_level > pl) {
            return 0;
        }
        return access_level < pl ? IA64_TLB_ALL : (IA64_TLB_R | IA64_TLB_X);
    case 6:
        if (access_level > pl) {
            return 0;
        }
        return access_level < pl ? IA64_TLB_ALL : (IA64_TLB_R | IA64_TLB_W);
    case 7:
        return access_level == 0 ? (IA64_TLB_R | IA64_TLB_X) : IA64_TLB_X;
    default:
        return 0;
    }
}

/* ---- ALAT (Advanced Load Address Table) ---- */
#define IA64_ALAT_ENTRIES    32

typedef struct IA64AlatEntry {
    uint64_t phys_addr;
    uint8_t  size;
    uint8_t  reg;
    bool     fp;
    bool     valid;
} IA64AlatEntry;

typedef struct IA64ExceptionFrame {
    uint64_t gr[IA64_GR_COUNT - 32];
    uint64_t nat[2];
    uint64_t ipsr;
    uint64_t iip;
    uint64_t ifs;
    uint64_t ifm;
    uint64_t bsp;
    uint64_t bspstore;
    uint64_t ifa;
    uint64_t isr;
    uint64_t itir;
    uint64_t iipa;
    uint64_t iim;
    uint64_t iha;
    uint64_t interrupted_iip;
    uint64_t rnat;
    uint32_t rse_cumulative_words;
    uint32_t rse_spill_words;
    uint64_t rse_spill_base;
    bool rse_bspstore_switched;
    bool rse_flushed;
    uint32_t rse_frame_depth;
    uint64_t rse_frame_gr[IA64_RSE_FRAME_MAX][IA64_GR_COUNT - 32];
    uint64_t rse_frame_nat[IA64_RSE_FRAME_MAX][2];
    uint8_t rse_frame_sof[IA64_RSE_FRAME_MAX];
    uint8_t rse_frame_sol[IA64_RSE_FRAME_MAX];
    uint8_t rse_frame_sor[IA64_RSE_FRAME_MAX];
    uint8_t rse_frame_rrb_gr[IA64_RSE_FRAME_MAX];
    uint64_t rse_frame_bsp[IA64_RSE_FRAME_MAX];
    uint64_t rse_frame_return_ip[IA64_RSE_FRAME_MAX];
    uint32_t rse_frame_cumulative_words[IA64_RSE_FRAME_MAX];
    uint32_t rse_cover_depth;
    uint64_t rse_cover_gr[IA64_RSE_FRAME_MAX][IA64_GR_COUNT - 32];
    uint64_t rse_cover_nat[IA64_RSE_FRAME_MAX][2];
    uint8_t rse_cover_sof[IA64_RSE_FRAME_MAX];
    uint64_t rse_cover_bsp[IA64_RSE_FRAME_MAX];
} IA64ExceptionFrame;

/* ---- Exception type enum (internal IDs, not IVT vectors) ---- */
typedef enum IA64Exception {
    IA64_EXCP_NONE = 0,
    IA64_EXCP_BREAK = 1,
    IA64_EXCP_ILLEGAL = 2,
    IA64_EXCP_RESERVED_TEMPLATE = 3,
    IA64_EXCP_VHPT_FAULT = 4,
    IA64_EXCP_ITLB_FAULT = 5,
    IA64_EXCP_DTLB_FAULT = 6,
    IA64_EXCP_ALT_ITLB = 7,
    IA64_EXCP_ALT_DTLB = 8,
    IA64_EXCP_DATA_NESTED_TLB = 9,
    IA64_EXCP_DATA_ACCESS = 10,
    IA64_EXCP_GENERAL = 11,
    IA64_EXCP_NAT_CONSUMPTION = 12,
    IA64_EXCP_EXTINT = 13,
    IA64_EXCP_UNALIGNED = 14,
    IA64_EXCP_PAGE_NOT_PRESENT = 15,
    IA64_EXCP_INST_ACCESS = 16,
    IA64_EXCP_DATA_DIRTY = 17,
    IA64_EXCP_INST_ACCESS_BIT = 18,
    IA64_EXCP_DATA_ACCESS_BIT = 19,
    IA64_EXCP_MAX,
} IA64Exception;

/* ---- IVT vector mapping table ---- */
extern const uint16_t ia64_ivt_vectors[IA64_EXCP_MAX];

static inline IA64Exception
ia64_pte_exception_for_access(uint64_t pte, uint8_t perm, uint8_t needed,
                              bool is_ifetch, bool is_write, uint64_t psr)
{
    if (!(pte & IA64_PTE_PRESENT)) {
        return IA64_EXCP_PAGE_NOT_PRESENT;
    }

    if ((perm & needed) != needed) {
        return is_ifetch ? IA64_EXCP_INST_ACCESS : IA64_EXCP_DATA_ACCESS;
    }

    if (is_ifetch) {
        if (!(pte & IA64_PTE_ACCESSED) && !(psr & IA64_PSR_IA)) {
            return IA64_EXCP_INST_ACCESS_BIT;
        }
    } else {
        if (!(pte & IA64_PTE_ACCESSED) && !(psr & IA64_PSR_DA)) {
            return IA64_EXCP_DATA_ACCESS_BIT;
        }
        if (is_write && !(pte & IA64_PTE_DIRTY) &&
            !(psr & IA64_PSR_DA)) {
            return IA64_EXCP_DATA_DIRTY;
        }
    }

    return IA64_EXCP_NONE;
}

/* ---- TLB entry ---- */
typedef struct IA64TlbEntry {
    uint64_t va;
    uint64_t pa;
    uint64_t ps;
    uint64_t pte;
    uint8_t  perm;
    uint8_t  ar;
    uint8_t  pl;
    uint8_t  valid;
    uint8_t  is_tr;
    uint8_t  pending_purge;
    uint32_t rid;
    uint32_t key;
    uint8_t  slot;
} IA64TlbEntry;

bool ia64_tlb_lookup(const IA64TlbEntry *tlb, uint8_t tlb_count,
                     uint64_t va, uint32_t rid, uint8_t access_level,
                     bool is_ifetch, uint64_t *pa, uint8_t *perm);

const IA64TlbEntry *ia64_tlb_find(const IA64TlbEntry *tlb,
                                  uint8_t tlb_count, uint64_t va,
                                  uint32_t rid, bool is_ifetch);

bool ia64_tlb_match(const IA64TlbEntry *entry, uint64_t va,
                    uint32_t rid, bool is_ifetch);

bool ia64_tlb_probe(const IA64TlbEntry *tlb, uint8_t tlb_count,
                    uint64_t va, uint32_t rid, uint8_t access_level,
                    bool is_ifetch, uint64_t *pa, uint8_t *perm);

static inline bool ia64_tlb_entry_present(const IA64TlbEntry *entry)
{
    return entry->pte & IA64_PTE_PRESENT;
}

static inline void ia64_tlb_entry_translate(const IA64TlbEntry *entry,
                                            uint64_t va,
                                            uint8_t access_level,
                                            uint64_t *pa, uint8_t *perm)
{
    uint64_t page_offset = va & (entry->ps - 1);

    *pa = (entry->pa & ~(entry->ps - 1)) | page_offset;
    *perm = ia64_tlb_entry_present(entry) ?
            ia64_tlb_effective_perm(entry->ar, entry->pl, access_level) : 0;
}

/* ---- CPU architectural state ---- */
typedef struct CPUArchState {
    /* General / Predicate / Branch registers */
    uint64_t gr[IA64_GR_COUNT];
    uint64_t pr[IA64_PR_COUNT];
    uint64_t br[IA64_BR_COUNT];
    uint64_t ip;
    uint64_t last_successful_bundle;
    uint64_t psr;
    /* PSR.ic changes remain in-flight until a data serialization event. */
    bool psr_ic_inflight;
    uint64_t psr_suppression_before_insn;

    /* NaT bits for GRs (2x64 bits, little-endian bit numbering) */
    uint64_t nat[2];

    /* Inactive bank for GR16-GR31 selected by PSR.bn/bsw. */
    uint64_t banked_gr[16];
    uint16_t banked_nat;

    /* Fault/exception state (for simple HMP reporting) */
    uint64_t fault_ip;
    uint64_t fault_imm;
    uint64_t fault_tmpl;
    uint32_t exception;
    uint32_t fault_slot;

    /* Control Registers */
    uint64_t cr[IA64_CR_COUNT];
#define cr_dcr    cr[0]
#define cr_itm    cr[1]
#define cr_iva    cr[2]
#define cr_pta    cr[8]
#define cr_ipsr   cr[16]
#define cr_isr    cr[17]
#define cr_iip    cr[19]
#define cr_ifa    cr[20]
#define cr_itir   cr[21]
#define cr_iipa   cr[22]
#define cr_ifs    cr[23]
#define cr_iim    cr[24]
#define cr_iha    cr[25]

    /* Model-specific registers */
    uint64_t msr[IA64_MSR_COUNT];
    uint64_t pmc[IA64_PMC_COUNT];
    uint64_t pmd[IA64_PMD_COUNT];
    uint64_t pkr[IA64_PKR_COUNT];

    /* Debug and instruction break registers */
    uint64_t dbr[IA64_DBR_COUNT];
    uint64_t ibr[IA64_IBR_COUNT];
    uint64_t dahr[8];

    /* Region Registers */
    uint64_t rr[8];

    /* Application Registers */
    uint64_t ar[IA64_AR_COUNT];
#define ar_kr0    ar[0]
#define ar_kr7    ar[7]
#define ar_rsc    ar[16]
#define ar_bsp    ar[17]
#define ar_bspstore ar[18]
#define ar_rnat   ar[19]
#define ar_fcr    ar[21]
#define ar_eflag  ar[24]
#define ar_csd    ar[25]
#define ar_ssd    ar[26]
#define ar_cflg   ar[27]
#define ar_fsr    ar[28]
#define ar_fir    ar[29]
#define ar_fdr    ar[30]
#define ar_ccv    ar[32]
#define ar_unat   ar[36]
#define ar_fpsr   ar[40]
#define ar_itc    ar[44]
#define ar_pfs    ar[64]
#define ar_lc     ar[65]
#define ar_ec     ar[66]

    /* Current Frame Marker (derived from pfs bits) */
    uint8_t cfm_sof;
    uint8_t cfm_sol;
    uint8_t cfm_sor;
    uint8_t cfm_rrb_gr;

    /* TLB */
    IA64TlbEntry tlb_data[IA64_TLB_MAX];
    IA64TlbEntry tlb_inst[IA64_TLB_MAX];
    uint8_t       tlb_data_count;
    uint8_t       tlb_inst_count;
    uint8_t       tlb_data_replace;
    uint8_t       tlb_inst_replace;

    /* pending external interrupt */
    uint8_t pending_extint;

    /* Local SAPIC state (IA-64 on-die interrupt controller) */
    uint64_t sapic_irr[4];
    uint64_t sapic_isr[4];

    /* PAL machine-check/PMI registration state */
    bool pal_mc_expected;
    uint64_t pal_mc_save_addr;
    uint64_t pal_pmi_entry;
    bool pal_proc_copy_valid;
    uint64_t pal_proc_copy_addr;
    uint64_t pal_interrupt_block_addr;
    uint64_t pal_io_block_addr;

    /* RSE dirty-region and spill tracking */
    uint32_t rse_cumulative_words; /* total stacked GR words across all frames */
    uint32_t rse_spill_words;      /* words spilled by last flushrs */
    uint64_t rse_spill_base;       /* physical address where last spill started */
    bool rse_bspstore_switched;    /* BSPSTORE moved outside the last spill */
    bool rse_flushed;              /* flushrs executed since BSPSTORE write */
    uint32_t rse_frame_depth;
    uint64_t rse_frame_gr[IA64_RSE_FRAME_MAX][IA64_GR_COUNT - 32];
    uint64_t rse_frame_nat[IA64_RSE_FRAME_MAX][2];
    uint8_t rse_frame_sof[IA64_RSE_FRAME_MAX];
    uint8_t rse_frame_sol[IA64_RSE_FRAME_MAX];
    uint8_t rse_frame_sor[IA64_RSE_FRAME_MAX];
    uint8_t rse_frame_rrb_gr[IA64_RSE_FRAME_MAX];
    uint64_t rse_frame_bsp[IA64_RSE_FRAME_MAX];
    uint64_t rse_frame_return_ip[IA64_RSE_FRAME_MAX];
    uint32_t rse_frame_cumulative_words[IA64_RSE_FRAME_MAX];
    uint32_t rse_cover_depth;
    uint64_t rse_cover_gr[IA64_RSE_FRAME_MAX][IA64_GR_COUNT - 32];
    uint64_t rse_cover_nat[IA64_RSE_FRAME_MAX][2];
    uint8_t rse_cover_sof[IA64_RSE_FRAME_MAX];
    uint64_t rse_cover_bsp[IA64_RSE_FRAME_MAX];

    uint32_t excp_frame_depth;
    IA64ExceptionFrame excp_frames[IA64_EXCP_FRAME_MAX];

    /* ALAT (Advanced Load Address Table) */
    IA64AlatEntry alat[IA64_ALAT_ENTRIES];

    /* ITC (Interval Timer Counter) timebase */
    int64_t itc_delta;
    uint64_t itm_armed_value;
    uint64_t itm_last_match;
    bool itm_armed;
    bool itm_last_match_valid;

    /* Performance counter */
    uint64_t bundles_retired;

    /* Floating-point registers and status */
    uint64_t fr[IA64_FR_COUNT];
    uint64_t fr_nat[2];
    /* FR value currently holds the IA-64 significand field directly. */
    uint64_t fr_sig[2];
    float_status fp_status;
} CPUIA64State;

static inline uint8_t ia64_rr_index(uint64_t va)
{
    return (va >> IA64_REGION_SHIFT) & IA64_REGION_MASK;
}

static inline uint32_t ia64_region_rid(const CPUIA64State *env, uint64_t va)
{
    return ia64_rr_rid(env->rr[ia64_rr_index(va)]);
}

static inline bool ia64_current_code_tlb_ed(const CPUIA64State *env)
{
    const IA64TlbEntry *entry;
    uint32_t rid;

    if (!(env->psr & IA64_PSR_IT)) {
        return false;
    }

    rid = ia64_region_rid(env, env->ip);
    entry = ia64_tlb_find(env->tlb_inst, env->tlb_inst_count, env->ip,
                          rid, true);
    return entry && (entry->pte & IA64_PTE_ED);
}

static inline uint64_t ia64_region_itir(const CPUIA64State *env, uint64_t va)
{
    uint64_t rr = env->rr[ia64_rr_index(va)];

    return (rr & (IA64_ITIR_PS_MASK << IA64_ITIR_PS_SHIFT)) |
           (((rr & IA64_RR_RID_MASK) >> IA64_RR_RID_SHIFT) <<
            IA64_ITIR_KEY_SHIFT);
}

static inline bool ia64_sal_boot_environment_active(const CPUIA64State *env)
{
    return env->cr_iva == IA64_FIRMWARE_IVT_BASE &&
           (env->psr & IA64_PSR_IC) != 0;
}

static inline bool ia64_data_nested_tlb_active(const CPUIA64State *env)
{
    return !(env->psr & IA64_PSR_IC) && !env->psr_ic_inflight;
}

static inline bool ia64_sal_boot_virtual_pa(const CPUIA64State *env,
                                            uint64_t va, uint64_t *pa)
{
    /*
     * Before ExitBootServices(), IA-64 OS loaders execute under the SAL
     * environment and may run in virtual mode while SAL still owns IVA and
     * translation faults.  Model SAL's boot-time identity mappings when the
     * firmware IVT is still active.
     */
    if (!ia64_sal_boot_environment_active(env)) {
        return false;
    }

    if (ia64_rr_index(va) == 0 && va < IA64_FW_BOOT_IDENTITY_LIMIT) {
        *pa = va;
        return true;
    }

    return false;
}

static inline bool ia64_sal_boot_identity_pa(const CPUIA64State *env,
                                             uint64_t va, uint64_t *pa)
{
    uint64_t phys;

    /*
     * SAL owns the IVT until ExitBootServices() completes.  In that
     * environment its TLB miss handlers may install identity TC entries for
     * OS-loader misses, using the current region's RID.  This is a miss
     * fallback only; caller-installed TR/TC entries must take precedence.
     */
    if (!ia64_sal_boot_environment_active(env)) {
        return false;
    }

    phys = va & IA64_REGION7_PHYS_MASK;
    if (phys >= IA64_FW_BOOT_IDENTITY_LIMIT) {
        return false;
    }

    *pa = phys;
    return true;
}

static inline bool ia64_vhpt_config_valid(const CPUIA64State *env,
                                          uint8_t *size,
                                          bool *long_format)
{
    uint64_t pta = env->cr_pta;

    /*
     * PTA.ve gates only the hardware VHPT walker.  Software-visible thash and
     * IHA still use the configured PTA base, size, and format.
     */
    *size = (pta & IA64_PTA_SIZE_MASK) >> IA64_PTA_SIZE_SHIFT;
    *long_format = pta & IA64_PTA_VF;
    if (*size < 15 || *size > (*long_format ? 61 : 52)) {
        return false;
    }
    return true;
}

static inline bool ia64_vhpt_walker_enabled(const CPUIA64State *env,
                                            uint64_t va, bool is_ifetch,
                                            uint8_t *size,
                                            bool *long_format)
{
    if (!(env->cr_pta & IA64_PTA_VE)) {
        return false;
    }
    if (!ia64_vhpt_config_valid(env, size, long_format)) {
        return false;
    }
    if (!(env->rr[ia64_rr_index(va)] & IA64_RR_VE)) {
        return false;
    }
    if (!(env->psr & IA64_PSR_DT)) {
        return false;
    }
    if (is_ifetch &&
        (env->psr & (IA64_PSR_IT | IA64_PSR_IC)) !=
        (IA64_PSR_IT | IA64_PSR_IC)) {
        return false;
    }
    return true;
}

static inline bool ia64_exception_initializes_iha(int excp)
{
    return excp != IA64_EXCP_ALT_ITLB &&
           excp != IA64_EXCP_ALT_DTLB &&
           excp != IA64_EXCP_DATA_NESTED_TLB;
}

bool ia64_vhpt_walk(CPUIA64State *env, uint64_t va, uint32_t rid,
                    bool is_ifetch, uint64_t *pa, uint8_t *perm);
bool ia64_vhpt_walk_full(CPUIA64State *env, uint64_t va, uint32_t rid,
                         bool is_ifetch, uint64_t *pa, uint8_t *perm,
                         uint64_t *pte);
bool ia64_vhpt_pte_not_present(CPUIA64State *env, uint64_t va,
                               bool is_ifetch, uint64_t *entry_va);
bool ia64_vhpt_entry_accessible(CPUIA64State *env, uint64_t va,
                                bool is_ifetch, uint64_t *entry_va);
uint64_t ia64_vhpt_hash_address(CPUIA64State *env, uint64_t va);

void ia64_set_psr(CPUIA64State *env, uint64_t value);
void ia64_set_psr_bn(CPUIA64State *env, bool bank1);

void ia64_sapic_set_irq(CPUState *cs, uint8_t vector);
void ia64_sapic_update_interrupt(CPUIA64State *env);
bool ia64_sapic_has_pending(CPUIA64State *env);
int  ia64_sapic_accept(CPUIA64State *env);
void ia64_sapic_eoi(CPUIA64State *env);
int  ia64_sapic_get_ivr(CPUIA64State *env);
void ia64_itm_update(CPUIA64State *env, uint64_t itm_value);

#define IA64_ITC_NS_PER_TICK 5

static inline int64_t ia64_itc_clock_ns(void)
{
    return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
}

static inline uint64_t ia64_itc_read(CPUIA64State *env)
{
    int64_t elapsed = ia64_itc_clock_ns() - env->itc_delta;

    return env->ar_itc + (uint64_t)(elapsed / IA64_ITC_NS_PER_TICK);
}

static inline void ia64_itc_write(CPUIA64State *env, uint64_t value)
{
    env->ar_itc = value;
    env->itc_delta = ia64_itc_clock_ns();
    env->itm_last_match_valid = false;
}

struct ArchCPU {
    CPUState parent_obj;
    CPUIA64State env;
    QEMUTimer *itm_timer;
};

struct IA64CPUClass {
    CPUClass parent_class;

    DeviceRealize parent_realize;
    ResettablePhases parent_phases;
};

#endif
