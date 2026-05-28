/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * IA-64 CPU target skeleton.
 *
 * The target is still incomplete, but now has a runnable softmmu vCPU and a
 * semantic TCG translator for the current Phase 1 instruction subset.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/log.h"
#include "qemu/qemu-print.h"
#include "qemu/timer.h"
#include "cpu.h"
#include "decoder.h"
#include "exec/cputlb.h"
#include "exec/cpu-common.h"
#include "exec/page-protection.h"
#include "exec/target_page.h"
#include "exec/translation-block.h"
#include "hw/core/sysemu-cpu-ops.h"
#include "accel/tcg/cpu-ops.h"
#include "tcg/debug-assert.h"
#include "tcg/tcg-op.h"
#include "exec/translator.h"
#include "exec/helper-proto.h"
#include "exec/helper-gen.h"
#include "gdbstub/helpers.h"

#define HELPER_H "helper.h"
#include "exec/helper-info.c.inc"
#undef HELPER_H

typedef struct DisasContext {
    DisasContextBase base;
    CPUIA64State *env;
    int mmu_idx;
    uint8_t start_slot;
} DisasContext;

static TCGv_i64 cpu_ip;
static TCGv_i64 cpu_gr[IA64_GR_COUNT];
static TCGv_i64 cpu_pr[IA64_PR_COUNT];
static TCGv_i64 cpu_br[IA64_BR_COUNT];
static TCGv_i64 cpu_psr;
static TCGv_i64 cpu_fr[IA64_FR_COUNT];
static TCGv_i64 cpu_fr_nat[2];
static TCGv_i64 cpu_fr_sig[2];
static TCGv_i64 cpu_nat[2];

#define DISAS_EXIT DISAS_TARGET_0

#define IA64_TB_FLAG_DT       (1u << 0)
#define IA64_TB_FLAG_IT       (1u << 1)
#define IA64_TB_FLAG_RI_SHIFT 2
#define IA64_TB_FLAG_RI_MASK  (3u << IA64_TB_FLAG_RI_SHIFT)

#define IA64_COVER_B_MASK     0x1e1f8000000ULL
#define IA64_COVER_B_VALUE    0x10000000ULL

const uint16_t ia64_ivt_vectors[IA64_EXCP_MAX] = {
    [IA64_EXCP_NONE]             = 0,
    [IA64_EXCP_BREAK]            = 0x2c00,
    [IA64_EXCP_ILLEGAL]          = 0x5400,
    [IA64_EXCP_RESERVED_TEMPLATE] = 0x5400,
    [IA64_EXCP_VHPT_FAULT]       = 0x0000,
    [IA64_EXCP_ITLB_FAULT]       = 0x0400,
    [IA64_EXCP_DTLB_FAULT]       = 0x0800,
    [IA64_EXCP_ALT_ITLB]         = 0x0c00,
    [IA64_EXCP_ALT_DTLB]         = 0x1000,
    [IA64_EXCP_DATA_NESTED_TLB]  = 0x1400,
    [IA64_EXCP_DATA_ACCESS]      = 0x5300,
    [IA64_EXCP_GENERAL]          = 0x5400,
    [IA64_EXCP_NAT_CONSUMPTION]  = 0x5600,
    [IA64_EXCP_EXTINT]           = 0x3000,
    [IA64_EXCP_UNALIGNED]        = 0x5a00,
    [IA64_EXCP_PAGE_NOT_PRESENT] = 0x5000,
    [IA64_EXCP_INST_ACCESS]      = 0x5200,
    [IA64_EXCP_DATA_DIRTY]       = 0x2000,
    [IA64_EXCP_INST_ACCESS_BIT]  = 0x2400,
    [IA64_EXCP_DATA_ACCESS_BIT]  = 0x2800,
};

typedef enum Ia64SlotUnit {
    IA64_UNIT_RESERVED,
    IA64_UNIT_M,
    IA64_UNIT_I,
    IA64_UNIT_B,
    IA64_UNIT_F,
    IA64_UNIT_L,
    IA64_UNIT_X,
} Ia64SlotUnit;

typedef enum Ia64PredicateUpdate {
    IA64_PRED_UPDATE_NORMAL,
    IA64_PRED_UPDATE_AND,
    IA64_PRED_UPDATE_OR,
    IA64_PRED_UPDATE_OR_ANDCM,
} Ia64PredicateUpdate;

typedef enum Ia64Opcode {
    IA64_OP_ILLEGAL,
    IA64_OP_NOP,
    IA64_OP_BREAK,
    IA64_OP_ADDS,
    IA64_OP_ADDL,
    IA64_OP_SHLADD,
    IA64_OP_ADD,
    IA64_OP_ADD_ONE,
    IA64_OP_SUB,
    IA64_OP_SUB_ONE,
    IA64_OP_AND,
    IA64_OP_ANDCM,
    IA64_OP_OR,
    IA64_OP_XOR,
    IA64_OP_SUB_IMM,
    IA64_OP_AND_IMM,
    IA64_OP_ANDCM_IMM,
    IA64_OP_OR_IMM,
    IA64_OP_XOR_IMM,
    IA64_OP_CMP_EQ,
    IA64_OP_CMP_LT,
    IA64_OP_CMP_LE,
    IA64_OP_CMP_GT,
    IA64_OP_CMP_GE,
    IA64_OP_CMP_LTU,
    IA64_OP_CMP_LEU,
    IA64_OP_CMP_GTU,
    IA64_OP_CMP_GEU,
    IA64_OP_CMP_NE,
    IA64_OP_CMP_EQ_AND,
    IA64_OP_CMP_NE_AND,
    IA64_OP_CMP_GT_AND,
    IA64_OP_CMP_LE_AND,
    IA64_OP_CMP_GE_AND,
    IA64_OP_CMP_LT_AND,
    IA64_OP_CMP_EQ_OR,
    IA64_OP_CMP_NE_OR,
    IA64_OP_CMP_GT_OR,
    IA64_OP_CMP_LE_OR,
    IA64_OP_CMP_GE_OR,
    IA64_OP_CMP_LT_OR,
    IA64_OP_CMP_EQ_OR_ANDCM,
    IA64_OP_CMP_NE_OR_ANDCM,
    IA64_OP_CMP_GT_OR_ANDCM,
    IA64_OP_CMP_LE_OR_ANDCM,
    IA64_OP_CMP_GE_OR_ANDCM,
    IA64_OP_CMP_LT_OR_ANDCM,
    IA64_OP_CMP_EQ_IMM,
    IA64_OP_CMP_LT_IMM,
    IA64_OP_CMP_EQ_AND_IMM,
    IA64_OP_CMP_NE_AND_IMM,
    IA64_OP_CMP_EQ_OR_IMM,
    IA64_OP_CMP_NE_OR_IMM,
    IA64_OP_CMP_EQ_OR_ANDCM_IMM,
    IA64_OP_CMP_NE_OR_ANDCM_IMM,
    IA64_OP_CMP4_EQ_AND,
    IA64_OP_CMP4_NE_AND,
    IA64_OP_CMP4_EQ_OR,
    IA64_OP_CMP4_NE_OR,
    IA64_OP_CMP4_EQ_OR_ANDCM,
    IA64_OP_CMP4_NE_OR_ANDCM,
    IA64_OP_CMP4_GT_AND,
    IA64_OP_CMP4_LE_AND,
    IA64_OP_CMP4_GE_AND,
    IA64_OP_CMP4_LT_AND,
    IA64_OP_CMP4_GT_OR,
    IA64_OP_CMP4_LE_OR,
    IA64_OP_CMP4_GE_OR,
    IA64_OP_CMP4_LT_OR,
    IA64_OP_CMP4_GT_OR_ANDCM,
    IA64_OP_CMP4_LE_OR_ANDCM,
    IA64_OP_CMP4_GE_OR_ANDCM,
    IA64_OP_CMP4_LT_OR_ANDCM,
    IA64_OP_CMP4_EQ_OR_ANDCM_IMM,
    IA64_OP_CMP4_NE_OR_ANDCM_IMM,
    IA64_OP_CMP_LTU_IMM,
    IA64_OP_LD1,
    IA64_OP_LD2,
    IA64_OP_LD4,
    IA64_OP_LD8,
    IA64_OP_LD1S,
    IA64_OP_LD2S,
    IA64_OP_LD4S,
    IA64_OP_LD8S,
    IA64_OP_LD1A,
    IA64_OP_LD2A,
    IA64_OP_LD4A,
    IA64_OP_LD8A,
    IA64_OP_LD1SA,
    IA64_OP_LD2SA,
    IA64_OP_LD4SA,
    IA64_OP_LD8SA,
    IA64_OP_LD1FILL,
    IA64_OP_LD2FILL,
    IA64_OP_LD4FILL,
    IA64_OP_LD8FILL,
    IA64_OP_ST1,
    IA64_OP_ST2,
    IA64_OP_ST4,
    IA64_OP_ST8,
    IA64_OP_ST16,
    IA64_OP_ST1REL,
    IA64_OP_ST2REL,
    IA64_OP_ST4REL,
    IA64_OP_ST8REL,
    IA64_OP_ST1SPILL,
    IA64_OP_ST2SPILL,
    IA64_OP_ST4SPILL,
    IA64_OP_ST8SPILL,
    IA64_OP_BR_COND,
    IA64_OP_BR_CALL,
    IA64_OP_BR_CALL_INDIRECT,
    IA64_OP_BR_RET,
    IA64_OP_BR,
    IA64_OP_BR_IA,
    IA64_OP_BR_CLOOP,
    IA64_OP_SHL,
    IA64_OP_SHR,
    IA64_OP_SHRU,
    IA64_OP_SHL_IMM,
    IA64_OP_SHR_IMM,
    IA64_OP_SHRU_IMM,
    IA64_OP_SHRP_IMM,
    IA64_OP_DEPZ,
    IA64_OP_DEPZ_IMM,
    IA64_OP_DEP,
    IA64_OP_DEP_IMM,
    IA64_OP_EXTR,
    IA64_OP_EXTRU,
    IA64_OP_SXT1,
    IA64_OP_SXT2,
    IA64_OP_SXT4,
    IA64_OP_ZXT1,
    IA64_OP_ZXT2,
    IA64_OP_ZXT4,
    IA64_OP_PADD1,
    IA64_OP_PADD2,
    IA64_OP_PADD4,
    IA64_OP_PSUB1,
    IA64_OP_PSUB2,
    IA64_OP_PSUB4,
    IA64_OP_PSHLADD2,
    IA64_OP_PSHRADD2,
    IA64_OP_XCHG1,
    IA64_OP_XCHG2,
    IA64_OP_XCHG4,
    IA64_OP_XCHG8,
    IA64_OP_CMPXCHG1,
    IA64_OP_CMPXCHG2,
    IA64_OP_CMPXCHG4,
    IA64_OP_CMPXCHG8,
    IA64_OP_CMP8XCHG16,
    IA64_OP_FETCHADD4,
    IA64_OP_FETCHADD8,
    IA64_OP_MOVL,
    IA64_OP_MOV_BRGR,
    IA64_OP_MOV_GRBR,
    IA64_OP_MOV_PRGR,
    IA64_OP_MOV_GRPR,
    IA64_OP_MOV_PR_ROT_IMM,
    IA64_OP_MOV_ARGR,
    IA64_OP_MOV_GRAR,
    IA64_OP_MOV_IMMAR,
    IA64_OP_MOV_CRGR,
    IA64_OP_MOV_GRCR,
    IA64_OP_SSM,
    IA64_OP_RSM,
    IA64_OP_COVER,
    IA64_OP_ALLOC,
    IA64_OP_FLUSHRS,
    IA64_OP_LOADRS,
    IA64_OP_ITR_D,
    IA64_OP_ITR_I,
    IA64_OP_PTR_D,
    IA64_OP_PTR_I,
    IA64_OP_PTC_L,
    IA64_OP_PTC_G,
    IA64_OP_RFI,
    IA64_OP_LDFD,
    IA64_OP_LDFS,
    IA64_OP_LDF_FILL,
    IA64_OP_STFD,
    IA64_OP_STFS,
    IA64_OP_STF_SPILL,
    IA64_OP_FADD,
    IA64_OP_FSUB,
    IA64_OP_FMPY,
    IA64_OP_FMA,
    IA64_OP_XMA_L,
    IA64_OP_XMA_H,
    IA64_OP_XMA_HU,
    IA64_OP_XMPY_HU,
    IA64_OP_FCMP,
    IA64_OP_FMOV,
    IA64_OP_FCVT_XF,
    IA64_OP_FCVT_FX,
    IA64_OP_FCVT_FXU,
    IA64_OP_GETF_D,
    IA64_OP_GETF_S,
    IA64_OP_GETF_EXP,
    IA64_OP_SETF_D,
    IA64_OP_SETF_S,
    IA64_OP_SETF_EXP,
    IA64_OP_TPA,
    IA64_OP_SYNC_I,
    IA64_OP_CHK_S,
    IA64_OP_CHK_A,
    IA64_OP_CHK_A_CLR,
    IA64_OP_SRLZ,
    IA64_OP_SRLZ_D,
    IA64_OP_MF,
    IA64_OP_MF_A,
    IA64_OP_FWB,
    IA64_OP_PROBE_R,
    IA64_OP_PROBE_W,
    IA64_OP_PROBE_RW,
    IA64_OP_TAK,
    IA64_OP_THASH,
    IA64_OP_TTAG,
    IA64_OP_FC,
    IA64_OP_INVALA,
    IA64_OP_BR_WEXIT,
    IA64_OP_BR_WTOP,
    IA64_OP_BR_CEXIT,
    IA64_OP_BR_CTOP,
    IA64_OP_FCLASS,
    IA64_OP_FMERGE,
    IA64_OP_CMP4_EQ,
    IA64_OP_CMP4_LT,
    IA64_OP_CMP4_LE,
    IA64_OP_CMP4_GT,
    IA64_OP_CMP4_GE,
    IA64_OP_CMP4_LTU,
    IA64_OP_CMP4_LEU,
    IA64_OP_CMP4_GTU,
    IA64_OP_CMP4_GEU,
    IA64_OP_CMP4_EQ_IMM,
    IA64_OP_CMP4_LT_IMM,
    IA64_OP_CMP4_LTU_IMM,
    IA64_OP_CMP4_EQ_AND_IMM,
    IA64_OP_CMP4_NE_AND_IMM,
    IA64_OP_CMP4_EQ_OR_IMM,
    IA64_OP_CMP4_NE_OR_IMM,
    IA64_OP_TBIT_Z,
    IA64_OP_TBIT_NZ,
    IA64_OP_TBIT_Z_OR_ANDCM,
    IA64_OP_TBIT_NZ_OR_ANDCM,
    IA64_OP_TNAT_Z,
    IA64_OP_TNAT_NZ,
    IA64_OP_TNAT_NZ_AND,
    IA64_OP_TF_Z,
    IA64_OP_TF_NZ,
    IA64_OP_LD1C_CLR,
    IA64_OP_LD2C_CLR,
    IA64_OP_LD4C_CLR,
    IA64_OP_LD8C_CLR,
    IA64_OP_LD1C_NC,
    IA64_OP_LD2C_NC,
    IA64_OP_LD4C_NC,
    IA64_OP_LD8C_NC,
    IA64_OP_SHLADDP4,
    IA64_OP_MPY4,
    IA64_OP_MPYSHL4,
    IA64_OP_MPYSH,
    IA64_OP_MPYUH,
    IA64_OP_HINT_M,
    IA64_OP_HINT_I,
    IA64_OP_HINT_B,
    IA64_OP_HINT_F,
    IA64_OP_HINT_X,
    IA64_OP_PTC_E,
    IA64_OP_CLRRRB,
    IA64_OP_CLRRRB_PR,
    IA64_OP_CLZ,
    IA64_OP_POPCNT,
    IA64_OP_MUX,
    IA64_OP_LDFP8,
    IA64_OP_LDFPD,
    IA64_OP_LDFPS,
    IA64_OP_FMERGE_S,
    IA64_OP_FMERGE_SE,
    IA64_OP_FMIN,
    IA64_OP_FMAX,
    IA64_OP_FAMIN,
    IA64_OP_FAMAX,
    IA64_OP_FRCPA,
    IA64_OP_FPRCPA,
    IA64_OP_FSETC,
    IA64_OP_FCLRF,
    IA64_OP_FCHKF,
    IA64_OP_FCHKFS,
    IA64_OP_GETF_SIG,
    IA64_OP_SETF_SIG,
    IA64_OP_ITC_D,
    IA64_OP_ITC_I,
    IA64_OP_PTC_GA,
    IA64_OP_MOV_PSRGR,
    IA64_OP_MOV_GRPSR,
    IA64_OP_MOV_RRGR,
    IA64_OP_MOV_GRRR,
    IA64_OP_BSW0,
    IA64_OP_BSW1,
    IA64_OP_BRL_COND,
    IA64_OP_BRL_CALL,
    IA64_OP_ADDP4,
    IA64_OP_ADDP4_IMM,
    IA64_OP_EPC,
    IA64_OP_INVALAT,
    IA64_OP_MOV_PKRGR,
    IA64_OP_MOV_PKRGR_INDEXED,
    IA64_OP_MOV_GRPKR,
    IA64_OP_MOV_GRPKR_INDEXED,
    IA64_OP_MOV_UMGR,
    IA64_OP_MOV_GRUM,
    IA64_OP_MOV_IBRGR,
    IA64_OP_MOV_GRIBR,
    IA64_OP_MOV_IBRGR_INDEXED,
    IA64_OP_MOV_GRIBR_INDEXED,
    IA64_OP_MOV_DBRGR,
    IA64_OP_MOV_GRDBR,
    IA64_OP_MOV_DBRGR_INDEXED,
    IA64_OP_MOV_GRDBR_INDEXED,
    IA64_OP_MOV_PMCGR,
    IA64_OP_MOV_GRPMC,
    IA64_OP_MOV_PMCGR_INDEXED,
    IA64_OP_MOV_GRPMC_INDEXED,
    IA64_OP_MOV_PMDGR,
    IA64_OP_MOV_GRPMD,
    IA64_OP_MOV_PMDGR_INDEXED,
    IA64_OP_MOV_GRPMD_INDEXED,
    IA64_OP_MOV_CPUID,
    IA64_OP_MOV_CPUID_INDEXED,
    IA64_OP_MOV_DAHRGR_INDEXED,
    IA64_OP_MOV_MSRGR,
    IA64_OP_MOV_GRMSR,
    IA64_OP_MOV_IP,
    IA64_OP_MOV_CURRENT_IP,
    IA64_OP_FMS,
    IA64_OP_FNMA,
    IA64_OP_FSELECT,
    IA64_OP_FNORM,
    IA64_OP_FPABS,
    IA64_OP_FPNEG,
    IA64_OP_FPNEGABS,
    IA64_OP_FPRSQRTA,
    IA64_OP_FRSQRTA,
    IA64_OP_FPACK,
    IA64_OP_FAND,
    IA64_OP_FANDCM,
    IA64_OP_FOR,
    IA64_OP_FXOR,
    IA64_OP_FSWAP,
    IA64_OP_FSWAP_NL,
    IA64_OP_FSWAP_NR,
    IA64_OP_FMIX_LR,
    IA64_OP_FMIX_R,
    IA64_OP_FMIX_L,
    IA64_OP_FSXT_R,
    IA64_OP_FSXT_L,
    IA64_OP_FPMERGE,
    IA64_OP_FPMERGE_S,
    IA64_OP_FPMERGE_SE,
    IA64_OP_FPMIN,
    IA64_OP_FPMAX,
    IA64_OP_FPAMIN,
    IA64_OP_FPAMAX,
    IA64_OP_FPCMP,
    IA64_OP_FPCVT,
    IA64_OP_FPMA,
    IA64_OP_FPMS,
    IA64_OP_FPNMA,
    IA64_OP_VMSW,
    IA64_OP_RUM,
    IA64_OP_SUM_UM,
    IA64_OP_BRP,
    IA64_OP_PAVG1,
    IA64_OP_PAVG2,
    IA64_OP_PAVGSUB1,
    IA64_OP_PAVGSUB2,
    IA64_OP_PCMP1_EQ,
    IA64_OP_PCMP1_GT,
    IA64_OP_PCMP2_EQ,
    IA64_OP_PCMP2_GT,
    IA64_OP_PCMP4_EQ,
    IA64_OP_PCMP4_GT,
    IA64_OP_PMAX1_U,
    IA64_OP_PMAX2,
    IA64_OP_PMIN1_U,
    IA64_OP_PMIN2,
    IA64_OP_PMPY2_L,
    IA64_OP_PMPY2_R,
    IA64_OP_PMPYSH2,
    IA64_OP_PMPYSH2_U,
    IA64_OP_PSHL2,
    IA64_OP_PSHL4,
    IA64_OP_PSHR2,
    IA64_OP_PSHR2_U,
    IA64_OP_PSHR4,
    IA64_OP_PSHR4_U,
    IA64_OP_PSAD1,
    IA64_OP_MUX1,
    IA64_OP_MUX2,
    IA64_OP_MIX1_L,
    IA64_OP_MIX1_R,
    IA64_OP_MIX2_L,
    IA64_OP_MIX2_R,
    IA64_OP_MIX4_L,
    IA64_OP_MIX4_R,
    IA64_OP_PACK2_SSS,
    IA64_OP_PACK2_USS,
    IA64_OP_PACK4_SSS,
    IA64_OP_UNPACK1_H,
    IA64_OP_UNPACK1_L,
    IA64_OP_UNPACK2_H,
    IA64_OP_UNPACK2_L,
    IA64_OP_UNPACK4_H,
    IA64_OP_UNPACK4_L,
    IA64_OP_SUM,
    IA64_OP_CZX1_L,
    IA64_OP_CZX1_R,
    IA64_OP_CZX2_L,
    IA64_OP_CZX2_R,
    IA64_OP_LD16,
    IA64_OP_LDF8,
    IA64_OP_LDFE,
    IA64_OP_STF8,
    IA64_OP_STFE,
} Ia64Opcode;

typedef struct Ia64Instruction {
    Ia64Opcode opcode;
    Ia64SlotUnit unit;
    uint64_t raw;
    uint64_t address;
    uint8_t slot;
    uint8_t qp;
    uint8_t r1;
    uint8_t r2;
    uint8_t r3;
    uint8_t p1;
    uint8_t p2;
    uint8_t b1;
    uint8_t b2;
    int64_t imm;
    Ia64PredicateUpdate pred_update;
    bool hint_m_reg_increment;
    bool reg_base_update;
    bool mem_acquire;
    bool mem_release;
    bool compare_unc;
    bool clear_p2_before_predicate;
    bool check_fp;
    bool fp_load_speculative;
    bool fp_load_advanced;
    bool fp_load_check;
    bool fp_load_check_clear;
    bool probe_fault;
    bool probe_imm;
    bool valid;
} Ia64Instruction;

typedef struct Ia64A3AluPattern {
    uint8_t x4;
    uint8_t x2b;
    Ia64Opcode opcode;
    bool immediate;
} Ia64A3AluPattern;

static const Ia64A3AluPattern ia64_a3_alu_patterns[] = {
    { 0x0, 0, IA64_OP_ADD, false },
    { 0x0, 1, IA64_OP_ADD_ONE, false },
    { 0x0, 3, IA64_OP_MUX, false },
    { 0x1, 0, IA64_OP_SUB_ONE, false },
    { 0x1, 1, IA64_OP_SUB, false },
    { 0x3, 0, IA64_OP_AND, false },
    { 0x3, 1, IA64_OP_ANDCM, false },
    { 0x3, 2, IA64_OP_OR, false },
    { 0x3, 3, IA64_OP_XOR, false },
    { 0x4, 0, IA64_OP_SHL, false },
    { 0x4, 1, IA64_OP_SHRU, false },
    { 0x5, 0, IA64_OP_SHR, false },
    { 0x6, 0, IA64_OP_DEPZ, false },
    { 0x6, 1, IA64_OP_DEP, false },
    { 0x7, 0, IA64_OP_EXTR, false },
    { 0x7, 1, IA64_OP_EXTRU, false },
    { 0x8, 0, IA64_OP_MPY4, false },
    { 0x8, 1, IA64_OP_MPYSH, false },
    { 0x8, 2, IA64_OP_MPYUH, false },
    { 0x9, 1, IA64_OP_SUB_IMM, true },
    { 0xa, 1, IA64_OP_POPCNT, false },
    { 0xb, 0, IA64_OP_AND_IMM, true },
    { 0xb, 1, IA64_OP_ANDCM_IMM, true },
    { 0xb, 2, IA64_OP_OR_IMM, true },
    { 0xb, 3, IA64_OP_XOR_IMM, true },
};

static uint64_t ia64_bits(uint64_t value, unsigned low, unsigned width)
{
    return (value >> low) & ((1ULL << width) - 1);
}

static uint64_t ia64_b_op(uint64_t value)
{
    return ia64_bits(value, 37, 4);
}

static int64_t ia64_sign_extend(uint64_t value, unsigned width)
{
    const uint64_t sign = 1ULL << (width - 1);
    const uint64_t mask = (1ULL << width) - 1;

    value &= mask;
    return (int64_t)((value ^ sign) - sign);
}

static uint64_t ia64_immu21(uint64_t raw)
{
    return ia64_bits(raw, 6, 20) | (ia64_bits(raw, 36, 1) << 20);
}

static int64_t ia64_imm14(uint64_t raw)
{
    return ia64_sign_extend(ia64_bits(raw, 13, 7) |
                            (ia64_bits(raw, 27, 6) << 7) |
                            (ia64_bits(raw, 36, 1) << 13), 14);
}

static int64_t ia64_imm8(uint64_t raw)
{
    return ia64_sign_extend(ia64_bits(raw, 13, 7) |
                            (ia64_bits(raw, 36, 1) << 7), 8);
}

static uint64_t ia64_pr_mask(uint64_t raw)
{
    uint64_t imm17 = (ia64_bits(raw, 6, 7) << 1) |
                     (ia64_bits(raw, 24, 8) << 8) |
                     (ia64_bits(raw, 36, 1) << 16);

    return ia64_sign_extend(imm17, 17) & ~1ULL;
}

static uint64_t ia64_pr_rot_imm(uint64_t raw)
{
    uint64_t imm = ia64_bits(raw, 6, 7) |
                   (ia64_bits(raw, 13, 7) << 7) |
                   (ia64_bits(raw, 20, 4) << 14) |
                   (ia64_bits(raw, 24, 8) << 18) |
                   (ia64_bits(raw, 32, 1) << 26) |
                   (ia64_bits(raw, 36, 1) << 27);

    return imm << 16;
}

static uint64_t ia64_psr_mask(uint64_t raw)
{
    return ia64_bits(raw, 6, 7) |
           (ia64_bits(raw, 13, 7) << 7) |
           (ia64_bits(raw, 20, 7) << 14) |
           (ia64_bits(raw, 31, 2) << 21) |
           (ia64_bits(raw, 36, 1) << 23);
}

static uint64_t ia64_low_mask(uint64_t len)
{
    return len >= 64 ? UINT64_MAX : ((1ULL << len) - 1);
}

static uint64_t ia64_bitfield_effective_len(uint64_t pos, uint64_t len)
{
    pos &= 0x3f;
    return len > 64 - pos ? 64 - pos : len;
}

static uint64_t ia64_deposit_mask(uint64_t pos, uint64_t len)
{
    len = ia64_bitfield_effective_len(pos, len);
    return ia64_low_mask(len) << (pos & 0x3f);
}

static int64_t ia64_imm22(uint64_t raw)
{
    return ia64_sign_extend(ia64_bits(raw, 13, 7) |
                            (ia64_bits(raw, 27, 9) << 7) |
                            (ia64_bits(raw, 22, 5) << 16) |
                            (ia64_bits(raw, 36, 1) << 21), 22);
}

static int64_t ia64_branch_disp(uint64_t raw)
{
    const uint64_t field = ia64_bits(raw, 13, 20) |
                           (ia64_bits(raw, 36, 1) << 20);

    return ia64_sign_extend(field, 21) * 16;
}

static uint64_t ia64_mlx_x1_imm62(uint64_t l_slot, uint64_t x_slot)
{
    return ia64_immu21(x_slot) | (ia64_bits(l_slot, 0, 41) << 21);
}

static int64_t ia64_mlx_brl_disp(uint64_t l_slot, uint64_t x_slot)
{
    const uint64_t field = ia64_bits(x_slot, 13, 20) |
                           (ia64_bits(l_slot, 0, 39) << 20) |
                           (ia64_bits(x_slot, 36, 1) << 59);

    return ia64_sign_extend(field, 60) * 16;
}

static void ia64_fill_mlx_movl(Ia64Instruction *insn,
                               uint64_t l_slot, uint64_t x_slot)
{
    uint64_t i     = (x_slot >> 36) & 1;
    uint64_t imm9d = (x_slot >> 27) & 0x1ff;
    uint64_t imm5c = (x_slot >> 22) & 0x1f;
    uint64_t ic    = (x_slot >> 21) & 1;
    uint64_t imm7b = (x_slot >> 13) & 0x7f;
    uint64_t imm41 = l_slot & 0x1ffffffffffULL;
    uint64_t imm64 = (imm7b)
                   | (imm9d << 7)
                   | (imm5c << 16)
                   | (ic << 21)
                   | (imm41 << 22)
                   | (i << 63);

    insn->qp = x_slot & 0x3f;
    insn->r1 = (x_slot >> 6) & 0x7f;
    insn->imm = (int64_t)imm64;
}

static int64_t ia64_chk_disp(uint64_t raw)
{
    const uint64_t field = ia64_bits(raw, 6, 7) |
                           (ia64_bits(raw, 20, 13) << 7) |
                           (ia64_bits(raw, 36, 1) << 20);

    return ia64_sign_extend(field, 21) * 16;
}

static int64_t ia64_chk_a_disp(uint64_t raw)
{
    const uint64_t field = ia64_bits(raw, 13, 20) |
                           (ia64_bits(raw, 36, 1) << 20);

    return ia64_sign_extend(field, 21) * 16;
}

static bool ia64_address_matches_physical_entry(uint64_t address,
                                                uint64_t entry_pa)
{
    uint64_t pa;

    if (address == entry_pa) {
        return true;
    }

    if (ia64_firmware_identity_pa(address, &pa) ||
        ia64_region7_identity_pa(address, &pa)) {
        return pa == entry_pa;
    }

    return false;
}

static bool ia64_is_pal_proc_break(CPUIA64State *env, uint64_t address)
{
    const uint64_t pal_proc_entry_pa = IA64_FW_IDENTITY_BASE + 0x60;

    if (ia64_address_matches_physical_entry(address, pal_proc_entry_pa)) {
        return true;
    }

    return env->pal_proc_copy_valid &&
           ia64_address_matches_physical_entry(address,
                                               env->pal_proc_copy_addr);
}

static Ia64Opcode ia64_memory_opcode_from_x6a(uint64_t x6a)
{
    switch (x6a) {
    case 0x00:
        return IA64_OP_LD1;
    case 0x01:
        return IA64_OP_LD2;
    case 0x02:
        return IA64_OP_LD4;
    case 0x03:
        return IA64_OP_LD8;
    case 0x04:
        return IA64_OP_LD1S;
    case 0x05:
        return IA64_OP_LD2S;
    case 0x06:
        return IA64_OP_LD4S;
    case 0x07:
        return IA64_OP_LD8S;
    case 0x08:
        return IA64_OP_LD1A;
    case 0x09:
        return IA64_OP_LD2A;
    case 0x0a:
        return IA64_OP_LD4A;
    case 0x0b:
        return IA64_OP_LD8A;
    case 0x0c:
        return IA64_OP_LD1SA;
    case 0x0d:
        return IA64_OP_LD2SA;
    case 0x0e:
        return IA64_OP_LD4SA;
    case 0x0f:
        return IA64_OP_LD8SA;
    case 0x10:
        return IA64_OP_LD1;
    case 0x11:
        return IA64_OP_LD2;
    case 0x12:
        return IA64_OP_LD4;
    case 0x13:
        return IA64_OP_LD8;
    case 0x14:
        return IA64_OP_LD1;
    case 0x15:
        return IA64_OP_LD2;
    case 0x16:
        return IA64_OP_LD4;
    case 0x17:
        return IA64_OP_LD8;
    case 0x18:
        return IA64_OP_LD1FILL;
    case 0x19:
        return IA64_OP_LD2FILL;
    case 0x1a:
        return IA64_OP_LD4FILL;
    case 0x1b:
        return IA64_OP_LD8FILL;
    case 0x20:
        return IA64_OP_LD1C_CLR;
    case 0x21:
        return IA64_OP_LD2C_CLR;
    case 0x22:
        return IA64_OP_LD4C_CLR;
    case 0x23:
        return IA64_OP_LD8C_CLR;
    case 0x24:
        return IA64_OP_LD1C_NC;
    case 0x25:
        return IA64_OP_LD2C_NC;
    case 0x26:
        return IA64_OP_LD4C_NC;
    case 0x27:
        return IA64_OP_LD8C_NC;
    case 0x28:
        return IA64_OP_LD1C_CLR;
    case 0x29:
        return IA64_OP_LD2C_CLR;
    case 0x2a:
        return IA64_OP_LD4C_CLR;
    case 0x2b:
        return IA64_OP_LD8C_CLR;
    case 0x30:
        return IA64_OP_ST1;
    case 0x31:
        return IA64_OP_ST2;
    case 0x32:
        return IA64_OP_ST4;
    case 0x33:
        return IA64_OP_ST8;
    case 0x34:
        return IA64_OP_ST1REL;
    case 0x35:
        return IA64_OP_ST2REL;
    case 0x36:
        return IA64_OP_ST4REL;
    case 0x37:
        return IA64_OP_ST8REL;
    case 0x38:
        return IA64_OP_ST1SPILL;
    case 0x39:
        return IA64_OP_ST2SPILL;
    case 0x3a:
        return IA64_OP_ST4SPILL;
    case 0x3b:
        return IA64_OP_ST8SPILL;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static bool ia64_memory_x6a_is_acquire_load(uint64_t x6a)
{
    return (x6a >= 0x14 && x6a <= 0x17) ||
           (x6a >= 0x28 && x6a <= 0x2b);
}

static Ia64Opcode ia64_speculative_load_opcode_from_x6a(uint64_t x6a)
{
    switch (x6a) {
    case 0x00:
        return IA64_OP_LD1S;
    case 0x01:
        return IA64_OP_LD2S;
    case 0x02:
        return IA64_OP_LD4S;
    case 0x03:
        return IA64_OP_LD8S;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static Ia64Opcode ia64_fp_load_opcode_from_x6a(uint64_t x6a)
{
    if ((x6a <= 0x0f) || (x6a >= 0x20 && x6a <= 0x27)) {
        switch (x6a & 3) {
        case 0:
            return IA64_OP_LDFE;
        case 1:
            return IA64_OP_LDF8;
        case 2:
            return IA64_OP_LDFS;
        case 3:
            return IA64_OP_LDFD;
        }
    }

    switch (x6a) {
    case 0x1b:
        return IA64_OP_LDF_FILL;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static void ia64_fp_load_attrs_from_x6a(Ia64Instruction *insn, uint64_t x6a)
{
    switch (x6a >> 2) {
    case 1:
        insn->fp_load_speculative = true;
        break;
    case 2:
        insn->fp_load_advanced = true;
        break;
    case 3:
        insn->fp_load_speculative = true;
        insn->fp_load_advanced = true;
        break;
    case 8:
        insn->fp_load_check = true;
        insn->fp_load_check_clear = true;
        break;
    case 9:
        insn->fp_load_check = true;
        break;
    default:
        break;
    }
}

static Ia64Opcode ia64_fp_load_pair_opcode_from_x6a(uint64_t x6a)
{
    if ((x6a <= 0x0f || (x6a >= 0x20 && x6a <= 0x27)) &&
        (x6a & 3) != 0) {
        switch (x6a & 3) {
        case 1:
            return IA64_OP_LDFP8;
        case 2:
            return IA64_OP_LDFPS;
        case 3:
            return IA64_OP_LDFPD;
        }
    }

    return IA64_OP_ILLEGAL;
}

static Ia64Opcode ia64_fp_store_opcode_from_x6a(uint64_t x6a)
{
    switch (x6a) {
    case 0x30:
        return IA64_OP_STFE;
    case 0x31:
        return IA64_OP_STF8;
    case 0x32:
        return IA64_OP_STFS;
    case 0x33:
        return IA64_OP_STFD;
    case 0x3b:
        return IA64_OP_STF_SPILL;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static Ia64Opcode ia64_check_load_opcode_from_x6a(uint64_t x6a, bool clr)
{
    switch (x6a) {
    case 0x00:
        return clr ? IA64_OP_LD1C_CLR : IA64_OP_LD1C_NC;
    case 0x01:
        return clr ? IA64_OP_LD2C_CLR : IA64_OP_LD2C_NC;
    case 0x02:
        return clr ? IA64_OP_LD4C_CLR : IA64_OP_LD4C_NC;
    case 0x03:
        return clr ? IA64_OP_LD8C_CLR : IA64_OP_LD8C_NC;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static Ia64Opcode ia64_fetchadd_opcode_from_x6a(uint64_t x6a)
{
    switch (x6a) {
    case 0x12:
    case 0x16:
        return IA64_OP_FETCHADD4;
    case 0x13:
    case 0x17:
        return IA64_OP_FETCHADD8;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static bool ia64_fetchadd_x6a_is_acquire(uint64_t x6a)
{
    return x6a == 0x12 || x6a == 0x13;
}

static bool ia64_fetchadd_x6a_is_release(uint64_t x6a)
{
    return x6a == 0x16 || x6a == 0x17;
}

static Ia64Opcode ia64_cmpxchg_acqrel_opcode_from_size(uint64_t size)
{
    switch (size) {
    case 0:
        return IA64_OP_CMPXCHG1;
    case 1:
        return IA64_OP_CMPXCHG2;
    case 2:
        return IA64_OP_CMPXCHG4;
    case 3:
        return IA64_OP_CMPXCHG8;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static Ia64Opcode ia64_xchg_opcode_from_size(uint64_t size)
{
    switch (size) {
    case 0:
        return IA64_OP_XCHG1;
    case 1:
        return IA64_OP_XCHG2;
    case 2:
        return IA64_OP_XCHG4;
    case 3:
        return IA64_OP_XCHG8;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static Ia64Opcode ia64_unpack_opcode_from_fields(uint64_t za, uint64_t zb,
                                                 uint64_t x2b)
{
    static const Ia64Opcode high[4] = {
        IA64_OP_UNPACK1_H, IA64_OP_UNPACK2_H, IA64_OP_UNPACK4_H,
        IA64_OP_ILLEGAL,
    };
    static const Ia64Opcode low[4] = {
        IA64_OP_UNPACK1_L, IA64_OP_UNPACK2_L, IA64_OP_UNPACK4_L,
        IA64_OP_ILLEGAL,
    };
    const unsigned size_code = (za << 1) | zb;

    if (x2b == 0) {
        return high[size_code];
    }
    if (x2b == 2) {
        return low[size_code];
    }
    return IA64_OP_ILLEGAL;
}

static int64_t ia64_fetchadd_imm(uint64_t inc3)
{
    static const int8_t values[8] = {
        16, 8, 4, 1, -16, -8, -4, -1,
    };

    return values[inc3 & 7];
}

static Ia64Opcode ia64_compare_opcode_from_cmp(uint64_t x2a, uint64_t ve)
{
    switch ((x2a << 1) | ve) {
    case 0:
        return IA64_OP_CMP_EQ;
    case 1:
        return IA64_OP_CMP_LT;
    case 2:
        return IA64_OP_CMP_LE;
    case 3:
        return IA64_OP_CMP_GT;
    case 4:
        return IA64_OP_CMP_GE;
    case 5:
        return IA64_OP_CMP_LTU;
    case 6:
        return IA64_OP_CMP_LEU;
    case 7:
        return IA64_OP_CMP_GTU;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static Ia64Opcode ia64_compare_zero_opcode(uint64_t major, bool cmp4,
                                           uint64_t ta, uint64_t c)
{
    static const Ia64Opcode zero_ops[3][2][4] = {
        {
            {
                IA64_OP_CMP_GT_AND,
                IA64_OP_CMP_LE_AND,
                IA64_OP_CMP_GE_AND,
                IA64_OP_CMP_LT_AND,
            },
            {
                IA64_OP_CMP4_GT_AND,
                IA64_OP_CMP4_LE_AND,
                IA64_OP_CMP4_GE_AND,
                IA64_OP_CMP4_LT_AND,
            },
        },
        {
            {
                IA64_OP_CMP_GT_OR,
                IA64_OP_CMP_LE_OR,
                IA64_OP_CMP_GE_OR,
                IA64_OP_CMP_LT_OR,
            },
            {
                IA64_OP_CMP4_GT_OR,
                IA64_OP_CMP4_LE_OR,
                IA64_OP_CMP4_GE_OR,
                IA64_OP_CMP4_LT_OR,
            },
        },
        {
            {
                IA64_OP_CMP_GT_OR_ANDCM,
                IA64_OP_CMP_LE_OR_ANDCM,
                IA64_OP_CMP_GE_OR_ANDCM,
                IA64_OP_CMP_LT_OR_ANDCM,
            },
            {
                IA64_OP_CMP4_GT_OR_ANDCM,
                IA64_OP_CMP4_LE_OR_ANDCM,
                IA64_OP_CMP4_GE_OR_ANDCM,
                IA64_OP_CMP4_LT_OR_ANDCM,
            },
        },
    };
    const unsigned relation = (ta << 1) | c;

    if (major < 0xc || major > 0xe) {
        return IA64_OP_ILLEGAL;
    }
    return zero_ops[major - 0xc][cmp4 ? 1 : 0][relation];
}

static Ia64Opcode ia64_f1_opcode_from_major(uint64_t major, uint64_t f2,
                                            uint64_t f4)
{
    switch (major) {
    case 8:
    case 9:
        if (f4 == 1) {
            return f2 == 0 ? IA64_OP_FNORM : IA64_OP_FADD;
        }
        return f2 == 0 ? IA64_OP_FMPY : IA64_OP_FMA;
    case 0xa:
    case 0xb:
        if (f4 == 1) {
            return f2 == 0 ? IA64_OP_FNORM : IA64_OP_FSUB;
        }
        return IA64_OP_FMS;
    case 0xc:
    case 0xd:
        return IA64_OP_FNMA;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static const Ia64A3AluPattern *ia64_lookup_a3_alu(uint64_t x4, uint64_t x2b)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(ia64_a3_alu_patterns); ++i) {
        const Ia64A3AluPattern *pattern = &ia64_a3_alu_patterns[i];
        if (pattern->x4 == x4 && pattern->x2b == x2b) {
            return pattern;
        }
    }
    return NULL;
}

static MemOp ia64_memop_for_opcode(Ia64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_LD1:
    case IA64_OP_LD1S:
    case IA64_OP_LD1A:
    case IA64_OP_LD1SA:
    case IA64_OP_LD1FILL:
    case IA64_OP_LD1C_CLR:
    case IA64_OP_LD1C_NC:
    case IA64_OP_ST1:
    case IA64_OP_ST1REL:
    case IA64_OP_ST1SPILL:
    case IA64_OP_XCHG1:
    case IA64_OP_CMPXCHG1:
        return MO_UB;
    case IA64_OP_LD2:
    case IA64_OP_LD2S:
    case IA64_OP_LD2A:
    case IA64_OP_LD2SA:
    case IA64_OP_LD2FILL:
    case IA64_OP_LD2C_CLR:
    case IA64_OP_LD2C_NC:
    case IA64_OP_ST2:
    case IA64_OP_ST2REL:
    case IA64_OP_ST2SPILL:
    case IA64_OP_XCHG2:
    case IA64_OP_CMPXCHG2:
        return MO_LEUW;
    case IA64_OP_LD4:
    case IA64_OP_LD4S:
    case IA64_OP_LD4A:
    case IA64_OP_LD4SA:
    case IA64_OP_LD4FILL:
    case IA64_OP_LD4C_CLR:
    case IA64_OP_LD4C_NC:
    case IA64_OP_ST4:
    case IA64_OP_ST4REL:
    case IA64_OP_ST4SPILL:
    case IA64_OP_XCHG4:
    case IA64_OP_CMPXCHG4:
    case IA64_OP_FETCHADD4:
        return MO_LEUL;
    case IA64_OP_LD8:
    case IA64_OP_LD8S:
    case IA64_OP_LD8A:
    case IA64_OP_LD8SA:
    case IA64_OP_LD8FILL:
    case IA64_OP_LD8C_CLR:
    case IA64_OP_LD8C_NC:
    case IA64_OP_ST8:
    case IA64_OP_ST8REL:
    case IA64_OP_ST8SPILL:
    case IA64_OP_XCHG8:
    case IA64_OP_CMPXCHG8:
    case IA64_OP_FETCHADD8:
        return MO_LEUQ;
    default:
        break;
    }
    g_assert_not_reached();
}

static uint32_t ia64_memop_size(MemOp memop)
{
    return 1u << (memop & MO_SIZE);
}

static bool ia64_opcode_is_store(Ia64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_ST1:
    case IA64_OP_ST2:
    case IA64_OP_ST4:
    case IA64_OP_ST8:
    case IA64_OP_ST16:
    case IA64_OP_ST1REL:
    case IA64_OP_ST2REL:
    case IA64_OP_ST4REL:
    case IA64_OP_ST8REL:
    case IA64_OP_ST1SPILL:
    case IA64_OP_ST2SPILL:
    case IA64_OP_ST4SPILL:
    case IA64_OP_ST8SPILL:
        return true;
    default:
        return false;
    }
}

static bool ia64_opcode_is_release_store(Ia64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_ST1REL:
    case IA64_OP_ST2REL:
    case IA64_OP_ST4REL:
    case IA64_OP_ST8REL:
        return true;
    default:
        return false;
    }
}

static bool ia64_opcode_is_load(Ia64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_LD1:
    case IA64_OP_LD2:
    case IA64_OP_LD4:
    case IA64_OP_LD8:
    case IA64_OP_LD1S:
    case IA64_OP_LD2S:
    case IA64_OP_LD4S:
    case IA64_OP_LD8S:
    case IA64_OP_LD1A:
    case IA64_OP_LD2A:
    case IA64_OP_LD4A:
    case IA64_OP_LD8A:
    case IA64_OP_LD1SA:
    case IA64_OP_LD2SA:
    case IA64_OP_LD4SA:
    case IA64_OP_LD8SA:
    case IA64_OP_LD1FILL:
    case IA64_OP_LD2FILL:
    case IA64_OP_LD4FILL:
    case IA64_OP_LD8FILL:
    case IA64_OP_LD1C_CLR:
    case IA64_OP_LD2C_CLR:
    case IA64_OP_LD4C_CLR:
    case IA64_OP_LD8C_CLR:
    case IA64_OP_LD1C_NC:
    case IA64_OP_LD2C_NC:
    case IA64_OP_LD4C_NC:
    case IA64_OP_LD8C_NC:
        return true;
    default:
        return false;
    }
}

static bool ia64_opcode_has_firmware_unaligned_load_assist(Ia64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_LD1:
    case IA64_OP_LD2:
    case IA64_OP_LD4:
    case IA64_OP_LD8:
    case IA64_OP_LD1A:
    case IA64_OP_LD2A:
    case IA64_OP_LD4A:
    case IA64_OP_LD8A:
    case IA64_OP_LD1FILL:
    case IA64_OP_LD2FILL:
    case IA64_OP_LD4FILL:
    case IA64_OP_LD8FILL:
        return true;
    default:
        return false;
    }
}

static bool ia64_opcode_has_firmware_unaligned_store_assist(Ia64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_ST1:
    case IA64_OP_ST2:
    case IA64_OP_ST4:
    case IA64_OP_ST8:
    case IA64_OP_ST1REL:
    case IA64_OP_ST2REL:
    case IA64_OP_ST4REL:
    case IA64_OP_ST8REL:
    case IA64_OP_ST8SPILL:
        return true;
    default:
        return false;
    }
}

static bool ia64_opcode_is_advanced_load(Ia64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_LD1A:
    case IA64_OP_LD2A:
    case IA64_OP_LD4A:
    case IA64_OP_LD8A:
        return true;
    default:
        return false;
    }
}

static bool ia64_opcode_is_fill_load(Ia64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_LD1FILL:
    case IA64_OP_LD2FILL:
    case IA64_OP_LD4FILL:
    case IA64_OP_LD8FILL:
        return true;
    default:
        return false;
    }
}

static bool ia64_is_m_nop(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (0x7ULL << 33) |
                          (0xfULL << 27) | (0x3ULL << 31) |
                          (1ULL << 26);
    const uint64_t value = 1ULL << 27;

    return (raw & mask) == value;
}

static bool ia64_is_m_break(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (0x7ULL << 33) |
                          (0xfULL << 27) | (0x3ULL << 31);

    return (raw & mask) == 0;
}

static bool ia64_is_i_nop(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (0x7ULL << 33) |
                          (0x3fULL << 27) | (1ULL << 26);
    const uint64_t value = 1ULL << 27;

    return (raw & mask) == value;
}

static bool ia64_is_i_break(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (0x7ULL << 33) |
                          (0x3fULL << 27);

    return (raw & mask) == 0;
}

static bool ia64_is_b_nop(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (0x3fULL << 27);
    const uint64_t value = 2ULL << 37;

    return (raw & mask) == value;
}

static bool ia64_is_b_break(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (0x3fULL << 27);

    return (raw & mask) == 0;
}

static bool ia64_is_f_nop(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (1ULL << 33) |
                          (0x3fULL << 27);
    const uint64_t value = 1ULL << 27;

    return (raw & mask) == value;
}

static bool ia64_is_f_break(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (1ULL << 33) |
                          (0x3fULL << 27);

    return (raw & mask) == 0;
}

static Ia64Instruction ia64_base_insn(Ia64Opcode opcode, Ia64SlotUnit unit,
                                      uint64_t raw, uint64_t address,
                                      uint8_t slot)
{
    Ia64Instruction insn = {
        .opcode = opcode,
        .unit = unit,
        .raw = raw,
        .address = address,
        .slot = slot,
        .qp = ia64_bits(raw, 0, 6),
        .valid = true,
    };

    return insn;
}

static Ia64Instruction ia64_invalid_insn(Ia64SlotUnit unit, uint64_t raw,
                                         uint64_t address, uint8_t slot)
{
    Ia64Instruction insn = {
        .opcode = IA64_OP_ILLEGAL,
        .unit = unit,
        .raw = raw,
        .address = address,
        .slot = slot,
    };

    return insn;
}

/*
 * MLX long forms are reported at slot 1.  The paired X slot carries the
 * opcode/predicate and low immediate bits, and must not execute separately.
 */
static void ia64_apply_mlx_long_fixup(uint8_t template_code,
                                      const uint64_t slots[3],
                                      int slot, Ia64Instruction *insn,
                                      bool *skip_x_slot)
{
    if ((template_code != 4 && template_code != 5) || slot != 1) {
        return;
    }

    uint64_t x_slot = slots[2];
    uint64_t l_slot = slots[1];

    if (ia64_is_i_break(x_slot)) {
        *insn = ia64_base_insn(IA64_OP_BREAK, IA64_UNIT_X, x_slot,
                               insn->address, slot);
        insn->imm = ia64_mlx_x1_imm62(l_slot, x_slot);
        *skip_x_slot = true;
    } else if (ia64_b_op(x_slot) == 0xc &&
               ia64_bits(x_slot, 6, 3) == 0) {
        *insn = ia64_base_insn(IA64_OP_BRL_COND, IA64_UNIT_X, x_slot,
                               insn->address, slot);
        insn->imm = ia64_mlx_brl_disp(l_slot, x_slot);
        *skip_x_slot = true;
    } else if (ia64_b_op(x_slot) == 0xd) {
        *insn = ia64_base_insn(IA64_OP_BRL_CALL, IA64_UNIT_X, x_slot,
                               insn->address, slot);
        insn->b1 = ia64_bits(x_slot, 6, 3);
        insn->imm = ia64_mlx_brl_disp(l_slot, x_slot);
        *skip_x_slot = true;
    } else if (ia64_b_op(x_slot) == 0 &&
               ia64_bits(x_slot, 27, 6) == 1) {
        *insn = ia64_base_insn(IA64_OP_NOP, IA64_UNIT_L, l_slot,
                               insn->address, slot);
        insn->imm = ia64_mlx_x1_imm62(l_slot, x_slot);
        *skip_x_slot = true;
    } else if (insn->opcode == IA64_OP_MOVL && ia64_b_op(x_slot) == 6) {
        ia64_fill_mlx_movl(insn, l_slot, x_slot);
        *skip_x_slot = true;
    } else if (insn->opcode == IA64_OP_MOVL) {
        *insn = ia64_invalid_insn(IA64_UNIT_L, l_slot, insn->address, slot);
    }
}

static Ia64Instruction ia64_decode_insn(Ia64SlotUnit unit, uint64_t raw,
                                        uint64_t address, uint8_t slot)
{
    raw &= IA64_SLOT_MASK;

    if (unit == IA64_UNIT_RESERVED) {
        return ia64_invalid_insn(unit, raw, address, slot);
    }

    if (unit == IA64_UNIT_I &&
        ia64_b_op(raw) == 0 && ia64_bits(raw, 33, 3) == 7) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_MOV_GRBR, unit, raw, address, slot);

        /*
         * The btype/wh/ph/ih target-prediction fields are hints; the
         * architectural state update is still only BR[b1] = GR[r2].
         */
        insn.r2 = ia64_bits(raw, 6, 3);
        insn.r1 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if (unit == IA64_UNIT_M) {
        if (ia64_is_m_nop(raw)) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_NOP, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
        if (ia64_is_m_break(raw)) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_BREAK, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 6) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_ALLOC, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.imm = (ia64_bits(raw, 13, 7) << 0) |
                       (ia64_bits(raw, 20, 7) << 7) |
                       (ia64_bits(raw, 27, 4) << 14);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x21) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_UMGR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x29) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_GRUM, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 13, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x25) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_PSRGR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x2d) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_GRPSR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 13, 7);
            insn.imm = 1;
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x24) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_CRGR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x2c) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_GRCR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 13, 7);
            insn.r2 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_GRRR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 13, 7);
            insn.r2 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x10) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_RRGR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x1e) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_TPA, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            (ia64_bits(raw, 27, 6) == 0x1a ||
             ia64_bits(raw, 27, 6) == 0x1b ||
             ia64_bits(raw, 27, 6) == 0x1f)) {
            Ia64Opcode opcode;

            switch (ia64_bits(raw, 27, 6)) {
            case 0x1a:
                opcode = IA64_OP_THASH;
                break;
            case 0x1b:
                opcode = IA64_OP_TTAG;
                break;
            default:
                opcode = IA64_OP_TAK;
                break;
            }

            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x17 &&
            ia64_bits(raw, 13, 7) == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_CPUID_INDEXED, unit, raw,
                               address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x20) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_DAHRGR_INDEXED, unit, raw,
                               address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x16 &&
            ia64_bits(raw, 13, 7) == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_MSRGR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x06) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_GRMSR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            (ia64_bits(raw, 27, 6) == 0x11 ||
             ia64_bits(raw, 27, 6) == 0x12)) {
            Ia64Instruction insn =
                ia64_base_insn(ia64_bits(raw, 27, 6) == 0x12 ?
                               IA64_OP_MOV_IBRGR_INDEXED :
                               IA64_OP_MOV_DBRGR_INDEXED,
                               unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            (ia64_bits(raw, 27, 6) == 0x01 ||
             ia64_bits(raw, 27, 6) == 0x02)) {
            Ia64Instruction insn =
                ia64_base_insn(ia64_bits(raw, 27, 6) == 0x02 ?
                               IA64_OP_MOV_GRIBR_INDEXED :
                               IA64_OP_MOV_GRDBR_INDEXED,
                               unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x03) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_GRPKR_INDEXED, unit, raw,
                               address, slot);
            insn.r1 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x13) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_PKRGR_INDEXED, unit, raw,
                               address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            (ia64_bits(raw, 27, 6) == 0x04 ||
             ia64_bits(raw, 27, 6) == 0x05)) {
            Ia64Instruction insn =
                ia64_base_insn(ia64_bits(raw, 27, 6) == 0x04 ?
                               IA64_OP_MOV_GRPMC_INDEXED :
                               IA64_OP_MOV_GRPMD_INDEXED,
                               unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            (ia64_bits(raw, 27, 6) == 0x14 ||
             ia64_bits(raw, 27, 6) == 0x15)) {
            Ia64Instruction insn =
                ia64_base_insn(ia64_bits(raw, 27, 6) == 0x14 ?
                               IA64_OP_MOV_PMCGR_INDEXED :
                               IA64_OP_MOV_PMDGR_INDEXED,
                               unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 0 &&
            ia64_bits(raw, 27, 6) == 0x01 &&
            ia64_bits(raw, 20, 7) == 64) {
            return ia64_base_insn(IA64_OP_HINT_M, unit, raw, address, slot);
        }
    }

    if (unit == IA64_UNIT_I || unit == IA64_UNIT_X) {
        if (unit == IA64_UNIT_I &&
            ia64_b_op(raw) == 0 &&
            ia64_bits(raw, 27, 6) == 0x01 &&
            ia64_bits(raw, 20, 7) == 64) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_HINT_I, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
        if (ia64_is_i_nop(raw)) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_NOP, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
        if (ia64_is_i_break(raw)) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_BREAK, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }

        if (unit == IA64_UNIT_I && ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 27, 2) == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_HINT_I, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }

        if (unit == IA64_UNIT_X && ia64_b_op(raw) == 1) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_HINT_X, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
    }

    if (unit == IA64_UNIT_B) {
        if (ia64_is_b_nop(raw)) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_NOP, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
        if (ia64_is_b_break(raw)) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_BREAK, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }

        if (ia64_b_op(raw) == 1 && ia64_bits(raw, 12, 1) == 0 &&
            ia64_bits(raw, 27, 2) == 0 && ia64_bits(raw, 32, 1) == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_HINT_B, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 8) {
        const uint64_t x2a = ia64_bits(raw, 34, 2);
        const uint64_t ve = ia64_bits(raw, 33, 1);

        if (x2a == 2 && ve == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_ADDS, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_imm14(raw);
            return insn;
        }

        const uint64_t x4 = ia64_bits(raw, 29, 4);
        const uint64_t x2b = ia64_bits(raw, 27, 2);
        const unsigned size_code = ve | (ia64_bits(raw, 36, 1) << 1);
        if (x2a == 1 && (x4 == 0 || x4 == 1) &&
            ((size_code < 2 && x2b <= 3) ||
             (size_code == 2 && x2b == 0))) {
            Ia64Opcode opcode = IA64_OP_ILLEGAL;
            if (x4 == 0) {
                if (size_code == 0) {
                    opcode = IA64_OP_PADD1;
                } else if (size_code == 1) {
                    opcode = IA64_OP_PADD2;
                } else if (size_code == 2) {
                    opcode = IA64_OP_PADD4;
                }
            } else {
                if (size_code == 0) {
                    opcode = IA64_OP_PSUB1;
                } else if (size_code == 1) {
                    opcode = IA64_OP_PSUB2;
                } else if (size_code == 2) {
                    opcode = IA64_OP_PSUB4;
                }
            }
            if (opcode != IA64_OP_ILLEGAL) {
                Ia64Instruction insn =
                    ia64_base_insn(opcode, unit, raw, address, slot);
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
                insn.imm = x2b;
                return insn;
            }
        }

        if (x2a == 1 && size_code == 1 && x4 == 4) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_PSHLADD2, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = x2b + 1;
            return insn;
        }

        if (x2a == 1 && size_code == 1 && x4 == 6 && x2b <= 2) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_PSHRADD2, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = x2b + 1;
            return insn;
        }

        if (x2a == 1 &&
            (x4 == 2 || x4 == 3) &&
            (x2b == 2 || (x4 == 2 && x2b == 3)) &&
            ia64_bits(raw, 36, 1) == 0) {
            Ia64Opcode opcode = IA64_OP_ILLEGAL;

            if (x4 == 2) {
                if (ve == 0) {
                    opcode = IA64_OP_PAVG1;
                } else {
                    opcode = IA64_OP_PAVG2;
                }
            } else if (x2b == 2) {
                if (ve == 0) {
                    opcode = IA64_OP_PAVGSUB1;
                } else {
                    opcode = IA64_OP_PAVGSUB2;
                }
            }
            if (opcode != IA64_OP_ILLEGAL) {
                Ia64Instruction insn =
                    ia64_base_insn(opcode, unit, raw, address, slot);
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
                insn.imm = x2b == 3;
                return insn;
            }
        }

        if ((x4 == 4 || x4 == 6) && x2a == 0 && ve == 0) {
            const uint64_t count = x2b;
            Ia64Opcode shladd_op = (x4 == 6) ?
                IA64_OP_SHLADDP4 : IA64_OP_SHLADD;
            Ia64Instruction insn =
                ia64_base_insn(shladd_op, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = count + 1;
            return insn;
        }

        if (x2a == 0 && ve == 0) {
            const Ia64A3AluPattern *pattern = ia64_lookup_a3_alu(x4, x2b);

            if (pattern != NULL) {
                Ia64Instruction insn =
                    ia64_base_insn(pattern->opcode, unit, raw, address, slot);
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
                if (pattern->immediate) {
                    insn.imm = ia64_imm8(raw);
                } else {
                    insn.r2 = ia64_bits(raw, 13, 7);
                }
                return insn;
            }
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 9) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_ADDL, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r3 = ia64_bits(raw, 20, 2);
        insn.imm = ia64_imm22(raw);
        return insn;
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 1 &&
        (ia64_bits(raw, 33, 3) == 1 || ia64_bits(raw, 33, 3) == 3)) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_CHK_S, unit, raw, address, slot);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.imm = ia64_chk_disp(raw);
        insn.check_fp = ia64_bits(raw, 33, 3) == 3;
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 33, 3) == 1) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_CHK_S, unit, raw, address, slot);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.imm = ia64_chk_disp(raw);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_bits(raw, 33, 1) == 0 &&
        ia64_bits(raw, 36, 1) == 0 &&
        (ia64_bits(raw, 34, 2) == 0 || ia64_bits(raw, 34, 2) == 1) &&
        (ia64_b_op(raw) == 0xc || ia64_b_op(raw) == 0xd ||
         ia64_b_op(raw) == 0xe)) {
        const bool cmp4 = ia64_bits(raw, 34, 2) == 1;
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        switch (ia64_b_op(raw)) {
        case 0xc:
            opcode = cmp4 ? IA64_OP_CMP4_LT : IA64_OP_CMP_LT;
            break;
        case 0xd:
            opcode = cmp4 ? IA64_OP_CMP4_LTU : IA64_OP_CMP_LTU;
            break;
        case 0xe:
            opcode = cmp4 ? IA64_OP_CMP4_EQ : IA64_OP_CMP_EQ;
            break;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.compare_unc = ia64_bits(raw, 12, 1) != 0;
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 34, 2) == 1 &&
        ia64_bits(raw, 33, 1) == 1 &&
        ia64_b_op(raw) == 0xc) {
        Ia64Instruction insn =
            ia64_base_insn(ia64_bits(raw, 12, 1) ?
                           IA64_OP_CMP4_NE_AND : IA64_OP_CMP4_EQ_AND,
                           unit, raw, address, slot);
        insn.p1 = ia64_bits(raw, 6, 6);
        insn.p2 = ia64_bits(raw, 27, 6);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        (ia64_b_op(raw) == 0xc || ia64_b_op(raw) == 0xd ||
         ia64_b_op(raw) == 0xe) &&
        ia64_bits(raw, 36, 1) == 1 &&
        (ia64_bits(raw, 34, 2) == 0 || ia64_bits(raw, 34, 2) == 1)) {
        Ia64Opcode opcode =
            ia64_compare_zero_opcode(ia64_b_op(raw),
                                     ia64_bits(raw, 34, 2) == 1,
                                     ia64_bits(raw, 33, 1),
                                     ia64_bits(raw, 12, 1));
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = 0;
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xc &&
        ia64_bits(raw, 33, 1) == 1 &&
        (ia64_bits(raw, 34, 2) == 2 || ia64_bits(raw, 34, 2) == 3)) {
        const uint64_t x2a = ia64_bits(raw, 34, 2);
        const bool cmp4 = x2a == 3;
        const bool ne = ia64_bits(raw, 12, 1) != 0;
        Ia64Opcode opcode = cmp4 ?
            (ne ? IA64_OP_CMP4_NE_AND_IMM : IA64_OP_CMP4_EQ_AND_IMM) :
            (ne ? IA64_OP_CMP_NE_AND_IMM : IA64_OP_CMP_EQ_AND_IMM);
        Ia64Instruction insn = ia64_base_insn(opcode, unit, raw, address, slot);
        insn.p1 = ia64_bits(raw, 6, 6);
        insn.p2 = ia64_bits(raw, 27, 6);
        insn.imm = ia64_imm8(raw);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xc &&
        ia64_bits(raw, 33, 1) == 1 &&
        ia64_bits(raw, 34, 2) == 0 &&
        ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(ia64_bits(raw, 12, 1) ?
                           IA64_OP_CMP_NE_AND : IA64_OP_CMP_EQ_AND,
                           unit, raw, address, slot);
        insn.p1 = ia64_bits(raw, 6, 6);
        insn.p2 = ia64_bits(raw, 27, 6);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xc &&
        ia64_bits(raw, 33, 1) == 1 &&
        ia64_bits(raw, 34, 2) == 0 &&
        ia64_bits(raw, 36, 1) == 1) {
        Ia64Instruction insn =
            ia64_base_insn(ia64_bits(raw, 12, 1) ?
                           IA64_OP_CMP_LT_AND : IA64_OP_CMP_GE_AND,
                           unit, raw, address, slot);
        insn.p1 = ia64_bits(raw, 6, 6);
        insn.p2 = ia64_bits(raw, 27, 6);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xd && ia64_bits(raw, 12, 1) == 0 &&
        ia64_bits(raw, 33, 1) == 0 && ia64_bits(raw, 34, 2) == 0 &&
        ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_CMP_LTU, unit, raw, address, slot);
        insn.p1 = ia64_bits(raw, 6, 6);
        insn.p2 = ia64_bits(raw, 27, 6);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xc && ia64_bits(raw, 12, 1) == 0 &&
        ia64_bits(raw, 33, 1) == 0 && ia64_bits(raw, 34, 2) == 0 &&
        ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_CMP_LT, unit, raw, address, slot);
        insn.p1 = ia64_bits(raw, 6, 6);
        insn.p2 = ia64_bits(raw, 27, 6);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xc && ia64_bits(raw, 12, 1) == 0) {
        const uint64_t x2a = ia64_bits(raw, 34, 2);
        if (ia64_bits(raw, 33, 1) == 0 && (x2a == 2 || x2a == 3)) {
            Ia64Instruction insn =
                ia64_base_insn(x2a == 2 ? IA64_OP_CMP_LT_IMM :
                                           IA64_OP_CMP4_LT_IMM,
                               unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.imm = ia64_imm8(raw);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xc && ia64_bits(raw, 12, 1) == 1 &&
        ia64_bits(raw, 33, 1) == 0) {
        const uint64_t x2a = ia64_bits(raw, 34, 2);
        const uint64_t ve = ia64_bits(raw, 36, 1);
        if (x2a == 1 && ve == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP4_LT, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.compare_unc = true;
            return insn;
        }
        if (x2a == 2 || x2a == 3) {
            Ia64Instruction insn =
                ia64_base_insn(x2a == 2 ? IA64_OP_CMP_LT_IMM :
                                           IA64_OP_CMP4_LT_IMM,
                               unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.imm = ia64_imm8(raw);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.compare_unc = true;
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xe &&
        ia64_bits(raw, 36, 1) == 1) {
        const uint64_t x2 = ia64_bits(raw, 34, 2);
        const uint64_t ta = ia64_bits(raw, 33, 1);
        const uint64_t c = ia64_bits(raw, 12, 1);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        if (x2 == 0) {
            if (ta == 0 && c == 0) {
                opcode = IA64_OP_CMP_GT_OR_ANDCM;
            } else if (ta == 0 && c == 1) {
                opcode = IA64_OP_CMP_LE_OR_ANDCM;
            } else if (ta == 1 && c == 0) {
                opcode = IA64_OP_CMP_GE_OR_ANDCM;
            } else if (ta == 1 && c == 1) {
                opcode = IA64_OP_CMP_LT_OR_ANDCM;
            }
        } else if (x2 == 1) {
            if (ta == 0 && c == 0) {
                opcode = IA64_OP_CMP4_GT_OR_ANDCM;
            } else if (ta == 0 && c == 1) {
                opcode = IA64_OP_CMP4_LE_OR_ANDCM;
            } else if (ta == 1 && c == 0) {
                opcode = IA64_OP_CMP4_GE_OR_ANDCM;
            } else if (ta == 1 && c == 1) {
                opcode = IA64_OP_CMP4_LT_OR_ANDCM;
            }
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xc && ia64_bits(raw, 34, 2) == 0 &&
        ia64_bits(raw, 33, 1) == 0) {
        const uint64_t x4 = ia64_bits(raw, 29, 4);
        const uint64_t x2b = ia64_bits(raw, 27, 2);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;
        if (x4 == 0 && x2b == 0) {
            opcode = IA64_OP_PADD1;
        } else if (x4 == 0 && x2b == 1) {
            opcode = IA64_OP_PADD2;
        } else if (x4 == 0 && x2b == 2) {
            opcode = IA64_OP_PADD4;
        } else if (x4 == 1 && x2b == 0) {
            opcode = IA64_OP_PSUB1;
        } else if (x4 == 1 && x2b == 1) {
            opcode = IA64_OP_PSUB2;
        } else if (x4 == 1 && x2b == 2) {
            opcode = IA64_OP_PSUB4;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 8 &&
        ia64_bits(raw, 29, 4) == 9 &&
        ia64_bits(raw, 34, 2) == 1 &&
        ia64_bits(raw, 32, 1) == 1) {
        const uint64_t za = ia64_bits(raw, 36, 1);
        const uint64_t zb = ia64_bits(raw, 33, 1);
        const uint64_t x2b = ia64_bits(raw, 27, 2);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        if (x2b == 0 || x2b == 1) {
            if (za == 0 && zb == 0) {
                opcode = x2b == 0 ? IA64_OP_PCMP1_EQ : IA64_OP_PCMP1_GT;
            } else if (za == 0 && zb == 1) {
                opcode = x2b == 0 ? IA64_OP_PCMP2_EQ : IA64_OP_PCMP2_GT;
            } else if (za == 1 && zb == 0) {
                opcode = x2b == 0 ? IA64_OP_PCMP4_EQ : IA64_OP_PCMP4_GT;
            }
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 33, 1) == 1 && ia64_bits(raw, 34, 2) == 0 &&
        ia64_bits(raw, 36, 1) == 1) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        if ((x6 & ~1ULL) == 0) {
            opcode = IA64_OP_SHRU;
        } else if ((x6 & ~1ULL) == 4) {
            opcode = IA64_OP_SHR;
        } else if ((x6 & ~1ULL) == 8) {
            opcode = IA64_OP_SHL;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            if (opcode == IA64_OP_SHL) {
                insn.r2 = ia64_bits(raw, 20, 7);
                insn.r3 = ia64_bits(raw, 13, 7);
            } else {
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
            }
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 36, 1) == 1 &&
        ia64_bits(raw, 33, 3) == 0) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        if ((x6 & ~1ULL) == 0x1a) {
            opcode = IA64_OP_MPY4;
        } else if ((x6 & ~1ULL) == 0x1e) {
            opcode = IA64_OP_MPYSHL4;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 34, 2) == 0 &&
        ((ia64_bits(raw, 36, 1) == 0 && ia64_bits(raw, 33, 1) == 1) ||
         (ia64_bits(raw, 36, 1) == 1 && ia64_bits(raw, 33, 1) == 0)) &&
        (ia64_bits(raw, 27, 6) & ~1ULL) == 0x08) {
        Ia64Instruction insn =
            ia64_base_insn(ia64_bits(raw, 36, 1) ?
                           IA64_OP_PSHL4 : IA64_OP_PSHL2,
                           unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.imm = -1;
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 34, 2) == 3 &&
        ia64_bits(raw, 32, 1) == 0 &&
        ia64_bits(raw, 30, 2) == 1 &&
        ia64_bits(raw, 28, 2) == 1 &&
        ((ia64_bits(raw, 36, 1) == 0 && ia64_bits(raw, 33, 1) == 1) ||
         (ia64_bits(raw, 36, 1) == 1 && ia64_bits(raw, 33, 1) == 0)) &&
        ia64_bits(raw, 25, 2) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(ia64_bits(raw, 36, 1) ?
                           IA64_OP_PSHL4 : IA64_OP_PSHL2,
                           unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.imm = ia64_bits(raw, 20, 5);
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7) {
        const uint64_t pshr_sig = raw & 0x1fff0000000ULL;
        Ia64Opcode opcode = IA64_OP_ILLEGAL;
        bool fixed_count = false;

        switch (pshr_sig) {
        case 0xe220000000ULL:
            opcode = IA64_OP_PSHR2;
            break;
        case 0xe200000000ULL:
            opcode = IA64_OP_PSHR2_U;
            break;
        case 0xe630000000ULL:
            opcode = IA64_OP_PSHR2;
            fixed_count = true;
            break;
        case 0xe610000000ULL:
            opcode = IA64_OP_PSHR2_U;
            fixed_count = true;
            break;
        case 0xf020000000ULL:
            opcode = IA64_OP_PSHR4;
            break;
        case 0xf000000000ULL:
            opcode = IA64_OP_PSHR4_U;
            break;
        case 0xf430000000ULL:
            opcode = IA64_OP_PSHR4;
            fixed_count = true;
            break;
        case 0xf410000000ULL:
            opcode = IA64_OP_PSHR4_U;
            fixed_count = true;
            break;
        }

        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            if (fixed_count) {
                insn.imm = ia64_bits(raw, 14, 5);
            } else {
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.imm = -1;
            }
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 34, 2) == 3 &&
        ia64_bits(raw, 32, 1) == 0 &&
        ia64_bits(raw, 30, 2) == 2 &&
        ia64_bits(raw, 28, 2) == 2) {
        bool two_byte_form = ia64_bits(raw, 33, 1) != 0;
        Ia64Instruction insn =
            ia64_base_insn(two_byte_form ? IA64_OP_MUX2 : IA64_OP_MUX1,
                           unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.imm = two_byte_form ? ia64_bits(raw, 20, 8) :
                                   ia64_bits(raw, 20, 4);
        if (!two_byte_form &&
            !(insn.imm == 0 || (insn.imm >= 8 && insn.imm <= 11))) {
            return ia64_invalid_insn(unit, raw, address, slot);
        }
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 27, 6) == 0x12 &&
        ia64_bits(raw, 33, 3) == 3 &&
        ia64_bits(raw, 13, 7) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_POPCNT, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 27, 6) == 0x1a &&
        ia64_bits(raw, 33, 3) == 3 &&
        ia64_bits(raw, 13, 7) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_CLZ, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 33, 3) == 5) {
        const uint64_t x6 = ia64_bits(raw, 27, 6) & ~1ULL;
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        if (x6 == 0x1e) {
            opcode = IA64_OP_PMPY2_L;
        } else if (x6 == 0x1a) {
            opcode = IA64_OP_PMPY2_R;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 33, 3) == 1) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;
        uint64_t shift = 0;

        switch (x6) {
        case 0x06:
            opcode = IA64_OP_PMPYSH2;
            shift = 0;
            break;
        case 0x0e:
            opcode = IA64_OP_PMPYSH2;
            shift = 7;
            break;
        case 0x16:
            opcode = IA64_OP_PMPYSH2;
            shift = 15;
            break;
        case 0x1e:
            opcode = IA64_OP_PMPYSH2;
            shift = 16;
            break;
        case 0x02:
            opcode = IA64_OP_PMPYSH2_U;
            shift = 0;
            break;
        case 0x0a:
            opcode = IA64_OP_PMPYSH2_U;
            shift = 7;
            break;
        case 0x12:
            opcode = IA64_OP_PMPYSH2_U;
            shift = 15;
            break;
        case 0x1a:
            opcode = IA64_OP_PMPYSH2_U;
            shift = 16;
            break;
        }

        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = shift;
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ((ia64_bits(raw, 27, 6) & ~1ULL) == 0x10 ||
         (ia64_bits(raw, 27, 6) & ~1ULL) == 0x14)) {
        const uint64_t x6 = ia64_bits(raw, 27, 6) & ~1ULL;
        const uint64_t x3 = ia64_bits(raw, 33, 3);
        const bool right = x6 == 0x10;
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        if (x3 == 4 && ia64_bits(raw, 36, 1) == 0) {
            opcode = right ? IA64_OP_MIX1_R : IA64_OP_MIX1_L;
        } else if (x3 == 5 && ia64_bits(raw, 36, 1) == 0) {
            opcode = right ? IA64_OP_MIX2_R : IA64_OP_MIX2_L;
        } else if (x3 == 4 && ia64_bits(raw, 36, 1) == 1) {
            opcode = right ? IA64_OP_MIX4_R : IA64_OP_MIX4_L;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 34, 2) == 2 &&
        ia64_bits(raw, 32, 1) == 0 &&
        ia64_bits(raw, 30, 2) == 0) {
        const uint64_t za = ia64_bits(raw, 36, 1);
        const uint64_t zb = ia64_bits(raw, 33, 1);
        const uint64_t x2b = ia64_bits(raw, 28, 2);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        if (za == 0 && zb == 1 && x2b == 0) {
            opcode = IA64_OP_PACK2_USS;
        } else if (za == 0 && zb == 1 && x2b == 2) {
            opcode = IA64_OP_PACK2_SSS;
        } else if (za == 1 && zb == 0 && x2b == 2) {
            opcode = IA64_OP_PACK4_SSS;
        } else if (za == 0 && zb == 0 && x2b == 1) {
            opcode = IA64_OP_PMIN1_U;
        } else if (za == 0 && zb == 1 && x2b == 3) {
            opcode = IA64_OP_PMIN2;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 34, 2) == 2 &&
        ia64_bits(raw, 32, 1) == 0 &&
        ia64_bits(raw, 30, 2) == 1) {
        const uint64_t za = ia64_bits(raw, 36, 1);
        const uint64_t zb = ia64_bits(raw, 33, 1);
        const uint64_t x2b = ia64_bits(raw, 28, 2);

        if (za == 0 && zb == 0 && x2b == 1) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_PMAX1_U, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
        if (za == 0 && zb == 1 && x2b == 3) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_PMAX2, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 34, 2) == 2 &&
        ia64_bits(raw, 32, 1) == 0 &&
        ia64_bits(raw, 30, 2) == 2 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 33, 1) == 0 &&
        ia64_bits(raw, 28, 2) == 3) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_PSAD1, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 34, 2) == 2 &&
        ia64_bits(raw, 32, 1) == 0 &&
        ia64_bits(raw, 30, 2) == 1) {
        Ia64Opcode opcode =
            ia64_unpack_opcode_from_fields(ia64_bits(raw, 36, 1),
                                           ia64_bits(raw, 33, 1),
                                           ia64_bits(raw, 28, 2));

        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 33, 4) == 0) {
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        switch (ia64_bits(raw, 27, 6)) {
        case 0x18: opcode = IA64_OP_CZX1_L; break;
        case 0x1c: opcode = IA64_OP_CZX1_R; break;
        case 0x19: opcode = IA64_OP_CZX2_L; break;
        case 0x1d: opcode = IA64_OP_CZX2_R; break;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xd && ia64_bits(raw, 34, 2) == 0 &&
        ia64_bits(raw, 33, 1) == 0) {
        const uint64_t x4 = ia64_bits(raw, 29, 4);
        const uint64_t x2b = ia64_bits(raw, 27, 2);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;
        if (x4 == 0 && x2b == 0) {
            opcode = IA64_OP_SXT1;
        } else if (x4 == 0 && x2b == 1) {
            opcode = IA64_OP_SXT2;
        } else if (x4 == 0 && x2b == 2) {
            opcode = IA64_OP_SXT4;
        } else if (x4 == 1 && x2b == 0) {
            opcode = IA64_OP_ZXT1;
        } else if (x4 == 1 && x2b == 1) {
            opcode = IA64_OP_ZXT2;
        } else if (x4 == 1 && x2b == 2) {
            opcode = IA64_OP_ZXT4;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    /* CMP-immediate: M/I-unit, b_op == 0xd, bits-34:33 != 0 */
    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xd &&
        !(ia64_bits(raw, 34, 2) == 0 && ia64_bits(raw, 33, 1) == 0)) {
        const uint64_t x2a = ia64_bits(raw, 34, 2);
        const uint64_t ve = ia64_bits(raw, 36, 1);
        const uint64_t x = ia64_bits(raw, 33, 1);
        const bool compare_unc = ia64_bits(raw, 12, 1) != 0;
        Ia64Opcode opcode = ia64_compare_opcode_from_cmp(x2a, ve);

        if (x == 1 && (x2a == 2 || x2a == 3)) {
            const bool cmp4 = x2a == 3;
            const bool ne = ia64_bits(raw, 12, 1) != 0;
            opcode = cmp4 ?
                (ne ? IA64_OP_CMP4_NE_OR_IMM : IA64_OP_CMP4_EQ_OR_IMM) :
                (ne ? IA64_OP_CMP_NE_OR_IMM : IA64_OP_CMP_EQ_OR_IMM);
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.imm = ia64_imm8(raw);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ve == 1 && (x2a == 0 || x2a == 1)) {
            const uint64_t c = ia64_bits(raw, 12, 1);
            if (x2a == 0) {
                if (x == 0 && c == 0) {
                    opcode = IA64_OP_CMP_GT_OR;
                } else if (x == 0 && c == 1) {
                    opcode = IA64_OP_CMP_LE_OR;
                } else if (x == 1 && c == 0) {
                    opcode = IA64_OP_CMP_GE_OR;
                } else {
                    opcode = IA64_OP_CMP_LT_OR;
                }
            } else {
                if (x == 0 && c == 0) {
                    opcode = IA64_OP_CMP4_GT_OR;
                } else if (x == 0 && c == 1) {
                    opcode = IA64_OP_CMP4_LE_OR;
                } else if (x == 1 && c == 0) {
                    opcode = IA64_OP_CMP4_GE_OR;
                } else {
                    opcode = IA64_OP_CMP4_LT_OR;
                }
            }
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (x == 1 && x2a == 0 && ve == 0) {
            Ia64Instruction insn =
                ia64_base_insn(compare_unc ? IA64_OP_CMP_NE_OR :
                                             IA64_OP_CMP_EQ_OR,
                               unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
        if (x == 1 && x2a == 1 && ve == 0) {
            Ia64Instruction insn =
                ia64_base_insn(compare_unc ? IA64_OP_CMP4_NE_OR :
                                             IA64_OP_CMP4_EQ_OR,
                               unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (opcode != IA64_OP_ILLEGAL && x == 0 && x2a == 1 && ve == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP4_LTU, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
        if (x == 0 && x2a == 2) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP_LTU_IMM, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.imm = ia64_imm8(raw);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.compare_unc = compare_unc;
            return insn;
        }
        if (x == 0 && x2a == 3) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP4_LTU_IMM, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.imm = ia64_imm8(raw);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.compare_unc = compare_unc;
            return insn;
        }
        if (opcode != IA64_OP_ILLEGAL && x == 0) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xe && ia64_bits(raw, 12, 1) == 0) {
        const uint64_t x2a = ia64_bits(raw, 34, 2);
        const uint64_t ve = ia64_bits(raw, 36, 1);
        const uint64_t x = ia64_bits(raw, 33, 1);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        if (x == 0 && x2a == 1 && ve == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP4_EQ, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (x == 0 && x2a == 3) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP4_EQ_IMM, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_imm8(raw);
            return insn;
        }

        if (x == 1 && x2a == 3) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP4_EQ_OR_ANDCM_IMM, unit, raw,
                               address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_imm8(raw);
            return insn;
        }

        if (x == 1 && x2a == 0 && ve == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP_EQ_OR_ANDCM, unit, raw,
                               address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (x == 1 && x2a == 1 && ve == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP4_EQ_OR_ANDCM, unit, raw,
                               address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (x == 1 && x2a == 1 && ve == 1 &&
            ia64_bits(raw, 13, 7) == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP4_GE_OR_ANDCM, unit, raw,
                               address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (x == 1 && x2a == 2) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP_EQ_OR_ANDCM_IMM, unit, raw,
                               address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_imm8(raw);
            return insn;
        }

        if (x == 0 && x2a == 2) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP_EQ_IMM, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_imm8(raw);
            return insn;
        }
        if (x == 0 && x2a == 3) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP4_EQ_IMM, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_imm8(raw);
            return insn;
        }

        if (x == 0) {
            opcode = ia64_compare_opcode_from_cmp(x2a, ve);
            if (opcode == IA64_OP_ILLEGAL && x2a == 3 && ve == 1) {
                opcode = IA64_OP_CMP_NE;
            }
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 5 &&
        ia64_bits(raw, 33, 1) == 0 && ia64_bits(raw, 34, 2) == 3) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_SHRP_IMM, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.imm = ia64_bits(raw, 27, 6);
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 5 &&
        ia64_bits(raw, 33, 1) == 1 && ia64_bits(raw, 34, 2) == 1 &&
        ia64_bits(raw, 20, 7) >= 64) {
        const uint64_t imm8 = ia64_bits(raw, 13, 7) |
                              (ia64_bits(raw, 36, 1) << 7);
        const uint64_t len = ia64_bits(raw, 27, 6) + 1;
        const uint64_t pos = 127 - ia64_bits(raw, 20, 7);
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_DEPZ_IMM, unit, raw, address, slot);

        insn.r1 = ia64_bits(raw, 6, 7);
        insn.imm = pos | (len << 6) | (imm8 << 13);
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 5 &&
        ia64_bits(raw, 33, 1) == 1 && ia64_bits(raw, 34, 2) == 1) {
        const uint64_t len = ia64_bits(raw, 27, 6) + 1;
        const uint64_t pos = 63 - ia64_bits(raw, 20, 7);
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_DEPZ, unit, raw, address, slot);

        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.imm = pos | (len << 6);
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 4 &&
        !(ia64_bits(raw, 27, 9) == 0xe1 &&
          ia64_bits(raw, 36, 1) == 0)) {
        const uint64_t len = (ia64_bits(raw, 27, 4) + 1) & 0x3f;
        const uint64_t cpos = ia64_bits(raw, 31, 2) |
                              (ia64_bits(raw, 33, 1) << 2) |
                              (ia64_bits(raw, 34, 2) << 3) |
                              (ia64_bits(raw, 36, 1) << 5);
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_DEP, unit, raw, address, slot);

        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.imm = (63 - cpos) | (len << 6);
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 5 &&
        ia64_bits(raw, 33, 1) == 1 && ia64_bits(raw, 34, 2) == 3) {
        const uint64_t len = ia64_bits(raw, 27, 6) + 1;
        const uint64_t pos = 63 - (ia64_bits(raw, 13, 7) >> 1);
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_DEP_IMM, unit, raw, address, slot);

        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.imm = pos | (len << 6) | (ia64_bits(raw, 36, 1) << 13);
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 5 &&
        ia64_bits(raw, 34, 2) == 1) {
        const uint64_t x3 = ia64_bits(raw, 33, 3);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;
        if (x3 == 2) {
            uint64_t pos_sign = ia64_bits(raw, 13, 7);
            Ia64Instruction insn = ia64_base_insn(
                (pos_sign & 1) ? IA64_OP_EXTR : IA64_OP_EXTRU,
                unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = (pos_sign >> 1) |
                       ((ia64_bits(raw, 27, 6) + 1) << 6);
            return insn;
        } else if (x3 == 3) {
            opcode = IA64_OP_SHL_IMM;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            if (opcode == IA64_OP_SHL_IMM) {
                insn.r3 = ia64_bits(raw, 13, 7);
                insn.imm = 63 - ia64_bits(raw, 20, 6);
            } else {
                insn.r3 = ia64_bits(raw, 20, 7);
                insn.imm = 63 - ia64_bits(raw, 27, 6);
            }
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 33, 1) == 0 && ia64_bits(raw, 34, 2) == 1) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_MOV_PR_ROT_IMM, unit, raw, address, slot);
        insn.imm = ia64_pr_rot_imm(raw);
        return insn;
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 33, 1) == 0 && ia64_bits(raw, 34, 2) == 0 &&
        ia64_bits(raw, 36, 1) == 0) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);

        if (x6 == 0x0a) {
            return ia64_base_insn(IA64_OP_LOADRS, unit, raw, address, slot);
        } else if (x6 == 0x0c) {
            return ia64_base_insn(IA64_OP_FLUSHRS, unit, raw, address, slot);
        } else if (x6 == 0x10) {
            return ia64_base_insn(IA64_OP_INVALA, unit, raw, address, slot);
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0) {
        const uint64_t x3 = ia64_bits(raw, 33, 3);
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;
        if (unit == IA64_UNIT_I && x3 == 0 && x6 == 0x31) {
            opcode = IA64_OP_MOV_BRGR;  /* mov r=b (BR to GR) */
        } else if (x3 == 0 && x6 == 0x33) {
            opcode = IA64_OP_MOV_PRGR;  /* mov r=pr (PR to GR) */
        } else if (unit == IA64_UNIT_I && x3 == 0 && x6 == 0x30) {
            opcode = IA64_OP_MOV_CURRENT_IP;
        } else if (x3 == 3) {
            opcode = IA64_OP_MOV_GRPR;  /* mov pr=r (GR to PR) */
        } else if (x3 == 0 && x6 == 0x32) {
            opcode = IA64_OP_MOV_ARGR;  /* mov r=ar (AR to GR) */
        } else if (x3 == 0 && x6 == 0x2a) {
            opcode = IA64_OP_MOV_GRAR;  /* mov ar=r (GR to AR) */
        } else if (x3 == 0 && x6 == 0x0a) {
            opcode = IA64_OP_MOV_IMMAR; /* mov ar=imm */
        } else if (unit == IA64_UNIT_M && x3 == 0 && x6 == 0x28) {
            opcode = IA64_OP_MOV_IMMAR; /* mov.m ar=imm */
        } else if (unit == IA64_UNIT_I && x3 == 0 && x6 == 0x10) {
            opcode = IA64_OP_ZXT1;
        } else if (unit == IA64_UNIT_I && x3 == 0 && x6 == 0x11) {
            opcode = IA64_OP_ZXT2;
        } else if (unit == IA64_UNIT_I && x3 == 0 && x6 == 0x12) {
            opcode = IA64_OP_ZXT4;
        } else if (unit == IA64_UNIT_I && x3 == 0 && x6 == 0x14) {
            opcode = IA64_OP_SXT1;
        } else if (unit == IA64_UNIT_I && x3 == 0 && x6 == 0x15) {
            opcode = IA64_OP_SXT2;
        } else if (unit == IA64_UNIT_I && x3 == 0 && x6 == 0x16) {
            opcode = IA64_OP_SXT4;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            if (opcode == IA64_OP_SXT1 || opcode == IA64_OP_SXT2 ||
                opcode == IA64_OP_SXT4 || opcode == IA64_OP_ZXT1 ||
                opcode == IA64_OP_ZXT2 || opcode == IA64_OP_ZXT4) {
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
            } else if (opcode == IA64_OP_MOV_CURRENT_IP) {
                insn.r1 = ia64_bits(raw, 6, 7);
            } else if (opcode == IA64_OP_MOV_GRPR) {
                insn.r1 = ia64_bits(raw, 13, 7);
                insn.imm = ia64_pr_mask(raw);
            } else if (opcode == IA64_OP_MOV_GRAR) {
                insn.r1 = ia64_bits(raw, 13, 7);
                insn.r2 = ia64_bits(raw, 20, 7);
            } else if (opcode == IA64_OP_MOV_IMMAR) {
                insn.r2 = ia64_bits(raw, 20, 7);
                insn.imm = ia64_bits(raw, 13, 7);
            } else if (opcode == IA64_OP_MOV_ARGR) {
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = ia64_bits(raw, 20, 7);
            } else {
                /*
                 * BR/PR-to-GR: TCG emitter reads insn->r1 as GR destination,
                 * insn->r2 as BR/PR source.
                 */
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = ia64_bits(raw, 13, 3);
            }
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 1 && ia64_bits(raw, 33, 3) == 0) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        if (x6 == 0x22) {
            opcode = IA64_OP_MOV_ARGR;  /* mov.m r=ar */
        } else if (x6 == 0x2a) {
            opcode = IA64_OP_MOV_GRAR;  /* mov.m ar=r */
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);

            if (opcode == IA64_OP_MOV_ARGR) {
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = ia64_bits(raw, 20, 7);
            } else {
                insn.r1 = ia64_bits(raw, 13, 7);
                insn.r2 = ia64_bits(raw, 20, 7);
            }
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xe && ia64_bits(raw, 12, 1) == 1) {
        const uint64_t x2a = ia64_bits(raw, 34, 2);
        const uint64_t ve = ia64_bits(raw, 36, 1);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;
        if (ia64_bits(raw, 33, 1) == 0 && (x2a == 2 || x2a == 3)) {
            Ia64Instruction insn =
                ia64_base_insn(x2a == 2 ? IA64_OP_CMP_EQ_IMM :
                                           IA64_OP_CMP4_EQ_IMM,
                               unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_imm8(raw);
            insn.compare_unc = true;
            return insn;
        }
        if (ia64_bits(raw, 33, 1) == 1 && x2a == 2) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP_NE_OR_ANDCM_IMM, unit, raw,
                               address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_imm8(raw);
            return insn;
        }
        if (ia64_bits(raw, 33, 1) == 1 && x2a == 0 && ve == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP_NE_OR_ANDCM, unit, raw,
                               address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
        if (ia64_bits(raw, 33, 1) == 1 && x2a == 1 && ve == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP4_NE_OR_ANDCM, unit, raw,
                               address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
        if (ia64_bits(raw, 33, 1) == 1 && x2a == 3) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP4_NE_OR_ANDCM_IMM, unit, raw,
                               address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_imm8(raw);
            return insn;
        }
        if (ia64_bits(raw, 33, 1) == 0) {
            switch ((x2a << 1) | ve) {
            case 0: opcode = IA64_OP_CMP4_EQ; break;
            case 1: opcode = IA64_OP_CMP4_LT; break;
            case 2: opcode = IA64_OP_CMP4_LE; break;
            case 3: opcode = IA64_OP_CMP4_GT; break;
            case 4: opcode = IA64_OP_CMP4_GE; break;
            case 5: opcode = IA64_OP_CMP4_LTU; break;
            case 6: opcode = IA64_OP_CMP4_LEU; break;
            case 7: opcode = IA64_OP_CMP4_GTU; break;
            case 8: opcode = IA64_OP_CMP4_GEU; break;
            }
        } else {
            switch ((x2a << 1) | ve) {
            case 0: opcode = IA64_OP_TBIT_Z;  break;
            case 1: opcode = IA64_OP_TBIT_NZ; break;
            case 2: opcode = IA64_OP_TNAT_Z;  break;
            case 3: opcode = IA64_OP_TNAT_NZ; break;
            }
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_I &&
        ia64_b_op(raw) == 5 &&
        ia64_bits(raw, 34, 2) == 0) {
        const bool bit13 = ia64_bits(raw, 13, 1);
        const bool bit33 = ia64_bits(raw, 33, 1);
        const bool bit36 = ia64_bits(raw, 36, 1);
        const bool nz_form = ia64_bits(raw, 12, 1);
        const bool is_tf = bit13 && ia64_bits(raw, 19, 1) == 1 &&
                           ia64_bits(raw, 20, 7) == 0;
        const bool is_tnat = bit13 && !is_tf;
        const bool is_tbit = !bit13;

        if (is_tbit || is_tnat || is_tf) {
            Ia64Instruction insn =
                ia64_base_insn(is_tf ?
                               (nz_form && (bit33 || bit36) ?
                                IA64_OP_TF_NZ : IA64_OP_TF_Z) :
                               is_tnat ?
                               (nz_form && (bit33 || bit36) ?
                                IA64_OP_TNAT_NZ : IA64_OP_TNAT_Z) :
                               (nz_form && (bit33 || bit36) ?
                                IA64_OP_TBIT_NZ : IA64_OP_TBIT_Z),
                               unit, raw, address, slot);

            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            if (is_tbit) {
                insn.imm = ia64_bits(raw, 14, 6);
            } else if (is_tf) {
                insn.imm = 32 + ia64_bits(raw, 14, 5);
            }
            if (!bit33 && !bit36) {
                insn.compare_unc = nz_form;
            } else if (!bit33 && bit36) {
                insn.pred_update = IA64_PRED_UPDATE_AND;
            } else if (bit33 && !bit36) {
                insn.pred_update = IA64_PRED_UPDATE_OR;
            } else {
                insn.pred_update = IA64_PRED_UPDATE_OR_ANDCM;
            }
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_bits(raw, 12, 1) == 0 &&
        ia64_bits(raw, 33, 1) == 0 &&
        ia64_bits(raw, 34, 2) == 1 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_b_op(raw) == 0xc) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_CMP4_LT, unit, raw, address, slot);
        insn.p1 = ia64_bits(raw, 6, 6);
        insn.p2 = ia64_bits(raw, 27, 6);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 0) {
        const uint64_t x2a = ia64_bits(raw, 34, 2);
        const uint64_t ar_num = ia64_bits(raw, 13, 7);
        Ia64Opcode opcode;
        if (x2a == 0) {
            opcode = IA64_OP_MOV_ARGR;
        } else if (x2a == 1) {
            opcode = IA64_OP_MOV_GRAR;
        } else {
            opcode = IA64_OP_ILLEGAL;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ar_num;
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xb && ia64_bits(raw, 33, 1) == 0) {
        const uint64_t x2a = ia64_bits(raw, 34, 2);
        const uint64_t cr_num = ia64_bits(raw, 13, 7);
        Ia64Opcode opcode;
        if (x2a == 0) {
            if (cr_num == 4) {
                opcode = IA64_OP_MOV_UMGR;
            } else if (cr_num == 13) {
                opcode = IA64_OP_MOV_CPUID;
            } else if (cr_num == 19) {
                opcode = IA64_OP_MOV_IP;
            } else if (cr_num >= 12 && cr_num <= 19) {
                opcode = IA64_OP_MOV_IBRGR;
            } else {
                opcode = IA64_OP_MOV_CRGR;
            }
        } else if (x2a == 1) {
            if (cr_num == 4) {
                opcode = IA64_OP_MOV_GRUM;
            } else if (cr_num >= 12 && cr_num <= 19) {
                opcode = IA64_OP_MOV_GRIBR;
            } else {
                opcode = IA64_OP_MOV_GRCR;
            }
        } else {
            opcode = IA64_OP_ILLEGAL;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = cr_num;
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 1 &&
        ia64_bits(raw, 34, 2) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_ALLOC, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.imm = (ia64_bits(raw, 13, 7) << 0) |
                   (ia64_bits(raw, 20, 7) << 7) |
                   (ia64_bits(raw, 27, 5) << 14);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 1 &&
        ia64_bits(raw, 34, 2) == 1 && ia64_bits(raw, 27, 6) == 0 &&
        ia64_bits(raw, 36, 1) == 0) {
        return ia64_base_insn(IA64_OP_COVER, unit, raw, address, slot);
    }

    if (unit == IA64_UNIT_B &&
        (raw & IA64_COVER_B_MASK) == IA64_COVER_B_VALUE) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_COVER, unit, raw, address, slot);
        insn.qp = 0;
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 1 &&
        ia64_bits(raw, 34, 2) == 3 && ia64_bits(raw, 27, 6) == 0 &&
        ia64_bits(raw, 36, 1) == 0) {
        return ia64_base_insn(IA64_OP_FLUSHRS, unit, raw, address, slot);
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 1 &&
        ia64_bits(raw, 34, 2) == 3 && ia64_bits(raw, 27, 1) == 1 &&
        ia64_bits(raw, 36, 1) == 0) {
        return ia64_base_insn(IA64_OP_LOADRS, unit, raw, address, slot);
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 1 &&
        ia64_bits(raw, 34, 2) == 3 &&
        ia64_bits(raw, 27, 6) == 0x0a) {
        return ia64_base_insn(IA64_OP_CLRRRB, unit, raw, address, slot);
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 1 &&
        ia64_bits(raw, 34, 2) == 3 &&
        ia64_bits(raw, 27, 6) == 0x0b) {
        return ia64_base_insn(IA64_OP_CLRRRB_PR, unit, raw, address, slot);
    }

    if (unit == IA64_UNIT_B && (raw & ~0x3fULL) == 0x20000000ULL) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_CLRRRB, unit, raw, address, slot);
        insn.qp = 0;
        return insn;
    }

    if (unit == IA64_UNIT_B && (raw & ~0x3fULL) == 0x28000000ULL) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_CLRRRB_PR, unit, raw, address, slot);
        insn.qp = 0;
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 0 &&
        ia64_bits(raw, 34, 2) == 2 && ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_SSM, unit, raw, address, slot);
        insn.imm = ia64_imm22(raw);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 0 &&
        ia64_bits(raw, 34, 2) == 3 && ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_RSM, unit, raw, address, slot);
        insn.imm = ia64_imm22(raw);
        return insn;
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 && ia64_bits(raw, 27, 1) == 0 &&
        ia64_bits(raw, 28, 2) == 0) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        const Ia64Opcode opcode = ia64_memory_opcode_from_x6a(x6a);
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.mem_acquire = ia64_memory_x6a_is_acquire_load(x6a);
            insn.mem_release = ia64_opcode_is_release_store(opcode);
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 27, 1) == 1 &&
        (ia64_bits(raw, 30, 6) == 0x28 ||
         ia64_bits(raw, 30, 6) == 0x2c)) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_LD16, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.mem_acquire = ia64_bits(raw, 30, 6) == 0x2c;
        return insn;
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 33, 3) == 6 &&
        (ia64_bits(raw, 27, 6) & ~0x26ULL) == 0x01) {
        uint64_t x6 = ia64_bits(raw, 27, 6);
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_ST16, unit, raw, address, slot);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.mem_release = (x6 & 0x20) != 0;
        return insn;
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 5) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        const Ia64Opcode opcode = ia64_memory_opcode_from_x6a(x6a);
        if (ia64_opcode_is_load(opcode)) {
            /* Cache hint bits do not affect the architectural load result. */
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            uint64_t imm9 = ia64_bits(raw, 13, 7) |
                            (ia64_bits(raw, 27, 1) << 7) |
                            (ia64_bits(raw, 36, 1) << 8);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_sign_extend(imm9, 9);
            insn.mem_acquire = ia64_memory_x6a_is_acquire_load(x6a);
            return insn;
        }
        if (ia64_opcode_is_store(opcode)) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            uint64_t imm9 = ia64_bits(raw, 6, 7) |
                            (ia64_bits(raw, 27, 1) << 7) |
                            (ia64_bits(raw, 36, 1) << 8);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_sign_extend(imm9, 9);
            insn.mem_release = ia64_opcode_is_release_store(opcode);
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 27, 1) == 1 &&
        (ia64_bits(raw, 30, 6) == 0x20 ||
         ia64_bits(raw, 30, 6) == 0x24)) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_CMP8XCHG16, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.mem_acquire = ia64_bits(raw, 32, 1) == 0;
        insn.mem_release = ia64_bits(raw, 32, 1) != 0;
        return insn;
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 27, 1) == 1 &&
        ia64_bits(raw, 33, 3) == 0) {
        const uint64_t size = ia64_bits(raw, 30, 1) |
                              (ia64_bits(raw, 31, 1) << 1);
        const Ia64Opcode opcode = ia64_cmpxchg_acqrel_opcode_from_size(size);
        Ia64Instruction insn =
            ia64_base_insn(opcode, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.mem_acquire = ia64_bits(raw, 32, 1) == 0;
        insn.mem_release = ia64_bits(raw, 32, 1) != 0;
        return insn;
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 27, 1) == 1 &&
        ia64_bits(raw, 32, 1) == 0 &&
        ia64_bits(raw, 33, 3) == 1) {
        const uint64_t size = ia64_bits(raw, 30, 1) |
                              (ia64_bits(raw, 31, 1) << 1);
        const Ia64Opcode opcode = ia64_xchg_opcode_from_size(size);
        Ia64Instruction insn =
            ia64_base_insn(opcode, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.mem_acquire = true;
        return insn;
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 27, 2) == 1) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        const Ia64Opcode opcode =
            ia64_speculative_load_opcode_from_x6a(x6a);
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 27, 1) == 0) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        const Ia64Opcode opcode = ia64_memory_opcode_from_x6a(x6a);
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.mem_acquire = ia64_memory_x6a_is_acquire_load(x6a);
            insn.mem_release = ia64_opcode_is_release_store(opcode);
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 && ia64_bits(raw, 27, 2) == 3) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        const bool is_nc = ia64_bits(raw, 29, 1);
        const Ia64Opcode opcode =
            ia64_check_load_opcode_from_x6a(x6a, !is_nc);
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 1 && ia64_bits(raw, 27, 1) == 0) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        const Ia64Opcode opcode = ia64_memory_opcode_from_x6a(x6a);
        if (ia64_opcode_is_load(opcode)) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.reg_base_update = true;
            insn.mem_acquire = ia64_memory_x6a_is_acquire_load(x6a);
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 27, 1) == 1) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        const Ia64Opcode opcode = ia64_fetchadd_opcode_from_x6a(x6a);
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_fetchadd_imm(ia64_bits(raw, 13, 3));
            insn.mem_acquire = ia64_fetchadd_x6a_is_acquire(x6a);
            insn.mem_release = ia64_fetchadd_x6a_is_release(x6a);
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 2 &&
        ia64_bits(raw, 36, 1) == 0 && ia64_bits(raw, 12, 1) == 0) {
        const uint64_t xhint = ia64_bits(raw, 27, 2);
        const uint64_t xm = ia64_bits(raw, 29, 2);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;
        if (xm == 0 && xhint == 0) {
            opcode = IA64_OP_XCHG1;
        } else if (xm == 0 && xhint == 1) {
            opcode = IA64_OP_XCHG2;
        } else if (xm == 1 && xhint == 0) {
            opcode = IA64_OP_XCHG4;
        } else if (xm == 1 && xhint == 1) {
            opcode = IA64_OP_XCHG8;
        } else if (xm == 2 && xhint == 0) {
            opcode = IA64_OP_CMPXCHG1;
        } else if (xm == 2 && xhint == 1) {
            opcode = IA64_OP_CMPXCHG2;
        } else if (xm == 3 && xhint == 0) {
            opcode = IA64_OP_CMPXCHG4;
        } else if (xm == 3 && xhint == 1) {
            opcode = IA64_OP_CMPXCHG8;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.mem_acquire = true;
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 3 &&
        ia64_bits(raw, 36, 1) == 0) {
        const uint64_t x2 = ia64_bits(raw, 27, 1);
        const uint64_t xm = ia64_bits(raw, 29, 2);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;
        if (xm == 0 && x2 == 0) {
            opcode = IA64_OP_FETCHADD4;
        } else if (xm == 1 && x2 == 0) {
            opcode = IA64_OP_FETCHADD8;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.mem_acquire = true;
            return insn;
        }
    }

    if (unit == IA64_UNIT_F) {
        if (ia64_is_f_nop(raw)) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_NOP, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
        if (ia64_is_f_break(raw)) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_BREAK, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 1) == 0 &&
            ia64_bits(raw, 27, 6) == 0x10 &&
            ia64_bits(raw, 13, 7) == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_FPABS, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 20, 7);
            return insn;
        }
        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 1) == 0 &&
            ia64_bits(raw, 27, 6) == 0x11) {
            const uint64_t f2 = ia64_bits(raw, 13, 7);
            const uint64_t f3 = ia64_bits(raw, 20, 7);

            if (f2 == 0 || f2 == f3) {
                Ia64Instruction insn =
                    ia64_base_insn(f2 == 0 ? IA64_OP_FPNEGABS :
                                             IA64_OP_FPNEG,
                                   unit, raw, address, slot);
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = f3;
                return insn;
            }
        }
        if ((ia64_b_op(raw) == 0 || ia64_b_op(raw) == 1) &&
            ia64_bits(raw, 36, 1) == 1 &&
            ia64_bits(raw, 33, 1) == 1) {
            Ia64Instruction insn =
                ia64_base_insn(ia64_b_op(raw) == 0 ? IA64_OP_FRSQRTA :
                                                     IA64_OP_FPRSQRTA,
                               unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.clear_p2_before_predicate = true;
            return insn;
        }
        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 36, 1) == 0 &&
            ia64_bits(raw, 33, 1) == 1) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_FPRCPA, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.clear_p2_before_predicate = true;
            return insn;
        }
        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 36, 1) == 0 &&
            ia64_bits(raw, 33, 1) == 0) {
            uint64_t form = ia64_bits(raw, 27, 6);
            Ia64Opcode opcode = IA64_OP_ILLEGAL;

            if (form == 0x10 || form == 0x11 || form == 0x12) {
                opcode = form == 0x10 ? IA64_OP_FPMERGE_S :
                         form == 0x11 ? IA64_OP_FPMERGE :
                                          IA64_OP_FPMERGE_SE;
            } else if (form >= 0x14 && form <= 0x17) {
                opcode = form == 0x14 ? IA64_OP_FPMIN :
                         form == 0x15 ? IA64_OP_FPMAX :
                         form == 0x16 ? IA64_OP_FPAMIN :
                                         IA64_OP_FPAMAX;
            } else if (form >= 0x18 && form <= 0x1b) {
                opcode = IA64_OP_FPCVT;
            } else if (form >= 0x30 && form <= 0x37) {
                opcode = IA64_OP_FPCMP;
            }

            if (opcode != IA64_OP_ILLEGAL) {
                Ia64Instruction insn =
                    ia64_base_insn(opcode, unit, raw, address, slot);
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
                insn.p1 = ia64_bits(raw, 34, 2);
                insn.imm = form & 7;
                return insn;
            }
        }
        if (ia64_b_op(raw) == 1) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_HINT_F, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }

        const uint64_t x = ia64_bits(raw, 36, 1);
        const uint64_t x6 = ia64_bits(raw, 30, 6);
        const uint64_t form = ia64_bits(raw, 27, 6);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        if (ia64_b_op(raw) == 4) {
            opcode = IA64_OP_FCMP;
        } else if (ia64_b_op(raw) == 8 && x == 1 &&
                   (x6 == 0x00 || x6 == 0x02 || x6 == 0x04 ||
                    x6 == 0x08 || x6 == 0x0a || x6 == 0x0c ||
                    x6 == 0x0e)) {
            if (x6 == 0x00) {
                opcode = IA64_OP_FMA;
            } else if (x6 == 0x02) {
                opcode = IA64_OP_FMPY;
            } else if (x6 == 0x04) {
                opcode = IA64_OP_FCMP;
            } else if (x6 == 0x08) {
                opcode = IA64_OP_FMIN;
            } else if (x6 == 0x0a) {
                opcode = IA64_OP_FMAX;
            } else if (x6 == 0x0c) {
                opcode = IA64_OP_FAMIN;
            } else if (x6 == 0x0e) {
                opcode = IA64_OP_FAMAX;
            }
        } else if (x == 0 && ia64_b_op(raw) >= 8 &&
                   ia64_b_op(raw) <= 0xd) {
            opcode = ia64_f1_opcode_from_major(ia64_b_op(raw),
                                               ia64_bits(raw, 13, 7),
                                               ia64_bits(raw, 27, 7));
        } else if (x == 1 &&
                   (ia64_b_op(raw) == 0x8 ||
                    ia64_b_op(raw) == 0xa ||
                    ia64_b_op(raw) == 0xc)) {
            opcode = ia64_f1_opcode_from_major(ia64_b_op(raw),
                                               ia64_bits(raw, 13, 7),
                                               ia64_bits(raw, 27, 7));
        } else if (x == 1 &&
                   (ia64_b_op(raw) == 0x9 ||
                    ia64_b_op(raw) == 0xb ||
                    ia64_b_op(raw) == 0xd)) {
            opcode = ia64_b_op(raw) == 0x9 ? IA64_OP_FPMA :
                     ia64_b_op(raw) == 0xb ? IA64_OP_FPMS :
                                             IA64_OP_FPNMA;
        } else if (ia64_b_op(raw) == 0 &&
                   ia64_bits(raw, 33, 1) == 0 &&
                   form >= 0x14 && form <= 0x17) {
            opcode = form == 0x14 ? IA64_OP_FMIN :
                     form == 0x15 ? IA64_OP_FMAX :
                     form == 0x16 ? IA64_OP_FAMIN :
                                    IA64_OP_FAMAX;
        } else if (ia64_b_op(raw) == 0 && x == 0 &&
                   ia64_bits(raw, 33, 1) == 0 && form == 0x1c) {
            opcode = IA64_OP_FCVT_XF;
        } else if (ia64_b_op(raw) == 0 && x == 0 &&
                   ia64_bits(raw, 33, 1) == 1) {
            opcode = IA64_OP_FRCPA;
        } else if (ia64_b_op(raw) == 0 &&
                   ia64_bits(raw, 33, 1) == 0 &&
                   ia64_bits(raw, 34, 3) == 0 &&
                   ia64_bits(raw, 27, 6) == 0x28) {
            opcode = IA64_OP_FPACK;
        } else if (ia64_b_op(raw) == 0 && x == 0 &&
                   ia64_bits(raw, 33, 1) == 0 &&
                   form >= 0x18 && form <= 0x1b) {
            opcode = (form & 1) ? IA64_OP_FCVT_FXU : IA64_OP_FCVT_FX;
        } else if (ia64_b_op(raw) == 0 && x == 0 && x6 == 0x02 &&
                   (ia64_bits(raw, 27, 6) == 0x10 ||
                    ia64_bits(raw, 27, 6) == 0x11 ||
                    ia64_bits(raw, 27, 6) == 0x12)) {
            opcode = form == 0x10 ? IA64_OP_FMERGE_S :
                     form == 0x11 ? IA64_OP_FMERGE :
                                      IA64_OP_FMERGE_SE;
        } else if (ia64_b_op(raw) == 0 && x == 0 &&
                   ia64_bits(raw, 33, 1) == 0 &&
                   (ia64_bits(raw, 27, 6) == 0x04 ||
                    ia64_bits(raw, 27, 6) == 0x05 ||
                    ia64_bits(raw, 27, 6) == 0x08)) {
            opcode = form == 0x04 ? IA64_OP_FSETC :
                     form == 0x05 ? IA64_OP_FCLRF :
                                     IA64_OP_FCHKF;
        } else if (ia64_b_op(raw) == 0 &&
                   ia64_bits(raw, 33, 1) == 0 &&
                   ((form >= 0x2c && form <= 0x2f) ||
                    (form >= 0x34 && form <= 0x36) ||
                    (form >= 0x39 && form <= 0x3d))) {
            switch (ia64_bits(raw, 27, 6)) {
            case 0x2c:
                opcode = IA64_OP_FAND;
                break;
            case 0x2d:
                opcode = IA64_OP_FANDCM;
                break;
            case 0x2e:
                opcode = IA64_OP_FOR;
                break;
            case 0x2f:
                opcode = IA64_OP_FXOR;
                break;
            case 0x34:
                opcode = IA64_OP_FSWAP;
                break;
            case 0x35:
                opcode = IA64_OP_FSWAP_NL;
                break;
            case 0x36:
                opcode = IA64_OP_FSWAP_NR;
                break;
            case 0x39:
                opcode = IA64_OP_FMIX_LR;
                break;
            case 0x3a:
                opcode = IA64_OP_FMIX_R;
                break;
            case 0x3b:
                opcode = IA64_OP_FMIX_L;
                break;
            case 0x3c:
                opcode = IA64_OP_FSXT_R;
                break;
            case 0x3d:
                opcode = IA64_OP_FSXT_L;
                break;
            }
        } else if (ia64_b_op(raw) == 0 && x == 0) {
            opcode = IA64_OP_FMOV;
        } else if (ia64_b_op(raw) == 0xe && x == 0) {
            opcode = IA64_OP_FSELECT;
        } else if (ia64_b_op(raw) == 0xe && x == 1 &&
                   ia64_bits(raw, 34, 2) == 0) {
            opcode = IA64_OP_XMA_L;
        } else if (ia64_b_op(raw) == 0xe && x == 1 &&
                   ia64_bits(raw, 34, 2) == 3) {
            opcode = IA64_OP_XMA_H;
        } else if (ia64_b_op(raw) == 0xe && x == 1 &&
                   ia64_bits(raw, 34, 2) == 2) {
            opcode = ia64_bits(raw, 13, 7) == 0 ?
                IA64_OP_XMPY_HU : IA64_OP_XMA_HU;
        }

        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.p1 = (opcode == IA64_OP_FMA ||
                       opcode == IA64_OP_FMS ||
                       opcode == IA64_OP_FNMA ||
                       opcode == IA64_OP_XMA_L ||
                       opcode == IA64_OP_XMA_H ||
                       opcode == IA64_OP_XMA_HU ||
                       opcode == IA64_OP_XMPY_HU) ?
                ia64_bits(raw, 27, 7) : ia64_bits(raw, 27, 6);
            if (opcode == IA64_OP_FCMP) {
                insn.p1 = ia64_bits(raw, 6, 6);
                insn.p2 = ia64_bits(raw, 27, 6);
                insn.imm = (ia64_bits(raw, 33, 1) << 1) |
                           ia64_bits(raw, 36, 1);
                insn.compare_unc = ia64_bits(raw, 12, 1) != 0;
            } else if (opcode == IA64_OP_FSETC) {
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
                insn.p1 = ia64_bits(raw, 34, 2);
            } else if (opcode == IA64_OP_FCLRF) {
                insn.p1 = ia64_bits(raw, 34, 2);
            } else if (opcode == IA64_OP_FCHKF) {
                insn.p1 = ia64_bits(raw, 34, 2);
                insn.imm = ia64_sign_extend(ia64_bits(raw, 6, 21), 21) * 16;
            }
            if (opcode == IA64_OP_FMA ||
                opcode == IA64_OP_FMS ||
                opcode == IA64_OP_FNMA) {
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
                insn.p1 = ia64_bits(raw, 27, 7);
            } else if (opcode == IA64_OP_FPMA ||
                       opcode == IA64_OP_FPMS ||
                       opcode == IA64_OP_FPNMA) {
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
                insn.p1 = ia64_bits(raw, 27, 7);
            } else if (opcode == IA64_OP_FSELECT) {
                insn.p1 = ia64_bits(raw, 27, 7);
            } else if (opcode == IA64_OP_FMPY) {
                insn.r2 = ia64_bits(raw, 20, 7);
                insn.r3 = ia64_bits(raw, 27, 7);
            } else if (opcode == IA64_OP_FSUB) {
                insn.r2 = ia64_bits(raw, 20, 7);
                insn.r3 = ia64_bits(raw, 13, 7);
            } else if (opcode == IA64_OP_FCVT_FX ||
                       opcode == IA64_OP_FCVT_FXU) {
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.imm = form & 3;
            } else if (opcode == IA64_OP_FRCPA) {
                insn.p2 = insn.p1;
                insn.clear_p2_before_predicate = true;
            }
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 6 &&
        ia64_bits(raw, 27, 1) == 0) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        Ia64Opcode opcode = ia64_fp_load_opcode_from_x6a(x6a);
        bool is_store = opcode == IA64_OP_ILLEGAL;

        if (is_store) {
            opcode = ia64_fp_store_opcode_from_x6a(x6a);
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            ia64_fp_load_attrs_from_x6a(&insn, x6a);
            if (is_store) {
                insn.r2 = ia64_bits(raw, 13, 7);
            } else {
                insn.r1 = ia64_bits(raw, 6, 7);
                if (ia64_bits(raw, 36, 1) == 1) {
                    insn.r2 = ia64_bits(raw, 13, 7);
                    insn.reg_base_update = true;
                }
            }
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 6) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        if (x6a >= 0x2c && x6a <= 0x2f) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_HINT_M, unit, raw, address, slot);
            insn.r3 = ia64_bits(raw, 20, 7);
            if (ia64_bits(raw, 36, 1) == 1 && ia64_bits(raw, 27, 1) == 0) {
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.hint_m_reg_increment = true;
            }
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 7) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        if (x6a >= 0x2c && x6a <= 0x2f) {
            uint64_t imm9 = (ia64_bits(raw, 36, 1) << 8) |
                            (ia64_bits(raw, 27, 1) << 7) |
                            ia64_bits(raw, 13, 7);
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_HINT_M, unit, raw, address, slot);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_sign_extend(imm9, 9);
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 7) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        Ia64Opcode opcode = ia64_fp_load_opcode_from_x6a(x6a);

        if (opcode != IA64_OP_ILLEGAL) {
            uint64_t imm9 = ia64_bits(raw, 13, 7) |
                            (ia64_bits(raw, 27, 1) << 7) |
                            (ia64_bits(raw, 36, 1) << 8);
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            ia64_fp_load_attrs_from_x6a(&insn, x6a);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_sign_extend(imm9, 9);
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 7) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        Ia64Opcode opcode = ia64_fp_store_opcode_from_x6a(x6a);

        if (opcode != IA64_OP_ILLEGAL) {
            uint64_t imm9 = ia64_bits(raw, 6, 7) |
                            (ia64_bits(raw, 27, 1) << 7) |
                            (ia64_bits(raw, 36, 1) << 8);
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_sign_extend(imm9, 9);
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 6 &&
        ia64_bits(raw, 27, 1) == 1) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        Ia64Opcode opcode = ia64_fp_load_pair_opcode_from_x6a(x6a);
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            ia64_fp_load_attrs_from_x6a(&insn, x6a);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            if (ia64_bits(raw, 36, 1) == 1) {
                insn.imm = opcode == IA64_OP_LDFPS ? 8 : 16;
            }
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 7 &&
        ia64_bits(raw, 28, 2) == 0) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;
        if (x6a == 0x02) {
            opcode = IA64_OP_STFD;
        } else if (x6a == 0x03) {
            opcode = IA64_OP_STFS;
        } else if (x6a == 0x3b) {
            opcode = IA64_OP_STF_SPILL;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            uint64_t imm9 = ia64_bits(raw, 6, 7) |
                            (ia64_bits(raw, 27, 1) << 7) |
                            (ia64_bits(raw, 36, 1) << 8);
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_sign_extend(imm9, 9);
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0x9 && ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 34, 2) == 0 && ia64_bits(raw, 27, 6) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_GETF_D, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 8 && ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 34, 2) == 2) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_SETF_D, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0x4 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xe1 &&
        ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_GETF_SIG, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0x4 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xe9 &&
        ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_GETF_EXP, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0x4 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xf1 &&
        ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_GETF_S, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0x4 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xf9 &&
        ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_GETF_D, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0x6 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xe1 &&
        ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_SETF_SIG, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0x6 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xe9 &&
        ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_SETF_EXP, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0x6 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xf1 &&
        ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_SETF_S, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0x6 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xf9 &&
        ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_SETF_D, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0x9 && ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 34, 2) == 1 && ia64_bits(raw, 27, 6) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_GETF_SIG, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 8 && ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 34, 2) == 3) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_SETF_SIG, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 1 &&
        ia64_bits(raw, 34, 2) == 2 && ia64_bits(raw, 27, 2) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_TPA, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 1 &&
        ia64_bits(raw, 34, 2) == 2 && ia64_bits(raw, 27, 2) == 1) {
        return ia64_base_insn(IA64_OP_SYNC_I, unit, raw, address, slot);
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 1 &&
        ia64_bits(raw, 34, 2) == 2 && ia64_bits(raw, 27, 2) == 2) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_CHK_S, unit, raw, address, slot);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r1 = ia64_bits(raw, 20, 7);
        insn.imm = ia64_chk_disp(raw);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 1 &&
        ia64_bits(raw, 34, 2) == 2 && ia64_bits(raw, 27, 2) == 3) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_CHK_A, unit, raw, address, slot);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r1 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 0 &&
        (ia64_bits(raw, 33, 3) == 4 ||
         ia64_bits(raw, 33, 3) == 5 ||
         ia64_bits(raw, 33, 3) == 6 ||
         ia64_bits(raw, 33, 3) == 7)) {
        const uint64_t x3 = ia64_bits(raw, 33, 3);
        Ia64Instruction insn =
            ia64_base_insn((x3 == 4 || x3 == 6) ?
                           IA64_OP_CHK_A : IA64_OP_CHK_A_CLR,
                           unit, raw, address, slot);
        insn.r2 = ia64_bits(raw, 6, 7);
        insn.imm = ia64_chk_a_disp(raw);
        insn.check_fp = x3 >= 6;
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 33, 1) == 0 &&
        ia64_bits(raw, 34, 2) == 2 &&
        (ia64_bits(raw, 27, 2) == 2 ||
         ia64_bits(raw, 27, 2) == 3) &&
        ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_CHK_A, unit, raw, address, slot);
        insn.r2 = ia64_bits(raw, 6, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 1 &&
        ia64_bits(raw, 34, 2) == 3 && ia64_bits(raw, 27, 2) == 3) {
        return ia64_base_insn(IA64_OP_CHK_A_CLR, unit, raw, address, slot);
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0 && ia64_bits(raw, 33, 1) == 1 &&
        ia64_bits(raw, 34, 2) == 2 && ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_CHK_A_CLR, unit, raw, address, slot);
        insn.r2 = ia64_bits(raw, 6, 7);
        return insn;
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 1 &&
        ia64_bits(raw, 33, 3) == 0) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        if (x6 == 0x18) {
            opcode = IA64_OP_PROBE_R;
        } else if (x6 == 0x19) {
            opcode = IA64_OP_PROBE_W;
        } else if (x6 == 0x31) {
            opcode = IA64_OP_PROBE_RW;
        } else if (x6 == 0x32) {
            opcode = IA64_OP_PROBE_R;
        } else if (x6 == 0x33) {
            opcode = IA64_OP_PROBE_W;
        } else if (x6 == 0x38) {
            opcode = IA64_OP_PROBE_R;
        } else if (x6 == 0x39) {
            opcode = IA64_OP_PROBE_W;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r3 = ia64_bits(raw, 20, 7);
            if (x6 == 0x18 || x6 == 0x19) {
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.imm = ia64_bits(raw, 13, 2);
                insn.probe_imm = true;
            } else if (x6 == 0x31 || x6 == 0x32 || x6 == 0x33) {
                insn.imm = ia64_bits(raw, 13, 2);
                insn.probe_fault = true;
                insn.probe_imm = true;
            } else {
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = ia64_bits(raw, 13, 7);
            }
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 1 &&
        ia64_bits(raw, 34, 2) == 2 && ia64_bits(raw, 27, 4) == 4) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_TAK, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 1 &&
        ia64_bits(raw, 34, 2) == 2 && ia64_bits(raw, 27, 4) == 5) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_THASH, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 1 &&
        ia64_bits(raw, 34, 2) == 2 && ia64_bits(raw, 27, 4) == 6) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_TTAG, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 1 &&
        ia64_bits(raw, 34, 2) == 3 && ia64_bits(raw, 27, 4) == 2) {
        return ia64_base_insn(IA64_OP_FC, unit, raw, address, slot);
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 1 &&
        ia64_bits(raw, 33, 3) == 0 &&
        ia64_bits(raw, 27, 6) == 0x30) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_FC, unit, raw, address, slot);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 1 &&
        ia64_bits(raw, 34, 2) == 3 && ia64_bits(raw, 27, 4) == 3) {
        return ia64_base_insn(IA64_OP_INVALA, unit, raw, address, slot);
    }

    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 6, 3) == 2) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_BR_WEXIT, unit, raw, address, slot);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }

    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 6, 3) == 3) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_BR_WTOP, unit, raw, address, slot);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }

    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 6, 3) == 6) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_BR_CEXIT, unit, raw, address, slot);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }

    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 6, 3) == 7) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_BR_CTOP, unit, raw, address, slot);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }

    if (unit == IA64_UNIT_B &&
        (ia64_b_op(raw) == 2 || ia64_b_op(raw) == 7)) {
        return ia64_base_insn(IA64_OP_BRP, unit, raw, address, slot);
    }

    if (unit == IA64_UNIT_F && ia64_b_op(raw) == 5) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_FCLASS, unit, raw, address, slot);
        insn.p1 = ia64_bits(raw, 6, 6);
        insn.p2 = ia64_bits(raw, 27, 6);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.imm = (ia64_bits(raw, 20, 7) << 2) |
                   ia64_bits(raw, 33, 2);
        insn.compare_unc = ia64_bits(raw, 12, 1) != 0;
        return insn;
    }

    if (unit == IA64_UNIT_F && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 30, 6) == 0x0c &&
        ia64_bits(raw, 27, 2) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_FCHKFS, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 0) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        const uint64_t x4 = x6 & 0xf;
        Ia64Opcode opcode = IA64_OP_ILLEGAL;
        if (x6 == 0x31) {
            opcode = IA64_OP_SRLZ;
        } else if (x6 == 0x30) {
            opcode = IA64_OP_SRLZ_D;
        } else if (x6 == 0x33) {
            opcode = IA64_OP_SYNC_I;
        } else if (x6 == 0x20) {
            opcode = IA64_OP_FWB;
        } else if (x4 == 0x04) {
            opcode = IA64_OP_SUM_UM;
        } else if (x4 == 0x05) {
            opcode = IA64_OP_RUM;
        } else if (x4 == 0x06) {
            opcode = IA64_OP_SSM;
        } else if (x4 == 0x07) {
            opcode = IA64_OP_RSM;
        } else if (x6 == 0x22) {
            opcode = IA64_OP_MF;
        } else if (x6 == 0x23) {
            opcode = IA64_OP_MF_A;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            if (opcode == IA64_OP_SUM_UM || opcode == IA64_OP_RUM ||
                opcode == IA64_OP_SSM || opcode == IA64_OP_RSM) {
                insn.imm = ia64_psr_mask(raw);
            }
            return insn;
        }
    }

    if (unit == IA64_UNIT_L) {
        /*
         * movl r1 = imm64 (X2 format, MLX template).
         * In MLX, the L-slot carries imm41 (bits 62:22), and the X-slot
         * carries opcode(6), r1 and the remaining immediate fields.
         * r1/imm are completed during the MLX fixup pass.
         */
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_MOVL, unit, raw, address, slot);
        insn.r1 = 0;   /* filled by MLX fixup */
        insn.imm = 0;  /* filled by MLX fixup */
        return insn;
    }

    if (unit == IA64_UNIT_X && ia64_b_op(raw) == 6) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_MOVL, unit, raw, address, slot);
        insn.r1 = 0;   /* filled by MLX fixup */
        insn.imm = 0;  /* filled by MLX fixup */
        return insn;
    }

    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 6, 3) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_BR_COND, unit, raw, address, slot);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }

    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 12, 1) == 0 && ia64_bits(raw, 6, 3) == 1) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_BR, unit, raw, address, slot);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }

    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 6, 3) == 5) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_BR_CLOOP, unit, raw, address, slot);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }

    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 12, 1) == 0 && ia64_bits(raw, 6, 3) == 4) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_BR_IA, unit, raw, address, slot);
        insn.b2 = ia64_bits(raw, 13, 3);
        return insn;
    }

    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 27, 6) == 0x20) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_BR_IA, unit, raw, address, slot);
        insn.b2 = ia64_bits(raw, 13, 3);
        return insn;
    }

    /* Indirect call: br.call bRet=bTarget, B5. Completers are hints. */
    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 1 &&
        ia64_bits(raw, 32, 1) == 1) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_BR_CALL_INDIRECT, unit, raw, address, slot);
        insn.b2 = ia64_bits(raw, 13, 3);  /* target branch register */
        insn.b1 = ia64_bits(raw, 6, 3);   /* return branch register */
        return insn;
    }

    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 5) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_BR_CALL, unit, raw, address, slot);
        insn.b1 = ia64_bits(raw, 6, 3);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }

    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 27, 6) == 0x21 && ia64_bits(raw, 6, 3) == 4) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_BR_RET, unit, raw, address, slot);
        insn.b2 = ia64_bits(raw, 13, 3);
        return insn;
    }

    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 0) {
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        switch (ia64_bits(raw, 27, 6)) {
        case 0x02: opcode = IA64_OP_COVER; break;
        case 0x04: opcode = IA64_OP_CLRRRB; break;
        case 0x05: opcode = IA64_OP_CLRRRB_PR; break;
        case 0x08: opcode = IA64_OP_RFI; break;
        case 0x0c: opcode = IA64_OP_BSW0; break;
        case 0x0d: opcode = IA64_OP_BSW1; break;
        case 0x10: opcode = IA64_OP_EPC; break;
        }

        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.qp = 0;
            return insn;
        }
    }

    /*
     * A. Translation register/cache operations: M-unit, b_op == 1.
     */
    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 1 &&
        ia64_bits(raw, 33, 3) == 0) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        switch (x6) {
        case 0x09: opcode = IA64_OP_PTC_L; break;
        case 0x0a: opcode = IA64_OP_PTC_G; break;
        case 0x0b: opcode = IA64_OP_PTC_GA; break;
        case 0x0c: opcode = IA64_OP_PTR_D; break;
        case 0x0d: opcode = IA64_OP_PTR_I; break;
        case 0x0e: opcode = IA64_OP_ITR_D; break;
        case 0x0f: opcode = IA64_OP_ITR_I; break;
        case 0x2e: opcode = IA64_OP_ITC_D; break;
        case 0x2f: opcode = IA64_OP_ITC_I; break;
        case 0x34: opcode = IA64_OP_PTC_E; break;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    /* B. TLB ops: M-unit, b_op == 0, distinguished by bits(27,6) */
    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 0) {
        const uint64_t x6b = ia64_bits(raw, 27, 6);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;
        switch (x6b) {
        case 0x11: opcode = IA64_OP_PTC_L; break;
        case 0x12: opcode = IA64_OP_PTC_G; break;
        case 0x13: opcode = IA64_OP_PTC_GA; break;
        case 0x14: opcode = IA64_OP_ITR_D; break;
        case 0x15: opcode = IA64_OP_ITR_I; break;
        case 0x16: opcode = IA64_OP_PTR_D; break;
        case 0x17: opcode = IA64_OP_PTR_I; break;
        case 0x18: opcode = IA64_OP_ITC_D; break;
        case 0x19: opcode = IA64_OP_ITC_I; break;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    /* C. MOV PSR <-> GR: M/I-unit, b_op == 0xa */
    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 0 &&
        ia64_bits(raw, 34, 2) == 2 && ia64_bits(raw, 36, 1) == 1) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_MOV_PSRGR, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        return insn;
    }
    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 0 &&
        ia64_bits(raw, 34, 2) == 3 && ia64_bits(raw, 36, 1) == 1) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_MOV_GRPSR, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        return insn;
    }

    /* D. MOV RR <-> GR: M/I-unit, b_op == 0xa */
    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xb && ia64_bits(raw, 33, 1) == 0 &&
        ia64_bits(raw, 34, 2) == 2) {
        const uint64_t rr_num = ia64_bits(raw, 13, 7);
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_MOV_RRGR, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = rr_num;
        return insn;
    }
    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xb && ia64_bits(raw, 33, 1) == 0 &&
        ia64_bits(raw, 34, 2) == 3) {
        const uint64_t rr_num = ia64_bits(raw, 13, 7);
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_MOV_GRRR, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = rr_num;
        return insn;
    }

    /* E. MOV PKR <-> GR: M/I-unit, b_op == 0xa */
    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 0 &&
        ia64_bits(raw, 34, 2) == 2 && ia64_bits(raw, 36, 1) == 1 &&
        ia64_bits(raw, 27, 2) == 2) {
        const uint64_t pkr_num = ia64_bits(raw, 13, 7);
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_MOV_PKRGR, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = pkr_num;
        return insn;
    }
    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 0 &&
        ia64_bits(raw, 34, 2) == 3 && ia64_bits(raw, 36, 1) == 1 &&
        ia64_bits(raw, 27, 2) == 2) {
        const uint64_t pkr_num = ia64_bits(raw, 13, 7);
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_MOV_GRPKR, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = pkr_num;
        return insn;
    }

    /* VMSW.0 / VMSW.1: B-unit, opcode 0, x6 0x18/0x19. */
    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 0 &&
        (ia64_bits(raw, 27, 6) == 0x18 ||
         ia64_bits(raw, 27, 6) == 0x19)) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_VMSW, unit, raw, address, slot);
        insn.imm = ia64_bits(raw, 27, 6) & 1;
        insn.qp = 0;
        return insn;
    }

    /* BSW.0 / BSW.1 */
    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I || unit == IA64_UNIT_B) &&
        ia64_b_op(raw) == 0 && ia64_bits(raw, 27, 6) == 0x0c) {
        return ia64_base_insn(IA64_OP_BSW0, unit, raw, address, slot);
    }
    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I || unit == IA64_UNIT_B) &&
        ia64_b_op(raw) == 0 && ia64_bits(raw, 27, 6) == 0x0d) {
        return ia64_base_insn(IA64_OP_BSW1, unit, raw, address, slot);
    }

    /* F. BRL.COND / BRL.CALL: X-unit (MLX template, slot 1) */
    if (unit == IA64_UNIT_X && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 12, 1) == 0 && ia64_bits(raw, 6, 3) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_BRL_COND, unit, raw, address, slot);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }
    if (unit == IA64_UNIT_X && ia64_b_op(raw) == 5 &&
        ia64_bits(raw, 12, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_BRL_CALL, unit, raw, address, slot);
        insn.b1 = ia64_bits(raw, 6, 3);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }

    /* G. EPC: M/I-unit, b_op == 0xa */
    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 1 &&
        ia64_bits(raw, 34, 2) == 2 && ia64_bits(raw, 27, 4) == 7) {
        return ia64_base_insn(IA64_OP_EPC, unit, raw, address, slot);
    }

    /* H. ADDP4 / ADDS-imm: M/I-unit, b_op == 8
     *
     * Register form (addp4 r1=r2,r3): x3=0, x4=2, x2b=0.
     * Immediate form (addp4/adds r1=imm,r3): bits 34:33 may carry
     * immediate value bits (up to 3), so we accept any x3 for the
     * I-unit path and decode it as an ADDP4/adds immediate.
     */
    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 8) {
        const uint64_t x4 = ia64_bits(raw, 29, 4);
        const uint64_t x2b = ia64_bits(raw, 27, 2);
        const uint64_t x3 = ia64_bits(raw, 33, 3);

        /* register form — a clean {0,2,0} */
        if (x3 == 0 && x4 == 2 && x2b == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_ADDP4, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        /*
         * A4 addp4 immediate uses x2a=3/ve=0; bits 36 and 32:27 are part
         * of the 14-bit signed immediate, not register-form extensions.
         */
        if (ia64_bits(raw, 34, 2) == 3 && ia64_bits(raw, 33, 1) == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_ADDP4_IMM, unit, raw, address, slot);
            insn.imm = ia64_imm14(raw);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    /* I. INVALAT: M/I-unit, b_op == 0xa */
    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xa && ia64_bits(raw, 33, 1) == 1 &&
        ia64_bits(raw, 34, 2) == 3 && ia64_bits(raw, 27, 4) == 4) {
        return ia64_base_insn(IA64_OP_INVALAT, unit, raw, address, slot);
    }

    return ia64_invalid_insn(unit, raw, address, slot);
}

static TCGv_i64 ia64_gr_src(uint8_t reg)
{
    return reg == 0 ? tcg_constant_i64(0) : cpu_gr[reg];
}

static bool ia64_fr_is_writable(uint8_t reg)
{
    return reg > 1;
}

static void ia64_gen_fr_nat_clear(uint8_t reg)
{
    if (reg <= 1) {
        return;
    }

    tcg_gen_andi_i64(cpu_fr_nat[reg / 64], cpu_fr_nat[reg / 64],
                     ~(1ULL << (reg % 64)));
}

static void ia64_gen_fr_sig_clear(uint8_t reg)
{
    if (reg <= 1) {
        return;
    }

    tcg_gen_andi_i64(cpu_fr_sig[reg / 64], cpu_fr_sig[reg / 64],
                     ~(1ULL << (reg % 64)));
}

static void ia64_gen_fr_sig_set(uint8_t reg)
{
    if (reg <= 1) {
        return;
    }

    tcg_gen_ori_i64(cpu_fr_sig[reg / 64], cpu_fr_sig[reg / 64],
                    1ULL << (reg % 64));
}

static void ia64_gen_fr_nat_set(uint8_t reg)
{
    if (reg <= 1) {
        return;
    }

    tcg_gen_ori_i64(cpu_fr_nat[reg / 64], cpu_fr_nat[reg / 64],
                    1ULL << (reg % 64));
    ia64_gen_fr_sig_clear(reg);
}

static TCGv_i64 ia64_gen_fr_nat_read(uint8_t reg)
{
    TCGv_i64 bit = tcg_temp_new_i64();

    if (reg <= 1) {
        tcg_gen_movi_i64(bit, 0);
        return bit;
    }

    tcg_gen_shri_i64(bit, cpu_fr_nat[reg / 64], reg % 64);
    tcg_gen_andi_i64(bit, bit, 1);
    return bit;
}

static void ia64_gen_fr_nat_assign(uint8_t reg, TCGv_i64 bit)
{
    TCGv_i64 shifted;

    if (reg <= 1) {
        return;
    }

    shifted = tcg_temp_new_i64();
    tcg_gen_andi_i64(shifted, bit, 1);
    tcg_gen_shli_i64(shifted, shifted, reg % 64);
    tcg_gen_andi_i64(cpu_fr_nat[reg / 64], cpu_fr_nat[reg / 64],
                     ~(1ULL << (reg % 64)));
    tcg_gen_or_i64(cpu_fr_nat[reg / 64], cpu_fr_nat[reg / 64], shifted);
    tcg_gen_not_i64(shifted, shifted);
    tcg_gen_and_i64(cpu_fr_sig[reg / 64], cpu_fr_sig[reg / 64], shifted);
}

static void ia64_gen_fr_nat_from_2(uint8_t dst, uint8_t src1, uint8_t src2)
{
    TCGv_i64 bit = ia64_gen_fr_nat_read(src1);
    TCGv_i64 src_bit = ia64_gen_fr_nat_read(src2);

    tcg_gen_or_i64(bit, bit, src_bit);
    ia64_gen_fr_nat_assign(dst, bit);
}

static void ia64_gen_fr_nat_from_3(uint8_t dst, uint8_t src1, uint8_t src2,
                                   uint8_t src3)
{
    TCGv_i64 bit = ia64_gen_fr_nat_read(src1);
    TCGv_i64 src_bit = ia64_gen_fr_nat_read(src2);

    tcg_gen_or_i64(bit, bit, src_bit);
    src_bit = ia64_gen_fr_nat_read(src3);
    tcg_gen_or_i64(bit, bit, src_bit);
    ia64_gen_fr_nat_assign(dst, bit);
}

static TCGv_i64 ia64_fr_src(uint8_t reg)
{
    if (reg == 0) {
        return tcg_constant_i64(0);
    }
    if (reg == 1) {
        return tcg_constant_i64(IA64_FR_ONE);
    }
    return cpu_fr[reg];
}

static void ia64_gen_fr_mov(uint8_t reg, TCGv_i64 value)
{
    if (ia64_fr_is_writable(reg)) {
        tcg_gen_mov_i64(cpu_fr[reg], value);
        ia64_gen_fr_nat_clear(reg);
        ia64_gen_fr_sig_clear(reg);
    }
}

static void ia64_gen_fr_mov_sig(uint8_t reg, TCGv_i64 value)
{
    if (ia64_fr_is_writable(reg)) {
        tcg_gen_mov_i64(cpu_fr[reg], value);
        ia64_gen_fr_nat_clear(reg);
        ia64_gen_fr_sig_set(reg);
    }
}

static void ia64_gen_fr_ld(uint8_t reg, TCGv_i64 addr, int mmu_idx, MemOp memop)
{
    TCGv_i64 dst = ia64_fr_is_writable(reg) ? cpu_fr[reg] : tcg_temp_new_i64();

    tcg_gen_qemu_ld_i64(dst, addr, mmu_idx, memop);
    ia64_gen_fr_nat_clear(reg);
    ia64_gen_fr_sig_clear(reg);
}

static void ia64_gen_raise_exception(uint32_t exception, uint64_t fault_ip,
                                     uint64_t fault_imm, uint32_t fault_slot);

static void ia64_gen_branch_if_alignment_fault(TCGv_i64 addr, uint32_t size,
                                               bool always_fault,
                                               TCGLabel *fault)
{
    TCGv_i64 tmp;
    TCGLabel *ok;

    if (size <= 1) {
        return;
    }

    ok = gen_new_label();
    tmp = tcg_temp_new_i64();
    tcg_gen_andi_i64(tmp, addr, size - 1);
    tcg_gen_brcondi_i64(TCG_COND_EQ, tmp, 0, ok);

    if (always_fault) {
        tcg_gen_br(fault);
    } else {
        tcg_gen_andi_i64(tmp, cpu_psr, IA64_PSR_AC);
        tcg_gen_brcondi_i64(TCG_COND_NE, tmp, 0, fault);

        tcg_gen_andi_i64(tmp, addr, 0xfff);
        tcg_gen_addi_i64(tmp, tmp, size - 1);
        tcg_gen_brcondi_i64(TCG_COND_GTU, tmp, 0xfff, fault);
    }

    gen_set_label(ok);
}

static void ia64_gen_check_alignment_access(const Ia64Instruction *insn,
                                            TCGv_i64 addr, uint32_t size,
                                            bool always_fault,
                                            uint64_t isr_access)
{
    TCGLabel *fault;
    TCGLabel *ok;

    if (size <= 1) {
        return;
    }

    fault = gen_new_label();
    ok = gen_new_label();
    ia64_gen_branch_if_alignment_fault(addr, size, always_fault, fault);
    tcg_gen_br(ok);

    gen_set_label(fault);
    tcg_gen_movi_i64(cpu_ip, insn->address);
    gen_helper_raise_unaligned(tcg_env, addr, tcg_constant_i64(isr_access),
                               tcg_constant_i64(insn->address),
                               tcg_constant_i32(insn->slot));
    gen_set_label(ok);
}

static void ia64_gen_check_alignment(const Ia64Instruction *insn,
                                     TCGv_i64 addr, uint32_t size,
                                     bool always_fault, bool is_write)
{
    ia64_gen_check_alignment_access(insn, addr, size, always_fault,
                                    is_write ? IA64_ISR_W : IA64_ISR_R);
}

static TCGLabel *ia64_gen_predicate_skip(const Ia64Instruction *insn,
                                         TCGv_i64 qp_value)
{
    TCGLabel *skip;

    if (insn->qp == 0) {
        return NULL;
    }

    skip = gen_new_label();
    tcg_gen_brcondi_i64(TCG_COND_EQ, qp_value, 0, skip);
    return skip;
}

static void ia64_gen_predicate_end(TCGLabel *skip)
{
    if (skip != NULL) {
        gen_set_label(skip);
    }
}

static void ia64_gen_clear_unc_compare_targets(const Ia64Instruction *insn)
{
    if (insn->compare_unc) {
        if (insn->p1 != 0) {
            tcg_gen_movi_i64(cpu_pr[insn->p1], 0);
        }
        if (insn->p2 != 0) {
            tcg_gen_movi_i64(cpu_pr[insn->p2], 0);
        }
        tcg_gen_movi_i64(cpu_pr[0], 1);
    }
}

static bool ia64_compare_has_equal_targets(const Ia64Instruction *insn)
{
    if (insn->p1 != insn->p2) {
        return false;
    }

    switch (insn->opcode) {
    case IA64_OP_CMP_EQ:
    case IA64_OP_CMP_LT:
    case IA64_OP_CMP_LE:
    case IA64_OP_CMP_GT:
    case IA64_OP_CMP_GE:
    case IA64_OP_CMP_LTU:
    case IA64_OP_CMP_LEU:
    case IA64_OP_CMP_GTU:
    case IA64_OP_CMP_GEU:
    case IA64_OP_CMP_NE:
    case IA64_OP_CMP_EQ_AND:
    case IA64_OP_CMP_NE_AND:
    case IA64_OP_CMP_GT_AND:
    case IA64_OP_CMP_LE_AND:
    case IA64_OP_CMP_GE_AND:
    case IA64_OP_CMP_LT_AND:
    case IA64_OP_CMP_EQ_OR:
    case IA64_OP_CMP_NE_OR:
    case IA64_OP_CMP_GT_OR:
    case IA64_OP_CMP_LE_OR:
    case IA64_OP_CMP_GE_OR:
    case IA64_OP_CMP_LT_OR:
    case IA64_OP_CMP_EQ_OR_ANDCM:
    case IA64_OP_CMP_NE_OR_ANDCM:
    case IA64_OP_CMP_GT_OR_ANDCM:
    case IA64_OP_CMP_LE_OR_ANDCM:
    case IA64_OP_CMP_GE_OR_ANDCM:
    case IA64_OP_CMP_LT_OR_ANDCM:
    case IA64_OP_CMP_EQ_IMM:
    case IA64_OP_CMP_LT_IMM:
    case IA64_OP_CMP_EQ_AND_IMM:
    case IA64_OP_CMP_NE_AND_IMM:
    case IA64_OP_CMP_EQ_OR_IMM:
    case IA64_OP_CMP_NE_OR_IMM:
    case IA64_OP_CMP_EQ_OR_ANDCM_IMM:
    case IA64_OP_CMP_NE_OR_ANDCM_IMM:
    case IA64_OP_CMP_LTU_IMM:
    case IA64_OP_CMP4_EQ:
    case IA64_OP_CMP4_LT:
    case IA64_OP_CMP4_LE:
    case IA64_OP_CMP4_GT:
    case IA64_OP_CMP4_GE:
    case IA64_OP_CMP4_LTU:
    case IA64_OP_CMP4_LEU:
    case IA64_OP_CMP4_GTU:
    case IA64_OP_CMP4_GEU:
    case IA64_OP_CMP4_EQ_AND:
    case IA64_OP_CMP4_NE_AND:
    case IA64_OP_CMP4_EQ_OR:
    case IA64_OP_CMP4_NE_OR:
    case IA64_OP_CMP4_EQ_OR_ANDCM:
    case IA64_OP_CMP4_NE_OR_ANDCM:
    case IA64_OP_CMP4_GT_AND:
    case IA64_OP_CMP4_LE_AND:
    case IA64_OP_CMP4_GE_AND:
    case IA64_OP_CMP4_LT_AND:
    case IA64_OP_CMP4_GT_OR:
    case IA64_OP_CMP4_LE_OR:
    case IA64_OP_CMP4_GE_OR:
    case IA64_OP_CMP4_LT_OR:
    case IA64_OP_CMP4_GT_OR_ANDCM:
    case IA64_OP_CMP4_LE_OR_ANDCM:
    case IA64_OP_CMP4_GE_OR_ANDCM:
    case IA64_OP_CMP4_LT_OR_ANDCM:
    case IA64_OP_CMP4_EQ_OR_ANDCM_IMM:
    case IA64_OP_CMP4_NE_OR_ANDCM_IMM:
    case IA64_OP_CMP4_EQ_IMM:
    case IA64_OP_CMP4_LT_IMM:
    case IA64_OP_CMP4_LTU_IMM:
    case IA64_OP_CMP4_EQ_AND_IMM:
    case IA64_OP_CMP4_NE_AND_IMM:
    case IA64_OP_CMP4_EQ_OR_IMM:
    case IA64_OP_CMP4_NE_OR_IMM:
    case IA64_OP_TBIT_Z:
    case IA64_OP_TBIT_NZ:
    case IA64_OP_TBIT_Z_OR_ANDCM:
    case IA64_OP_TBIT_NZ_OR_ANDCM:
    case IA64_OP_TNAT_Z:
    case IA64_OP_TNAT_NZ:
    case IA64_OP_TNAT_NZ_AND:
    case IA64_OP_TF_Z:
    case IA64_OP_TF_NZ:
    case IA64_OP_FCMP:
    case IA64_OP_FCLASS:
        return true;
    default:
        return false;
    }
}

static void ia64_gen_predicate_test_write(const Ia64Instruction *insn,
                                          TCGv_i64 cond, TCGv_i64 not_cond)
{
    switch (insn->pred_update) {
    case IA64_PRED_UPDATE_AND: {
        TCGLabel *done = gen_new_label();

        tcg_gen_brcondi_i64(TCG_COND_NE, cond, 0, done);
        if (insn->p1 != 0) {
            tcg_gen_movi_i64(cpu_pr[insn->p1], 0);
        }
        if (insn->p2 != 0) {
            tcg_gen_movi_i64(cpu_pr[insn->p2], 0);
        }
        gen_set_label(done);
        break;
    }
    case IA64_PRED_UPDATE_OR: {
        TCGLabel *done = gen_new_label();

        tcg_gen_brcondi_i64(TCG_COND_EQ, cond, 0, done);
        if (insn->p1 != 0) {
            tcg_gen_movi_i64(cpu_pr[insn->p1], 1);
        }
        if (insn->p2 != 0) {
            tcg_gen_movi_i64(cpu_pr[insn->p2], 1);
        }
        gen_set_label(done);
        break;
    }
    case IA64_PRED_UPDATE_OR_ANDCM: {
        TCGLabel *done = gen_new_label();

        tcg_gen_brcondi_i64(TCG_COND_EQ, cond, 0, done);
        if (insn->p1 != 0) {
            tcg_gen_movi_i64(cpu_pr[insn->p1], 1);
        }
        if (insn->p2 != 0) {
            tcg_gen_movi_i64(cpu_pr[insn->p2], 0);
        }
        gen_set_label(done);
        break;
    }
    case IA64_PRED_UPDATE_NORMAL:
        if (insn->p1 != 0) {
            tcg_gen_mov_i64(cpu_pr[insn->p1], cond);
        }
        if (insn->p2 != 0) {
            tcg_gen_mov_i64(cpu_pr[insn->p2], not_cond);
        }
        break;
    }
}

static void ia64_gen_addp4_result(TCGv_i64 dst, TCGv_i64 src1, TCGv_i64 src3)
{
    TCGv_i64 low = tcg_temp_new_i64();
    TCGv_i64 high = tcg_temp_new_i64();

    tcg_gen_add_i64(low, src1, src3);
    tcg_gen_ext32u_i64(low, low);
    tcg_gen_shri_i64(high, src3, 30);
    tcg_gen_andi_i64(high, high, 3);
    tcg_gen_shli_i64(high, high, 61);
    tcg_gen_or_i64(dst, low, high);
}

static void ia64_gen_saturate_signed_i64(TCGv_i64 value, int bits)
{
    int64_t min_value = -(1LL << (bits - 1));
    int64_t max_value = (1LL << (bits - 1)) - 1;
    TCGLabel *ge_min = gen_new_label();
    TCGLabel *le_max = gen_new_label();

    tcg_gen_brcondi_i64(TCG_COND_GE, value, min_value, ge_min);
    tcg_gen_movi_i64(value, min_value);
    gen_set_label(ge_min);
    tcg_gen_brcondi_i64(TCG_COND_LE, value, max_value, le_max);
    tcg_gen_movi_i64(value, max_value);
    gen_set_label(le_max);
}

static void ia64_gen_set_fault_slot(uint8_t slot)
{
    tcg_gen_st_i32(tcg_constant_i32(slot), tcg_env,
                   offsetof(CPUIA64State, fault_slot));
}

static void ia64_gen_clear_ri(void)
{
    tcg_gen_andi_i64(cpu_psr, cpu_psr, ~IA64_PSR_RI_MASK);
}

static void ia64_gen_set_ri(uint8_t slot)
{
    ia64_gen_clear_ri();
    if (slot != 0) {
        tcg_gen_ori_i64(cpu_psr, cpu_psr,
                        (uint64_t)slot << IA64_PSR_RI_SHIFT);
    }
}

static void ia64_gen_note_successful_bundle(uint64_t bundle_ip)
{
    TCGv_i64 collecting = tcg_temp_new_i64();
    TCGv_i64 suppression = tcg_temp_new_i64();
    TCGLabel *l_done = gen_new_label();
    TCGLabel *l_no_suppression = gen_new_label();

    /* Handler code with PSR.ic cleared must not advance the next IIPA value. */
    tcg_gen_andi_i64(collecting, cpu_psr, IA64_PSR_IC);
    tcg_gen_brcondi_i64(TCG_COND_EQ, collecting, 0, l_done);
    tcg_gen_st_i64(tcg_constant_i64(ia64_ip_bundle_addr(bundle_ip)), tcg_env,
                   offsetof(CPUIA64State, last_successful_bundle));
    gen_set_label(l_done);
    tcg_gen_ld_i64(suppression, tcg_env,
                   offsetof(CPUIA64State, psr_suppression_before_insn));
    tcg_gen_brcondi_i64(TCG_COND_EQ, suppression, 0, l_no_suppression);
    gen_helper_clear_psr_fault_suppression(tcg_env);
    gen_set_label(l_no_suppression);
}

static void ia64_gen_exit_to(uint64_t ip)
{
    ia64_gen_clear_ri();
    tcg_gen_movi_i64(cpu_ip, ip);
    tcg_gen_exit_tb(NULL, 0);
}

static void ia64_gen_exit_to_completed(uint64_t ip, uint64_t completed_ip)
{
    ia64_gen_note_successful_bundle(completed_ip);
    ia64_gen_exit_to(ip);
}

static void ia64_gen_exit_to_slot(uint64_t ip, uint8_t slot)
{
    if (slot >= 3) {
        ia64_gen_exit_to(ip + 16);
        return;
    }

    ia64_gen_clear_ri();
    tcg_gen_ori_i64(cpu_psr, cpu_psr,
                    (uint64_t)slot << IA64_PSR_RI_SHIFT);
    tcg_gen_movi_i64(cpu_ip, ip);
    tcg_gen_exit_tb(NULL, 0);
}

static void ia64_gen_exit_to_slot_completed(uint64_t ip, uint8_t slot,
                                            uint64_t completed_ip)
{
    ia64_gen_note_successful_bundle(completed_ip);
    ia64_gen_exit_to_slot(ip, slot);
}

static void ia64_gen_raise_exception(uint32_t exception, uint64_t fault_ip,
                                     uint64_t fault_imm, uint32_t fault_slot)
{
    tcg_gen_movi_i64(cpu_ip, fault_ip);
    gen_helper_raise_exception(tcg_env, tcg_constant_i32(exception),
                                tcg_constant_i64(fault_ip),
                                tcg_constant_i64(fault_imm),
                                tcg_constant_i32(fault_slot));
}

static void ia64_gen_gr_nat_clear(uint8_t reg)
{
    if (reg == 0) {
        return;
    }

    tcg_gen_andi_i64(cpu_nat[reg / 64], cpu_nat[reg / 64],
                     ~(1ULL << (reg % 64)));
}

static void ia64_gen_gr_nat_set(uint8_t reg)
{
    if (reg == 0) {
        return;
    }

    tcg_gen_ori_i64(cpu_nat[reg / 64], cpu_nat[reg / 64],
                    1ULL << (reg % 64));
}

static void ia64_gen_gr_write_nat_clear(uint8_t reg, TCGv_i64 value)
{
    if (reg == 0) {
        return;
    }
    tcg_gen_mov_i64(cpu_gr[reg], value);
    ia64_gen_gr_nat_clear(reg);
}

typedef enum Ia64NatConsumptionKind {
    IA64_NAT_ACCESS,
    IA64_NAT_NON_ACCESS,
} Ia64NatConsumptionKind;

static void ia64_gen_gr_nat_assign(uint8_t reg, TCGv_i64 bit)
{
    TCGv_i64 shifted;

    if (reg == 0) {
        return;
    }

    shifted = tcg_temp_new_i64();
    tcg_gen_andi_i64(shifted, bit, 1);
    tcg_gen_shli_i64(shifted, shifted, reg % 64);
    tcg_gen_andi_i64(cpu_nat[reg / 64], cpu_nat[reg / 64],
                     ~(1ULL << (reg % 64)));
    tcg_gen_or_i64(cpu_nat[reg / 64], cpu_nat[reg / 64], shifted);
}

static TCGv_i64 ia64_gen_gr_nat_read(uint8_t reg)
{
    TCGv_i64 bit = tcg_temp_new_i64();

    if (reg == 0) {
        tcg_gen_movi_i64(bit, 0);
        return bit;
    }

    tcg_gen_shri_i64(bit, cpu_nat[reg / 64], reg % 64);
    tcg_gen_andi_i64(bit, bit, 1);
    return bit;
}

static void ia64_gen_gr_nat_from_1(uint8_t dst, uint8_t src)
{
    if (dst == 0) {
        return;
    }

    ia64_gen_gr_nat_assign(dst, ia64_gen_gr_nat_read(src));
}

static void ia64_gen_gr_nat_from_2(uint8_t dst, uint8_t src1, uint8_t src2)
{
    TCGv_i64 bit;
    TCGv_i64 src_bit;

    if (dst == 0) {
        return;
    }

    bit = ia64_gen_gr_nat_read(src1);
    src_bit = ia64_gen_gr_nat_read(src2);
    tcg_gen_or_i64(bit, bit, src_bit);
    ia64_gen_gr_nat_assign(dst, bit);
}

static void ia64_gen_gr_nat_from_3(uint8_t dst, uint8_t src1, uint8_t src2,
                                   uint8_t src3)
{
    TCGv_i64 bit;
    TCGv_i64 src_bit;

    if (dst == 0) {
        return;
    }

    bit = ia64_gen_gr_nat_read(src1);
    src_bit = ia64_gen_gr_nat_read(src2);
    tcg_gen_or_i64(bit, bit, src_bit);
    src_bit = ia64_gen_gr_nat_read(src3);
    tcg_gen_or_i64(bit, bit, src_bit);
    ia64_gen_gr_nat_assign(dst, bit);
}

static void ia64_gen_pshr(const Ia64Instruction *insn, int lane_bits,
                          bool unsigned_shift)
{
    const int lanes = 64 / lane_bits;
    const uint64_t lane_mask = (1ULL << lane_bits) - 1;
    TCGv_i64 result;
    TCGv_i64 count;
    TCGv_i64 clamped_count;

    if (insn->r1 == 0) {
        return;
    }

    result = tcg_temp_new_i64();
    count = tcg_temp_new_i64();
    clamped_count = tcg_temp_new_i64();

    if (insn->imm >= 0) {
        tcg_gen_movi_i64(count, insn->imm);
    } else {
        tcg_gen_mov_i64(count, ia64_gr_src(insn->r2));
    }
    tcg_gen_movcond_i64(TCG_COND_GTU, clamped_count, count,
                        tcg_constant_i64(lane_bits),
                        tcg_constant_i64(lane_bits), count);

    tcg_gen_movi_i64(result, 0);
    for (int i = 0; i < lanes; i++) {
        TCGv_i64 lane = tcg_temp_new_i64();

        tcg_gen_extract_i64(lane, ia64_gr_src(insn->r3),
                            i * lane_bits, lane_bits);
        if (!unsigned_shift) {
            if (lane_bits == 16) {
                tcg_gen_ext16s_i64(lane, lane);
            } else {
                tcg_gen_ext32s_i64(lane, lane);
            }
            tcg_gen_sar_i64(lane, lane, clamped_count);
        } else {
            tcg_gen_shr_i64(lane, lane, clamped_count);
        }
        tcg_gen_andi_i64(lane, lane, lane_mask);
        tcg_gen_shli_i64(lane, lane, i * lane_bits);
        tcg_gen_or_i64(result, result, lane);
    }

    tcg_gen_mov_i64(cpu_gr[insn->r1], result);
    if (insn->imm >= 0) {
        ia64_gen_gr_nat_from_1(insn->r1, insn->r3);
    } else {
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
    }
}

static void ia64_gen_pshl(const Ia64Instruction *insn, int lane_bits)
{
    const int lanes = 64 / lane_bits;
    const uint64_t lane_mask = (1ULL << lane_bits) - 1;
    TCGv_i64 result;
    TCGv_i64 count;
    TCGv_i64 clamped_count;

    if (insn->r1 == 0) {
        return;
    }

    result = tcg_temp_new_i64();
    count = tcg_temp_new_i64();
    clamped_count = tcg_temp_new_i64();

    if (insn->imm >= 0) {
        tcg_gen_movi_i64(count, insn->imm);
    } else {
        tcg_gen_mov_i64(count, ia64_gr_src(insn->r3));
    }
    tcg_gen_movcond_i64(TCG_COND_GTU, clamped_count, count,
                        tcg_constant_i64(lane_bits),
                        tcg_constant_i64(lane_bits), count);

    tcg_gen_movi_i64(result, 0);
    for (int i = 0; i < lanes; i++) {
        TCGv_i64 lane = tcg_temp_new_i64();

        tcg_gen_extract_i64(lane, ia64_gr_src(insn->r2),
                            i * lane_bits, lane_bits);
        tcg_gen_shl_i64(lane, lane, clamped_count);
        tcg_gen_andi_i64(lane, lane, lane_mask);
        tcg_gen_shli_i64(lane, lane, i * lane_bits);
        tcg_gen_or_i64(result, result, lane);
    }

    tcg_gen_mov_i64(cpu_gr[insn->r1], result);
    if (insn->imm >= 0) {
        ia64_gen_gr_nat_from_1(insn->r1, insn->r2);
    } else {
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
    }
}

static void ia64_gen_check_nat_consumption(const Ia64Instruction *insn,
                                           uint8_t reg, uint64_t isr_access,
                                           Ia64NatConsumptionKind kind)
{
    TCGv_i64 nat;
    TCGLabel *ok;

    if (reg == 0) {
        return;
    }

    nat = ia64_gen_gr_nat_read(reg);
    ok = gen_new_label();
    tcg_gen_brcondi_i64(TCG_COND_EQ, nat, 0, ok);
    tcg_gen_movi_i64(cpu_ip, insn->address);
    gen_helper_raise_nat_consumption(tcg_env, tcg_constant_i64(isr_access),
                                     tcg_constant_i32(kind ==
                                                      IA64_NAT_NON_ACCESS),
                                     tcg_constant_i64(insn->address),
                                     tcg_constant_i32(insn->slot));
    gen_set_label(ok);
}

static void ia64_gen_check_nat_access(const Ia64Instruction *insn,
                                      uint8_t reg, bool is_write)
{
    ia64_gen_check_nat_consumption(insn, reg,
                                   is_write ? IA64_ISR_W : IA64_ISR_R,
                                   IA64_NAT_ACCESS);
}

static void ia64_gen_memory_acquire(const Ia64Instruction *insn)
{
    if (insn->mem_acquire) {
        tcg_gen_mb(TCG_MO_ALL);
    }
}

static void ia64_gen_memory_release(const Ia64Instruction *insn)
{
    if (insn->mem_release) {
        tcg_gen_mb(TCG_MO_ALL);
    }
}

static void ia64_gen_check_nat_non_access(const Ia64Instruction *insn,
                                          uint8_t reg, bool is_write)
{
    ia64_gen_check_nat_consumption(insn, reg,
                                   is_write ? IA64_ISR_W : IA64_ISR_R,
                                   IA64_NAT_NON_ACCESS);
}

static void ia64_gen_check_nat_semaphore(const Ia64Instruction *insn,
                                         uint8_t reg,
                                         Ia64NatConsumptionKind kind)
{
    ia64_gen_check_nat_consumption(insn, reg, IA64_ISR_R | IA64_ISR_W,
                                   kind);
}

static void ia64_gen_load_reg_base_update_inputs(
    const Ia64Instruction *insn,
    TCGv_i64 *increment,
    TCGv_i64 *base_nat,
    TCGv_i64 *increment_nat)
{
    if (!insn->reg_base_update) {
        return;
    }

    *increment = tcg_temp_new_i64();
    *base_nat = ia64_gen_gr_nat_read(insn->r3);
    *increment_nat = ia64_gen_gr_nat_read(insn->r2);
    tcg_gen_mov_i64(*increment, ia64_gr_src(insn->r2));
}

static void ia64_gen_load_reg_base_update(const Ia64Instruction *insn,
                                          TCGv_i64 addr,
                                          TCGv_i64 increment,
                                          TCGv_i64 base_nat,
                                          TCGv_i64 increment_nat)
{
    TCGv_i64 new_base = tcg_temp_new_i64();
    TCGv_i64 new_nat = tcg_temp_new_i64();

    tcg_gen_add_i64(new_base, addr, increment);
    tcg_gen_mov_i64(cpu_gr[insn->r3], new_base);
    tcg_gen_or_i64(new_nat, base_nat, increment_nat);
    ia64_gen_gr_nat_assign(insn->r3, new_nat);
}

static void ia64_gen_ld_fill_nat(uint8_t reg, TCGv_i64 addr)
{
    TCGv_i64 unat = tcg_temp_new_i64();
    TCGv_i64 bitpos = tcg_temp_new_i64();
    TCGv_i64 natbit = tcg_temp_new_i64();

    gen_helper_read_ar(unat, tcg_env, tcg_constant_i32(36));
    tcg_gen_shri_i64(bitpos, addr, 3);
    tcg_gen_andi_i64(bitpos, bitpos, 0x3f);
    tcg_gen_shr_i64(natbit, unat, bitpos);
    tcg_gen_andi_i64(natbit, natbit, 1);
    ia64_gen_gr_nat_assign(reg, natbit);
}

static void ia64_gen_check_branch(TCGv_i64 failed, uint64_t target,
                                  uint64_t completed_ip)
{
    TCGLabel *l_done = gen_new_label();

    tcg_gen_brcondi_i64(TCG_COND_EQ, failed, 0, l_done);
    ia64_gen_note_successful_bundle(completed_ip);
    ia64_gen_clear_ri();
    tcg_gen_movi_i64(cpu_ip, target);
    tcg_gen_exit_tb(NULL, 0);
    gen_set_label(l_done);
}

static void ia64_gen_speculative_load(DisasContext *ctx,
                                      const Ia64Instruction *insn,
                                      bool advanced)
{
    MemOp mop = ia64_memop_for_opcode(insn->opcode);
    TCGv_i64 addr;
    TCGv_i64 increment = NULL;
    TCGv_i64 base_nat = NULL;
    TCGv_i64 increment_nat = NULL;
    TCGv_i64 ok;
    TCGLabel *l_fail;
    TCGLabel *l_done;

    if (insn->r1 == 0) {
        if (insn->imm != 0 && insn->r3 != 0) {
            tcg_gen_addi_i64(cpu_gr[insn->r3], cpu_gr[insn->r3], insn->imm);
        }
        return;
    }

    addr = tcg_temp_new_i64();
    ia64_gen_load_reg_base_update_inputs(insn, &increment, &base_nat,
                                         &increment_nat);
    ok = tcg_temp_new_i64();
    l_fail = gen_new_label();
    l_done = gen_new_label();

    tcg_gen_mov_i64(addr, ia64_gr_src(insn->r3));
    if (insn->r3 != 0) {
        TCGv_i64 addr_nat = ia64_gen_gr_nat_read(insn->r3);

        tcg_gen_brcondi_i64(TCG_COND_NE, addr_nat, 0, l_fail);
    }
    gen_helper_speculative_probe(ok, tcg_env, addr, tcg_constant_i32(0),
                                 tcg_constant_i32(0),
                                 tcg_constant_i32(ia64_memop_size(mop)));
    tcg_gen_brcondi_i64(TCG_COND_EQ, ok, 0, l_fail);

    tcg_gen_qemu_ld_i64(cpu_gr[insn->r1], addr, ctx->mmu_idx, mop);
    ia64_gen_gr_nat_clear(insn->r1);
    if (advanced) {
        gen_helper_set_alat(tcg_env, tcg_constant_i32(insn->r1), addr,
                            tcg_constant_i32(ia64_memop_size(mop)));
    }
    tcg_gen_br(l_done);

    gen_set_label(l_fail);
    if (advanced) {
        gen_helper_invalidate_alat_reg(tcg_env, tcg_constant_i32(insn->r1));
    }
    tcg_gen_movi_i64(cpu_gr[insn->r1], 0);
    ia64_gen_gr_nat_set(insn->r1);

    gen_set_label(l_done);
    if (insn->reg_base_update && insn->r3 != 0) {
        ia64_gen_load_reg_base_update(insn, addr, increment, base_nat,
                                      increment_nat);
    } else if (insn->imm != 0 && insn->r3 != 0) {
        tcg_gen_addi_i64(cpu_gr[insn->r3], addr, insn->imm);
    }
}

static uint32_t ia64_fp_load_size(Ia64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_LDFS:
        return 4;
    case IA64_OP_LDFD:
    case IA64_OP_LDF8:
        return 8;
    case IA64_OP_LDFE:
    case IA64_OP_LDF_FILL:
        return 16;
    default:
        g_assert_not_reached();
    }
}

static void ia64_gen_fp_load_value(DisasContext *ctx,
                                   const Ia64Instruction *insn,
                                   TCGv_i64 addr)
{
    switch (insn->opcode) {
    case IA64_OP_LDFS:
        ia64_gen_fr_ld(insn->r1, addr, ctx->mmu_idx, MO_LEUL);
        break;
    case IA64_OP_LDFD:
    case IA64_OP_LDF8:
    case IA64_OP_LDF_FILL:
        ia64_gen_fr_ld(insn->r1, addr, ctx->mmu_idx, MO_LEUQ);
        break;
    case IA64_OP_LDFE:
        gen_helper_ldfe(tcg_env, tcg_constant_i32(insn->r1), addr);
        break;
    default:
        g_assert_not_reached();
    }
}

static void ia64_gen_fp_load_base_update(const Ia64Instruction *insn,
                                         TCGv_i64 addr,
                                         TCGv_i64 increment,
                                         TCGv_i64 base_nat,
                                         TCGv_i64 increment_nat)
{
    if (insn->reg_base_update && insn->r3 != 0) {
        ia64_gen_load_reg_base_update(insn, addr, increment, base_nat,
                                      increment_nat);
    } else if (insn->imm != 0 && insn->r3 != 0) {
        tcg_gen_addi_i64(cpu_gr[insn->r3], addr, insn->imm);
    }
}

static void ia64_gen_fp_load(DisasContext *ctx, const Ia64Instruction *insn)
{
    const uint32_t size = ia64_fp_load_size(insn->opcode);
    TCGv_i64 addr = tcg_temp_new_i64();
    TCGv_i64 increment = NULL;
    TCGv_i64 base_nat = NULL;
    TCGv_i64 increment_nat = NULL;

    tcg_gen_mov_i64(addr, ia64_gr_src(insn->r3));
    ia64_gen_load_reg_base_update_inputs(insn, &increment, &base_nat,
                                         &increment_nat);

    if (insn->fp_load_check) {
        TCGv_i64 hit = tcg_temp_new_i64();
        TCGLabel *l_done = gen_new_label();

        gen_helper_check_load_alat_fp_addr(hit, tcg_env,
                                           tcg_constant_i32(insn->r1),
                                           addr, tcg_constant_i32(size),
                                           tcg_constant_i32(
                                               insn->fp_load_check_clear));
        tcg_gen_brcondi_i64(TCG_COND_NE, hit, 0, l_done);

        ia64_gen_check_nat_non_access(insn, insn->r3, false);
        ia64_gen_check_alignment(insn, addr, size, false, false);
        ia64_gen_fp_load_value(ctx, insn, addr);
        if (!insn->fp_load_check_clear) {
            gen_helper_set_alat_fp(tcg_env, tcg_constant_i32(insn->r1),
                                   addr, tcg_constant_i32(size));
        }

        gen_set_label(l_done);
        ia64_gen_fp_load_base_update(insn, addr, increment, base_nat,
                                     increment_nat);
        return;
    }

    if (insn->fp_load_speculative) {
        TCGv_i64 ok = tcg_temp_new_i64();
        TCGLabel *l_fail = gen_new_label();
        TCGLabel *l_done = gen_new_label();

        if (insn->r3 != 0) {
            TCGv_i64 addr_nat = ia64_gen_gr_nat_read(insn->r3);

            tcg_gen_brcondi_i64(TCG_COND_NE, addr_nat, 0, l_fail);
        }
        gen_helper_speculative_probe(ok, tcg_env, addr, tcg_constant_i32(0),
                                     tcg_constant_i32(0),
                                     tcg_constant_i32(size));
        tcg_gen_brcondi_i64(TCG_COND_EQ, ok, 0, l_fail);

        ia64_gen_fp_load_value(ctx, insn, addr);
        if (insn->fp_load_advanced) {
            gen_helper_set_alat_fp(tcg_env, tcg_constant_i32(insn->r1),
                                   addr, tcg_constant_i32(size));
        }
        tcg_gen_br(l_done);

        gen_set_label(l_fail);
        if (insn->fp_load_advanced) {
            gen_helper_invalidate_alat_fp_reg(tcg_env,
                                              tcg_constant_i32(insn->r1));
        }
        if (ia64_fr_is_writable(insn->r1)) {
            tcg_gen_movi_i64(cpu_fr[insn->r1], 0);
        }
        ia64_gen_fr_nat_set(insn->r1);

        gen_set_label(l_done);
        ia64_gen_fp_load_base_update(insn, addr, increment, base_nat,
                                     increment_nat);
        return;
    }

    ia64_gen_check_nat_non_access(insn, insn->r3, false);
    ia64_gen_check_alignment(insn, addr, size, false, false);
    ia64_gen_fp_load_value(ctx, insn, addr);
    if (insn->fp_load_advanced) {
        gen_helper_set_alat_fp(tcg_env, tcg_constant_i32(insn->r1),
                               addr, tcg_constant_i32(size));
    }
    ia64_gen_fp_load_base_update(insn, addr, increment, base_nat,
                                 increment_nat);
}

static uint32_t ia64_fp_load_pair_size(Ia64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_LDFPS:
        return 8;
    case IA64_OP_LDFPD:
    case IA64_OP_LDFP8:
        return 16;
    default:
        g_assert_not_reached();
    }
}

static void ia64_gen_fp_load_pair_value(DisasContext *ctx,
                                        const Ia64Instruction *insn,
                                        TCGv_i64 addr)
{
    TCGv_i64 second = tcg_temp_new_i64();

    switch (insn->opcode) {
    case IA64_OP_LDFPS:
        ia64_gen_fr_ld(insn->r1, addr, ctx->mmu_idx, MO_LEUL);
        tcg_gen_addi_i64(second, addr, 4);
        ia64_gen_fr_ld(insn->r2, second, ctx->mmu_idx, MO_LEUL);
        break;
    case IA64_OP_LDFPD:
    case IA64_OP_LDFP8:
        ia64_gen_fr_ld(insn->r1, addr, ctx->mmu_idx, MO_LEUQ);
        tcg_gen_addi_i64(second, addr, 8);
        ia64_gen_fr_ld(insn->r2, second, ctx->mmu_idx, MO_LEUQ);
        break;
    default:
        g_assert_not_reached();
    }
}

static void ia64_gen_fp_load_pair_nat_set(const Ia64Instruction *insn)
{
    if (ia64_fr_is_writable(insn->r1)) {
        tcg_gen_movi_i64(cpu_fr[insn->r1], 0);
    }
    if (ia64_fr_is_writable(insn->r2)) {
        tcg_gen_movi_i64(cpu_fr[insn->r2], 0);
    }
    ia64_gen_fr_nat_set(insn->r1);
    ia64_gen_fr_nat_set(insn->r2);
}

static void ia64_gen_fp_load_pair_base_update(const Ia64Instruction *insn,
                                              TCGv_i64 addr)
{
    if (insn->imm != 0 && insn->r3 != 0) {
        tcg_gen_addi_i64(cpu_gr[insn->r3], addr, insn->imm);
    }
}

static void ia64_gen_fp_load_pair(DisasContext *ctx,
                                  const Ia64Instruction *insn)
{
    const uint32_t size = ia64_fp_load_pair_size(insn->opcode);
    TCGv_i64 addr = tcg_temp_new_i64();

    tcg_gen_mov_i64(addr, ia64_gr_src(insn->r3));

    if (insn->fp_load_check) {
        TCGv_i64 hit = tcg_temp_new_i64();
        TCGLabel *l_done = gen_new_label();

        gen_helper_check_load_alat_fp_addr(hit, tcg_env,
                                           tcg_constant_i32(insn->r1),
                                           addr, tcg_constant_i32(size),
                                           tcg_constant_i32(
                                               insn->fp_load_check_clear));
        tcg_gen_brcondi_i64(TCG_COND_NE, hit, 0, l_done);

        ia64_gen_check_nat_non_access(insn, insn->r3, false);
        ia64_gen_check_alignment(insn, addr, size, false, false);
        ia64_gen_fp_load_pair_value(ctx, insn, addr);
        if (!insn->fp_load_check_clear) {
            gen_helper_set_alat_fp(tcg_env, tcg_constant_i32(insn->r1),
                                   addr, tcg_constant_i32(size));
        }

        gen_set_label(l_done);
        ia64_gen_fp_load_pair_base_update(insn, addr);
        return;
    }

    if (insn->fp_load_speculative) {
        TCGv_i64 ok = tcg_temp_new_i64();
        TCGLabel *l_fail = gen_new_label();
        TCGLabel *l_done = gen_new_label();

        if (insn->r3 != 0) {
            TCGv_i64 addr_nat = ia64_gen_gr_nat_read(insn->r3);

            tcg_gen_brcondi_i64(TCG_COND_NE, addr_nat, 0, l_fail);
        }
        gen_helper_speculative_probe(ok, tcg_env, addr, tcg_constant_i32(0),
                                     tcg_constant_i32(0),
                                     tcg_constant_i32(size));
        tcg_gen_brcondi_i64(TCG_COND_EQ, ok, 0, l_fail);

        ia64_gen_fp_load_pair_value(ctx, insn, addr);
        if (insn->fp_load_advanced) {
            gen_helper_set_alat_fp(tcg_env, tcg_constant_i32(insn->r1),
                                   addr, tcg_constant_i32(size));
        }
        tcg_gen_br(l_done);

        gen_set_label(l_fail);
        if (insn->fp_load_advanced) {
            gen_helper_invalidate_alat_fp_reg(tcg_env,
                                              tcg_constant_i32(insn->r1));
        }
        ia64_gen_fp_load_pair_nat_set(insn);

        gen_set_label(l_done);
        ia64_gen_fp_load_pair_base_update(insn, addr);
        return;
    }

    ia64_gen_check_nat_non_access(insn, insn->r3, false);
    ia64_gen_check_alignment(insn, addr, size, false, false);
    ia64_gen_fp_load_pair_value(ctx, insn, addr);
    if (insn->fp_load_advanced) {
        gen_helper_set_alat_fp(tcg_env, tcg_constant_i32(insn->r1),
                               addr, tcg_constant_i32(size));
    }
    ia64_gen_fp_load_pair_base_update(insn, addr);
}

static void ia64_gen_native_integer_write(const Ia64Instruction *insn)
{
    TCGv_i64 tmp;
    TCGv_i64 tmp2;

    if (insn->r1 == 0) {
        return;
    }

    switch (insn->opcode) {
    case IA64_OP_ADDS:
    case IA64_OP_ADDL:
        tcg_gen_addi_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3),
                         insn->imm);
        break;
    case IA64_OP_SHLADD:
        tmp = tcg_temp_new_i64();
        tcg_gen_shli_i64(tmp, ia64_gr_src(insn->r2), insn->imm);
        tcg_gen_add_i64(cpu_gr[insn->r1], tmp, ia64_gr_src(insn->r3));
        break;
    case IA64_OP_ADD:
        tcg_gen_add_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r2),
                        ia64_gr_src(insn->r3));
        break;
    case IA64_OP_ADD_ONE:
        tmp = tcg_temp_new_i64();
        tcg_gen_add_i64(tmp, ia64_gr_src(insn->r2), ia64_gr_src(insn->r3));
        tcg_gen_addi_i64(cpu_gr[insn->r1], tmp, 1);
        break;
    case IA64_OP_SUB:
        tcg_gen_sub_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r2),
                        ia64_gr_src(insn->r3));
        break;
    case IA64_OP_SUB_ONE:
        tmp = tcg_temp_new_i64();
        tcg_gen_sub_i64(tmp, ia64_gr_src(insn->r2), ia64_gr_src(insn->r3));
        tcg_gen_subi_i64(cpu_gr[insn->r1], tmp, 1);
        break;
    case IA64_OP_AND:
        tcg_gen_and_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r2),
                        ia64_gr_src(insn->r3));
        break;
    case IA64_OP_ANDCM:
        tmp = tcg_temp_new_i64();
        tcg_gen_not_i64(tmp, ia64_gr_src(insn->r3));
        tcg_gen_and_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r2), tmp);
        break;
    case IA64_OP_OR:
        tcg_gen_or_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r2),
                       ia64_gr_src(insn->r3));
        break;
    case IA64_OP_XOR:
        tcg_gen_xor_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r2),
                        ia64_gr_src(insn->r3));
        break;
    case IA64_OP_SHL:
        tmp = tcg_temp_new_i64();
        tcg_gen_andi_i64(tmp, ia64_gr_src(insn->r2), 0x3f);
        TCGv_i64 shifted_l = tcg_temp_new_i64();
        tcg_gen_shl_i64(shifted_l, ia64_gr_src(insn->r3), tmp);
        tcg_gen_movcond_i64(TCG_COND_GTU, cpu_gr[insn->r1],
                            ia64_gr_src(insn->r2), tcg_constant_i64(63),
                            tcg_constant_i64(0), shifted_l);
        break;
    case IA64_OP_SHRU:
        tmp = tcg_temp_new_i64();
        tcg_gen_andi_i64(tmp, ia64_gr_src(insn->r2), 0x3f);
        TCGv_i64 shifted_ru = tcg_temp_new_i64();
        tcg_gen_shr_i64(shifted_ru, ia64_gr_src(insn->r3), tmp);
        tcg_gen_movcond_i64(TCG_COND_GTU, cpu_gr[insn->r1],
                            ia64_gr_src(insn->r2), tcg_constant_i64(63),
                            tcg_constant_i64(0), shifted_ru);
        break;
    case IA64_OP_SHR:
        tmp = tcg_temp_new_i64();
        tcg_gen_movcond_i64(TCG_COND_GTU, tmp,
                            ia64_gr_src(insn->r2), tcg_constant_i64(63),
                            tcg_constant_i64(63), ia64_gr_src(insn->r2));
        tcg_gen_sar_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3), tmp);
        break;
    case IA64_OP_SHL_IMM:
        tcg_gen_shli_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3),
                         insn->imm & 0x3f);
        break;
    case IA64_OP_SHRU_IMM:
        tcg_gen_shri_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3),
                         insn->imm & 0x3f);
        break;
    case IA64_OP_SHR_IMM:
        tcg_gen_sari_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3),
                         insn->imm & 0x3f);
        break;
    case IA64_OP_DEPZ: {
        const uint64_t pos = insn->imm & 0x3f;
        const uint64_t len = (insn->imm >> 6) & 0x7f;

        tmp = tcg_temp_new_i64();
        tmp2 = tcg_temp_new_i64();
        tcg_gen_movi_i64(tmp, ia64_deposit_mask(pos, len));
        tcg_gen_shli_i64(tmp2, ia64_gr_src(insn->r2), pos);
        tcg_gen_and_i64(cpu_gr[insn->r1], tmp2, tmp);
        break;
    }
    case IA64_OP_DEPZ_IMM: {
        const uint64_t pos = insn->imm & 0x3f;
        const uint64_t len = (insn->imm >> 6) & 0x7f;
        const int64_t src = (int8_t)((insn->imm >> 13) & 0xff);
        uint64_t mask_value = ia64_deposit_mask(pos, len);

        tcg_gen_movi_i64(cpu_gr[insn->r1],
                         (((uint64_t)src << pos) & mask_value));
        break;
    }
    case IA64_OP_EXTRU: {
        const uint64_t pos = insn->imm & 0x3f;
        const uint64_t len = ia64_bitfield_effective_len(pos,
                                                         insn->imm >> 6);

        tmp = tcg_temp_new_i64();
        tmp2 = tcg_temp_new_i64();
        tcg_gen_movi_i64(tmp, ia64_low_mask(len));
        tcg_gen_shri_i64(tmp2, ia64_gr_src(insn->r3), pos);
        tcg_gen_and_i64(cpu_gr[insn->r1], tmp2, tmp);
        break;
    }
    case IA64_OP_SXT1:
        tcg_gen_ext8s_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3));
        break;
    case IA64_OP_SXT2:
        tcg_gen_ext16s_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3));
        break;
    case IA64_OP_SXT4:
        tcg_gen_ext32s_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3));
        break;
    case IA64_OP_ZXT1:
        tcg_gen_ext8u_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3));
        break;
    case IA64_OP_ZXT2:
        tcg_gen_ext16u_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3));
        break;
    case IA64_OP_ZXT4:
        tcg_gen_ext32u_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3));
        break;
    case IA64_OP_SHRP_IMM:
        if ((insn->imm & 0x3f) == 0) {
            tcg_gen_mov_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3));
        } else {
            tmp = tcg_temp_new_i64();
            tmp2 = tcg_temp_new_i64();
            tcg_gen_shri_i64(tmp, ia64_gr_src(insn->r3), insn->imm & 0x3f);
            tcg_gen_shli_i64(tmp2, ia64_gr_src(insn->r2),
                             64 - (insn->imm & 0x3f));
            tcg_gen_or_i64(cpu_gr[insn->r1], tmp, tmp2);
        }
        break;
    case IA64_OP_DEP: {
        TCGv_i64 mask = tcg_temp_new_i64();
        TCGv_i64 pos = tcg_temp_new_i64();
        TCGv_i64 len = tcg_temp_new_i64();
        TCGv_i64 base = tcg_temp_new_i64();
        TCGv_i64 shifted = tcg_temp_new_i64();
        tcg_gen_movi_i64(pos, insn->imm & 0x3f);
        tcg_gen_movi_i64(len, (insn->imm >> 6) & 0x3f);
        tcg_gen_movi_i64(mask, 1);
        tcg_gen_shl_i64(mask, mask, len);
        tcg_gen_subi_i64(mask, mask, 1);
        tcg_gen_shl_i64(mask, mask, pos);
        tcg_gen_not_i64(mask, mask);
        tcg_gen_and_i64(base, ia64_gr_src(insn->r3), mask);
        tcg_gen_not_i64(mask, mask);
        tcg_gen_shl_i64(shifted, ia64_gr_src(insn->r2), pos);
        tcg_gen_and_i64(shifted, shifted, mask);
        tcg_gen_or_i64(cpu_gr[insn->r1], base, shifted);
        break;
    }
    case IA64_OP_DEP_IMM: {
        const uint64_t pos = insn->imm & 0x3f;
        const uint64_t len = (insn->imm >> 6) & 0x7f;
        const uint64_t fill = (insn->imm >> 13) & 1;
        uint64_t mask_value = ia64_deposit_mask(pos, len);

        tmp = tcg_temp_new_i64();
        tmp2 = tcg_temp_new_i64();
        tcg_gen_movi_i64(tmp2, ~mask_value);
        tcg_gen_and_i64(tmp, ia64_gr_src(insn->r3), tmp2);
        if (fill) {
            tcg_gen_movi_i64(tmp2, mask_value);
            tcg_gen_or_i64(cpu_gr[insn->r1], tmp, tmp2);
        } else {
            tcg_gen_mov_i64(cpu_gr[insn->r1], tmp);
        }
        break;
    }
    case IA64_OP_EXTR: {
        TCGv_i64 pos = tcg_temp_new_i64();
        TCGv_i64 len_tcg = tcg_temp_new_i64();
        TCGv_i64 val = tcg_temp_new_i64();
        TCGv_i64 sign_bit = tcg_temp_new_i64();
        const uint64_t pos_imm = insn->imm & 0x3f;
        const uint64_t len_imm =
            ia64_bitfield_effective_len(pos_imm, insn->imm >> 6);
        tmp = tcg_temp_new_i64();
        tcg_gen_movi_i64(pos, pos_imm);
        tcg_gen_movi_i64(len_tcg, len_imm);
        tcg_gen_shr_i64(val, ia64_gr_src(insn->r3), pos);
        tcg_gen_movi_i64(tmp, ia64_low_mask(len_imm));
        tcg_gen_and_i64(val, val, tmp);
        tcg_gen_subi_i64(len_tcg, len_tcg, 1);
        tcg_gen_movi_i64(sign_bit, 1);
        tcg_gen_shl_i64(sign_bit, sign_bit, len_tcg);
        tcg_gen_xor_i64(val, val, sign_bit);
        tcg_gen_sub_i64(cpu_gr[insn->r1], val, sign_bit);
        break;
    }
    case IA64_OP_SUB_IMM:
        tmp = tcg_temp_new_i64();
        tcg_gen_movi_i64(tmp, insn->imm);
        tcg_gen_sub_i64(cpu_gr[insn->r1], tmp, ia64_gr_src(insn->r3));
        break;
    case IA64_OP_AND_IMM:
        tmp = tcg_temp_new_i64();
        tcg_gen_movi_i64(tmp, insn->imm);
        tcg_gen_and_i64(cpu_gr[insn->r1], tmp, ia64_gr_src(insn->r3));
        break;
    case IA64_OP_ANDCM_IMM:
        tmp = tcg_temp_new_i64();
        tmp2 = tcg_temp_new_i64();
        tcg_gen_movi_i64(tmp, insn->imm);
        tcg_gen_not_i64(tmp2, ia64_gr_src(insn->r3));
        tcg_gen_and_i64(cpu_gr[insn->r1], tmp, tmp2);
        break;
    case IA64_OP_OR_IMM:
        tmp = tcg_temp_new_i64();
        tcg_gen_movi_i64(tmp, insn->imm);
        tcg_gen_or_i64(cpu_gr[insn->r1], tmp, ia64_gr_src(insn->r3));
        break;
    case IA64_OP_XOR_IMM:
        tmp = tcg_temp_new_i64();
        tcg_gen_movi_i64(tmp, insn->imm);
        tcg_gen_xor_i64(cpu_gr[insn->r1], tmp, ia64_gr_src(insn->r3));
        break;
    case IA64_OP_SHLADDP4:
        tmp = tcg_temp_new_i64();
        tcg_gen_shli_i64(tmp, ia64_gr_src(insn->r2), insn->imm);
        ia64_gen_addp4_result(cpu_gr[insn->r1], tmp,
                              ia64_gr_src(insn->r3));
        break;
    case IA64_OP_MPY4: {
        TCGv_i64 tmpr2 = tcg_temp_new_i64();
        TCGv_i64 tmpr3 = tcg_temp_new_i64();
        tcg_gen_ext32u_i64(tmpr2, ia64_gr_src(insn->r2));
        tcg_gen_ext32u_i64(tmpr3, ia64_gr_src(insn->r3));
        tcg_gen_mul_i64(cpu_gr[insn->r1], tmpr2, tmpr3);
        break;
    }
    case IA64_OP_MPYSHL4: {
        TCGv_i64 tmpr2 = tcg_temp_new_i64();
        TCGv_i64 tmpr3 = tcg_temp_new_i64();
        TCGv_i64 mul_res = tcg_temp_new_i64();
        tcg_gen_shri_i64(tmpr2, ia64_gr_src(insn->r2), 32);
        tcg_gen_ext32u_i64(tmpr3, ia64_gr_src(insn->r3));
        tcg_gen_mul_i64(mul_res, tmpr2, tmpr3);
        tcg_gen_shli_i64(cpu_gr[insn->r1], mul_res, 32);
        break;
    }
    case IA64_OP_MPYSH: {
        TCGv_i64 tmpr2 = tcg_temp_new_i64();
        TCGv_i64 tmpr3 = tcg_temp_new_i64();
        TCGv_i64 mul_res = tcg_temp_new_i64();
        tcg_gen_ext32s_i64(tmpr2, ia64_gr_src(insn->r2));
        tcg_gen_ext32s_i64(tmpr3, ia64_gr_src(insn->r3));
        tcg_gen_mul_i64(mul_res, tmpr2, tmpr3);
        tcg_gen_sari_i64(cpu_gr[insn->r1], mul_res, 32);
        break;
    }
    case IA64_OP_MPYUH: {
        TCGv_i64 tmpr2 = tcg_temp_new_i64();
        TCGv_i64 tmpr3 = tcg_temp_new_i64();
        TCGv_i64 mul_res = tcg_temp_new_i64();
        tcg_gen_ext32u_i64(tmpr2, ia64_gr_src(insn->r2));
        tcg_gen_ext32u_i64(tmpr3, ia64_gr_src(insn->r3));
        tcg_gen_mul_i64(mul_res, tmpr2, tmpr3);
        tcg_gen_shri_i64(cpu_gr[insn->r1], mul_res, 32);
        break;
    }
    case IA64_OP_MUX: {
        TCGv_i64 r1_orig = tcg_temp_new_i64();
        tcg_gen_mov_i64(r1_orig, ia64_gr_src(insn->r1));
        tmp = tcg_temp_new_i64();
        tmp2 = tcg_temp_new_i64();
        tcg_gen_and_i64(tmp, ia64_gr_src(insn->r2), r1_orig);
        tcg_gen_not_i64(tmp2, ia64_gr_src(insn->r2));
        tcg_gen_and_i64(tmp2, tmp2, ia64_gr_src(insn->r3));
        tcg_gen_or_i64(cpu_gr[insn->r1], tmp, tmp2);
        break;
    }
    case IA64_OP_POPCNT:
        tcg_gen_ctpop_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3));
        break;
    case IA64_OP_CLZ:
        tcg_gen_clzi_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3), 64);
        break;
    case IA64_OP_ILLEGAL:
    case IA64_OP_NOP:
    case IA64_OP_BREAK:
    case IA64_OP_CMP_EQ:
    case IA64_OP_CMP_LT:
    case IA64_OP_CMP_LE:
    case IA64_OP_CMP_GT:
    case IA64_OP_CMP_GE:
    case IA64_OP_CMP_LTU:
    case IA64_OP_CMP_LEU:
    case IA64_OP_CMP_GTU:
    case IA64_OP_CMP_GEU:
    case IA64_OP_CMP_NE:
    case IA64_OP_CMP_EQ_AND:
    case IA64_OP_CMP_NE_AND:
    case IA64_OP_CMP_GT_AND:
    case IA64_OP_CMP_LE_AND:
    case IA64_OP_CMP_GE_AND:
    case IA64_OP_CMP_LT_AND:
    case IA64_OP_CMP_EQ_OR:
    case IA64_OP_CMP_NE_OR:
    case IA64_OP_CMP_GT_OR:
    case IA64_OP_CMP_LE_OR:
    case IA64_OP_CMP_GE_OR:
    case IA64_OP_CMP_LT_OR:
    case IA64_OP_CMP_EQ_OR_ANDCM:
    case IA64_OP_CMP_NE_OR_ANDCM:
    case IA64_OP_CMP_GT_OR_ANDCM:
    case IA64_OP_CMP_LE_OR_ANDCM:
    case IA64_OP_CMP_GE_OR_ANDCM:
    case IA64_OP_CMP_LT_OR_ANDCM:
    case IA64_OP_CMP_EQ_IMM:
    case IA64_OP_CMP_LT_IMM:
    case IA64_OP_CMP_EQ_AND_IMM:
    case IA64_OP_CMP_NE_AND_IMM:
    case IA64_OP_CMP_EQ_OR_IMM:
    case IA64_OP_CMP_NE_OR_IMM:
    case IA64_OP_CMP_EQ_OR_ANDCM_IMM:
    case IA64_OP_CMP_NE_OR_ANDCM_IMM:
    case IA64_OP_CMP4_EQ_AND:
    case IA64_OP_CMP4_NE_AND:
    case IA64_OP_CMP4_EQ_OR:
    case IA64_OP_CMP4_NE_OR:
    case IA64_OP_CMP4_EQ_OR_ANDCM:
    case IA64_OP_CMP4_NE_OR_ANDCM:
    case IA64_OP_CMP4_GT_AND:
    case IA64_OP_CMP4_LE_AND:
    case IA64_OP_CMP4_GE_AND:
    case IA64_OP_CMP4_LT_AND:
    case IA64_OP_CMP4_GT_OR:
    case IA64_OP_CMP4_LE_OR:
    case IA64_OP_CMP4_GE_OR:
    case IA64_OP_CMP4_LT_OR:
    case IA64_OP_CMP4_GT_OR_ANDCM:
    case IA64_OP_CMP4_LE_OR_ANDCM:
    case IA64_OP_CMP4_GE_OR_ANDCM:
    case IA64_OP_CMP4_LT_OR_ANDCM:
    case IA64_OP_CMP4_EQ_OR_ANDCM_IMM:
    case IA64_OP_CMP4_NE_OR_ANDCM_IMM:
    case IA64_OP_CMP4_EQ_AND_IMM:
    case IA64_OP_CMP4_NE_AND_IMM:
    case IA64_OP_CMP4_EQ_OR_IMM:
    case IA64_OP_CMP4_NE_OR_IMM:
    case IA64_OP_CMP_LTU_IMM:
    case IA64_OP_LD1:
    case IA64_OP_LD2:
    case IA64_OP_LD4:
    case IA64_OP_LD8:
    case IA64_OP_LD1S:
    case IA64_OP_LD2S:
    case IA64_OP_LD4S:
    case IA64_OP_LD8S:
    case IA64_OP_LD1A:
    case IA64_OP_LD2A:
    case IA64_OP_LD4A:
    case IA64_OP_LD8A:
    case IA64_OP_LD1SA:
    case IA64_OP_LD2SA:
    case IA64_OP_LD4SA:
    case IA64_OP_LD8SA:
    case IA64_OP_LD1FILL:
    case IA64_OP_LD2FILL:
    case IA64_OP_LD4FILL:
    case IA64_OP_LD8FILL:
    case IA64_OP_ST1:
    case IA64_OP_ST2:
    case IA64_OP_ST4:
    case IA64_OP_ST8:
    case IA64_OP_ST1REL:
    case IA64_OP_ST2REL:
    case IA64_OP_ST4REL:
    case IA64_OP_ST8REL:
    case IA64_OP_ST1SPILL:
    case IA64_OP_ST2SPILL:
    case IA64_OP_ST4SPILL:
    case IA64_OP_ST8SPILL:
    case IA64_OP_BR_COND:
    case IA64_OP_BR:
    case IA64_OP_BR_IA:
    case IA64_OP_BR_CLOOP:
    case IA64_OP_BR_CALL:
    case IA64_OP_BR_CALL_INDIRECT:
    case IA64_OP_BR_RET:
    case IA64_OP_PADD1:
    case IA64_OP_PADD2:
    case IA64_OP_PADD4:
    case IA64_OP_PSUB1:
    case IA64_OP_PSUB2:
    case IA64_OP_PSUB4:
    case IA64_OP_XCHG1:
    case IA64_OP_XCHG2:
    case IA64_OP_XCHG4:
    case IA64_OP_XCHG8:
    case IA64_OP_CMPXCHG1:
    case IA64_OP_CMPXCHG2:
    case IA64_OP_CMPXCHG4:
    case IA64_OP_CMPXCHG8:
    case IA64_OP_CMP8XCHG16:
    case IA64_OP_FETCHADD4:
    case IA64_OP_FETCHADD8:
    case IA64_OP_MOVL:
    case IA64_OP_MOV_BRGR:
    case IA64_OP_MOV_GRBR:
    case IA64_OP_MOV_PRGR:
    case IA64_OP_MOV_GRPR:
    case IA64_OP_MOV_PR_ROT_IMM:
    case IA64_OP_TBIT_Z:
    case IA64_OP_TBIT_NZ:
    case IA64_OP_TBIT_Z_OR_ANDCM:
    case IA64_OP_TBIT_NZ_OR_ANDCM:
    case IA64_OP_TNAT_Z:
    case IA64_OP_TNAT_NZ:
    case IA64_OP_TNAT_NZ_AND:
    case IA64_OP_TF_Z:
    case IA64_OP_TF_NZ:
    case IA64_OP_LD1C_CLR:
    case IA64_OP_LD2C_CLR:
    case IA64_OP_LD4C_CLR:
    case IA64_OP_LD8C_CLR:
    case IA64_OP_LD1C_NC:
    case IA64_OP_LD2C_NC:
    case IA64_OP_LD4C_NC:
    case IA64_OP_LD8C_NC:
    case IA64_OP_HINT_M:
    case IA64_OP_HINT_I:
    case IA64_OP_HINT_B:
    case IA64_OP_HINT_F:
    case IA64_OP_HINT_X:
    case IA64_OP_PTC_E:
    case IA64_OP_CLRRRB:
    case IA64_OP_CLRRRB_PR:
    case IA64_OP_LDFP8:
    case IA64_OP_LDFPD:
    case IA64_OP_LDFPS:
    case IA64_OP_FMERGE_S:
    case IA64_OP_FMERGE_SE:
    case IA64_OP_FMIN:
    case IA64_OP_FMAX:
    case IA64_OP_FAMIN:
    case IA64_OP_FAMAX:
    case IA64_OP_FRCPA:
    case IA64_OP_FPRCPA:
    case IA64_OP_FCHKFS:
    case IA64_OP_GETF_SIG:
    case IA64_OP_GETF_EXP:
    case IA64_OP_SETF_SIG:
    case IA64_OP_SETF_EXP:
    case IA64_OP_CMP4_EQ:
    case IA64_OP_CMP4_LT:
    case IA64_OP_CMP4_LE:
    case IA64_OP_CMP4_GT:
    case IA64_OP_CMP4_GE:
    case IA64_OP_CMP4_LTU:
    case IA64_OP_CMP4_LEU:
    case IA64_OP_CMP4_GTU:
    case IA64_OP_CMP4_GEU:
    case IA64_OP_CMP4_LT_IMM:
    case IA64_OP_CMP4_LTU_IMM:
        g_assert_not_reached();
    default:
        g_assert_not_reached();
    }
}

static void ia64_gen_native_integer_nat(const Ia64Instruction *insn)
{
    if (insn->r1 == 0) {
        return;
    }

    switch (insn->opcode) {
    case IA64_OP_ADDS:
    case IA64_OP_ADDL:
    case IA64_OP_SHL_IMM:
    case IA64_OP_SHRU_IMM:
    case IA64_OP_SHR_IMM:
    case IA64_OP_EXTRU:
    case IA64_OP_SXT1:
    case IA64_OP_SXT2:
    case IA64_OP_SXT4:
    case IA64_OP_ZXT1:
    case IA64_OP_ZXT2:
    case IA64_OP_ZXT4:
    case IA64_OP_DEP_IMM:
    case IA64_OP_EXTR:
    case IA64_OP_SUB_IMM:
    case IA64_OP_AND_IMM:
    case IA64_OP_ANDCM_IMM:
    case IA64_OP_OR_IMM:
    case IA64_OP_XOR_IMM:
    case IA64_OP_POPCNT:
    case IA64_OP_CLZ:
        ia64_gen_gr_nat_from_1(insn->r1, insn->r3);
        break;
    case IA64_OP_DEPZ:
        ia64_gen_gr_nat_from_1(insn->r1, insn->r2);
        break;
    case IA64_OP_DEPZ_IMM:
        ia64_gen_gr_nat_clear(insn->r1);
        break;
    case IA64_OP_SHLADD:
    case IA64_OP_ADD:
    case IA64_OP_ADD_ONE:
    case IA64_OP_SUB:
    case IA64_OP_SUB_ONE:
    case IA64_OP_AND:
    case IA64_OP_ANDCM:
    case IA64_OP_OR:
    case IA64_OP_XOR:
    case IA64_OP_SHL:
    case IA64_OP_SHRU:
    case IA64_OP_SHR:
    case IA64_OP_SHRP_IMM:
    case IA64_OP_DEP:
    case IA64_OP_SHLADDP4:
    case IA64_OP_MPY4:
    case IA64_OP_MPYSHL4:
    case IA64_OP_MPYSH:
    case IA64_OP_MPYUH:
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    case IA64_OP_MUX:
        ia64_gen_gr_nat_from_3(insn->r1, insn->r1, insn->r2, insn->r3);
        break;
    default:
        g_assert_not_reached();
    }
}

static bool ia64_gen_insn(DisasContext *ctx, const Ia64Instruction *insn)
{
    TCGLabel *skip;
    TCGv_i64 tmp;
    TCGv_i64 qp_value;
    const uint64_t next_ip = insn->address + 16;

    if (!insn->valid) {
        static unsigned invalid_logs;

        if (invalid_logs++ < 128) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "ia64 invalid insn ip=0x%016" PRIx64
                          " slot=%u unit=%u raw=0x%010" PRIx64 "\n",
                          insn->address, insn->slot, insn->unit,
                          insn->raw);
        }
        ia64_gen_raise_exception(IA64_EXCP_ILLEGAL, insn->address,
                                  insn->raw, insn->slot);
        return true;
    }

    qp_value = cpu_pr[insn->qp];
    if ((insn->compare_unc ||
         (insn->clear_p2_before_predicate && insn->qp == insn->p2)) &&
        insn->qp != 0) {
        TCGv_i64 saved_qp = tcg_temp_new_i64();

        tcg_gen_mov_i64(saved_qp, qp_value);
        qp_value = saved_qp;
    }
    if (insn->compare_unc && ia64_compare_has_equal_targets(insn)) {
        ia64_gen_raise_exception(IA64_EXCP_ILLEGAL, insn->address,
                                  insn->raw, insn->slot);
        return true;
    }
    if (insn->opcode == IA64_OP_ALLOC && insn->qp != 0) {
        ia64_gen_raise_exception(IA64_EXCP_ILLEGAL, insn->address,
                                  insn->raw, insn->slot);
        return true;
    }
    ia64_gen_clear_unc_compare_targets(insn);
    if (insn->clear_p2_before_predicate && insn->p2 != 0) {
        tcg_gen_movi_i64(cpu_pr[insn->p2], 0);
        tcg_gen_movi_i64(cpu_pr[0], 1);
    }
    skip = ia64_gen_predicate_skip(insn, qp_value);
    if (ia64_compare_has_equal_targets(insn)) {
        ia64_gen_raise_exception(IA64_EXCP_ILLEGAL, insn->address,
                                  insn->raw, insn->slot);
        if (skip == NULL) {
            return true;
        }
        ia64_gen_predicate_end(skip);
        return false;
    }

    switch (insn->opcode) {
    case IA64_OP_NOP:
    case IA64_OP_HINT_I:
    case IA64_OP_HINT_B:
    case IA64_OP_HINT_F:
    case IA64_OP_HINT_X:
        break;
    case IA64_OP_HINT_M:
        if (insn->hint_m_reg_increment && insn->r3 != 0) {
            tcg_gen_add_i64(cpu_gr[insn->r3], cpu_gr[insn->r3],
                            cpu_gr[insn->r2]);
        } else if (insn->imm != 0 && insn->r3 != 0) {
            tcg_gen_addi_i64(cpu_gr[insn->r3], cpu_gr[insn->r3], insn->imm);
        }
        break;
    case IA64_OP_CLRRRB:
    case IA64_OP_CLRRRB_PR:
        gen_helper_clrrrb_rse(tcg_env);
        if (skip == NULL) {
            ia64_gen_exit_to_completed(next_ip, insn->address);
            return true;
        }
        break;
    case IA64_OP_VMSW:
        gen_helper_vmsw(tcg_env, tcg_constant_i64(insn->imm));
        ia64_gen_exit_to_completed(next_ip, insn->address);
        if (skip == NULL) {
            return true;
        }
        break;
    case IA64_OP_RUM:
        gen_helper_rum(tcg_env, tcg_constant_i64(insn->imm));
        break;
    case IA64_OP_SUM_UM:
        gen_helper_sum_um(tcg_env, tcg_constant_i64(insn->imm));
        break;
    case IA64_OP_BRP:
        break;
    case IA64_OP_FSETC:
        gen_helper_fsetc(tcg_env, tcg_constant_i32(insn->p1),
                         tcg_constant_i32(insn->r2),
                         tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FCLRF:
        gen_helper_fclrf(tcg_env, tcg_constant_i32(insn->p1));
        break;
    case IA64_OP_FCHKF: {
        TCGv_i64 taken = tcg_temp_new_i64();
        gen_helper_fchkf(taken, tcg_env, tcg_constant_i32(insn->p1));
        ia64_gen_check_branch(taken, insn->address + insn->imm,
                              insn->address);
        break;
    }
    case IA64_OP_FCHKFS:
        gen_helper_fchkfs(tcg_env, tcg_constant_i32(insn->r1));
        break;
    case IA64_OP_BREAK:
        if ((insn->imm & 0x100000) &&
            ia64_is_pal_proc_break(ctx->env, insn->address)) {
            TCGv_i32 flags = tcg_temp_new_i32();
            TCGLabel *no_exit = gen_new_label();

            gen_helper_pal_dispatch(flags, tcg_env);
            tcg_gen_andi_i32(flags, flags,
                             IA64_PAL_DISPATCH_HALTED |
                             IA64_PAL_DISPATCH_EXIT_TB);
            tcg_gen_brcondi_i32(TCG_COND_EQ, flags, 0, no_exit);
            ia64_gen_exit_to_completed(next_ip, insn->address);
            gen_set_label(no_exit);
        } else {
            ia64_gen_raise_exception(IA64_EXCP_BREAK, insn->address,
                                      insn->imm, insn->slot);
            if (skip == NULL) {
                return true;
            }
        }
        break;
    case IA64_OP_ADDS:
    case IA64_OP_ADDL:
    case IA64_OP_SHLADD:
    case IA64_OP_ADD:
    case IA64_OP_ADD_ONE:
    case IA64_OP_SUB:
    case IA64_OP_SUB_ONE:
    case IA64_OP_AND:
    case IA64_OP_ANDCM:
    case IA64_OP_OR:
    case IA64_OP_XOR:
    case IA64_OP_SUB_IMM:
    case IA64_OP_AND_IMM:
    case IA64_OP_ANDCM_IMM:
    case IA64_OP_OR_IMM:
    case IA64_OP_XOR_IMM:
    case IA64_OP_SHL:
    case IA64_OP_SHRU:
    case IA64_OP_SHR:
    case IA64_OP_SHL_IMM:
    case IA64_OP_SHRU_IMM:
    case IA64_OP_SHR_IMM:
    case IA64_OP_DEPZ:
    case IA64_OP_DEPZ_IMM:
    case IA64_OP_EXTRU:
    case IA64_OP_SHRP_IMM:
    case IA64_OP_DEP:
    case IA64_OP_DEP_IMM:
    case IA64_OP_EXTR:
    case IA64_OP_SXT1:
    case IA64_OP_SXT2:
    case IA64_OP_SXT4:
    case IA64_OP_ZXT1:
    case IA64_OP_ZXT2:
    case IA64_OP_ZXT4:
    case IA64_OP_SHLADDP4:
    case IA64_OP_MPY4:
    case IA64_OP_MPYSHL4:
    case IA64_OP_MPYSH:
    case IA64_OP_MPYUH:
    case IA64_OP_MUX:
    case IA64_OP_POPCNT:
    case IA64_OP_CLZ:
        ia64_gen_native_integer_write(insn);
        ia64_gen_native_integer_nat(insn);
        break;
    case IA64_OP_CMP_EQ:
    case IA64_OP_CMP_LT:
    case IA64_OP_CMP_LE:
    case IA64_OP_CMP_GT:
    case IA64_OP_CMP_GE:
    case IA64_OP_CMP_LTU:
    case IA64_OP_CMP_LEU:
    case IA64_OP_CMP_GTU:
    case IA64_OP_CMP_GEU:
    case IA64_OP_CMP_NE:
    case IA64_OP_CMP_EQ_AND:
    case IA64_OP_CMP_NE_AND:
    case IA64_OP_CMP_GT_AND:
    case IA64_OP_CMP_LE_AND:
    case IA64_OP_CMP_GE_AND:
    case IA64_OP_CMP_LT_AND:
    case IA64_OP_CMP_EQ_OR:
    case IA64_OP_CMP_NE_OR:
    case IA64_OP_CMP_GT_OR:
    case IA64_OP_CMP_LE_OR:
    case IA64_OP_CMP_GE_OR:
    case IA64_OP_CMP_LT_OR:
    case IA64_OP_CMP_EQ_OR_ANDCM:
    case IA64_OP_CMP_NE_OR_ANDCM:
    case IA64_OP_CMP_GT_OR_ANDCM:
    case IA64_OP_CMP_LE_OR_ANDCM:
    case IA64_OP_CMP_GE_OR_ANDCM:
    case IA64_OP_CMP_LT_OR_ANDCM:
    case IA64_OP_CMP_EQ_IMM:
    case IA64_OP_CMP_LT_IMM:
    case IA64_OP_CMP_EQ_AND_IMM:
    case IA64_OP_CMP_NE_AND_IMM:
    case IA64_OP_CMP_EQ_OR_IMM:
    case IA64_OP_CMP_NE_OR_IMM:
    case IA64_OP_CMP_EQ_OR_ANDCM_IMM:
    case IA64_OP_CMP_NE_OR_ANDCM_IMM:
    case IA64_OP_CMP4_EQ_AND:
    case IA64_OP_CMP4_NE_AND:
    case IA64_OP_CMP4_EQ_OR:
    case IA64_OP_CMP4_NE_OR:
    case IA64_OP_CMP4_EQ_OR_ANDCM:
    case IA64_OP_CMP4_NE_OR_ANDCM:
    case IA64_OP_CMP4_GT_AND:
    case IA64_OP_CMP4_LE_AND:
    case IA64_OP_CMP4_GE_AND:
    case IA64_OP_CMP4_LT_AND:
    case IA64_OP_CMP4_GT_OR:
    case IA64_OP_CMP4_LE_OR:
    case IA64_OP_CMP4_GE_OR:
    case IA64_OP_CMP4_LT_OR:
    case IA64_OP_CMP4_GT_OR_ANDCM:
    case IA64_OP_CMP4_LE_OR_ANDCM:
    case IA64_OP_CMP4_GE_OR_ANDCM:
    case IA64_OP_CMP4_LT_OR_ANDCM:
    case IA64_OP_CMP4_EQ_OR_ANDCM_IMM:
    case IA64_OP_CMP4_NE_OR_ANDCM_IMM:
    case IA64_OP_CMP_LTU_IMM:
    case IA64_OP_CMP4_EQ:
    case IA64_OP_CMP4_LT:
    case IA64_OP_CMP4_LE:
    case IA64_OP_CMP4_GT:
    case IA64_OP_CMP4_GE:
    case IA64_OP_CMP4_LTU:
    case IA64_OP_CMP4_LEU:
    case IA64_OP_CMP4_GTU:
    case IA64_OP_CMP4_GEU:
    case IA64_OP_CMP4_EQ_IMM:
    case IA64_OP_CMP4_LT_IMM:
    case IA64_OP_CMP4_LTU_IMM:
    case IA64_OP_CMP4_EQ_AND_IMM:
    case IA64_OP_CMP4_NE_AND_IMM:
    case IA64_OP_CMP4_EQ_OR_IMM:
    case IA64_OP_CMP4_NE_OR_IMM: {
        TCGCond cond;
        bool is_cmp4 = false;
        bool is_cmp_imm = false;
        bool is_signed_cmp4 = false;
        bool is_and = false;
        bool is_or = false;
        bool is_or_andcm = false;
        switch (insn->opcode) {
        case IA64_OP_CMP_EQ:
            cond = TCG_COND_EQ;
            break;
        case IA64_OP_CMP_LT:
            cond = TCG_COND_LT;
            break;
        case IA64_OP_CMP_LE:
            cond = TCG_COND_LE;
            break;
        case IA64_OP_CMP_GT:
            cond = TCG_COND_GT;
            break;
        case IA64_OP_CMP_GE:
            cond = TCG_COND_GE;
            break;
        case IA64_OP_CMP_LTU:
            cond = TCG_COND_LTU;
            break;
        case IA64_OP_CMP_LEU:
            cond = TCG_COND_LEU;
            break;
        case IA64_OP_CMP_GTU:
            cond = TCG_COND_GTU;
            break;
        case IA64_OP_CMP_GEU:
            cond = TCG_COND_GEU;
            break;
        case IA64_OP_CMP_NE:
            cond = TCG_COND_NE;
            break;
        case IA64_OP_CMP_EQ_AND:
            cond = TCG_COND_EQ;
            is_and = true;
            break;
        case IA64_OP_CMP_NE_AND:
            cond = TCG_COND_NE;
            is_and = true;
            break;
        case IA64_OP_CMP_GT_AND:
            cond = TCG_COND_GT;
            is_and = true;
            break;
        case IA64_OP_CMP_LE_AND:
            cond = TCG_COND_LE;
            is_and = true;
            break;
        case IA64_OP_CMP_GE_AND:
            cond = TCG_COND_GE;
            is_and = true;
            break;
        case IA64_OP_CMP_LT_AND:
            cond = TCG_COND_LT;
            is_and = true;
            break;
        case IA64_OP_CMP_EQ_OR:
            cond = TCG_COND_EQ;
            is_or = true;
            break;
        case IA64_OP_CMP_NE_OR:
            cond = TCG_COND_NE;
            is_or = true;
            break;
        case IA64_OP_CMP_GT_OR:
            cond = TCG_COND_GT;
            is_or = true;
            break;
        case IA64_OP_CMP_LE_OR:
            cond = TCG_COND_LE;
            is_or = true;
            break;
        case IA64_OP_CMP_GE_OR:
            cond = TCG_COND_GE;
            is_or = true;
            break;
        case IA64_OP_CMP_LT_OR:
            cond = TCG_COND_LT;
            is_or = true;
            break;
        case IA64_OP_CMP_EQ_OR_ANDCM:
            cond = TCG_COND_EQ;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP_NE_OR_ANDCM:
            cond = TCG_COND_NE;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP_GT_OR_ANDCM:
            cond = TCG_COND_GT;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP_LE_OR_ANDCM:
            cond = TCG_COND_LE;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP_GE_OR_ANDCM:
            cond = TCG_COND_GE;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP_LT_OR_ANDCM:
            cond = TCG_COND_LT;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP_EQ_IMM:
            cond = TCG_COND_EQ;
            is_cmp_imm = true;
            break;
        case IA64_OP_CMP_LT_IMM:
            cond = TCG_COND_LT;
            is_cmp_imm = true;
            break;
        case IA64_OP_CMP_EQ_AND_IMM:
            cond = TCG_COND_EQ;
            is_cmp_imm = true;
            is_and = true;
            break;
        case IA64_OP_CMP_NE_AND_IMM:
            cond = TCG_COND_NE;
            is_cmp_imm = true;
            is_and = true;
            break;
        case IA64_OP_CMP_EQ_OR_IMM:
            cond = TCG_COND_EQ;
            is_cmp_imm = true;
            is_or = true;
            break;
        case IA64_OP_CMP_NE_OR_IMM:
            cond = TCG_COND_NE;
            is_cmp_imm = true;
            is_or = true;
            break;
        case IA64_OP_CMP_EQ_OR_ANDCM_IMM:
            cond = TCG_COND_EQ;
            is_cmp_imm = true;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP_NE_OR_ANDCM_IMM:
            cond = TCG_COND_NE;
            is_cmp_imm = true;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP4_EQ_AND:
            cond = TCG_COND_EQ;
            is_cmp4 = true;
            is_and = true;
            break;
        case IA64_OP_CMP4_NE_AND:
            cond = TCG_COND_NE;
            is_cmp4 = true;
            is_and = true;
            break;
        case IA64_OP_CMP4_EQ_OR:
            cond = TCG_COND_EQ;
            is_cmp4 = true;
            is_or = true;
            break;
        case IA64_OP_CMP4_NE_OR:
            cond = TCG_COND_NE;
            is_cmp4 = true;
            is_or = true;
            break;
        case IA64_OP_CMP4_EQ_OR_ANDCM:
            cond = TCG_COND_EQ;
            is_cmp4 = true;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP4_NE_OR_ANDCM:
            cond = TCG_COND_NE;
            is_cmp4 = true;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP4_GT_AND:
            cond = TCG_COND_GT;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_and = true;
            break;
        case IA64_OP_CMP4_LE_AND:
            cond = TCG_COND_LE;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_and = true;
            break;
        case IA64_OP_CMP4_GE_AND:
            cond = TCG_COND_GE;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_and = true;
            break;
        case IA64_OP_CMP4_LT_AND:
            cond = TCG_COND_LT;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_and = true;
            break;
        case IA64_OP_CMP4_GT_OR:
            cond = TCG_COND_GT;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_or = true;
            break;
        case IA64_OP_CMP4_LE_OR:
            cond = TCG_COND_LE;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_or = true;
            break;
        case IA64_OP_CMP4_GE_OR:
            cond = TCG_COND_GE;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_or = true;
            break;
        case IA64_OP_CMP4_LT_OR:
            cond = TCG_COND_LT;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_or = true;
            break;
        case IA64_OP_CMP4_GT_OR_ANDCM:
            cond = TCG_COND_GT;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP4_LE_OR_ANDCM:
            cond = TCG_COND_LE;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP4_GE_OR_ANDCM:
            cond = TCG_COND_GE;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP4_LT_OR_ANDCM:
            cond = TCG_COND_LT;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP4_EQ_OR_ANDCM_IMM:
            cond = TCG_COND_EQ;
            is_cmp4 = true;
            is_cmp_imm = true;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP4_NE_OR_ANDCM_IMM:
            cond = TCG_COND_NE;
            is_cmp4 = true;
            is_cmp_imm = true;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP_LTU_IMM:
            cond = TCG_COND_LTU;
            is_cmp_imm = true;
            break;
        case IA64_OP_CMP4_EQ:
            cond = TCG_COND_EQ;
            is_cmp4 = true;
            break;
        case IA64_OP_CMP4_LT:
            cond = TCG_COND_LT;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            break;
        case IA64_OP_CMP4_LE:
            cond = TCG_COND_LE;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            break;
        case IA64_OP_CMP4_GT:
            cond = TCG_COND_GT;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            break;
        case IA64_OP_CMP4_GE:
            cond = TCG_COND_GE;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            break;
        case IA64_OP_CMP4_LTU:
            cond = TCG_COND_LTU;
            is_cmp4 = true;
            break;
        case IA64_OP_CMP4_LEU:
            cond = TCG_COND_LEU;
            is_cmp4 = true;
            break;
        case IA64_OP_CMP4_GTU:
            cond = TCG_COND_GTU;
            is_cmp4 = true;
            break;
        case IA64_OP_CMP4_GEU:
            cond = TCG_COND_GEU;
            is_cmp4 = true;
            break;
        case IA64_OP_CMP4_EQ_IMM:
            cond = TCG_COND_EQ;
            is_cmp4 = true;
            is_cmp_imm = true;
            break;
        case IA64_OP_CMP4_LT_IMM:
            cond = TCG_COND_LT;
            is_cmp4 = true;
            is_cmp_imm = true;
            is_signed_cmp4 = true;
            break;
        case IA64_OP_CMP4_LTU_IMM:
            cond = TCG_COND_LTU;
            is_cmp4 = true;
            is_cmp_imm = true;
            break;
        case IA64_OP_CMP4_EQ_AND_IMM:
            cond = TCG_COND_EQ;
            is_cmp4 = true;
            is_cmp_imm = true;
            is_and = true;
            break;
        case IA64_OP_CMP4_NE_AND_IMM:
            cond = TCG_COND_NE;
            is_cmp4 = true;
            is_cmp_imm = true;
            is_and = true;
            break;
        case IA64_OP_CMP4_EQ_OR_IMM:
            cond = TCG_COND_EQ;
            is_cmp4 = true;
            is_cmp_imm = true;
            is_or = true;
            break;
        case IA64_OP_CMP4_NE_OR_IMM:
            cond = TCG_COND_NE;
            is_cmp4 = true;
            is_cmp_imm = true;
            is_or = true;
            break;
        default:
            cond = TCG_COND_EQ;
            break;
        }
        TCGv_i64 src2 = is_cmp_imm ? tcg_constant_i64(insn->imm)
                                   : ia64_gr_src(insn->r2);
        TCGv_i64 src3 = ia64_gr_src(insn->r3);
        TCGv_i64 src_nat = ia64_gen_gr_nat_read(insn->r3);
        TCGLabel *cmp_done = gen_new_label();

        if (!is_cmp_imm) {
            TCGv_i64 r2_nat = ia64_gen_gr_nat_read(insn->r2);
            tcg_gen_or_i64(src_nat, src_nat, r2_nat);
        }
        if (is_or || is_or_andcm) {
            tcg_gen_brcondi_i64(TCG_COND_NE, src_nat, 0, cmp_done);
        } else {
            TCGLabel *no_nat = gen_new_label();

            tcg_gen_brcondi_i64(TCG_COND_EQ, src_nat, 0, no_nat);
            if (insn->p1 != 0) {
                tcg_gen_movi_i64(cpu_pr[insn->p1], 0);
            }
            if (insn->p2 != 0) {
                tcg_gen_movi_i64(cpu_pr[insn->p2], 0);
            }
            tcg_gen_movi_i64(cpu_pr[0], 1);
            tcg_gen_br(cmp_done);
            gen_set_label(no_nat);
        }
        if (is_cmp4) {
            TCGv_i64 tmp_a = tcg_temp_new_i64();
            TCGv_i64 tmp_b = tcg_temp_new_i64();
            if (is_signed_cmp4) {
                tcg_gen_ext32s_i64(tmp_a, src2);
                tcg_gen_ext32s_i64(tmp_b, src3);
            } else {
                tcg_gen_ext32u_i64(tmp_a, src2);
                tcg_gen_ext32u_i64(tmp_b, src3);
            }
            src2 = tmp_a;
            src3 = tmp_b;
        }
        tmp = tcg_temp_new_i64();
        tcg_gen_setcond_i64(cond, tmp, src2, src3);
        if (is_and) {
            if (insn->p1 != 0) {
                tcg_gen_and_i64(cpu_pr[insn->p1], cpu_pr[insn->p1], tmp);
            }
            if (insn->p2 != 0) {
                TCGv_i64 not_tmp = tcg_temp_new_i64();
                tcg_gen_xori_i64(not_tmp, tmp, 1);
                tcg_gen_and_i64(cpu_pr[insn->p2], cpu_pr[insn->p2], not_tmp);
            }
        } else if (is_or) {
            if (insn->p1 != 0) {
                tcg_gen_or_i64(cpu_pr[insn->p1], cpu_pr[insn->p1], tmp);
            }
            if (insn->p2 != 0) {
                TCGv_i64 not_tmp = tcg_temp_new_i64();
                tcg_gen_xori_i64(not_tmp, tmp, 1);
                tcg_gen_or_i64(cpu_pr[insn->p2], cpu_pr[insn->p2], not_tmp);
            }
        } else if (is_or_andcm) {
            if (insn->p1 != 0) {
                tcg_gen_or_i64(cpu_pr[insn->p1], cpu_pr[insn->p1], tmp);
            }
            if (insn->p2 != 0) {
                TCGv_i64 not_tmp = tcg_temp_new_i64();
                tcg_gen_xori_i64(not_tmp, tmp, 1);
                tcg_gen_and_i64(cpu_pr[insn->p2], cpu_pr[insn->p2], not_tmp);
            }
        } else {
            if (insn->p1 != 0) {
                tcg_gen_mov_i64(cpu_pr[insn->p1], tmp);
            }
            if (insn->p2 != 0) {
                tcg_gen_xori_i64(cpu_pr[insn->p2], tmp, 1);
            }
        }
        tcg_gen_movi_i64(cpu_pr[0], 1);
        gen_set_label(cmp_done);
        break;
    }
    case IA64_OP_TBIT_Z:
    case IA64_OP_TBIT_NZ:
    case IA64_OP_TBIT_Z_OR_ANDCM:
    case IA64_OP_TBIT_NZ_OR_ANDCM: {
        const bool is_nz = insn->opcode == IA64_OP_TBIT_NZ ||
                           insn->opcode == IA64_OP_TBIT_NZ_OR_ANDCM;
        const bool old_or_andcm =
            insn->opcode == IA64_OP_TBIT_Z_OR_ANDCM ||
            insn->opcode == IA64_OP_TBIT_NZ_OR_ANDCM;
        TCGv_i64 bit = tcg_temp_new_i64();
        TCGv_i64 cond = tcg_temp_new_i64();
        TCGv_i64 not_cond = tcg_temp_new_i64();
        TCGv_i64 src_nat = ia64_gen_gr_nat_read(insn->r3);
        TCGLabel *tbit_done = gen_new_label();
        Ia64Instruction pred_insn = *insn;

        if (old_or_andcm) {
            pred_insn.pred_update = IA64_PRED_UPDATE_OR_ANDCM;
        }
        if (pred_insn.pred_update == IA64_PRED_UPDATE_OR ||
            pred_insn.pred_update == IA64_PRED_UPDATE_OR_ANDCM) {
            tcg_gen_brcondi_i64(TCG_COND_NE, src_nat, 0, tbit_done);
        } else {
            TCGLabel *no_nat = gen_new_label();

            tcg_gen_brcondi_i64(TCG_COND_EQ, src_nat, 0, no_nat);
            if (insn->p1 != 0) {
                tcg_gen_movi_i64(cpu_pr[insn->p1], 0);
            }
            if (insn->p2 != 0) {
                tcg_gen_movi_i64(cpu_pr[insn->p2], 0);
            }
            tcg_gen_movi_i64(cpu_pr[0], 1);
            tcg_gen_br(tbit_done);
            gen_set_label(no_nat);
        }

        tcg_gen_mov_i64(bit, ia64_gr_src(insn->r3));
        tcg_gen_shri_i64(bit, bit, insn->imm & 0x3f);
        tcg_gen_andi_i64(bit, bit, 1);
        if (is_nz) {
            tcg_gen_mov_i64(cond, bit);
        } else {
            tcg_gen_xori_i64(cond, bit, 1);
        }
        tcg_gen_xori_i64(not_cond, cond, 1);
        ia64_gen_predicate_test_write(&pred_insn, cond, not_cond);
        tcg_gen_movi_i64(cpu_pr[0], 1);
        gen_set_label(tbit_done);
        break;
    }
    case IA64_OP_TNAT_Z:
    case IA64_OP_TNAT_NZ:
    case IA64_OP_TNAT_NZ_AND: {
        const bool is_nz = insn->opcode == IA64_OP_TNAT_NZ ||
                           insn->opcode == IA64_OP_TNAT_NZ_AND;
        TCGv_i64 natbit = ia64_gen_gr_nat_read(insn->r3);
        TCGv_i64 cond = tcg_temp_new_i64();
        TCGv_i64 not_cond = tcg_temp_new_i64();
        Ia64Instruction pred_insn = *insn;

        if (is_nz) {
            tcg_gen_mov_i64(cond, natbit);
        } else {
            tcg_gen_xori_i64(cond, natbit, 1);
        }
        tcg_gen_xori_i64(not_cond, cond, 1);

        if (insn->opcode == IA64_OP_TNAT_NZ_AND) {
            pred_insn.pred_update = IA64_PRED_UPDATE_AND;
        }
        ia64_gen_predicate_test_write(&pred_insn, cond, not_cond);
        tcg_gen_movi_i64(cpu_pr[0], 1);
        break;
    }
    case IA64_OP_TF_Z:
    case IA64_OP_TF_NZ: {
        const bool is_nz = insn->opcode == IA64_OP_TF_NZ;
        TCGv_i64 features = tcg_temp_new_i64();
        TCGv_i64 cond = tcg_temp_new_i64();
        TCGv_i64 not_cond = tcg_temp_new_i64();

        gen_helper_read_cpuid(features, tcg_env, tcg_constant_i64(4));
        tcg_gen_shri_i64(features, features, insn->imm);
        tcg_gen_andi_i64(features, features, 1);
        if (is_nz) {
            tcg_gen_mov_i64(cond, features);
        } else {
            tcg_gen_xori_i64(cond, features, 1);
        }
        tcg_gen_xori_i64(not_cond, cond, 1);
        ia64_gen_predicate_test_write(insn, cond, not_cond);
        tcg_gen_movi_i64(cpu_pr[0], 1);
        break;
    }
    case IA64_OP_LD1:
    case IA64_OP_LD2:
    case IA64_OP_LD4:
    case IA64_OP_LD8:
        {
            TCGv_i64 addr = tcg_temp_new_i64();
            TCGv_i64 increment = NULL;
            TCGv_i64 base_nat = NULL;
            TCGv_i64 increment_nat = NULL;

            tcg_gen_mov_i64(addr, ia64_gr_src(insn->r3));
            ia64_gen_load_reg_base_update_inputs(insn, &increment, &base_nat,
                                                 &increment_nat);
            if (insn->r1 != 0) {
                MemOp mop = ia64_memop_for_opcode(insn->opcode);

                ia64_gen_check_nat_non_access(insn, insn->r3, false);
                ia64_gen_check_alignment(insn, addr, ia64_memop_size(mop),
                                         false, false);
                tcg_gen_qemu_ld_i64(cpu_gr[insn->r1], addr,
                                     ctx->mmu_idx, mop);
                ia64_gen_gr_nat_clear(insn->r1);
                ia64_gen_memory_acquire(insn);
            }
            if (insn->reg_base_update && insn->r3 != 0) {
                ia64_gen_load_reg_base_update(insn, addr, increment,
                                              base_nat, increment_nat);
            } else if (insn->imm != 0 && insn->r3 != 0) {
                tcg_gen_addi_i64(cpu_gr[insn->r3], addr, insn->imm);
            }
        }
        break;
    case IA64_OP_LD1S:
    case IA64_OP_LD2S:
    case IA64_OP_LD4S:
    case IA64_OP_LD8S:
        ia64_gen_speculative_load(ctx, insn, false);
        break;
    case IA64_OP_LD1A:
    case IA64_OP_LD2A:
    case IA64_OP_LD4A:
    case IA64_OP_LD8A:
        {
            TCGv_i64 addr = tcg_temp_new_i64();
            TCGv_i64 increment = NULL;
            TCGv_i64 base_nat = NULL;
            TCGv_i64 increment_nat = NULL;

            tcg_gen_mov_i64(addr, ia64_gr_src(insn->r3));
            ia64_gen_load_reg_base_update_inputs(insn, &increment, &base_nat,
                                                 &increment_nat);
            if (insn->r1 != 0) {
                MemOp mop = ia64_memop_for_opcode(insn->opcode);

                ia64_gen_check_nat_non_access(insn, insn->r3, false);
                ia64_gen_check_alignment(insn, addr, ia64_memop_size(mop),
                                         false, false);
                tcg_gen_qemu_ld_i64(cpu_gr[insn->r1], addr,
                                     ctx->mmu_idx, mop);
                ia64_gen_gr_nat_clear(insn->r1);
                gen_helper_set_alat(tcg_env, tcg_constant_i32(insn->r1),
                                    addr,
                                    tcg_constant_i32(ia64_memop_size(mop)));
            }
            if (insn->reg_base_update && insn->r3 != 0) {
                ia64_gen_load_reg_base_update(insn, addr, increment,
                                              base_nat, increment_nat);
            } else if (insn->imm != 0 && insn->r3 != 0) {
                tcg_gen_addi_i64(cpu_gr[insn->r3], addr, insn->imm);
            }
        }
        break;
    case IA64_OP_LD1SA:
    case IA64_OP_LD2SA:
    case IA64_OP_LD4SA:
    case IA64_OP_LD8SA:
        ia64_gen_speculative_load(ctx, insn, true);
        break;
    case IA64_OP_LD1FILL:
    case IA64_OP_LD2FILL:
    case IA64_OP_LD4FILL:
    case IA64_OP_LD8FILL:
        {
            TCGv_i64 addr = tcg_temp_new_i64();
            TCGv_i64 increment = NULL;
            TCGv_i64 base_nat = NULL;
            TCGv_i64 increment_nat = NULL;

            tcg_gen_mov_i64(addr, ia64_gr_src(insn->r3));
            ia64_gen_load_reg_base_update_inputs(insn, &increment, &base_nat,
                                                 &increment_nat);
            if (insn->r1 != 0) {
                MemOp mop = ia64_memop_for_opcode(insn->opcode);

                ia64_gen_check_nat_non_access(insn, insn->r3, false);
                ia64_gen_check_alignment(insn, addr, ia64_memop_size(mop),
                                         false, false);
                tcg_gen_qemu_ld_i64(cpu_gr[insn->r1], addr,
                                     ctx->mmu_idx, mop);
                ia64_gen_ld_fill_nat(insn->r1, addr);
                ia64_gen_memory_acquire(insn);
            }
            if (insn->reg_base_update && insn->r3 != 0) {
                ia64_gen_load_reg_base_update(insn, addr, increment,
                                              base_nat, increment_nat);
            } else if (insn->imm != 0 && insn->r3 != 0) {
                tcg_gen_addi_i64(cpu_gr[insn->r3], addr, insn->imm);
            }
        }
        break;
    case IA64_OP_LD1C_CLR:
    case IA64_OP_LD2C_CLR:
    case IA64_OP_LD4C_CLR:
    case IA64_OP_LD8C_CLR:
    case IA64_OP_LD1C_NC:
    case IA64_OP_LD2C_NC:
    case IA64_OP_LD4C_NC:
    case IA64_OP_LD8C_NC: {
        TCGv_i64 addr = tcg_temp_new_i64();
        TCGv_i64 increment = NULL;
        TCGv_i64 base_nat = NULL;
        TCGv_i64 increment_nat = NULL;

        tcg_gen_mov_i64(addr, ia64_gr_src(insn->r3));
        ia64_gen_load_reg_base_update_inputs(insn, &increment, &base_nat,
                                             &increment_nat);
        if (insn->r1 != 0) {
            MemOp mop = ia64_memop_for_opcode(insn->opcode);
            const bool clear = insn->opcode >= IA64_OP_LD1C_CLR &&
                               insn->opcode <= IA64_OP_LD8C_CLR;
            TCGv_i64 hit = tcg_temp_new_i64();
            TCGLabel *l_done = gen_new_label();

            gen_helper_check_load_alat_addr(hit, tcg_env,
                                            tcg_constant_i32(insn->r1),
                                            addr,
                                            tcg_constant_i32(
                                                ia64_memop_size(mop)),
                                            tcg_constant_i32(clear));
            tcg_gen_brcondi_i64(TCG_COND_NE, hit, 0, l_done);

            ia64_gen_check_nat_non_access(insn, insn->r3, false);
            ia64_gen_check_alignment(insn, addr, ia64_memop_size(mop),
                                     false, false);
            tcg_gen_qemu_ld_i64(cpu_gr[insn->r1], addr, ctx->mmu_idx, mop);
            ia64_gen_gr_nat_clear(insn->r1);
            ia64_gen_memory_acquire(insn);
            if (!clear) {
                gen_helper_set_alat(tcg_env, tcg_constant_i32(insn->r1),
                                    addr,
                                    tcg_constant_i32(ia64_memop_size(mop)));
            }

            gen_set_label(l_done);
        }
        if (insn->reg_base_update && insn->r3 != 0) {
            ia64_gen_load_reg_base_update(insn, addr, increment, base_nat,
                                          increment_nat);
        } else if (insn->imm != 0 && insn->r3 != 0) {
            tcg_gen_addi_i64(cpu_gr[insn->r3], addr, insn->imm);
        }
        break;
    }
    case IA64_OP_LD16:
        {
            TCGv_i64 high_addr = tcg_temp_new_i64();
            TCGv_i64 high = tcg_temp_new_i64();
            TCGv_i64 low = insn->r1 != 0 ? cpu_gr[insn->r1] :
                           tcg_temp_new_i64();

            ia64_gen_check_nat_non_access(insn, insn->r3, false);
            ia64_gen_check_alignment(insn, ia64_gr_src(insn->r3), 16, false,
                                     false);
            tcg_gen_qemu_ld_i64(low, ia64_gr_src(insn->r3),
                                ctx->mmu_idx, MO_LEUQ);
            tcg_gen_addi_i64(high_addr, ia64_gr_src(insn->r3), 8);
            tcg_gen_qemu_ld_i64(high, high_addr, ctx->mmu_idx, MO_LEUQ);
            ia64_gen_memory_acquire(insn);
            if (insn->r1 != 0) {
                ia64_gen_gr_nat_clear(insn->r1);
            }
            gen_helper_write_ar(tcg_env, tcg_constant_i32(25), high);
        }
        break;
    case IA64_OP_ST16:
        {
            TCGv_i64 high_addr = tcg_temp_new_i64();
            TCGv_i64 high = tcg_temp_new_i64();

            ia64_gen_check_nat_non_access(insn, insn->r3, true);
            ia64_gen_check_nat_access(insn, insn->r2, true);
            ia64_gen_check_alignment(insn, ia64_gr_src(insn->r3), 16, false,
                                     true);
            ia64_gen_memory_release(insn);
            tcg_gen_qemu_st_i64(ia64_gr_src(insn->r2),
                                ia64_gr_src(insn->r3), ctx->mmu_idx,
                                MO_LEUQ);
            tcg_gen_addi_i64(high_addr, ia64_gr_src(insn->r3), 8);
            gen_helper_read_ar(high, tcg_env, tcg_constant_i32(25));
            tcg_gen_qemu_st_i64(high, high_addr, ctx->mmu_idx, MO_LEUQ);
            gen_helper_invalidate_alat_store(tcg_env, ia64_gr_src(insn->r3),
                                             tcg_constant_i32(16));
        }
        break;
    case IA64_OP_ST1:
    case IA64_OP_ST2:
    case IA64_OP_ST4:
    case IA64_OP_ST8:
    case IA64_OP_ST1REL:
    case IA64_OP_ST2REL:
    case IA64_OP_ST4REL:
    case IA64_OP_ST8REL:
    case IA64_OP_ST1SPILL:
    case IA64_OP_ST2SPILL:
    case IA64_OP_ST4SPILL:
    case IA64_OP_ST8SPILL: {
        MemOp mop = ia64_memop_for_opcode(insn->opcode);
        bool spill = insn->opcode >= IA64_OP_ST1SPILL &&
                     insn->opcode <= IA64_OP_ST8SPILL;
        TCGv_i64 addr = tcg_temp_new_i64();
        TCGv_i64 value = tcg_temp_new_i64();

        ia64_gen_check_nat_non_access(insn, insn->r3, true);
        if (!spill) {
            ia64_gen_check_nat_access(insn, insn->r2, true);
        }
        tcg_gen_mov_i64(addr, ia64_gr_src(insn->r3));
        tcg_gen_mov_i64(value, ia64_gr_src(insn->r2));
        ia64_gen_check_alignment(insn, addr, ia64_memop_size(mop),
                                 false, true);
        ia64_gen_memory_release(insn);
        tcg_gen_qemu_st_i64(value, addr, ctx->mmu_idx, mop);
        gen_helper_invalidate_alat_store(tcg_env, addr,
                                         tcg_constant_i32(ia64_memop_size(mop)));
        if (insn->opcode == IA64_OP_ST8SPILL) {
            gen_helper_st_spill_unat(tcg_env, tcg_constant_i32(insn->r2),
                                     addr);
        }
        if (insn->imm != 0 && insn->r3 != 0) {
            tcg_gen_addi_i64(cpu_gr[insn->r3], addr, insn->imm);
        }
        break;
    }
    case IA64_OP_MOVL:
        if (insn->r1 != 0) {
            tcg_gen_movi_i64(cpu_gr[insn->r1], insn->imm);
            ia64_gen_gr_nat_clear(insn->r1);
        }
        break;
    case IA64_OP_ADDP4:
        if (insn->r1 != 0) {
            ia64_gen_addp4_result(cpu_gr[insn->r1], ia64_gr_src(insn->r2),
                                  ia64_gr_src(insn->r3));
            ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        }
        break;
    case IA64_OP_ADDP4_IMM:
        if (insn->r1 != 0) {
            TCGv_i64 imm = tcg_constant_i64(insn->imm);
            ia64_gen_addp4_result(cpu_gr[insn->r1], imm,
                                  ia64_gr_src(insn->r3));
            ia64_gen_gr_nat_from_1(insn->r1, insn->r3);
        }
        break;
    case IA64_OP_MOV_BRGR:
        ia64_gen_gr_write_nat_clear(insn->r1, cpu_br[insn->r2 & 7]);
        break;
    case IA64_OP_MOV_GRBR:
        tcg_gen_mov_i64(cpu_br[insn->r2 & 7],
                        ia64_gr_src(insn->r1));
        break;
    case IA64_OP_MOV_PRGR:
        if (insn->r1 != 0) {
            TCGv_i64 packed = tcg_temp_new_i64();

            gen_helper_read_pr(packed, tcg_env);
            ia64_gen_gr_write_nat_clear(insn->r1, packed);
        }
        break;
    case IA64_OP_MOV_GRPR:
        gen_helper_write_pr(tcg_env, ia64_gr_src(insn->r1),
                            tcg_constant_i64(insn->imm));
        break;
    case IA64_OP_MOV_PR_ROT_IMM:
        gen_helper_write_pr(tcg_env, tcg_constant_i64(insn->imm),
                            tcg_constant_i64(0xffffffffffff0000ULL));
        break;
    case IA64_OP_MOV_ARGR:
        if (insn->r1 != 0) {
            TCGv_i64 val = tcg_temp_new_i64();
            gen_helper_read_ar(val, tcg_env, tcg_constant_i32(insn->r2));
            ia64_gen_gr_write_nat_clear(insn->r1, val);
        }
        break;
    case IA64_OP_MOV_GRAR:
        gen_helper_write_ar(tcg_env, tcg_constant_i32(insn->r2),
                            ia64_gr_src(insn->r1));
        break;
    case IA64_OP_MOV_IMMAR:
        gen_helper_write_ar(tcg_env, tcg_constant_i32(insn->r2),
                            tcg_constant_i64(insn->imm));
        break;
    case IA64_OP_MOV_CRGR:
        if (insn->r1 != 0) {
            TCGv_i64 val = tcg_temp_new_i64();
            gen_helper_read_cr(val, tcg_env, tcg_constant_i32(insn->r2));
            ia64_gen_gr_write_nat_clear(insn->r1, val);
        }
        break;
    case IA64_OP_MOV_GRCR:
        gen_helper_write_cr(tcg_env, tcg_constant_i32(insn->r2),
                            ia64_gr_src(insn->r1));
        break;
    case IA64_OP_MOV_RRGR: {
        TCGv_i64 val = tcg_temp_new_i64();
        gen_helper_mov_rrgr_read(val, tcg_env, ia64_gr_src(insn->r2));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRRR:
        gen_helper_mov_grrr_write(tcg_env, ia64_gr_src(insn->r2),
                                  ia64_gr_src(insn->r1));
        break;
    case IA64_OP_MOV_PKRGR: {
        TCGv_i64 val = tcg_temp_new_i64();
        gen_helper_mov_pkrgr_read(val, tcg_env, tcg_constant_i32(insn->r2));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_PKRGR_INDEXED: {
        TCGv_i64 val = tcg_temp_new_i64();
        gen_helper_mov_pkrgr_indexed_read(val, tcg_env, ia64_gr_src(insn->r3));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRPKR:
        gen_helper_mov_grpkr_write(tcg_env, tcg_constant_i32(insn->r2),
                                   ia64_gr_src(insn->r1));
        break;
    case IA64_OP_MOV_GRPKR_INDEXED:
        gen_helper_mov_grpkr_indexed_write(tcg_env, ia64_gr_src(insn->r3),
                                           ia64_gr_src(insn->r1));
        break;
    case IA64_OP_MOV_UMGR: {
        TCGv_i64 val = tcg_temp_new_i64();
        tcg_gen_andi_i64(val, cpu_psr, IA64_PSR_UM_MASK);
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRUM: {
        TCGv_i64 new_psr = tcg_temp_new_i64();
        TCGv_i64 um = tcg_temp_new_i64();

        tcg_gen_andi_i64(new_psr, cpu_psr, ~IA64_PSR_UM_MASK);
        tcg_gen_andi_i64(um, ia64_gr_src(insn->r1), IA64_PSR_UM_MASK);
        tcg_gen_or_i64(new_psr, new_psr, um);
        gen_helper_mov_psr_write(tcg_env, new_psr, tcg_constant_i32(0));
        break;
    }
    case IA64_OP_MOV_IBRGR: {
        TCGv_i64 val = tcg_temp_new_i64();
        gen_helper_read_ibr(val, tcg_env, tcg_constant_i32(insn->r2 - 12));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRIBR:
        gen_helper_write_ibr(tcg_env, tcg_constant_i32(insn->r2 - 12),
                             ia64_gr_src(insn->r1));
        break;
    case IA64_OP_MOV_IBRGR_INDEXED:
    case IA64_OP_MOV_DBRGR_INDEXED: {
        TCGv_i64 index64 = tcg_temp_new_i64();
        TCGv_i32 index = tcg_temp_new_i32();
        TCGv_i64 val = tcg_temp_new_i64();

        tcg_gen_andi_i64(index64, ia64_gr_src(insn->r3), 7);
        tcg_gen_extrl_i64_i32(index, index64);
        if (insn->opcode == IA64_OP_MOV_IBRGR_INDEXED) {
            gen_helper_read_ibr(val, tcg_env, index);
        } else {
            gen_helper_read_dbr(val, tcg_env, index);
        }
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRIBR_INDEXED:
    case IA64_OP_MOV_GRDBR_INDEXED: {
        TCGv_i64 index64 = tcg_temp_new_i64();
        TCGv_i32 index = tcg_temp_new_i32();

        tcg_gen_andi_i64(index64, ia64_gr_src(insn->r3), 7);
        tcg_gen_extrl_i64_i32(index, index64);
        if (insn->opcode == IA64_OP_MOV_GRIBR_INDEXED) {
            gen_helper_write_ibr(tcg_env, index, ia64_gr_src(insn->r1));
        } else {
            gen_helper_write_dbr(tcg_env, index, ia64_gr_src(insn->r1));
        }
        break;
    }
    case IA64_OP_MOV_DBRGR: {
        TCGv_i64 val = tcg_temp_new_i64();
        gen_helper_read_dbr(val, tcg_env, tcg_constant_i32(insn->r2 - 8));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRDBR:
        gen_helper_write_dbr(tcg_env, tcg_constant_i32(insn->r2 - 8),
                             ia64_gr_src(insn->r1));
        break;
    case IA64_OP_MOV_PMCGR: {
        TCGv_i64 val = tcg_temp_new_i64();
        gen_helper_read_pmc(val, tcg_env, tcg_constant_i32(insn->r2 - 32));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRPMC:
        gen_helper_write_pmc(tcg_env, tcg_constant_i32(insn->r2 - 32),
                            ia64_gr_src(insn->r1));
        break;
    case IA64_OP_MOV_PMCGR_INDEXED: {
        TCGv_i64 val = tcg_temp_new_i64();
        gen_helper_read_pmc_indexed(val, tcg_env, ia64_gr_src(insn->r3));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRPMC_INDEXED:
        gen_helper_write_pmc_indexed(tcg_env, ia64_gr_src(insn->r3),
                                     ia64_gr_src(insn->r1));
        break;
    case IA64_OP_MOV_PMDGR: {
        TCGv_i64 val = tcg_temp_new_i64();
        gen_helper_read_pmd(val, tcg_env, tcg_constant_i32(insn->r2 - 64));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRPMD:
        gen_helper_write_pmd(tcg_env, tcg_constant_i32(insn->r2 - 64),
                            ia64_gr_src(insn->r1));
        break;
    case IA64_OP_MOV_PMDGR_INDEXED: {
        TCGv_i64 val = tcg_temp_new_i64();
        gen_helper_read_pmd_indexed(val, tcg_env, ia64_gr_src(insn->r3));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRPMD_INDEXED:
        gen_helper_write_pmd_indexed(tcg_env, ia64_gr_src(insn->r3),
                                     ia64_gr_src(insn->r1));
        break;
    case IA64_OP_MOV_CPUID: {
        TCGv_i64 val = tcg_temp_new_i64();
        gen_helper_read_cr(val, tcg_env, tcg_constant_i32(13));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_CPUID_INDEXED: {
        TCGv_i64 val = tcg_temp_new_i64();
        gen_helper_read_cpuid(val, tcg_env, ia64_gr_src(insn->r3));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_DAHRGR_INDEXED: {
        TCGv_i64 val = tcg_temp_new_i64();
        gen_helper_read_dahr_indexed(val, tcg_env, ia64_gr_src(insn->r3));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_MSRGR: {
        TCGv_i64 val = tcg_temp_new_i64();
        gen_helper_read_msr(val, tcg_env, ia64_gr_src(insn->r3));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRMSR:
        gen_helper_write_msr(tcg_env, ia64_gr_src(insn->r3),
                             ia64_gr_src(insn->r1));
        break;
    case IA64_OP_MOV_IP:
    case IA64_OP_MOV_CURRENT_IP:
        if (insn->r1 != 0) {
            tcg_gen_movi_i64(cpu_gr[insn->r1], insn->address);
            ia64_gen_gr_nat_clear(insn->r1);
        }
        break;
    case IA64_OP_SSM:
        gen_helper_ssm(tcg_env, tcg_constant_i64(insn->imm));
        break;
    case IA64_OP_RSM:
        gen_helper_rsm(tcg_env, tcg_constant_i64(insn->imm));
        break;
    case IA64_OP_MOV_PSRGR: {
        TCGv_i64 val = tcg_temp_new_i64();
        gen_helper_mov_psrgr_read(val, tcg_env, tcg_constant_i32(0));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRPSR:
        gen_helper_mov_psr_write(tcg_env, ia64_gr_src(insn->r1),
                                 tcg_constant_i32(insn->imm != 0));
        break;
    case IA64_OP_BSW0:
        gen_helper_set_psr_bn(tcg_env, tcg_constant_i32(0));
        if (skip == NULL) {
            ia64_gen_exit_to_completed(next_ip, insn->address);
            return true;
        }
        break;
    case IA64_OP_BSW1:
        gen_helper_set_psr_bn(tcg_env, tcg_constant_i32(1));
        if (skip == NULL) {
            ia64_gen_exit_to_completed(next_ip, insn->address);
            return true;
        }
        break;
    case IA64_OP_ALLOC: {
        uint64_t packed = (uint64_t)insn->imm;
        uint32_t sof  = (packed >> 0) & 0x7f;
        uint32_t sol  = (packed >> 7) & 0x7f;
        uint32_t sor  = (packed >> 14) & 0x1f;
        uint32_t rrb  = (packed >> 19) & 0x0f;
        if (sof > 96 || sol > sof || (sor << 3) > sof) {
            ia64_gen_raise_exception(IA64_EXCP_ILLEGAL, insn->address,
                                      insn->raw, insn->slot);
            return true;
        }
        gen_helper_alloc_rse(tcg_env,
                              tcg_constant_i32(insn->r1),
                              tcg_constant_i32(sof),
                              tcg_constant_i32(sol),
                              tcg_constant_i32(sor),
                              tcg_constant_i32(rrb));
        break;
    }
    case IA64_OP_COVER:
        gen_helper_cover_rse(tcg_env);
        break;
    case IA64_OP_FLUSHRS:
        gen_helper_flushrs_rse(tcg_env);
        break;
    case IA64_OP_LOADRS:
        gen_helper_loadrs_rse(tcg_env);
        break;
    case IA64_OP_ITR_D:
        gen_helper_itr_insert(tcg_env, ia64_gr_src(insn->r2),
                               ia64_gr_src(insn->r3),
                               tcg_constant_i32(1));
        break;
    case IA64_OP_ITR_I:
        gen_helper_itr_insert(tcg_env, ia64_gr_src(insn->r2),
                               ia64_gr_src(insn->r3),
                               tcg_constant_i32(0));
        ia64_gen_exit_to_slot_completed(insn->address, insn->slot + 1,
                                        insn->address);
        if (skip == NULL) {
            return true;
        }
        break;
    case IA64_OP_PTR_D:
        gen_helper_ptr_purge(tcg_env, ia64_gr_src(insn->r3),
                              ia64_gr_src(insn->r2),
                              tcg_constant_i32(1));
        break;
    case IA64_OP_PTR_I:
        gen_helper_ptr_purge(tcg_env, ia64_gr_src(insn->r3),
                              ia64_gr_src(insn->r2),
                              tcg_constant_i32(0));
        break;
    case IA64_OP_ITC_D:
        gen_helper_itc_insert(tcg_env, ia64_gr_src(insn->r2),
                              tcg_constant_i32(1));
        break;
    case IA64_OP_ITC_I:
        gen_helper_itc_insert(tcg_env, ia64_gr_src(insn->r2),
                              tcg_constant_i32(0));
        ia64_gen_exit_to_slot_completed(insn->address, insn->slot + 1,
                                        insn->address);
        if (skip == NULL) {
            return true;
        }
        break;
    case IA64_OP_PTC_L:
        gen_helper_ptc_purge(tcg_env, ia64_gr_src(insn->r3),
                              ia64_gr_src(insn->r2),
                              tcg_constant_i32(0));
        break;
    case IA64_OP_PTC_G:
        gen_helper_ptc_purge(tcg_env, ia64_gr_src(insn->r3),
                              ia64_gr_src(insn->r2),
                              tcg_constant_i32(1));
        break;
    case IA64_OP_PTC_E:
        gen_helper_ptc_purge(tcg_env, ia64_gr_src(insn->r3),
                              tcg_constant_i64(0),
                              tcg_constant_i32(2));
        break;
    case IA64_OP_PTC_GA:
        gen_helper_ptc_purge(tcg_env, ia64_gr_src(insn->r3),
                              ia64_gr_src(insn->r2),
                              tcg_constant_i32(3));
        break;
    case IA64_OP_LDFD:
    case IA64_OP_LDFS:
    case IA64_OP_LDF_FILL:
    case IA64_OP_LDF8:
    case IA64_OP_LDFE:
        ia64_gen_fp_load(ctx, insn);
        break;
    case IA64_OP_LDFP8:
    case IA64_OP_LDFPD:
    case IA64_OP_LDFPS:
        ia64_gen_fp_load_pair(ctx, insn);
        break;
    case IA64_OP_STFD:
        ia64_gen_check_nat_non_access(insn, insn->r3, true);
        ia64_gen_check_alignment(insn, ia64_gr_src(insn->r3), 8, false,
                                 true);
        tcg_gen_qemu_st_i64(ia64_fr_src(insn->r2), ia64_gr_src(insn->r3),
                             ctx->mmu_idx, MO_LEUQ);
        gen_helper_invalidate_alat_store(tcg_env, ia64_gr_src(insn->r3),
                                         tcg_constant_i32(8));
        if (insn->imm != 0 && insn->r3 != 0) {
            tcg_gen_addi_i64(cpu_gr[insn->r3], cpu_gr[insn->r3], insn->imm);
        }
        break;
    case IA64_OP_STFS:
        ia64_gen_check_nat_non_access(insn, insn->r3, true);
        ia64_gen_check_alignment(insn, ia64_gr_src(insn->r3), 4, false,
                                 true);
        tcg_gen_qemu_st_i64(ia64_fr_src(insn->r2), ia64_gr_src(insn->r3),
                             ctx->mmu_idx, MO_LEUL);
        gen_helper_invalidate_alat_store(tcg_env, ia64_gr_src(insn->r3),
                                         tcg_constant_i32(4));
        if (insn->imm != 0 && insn->r3 != 0) {
            tcg_gen_addi_i64(cpu_gr[insn->r3], cpu_gr[insn->r3], insn->imm);
        }
        break;
    case IA64_OP_STF_SPILL: {
        TCGv_i64 spill_tail = tcg_temp_new_i64();
        ia64_gen_check_nat_non_access(insn, insn->r3, true);
        ia64_gen_check_alignment(insn, ia64_gr_src(insn->r3), 16, false,
                                 true);
        tcg_gen_qemu_st_i64(ia64_fr_src(insn->r2), ia64_gr_src(insn->r3),
                             ctx->mmu_idx, MO_LEUQ);
        tcg_gen_addi_i64(spill_tail, ia64_gr_src(insn->r3), 8);
        tcg_gen_qemu_st_i64(tcg_constant_i64(0), spill_tail,
                             ctx->mmu_idx, MO_LEUQ);
        gen_helper_invalidate_alat_store(tcg_env, ia64_gr_src(insn->r3),
                                         tcg_constant_i32(16));
        if (insn->imm != 0 && insn->r3 != 0) {
            tcg_gen_addi_i64(cpu_gr[insn->r3], cpu_gr[insn->r3], insn->imm);
        }
        break;
    }
    case IA64_OP_STF8:
        ia64_gen_check_nat_non_access(insn, insn->r3, true);
        ia64_gen_check_alignment(insn, ia64_gr_src(insn->r3), 8, false,
                                 true);
        tcg_gen_qemu_st_i64(ia64_fr_src(insn->r2), ia64_gr_src(insn->r3),
                             ctx->mmu_idx, MO_LEUQ);
        gen_helper_invalidate_alat_store(tcg_env, ia64_gr_src(insn->r3),
                                         tcg_constant_i32(8));
        if (insn->imm != 0 && insn->r3 != 0) {
            tcg_gen_addi_i64(cpu_gr[insn->r3], cpu_gr[insn->r3], insn->imm);
        }
        break;
    case IA64_OP_STFE:
        ia64_gen_check_nat_non_access(insn, insn->r3, true);
        ia64_gen_check_alignment(insn, ia64_gr_src(insn->r3), 16, false,
                                 true);
        gen_helper_stfe(tcg_env, ia64_gr_src(insn->r3),
                        tcg_constant_i32(insn->r2));
        gen_helper_invalidate_alat_store(tcg_env, ia64_gr_src(insn->r3),
                                         tcg_constant_i32(10));
        if (insn->imm != 0 && insn->r3 != 0) {
            tcg_gen_addi_i64(cpu_gr[insn->r3], cpu_gr[insn->r3], insn->imm);
        }
        break;
    case IA64_OP_FADD:
        gen_helper_fadd(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FSUB:
        gen_helper_fsub(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FMPY:
        gen_helper_fmpy(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FMA:
        gen_helper_fma4(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3),
                        tcg_constant_i32(insn->p1));
        break;
    case IA64_OP_XMA_L:
        tmp = tcg_temp_new_i64();
        tcg_gen_mul_i64(tmp, ia64_fr_src(insn->r3), ia64_fr_src(insn->p1));
        if (ia64_fr_is_writable(insn->r1)) {
            tcg_gen_add_i64(cpu_fr[insn->r1], tmp, ia64_fr_src(insn->r2));
            ia64_gen_fr_sig_set(insn->r1);
            ia64_gen_fr_nat_from_3(insn->r1, insn->r2, insn->r3,
                                   insn->p1);
        }
        break;
    case IA64_OP_XMA_H: {
        TCGv_i64 lo = tcg_temp_new_i64();
        TCGv_i64 hi = ia64_fr_is_writable(insn->r1) ?
                      cpu_fr[insn->r1] : tcg_temp_new_i64();
        tcg_gen_muls2_i64(lo, hi, ia64_fr_src(insn->r3),
                          ia64_fr_src(insn->p1));
        tcg_gen_add2_i64(lo, hi, lo, hi, ia64_fr_src(insn->r2),
                         tcg_constant_i64(0));
        ia64_gen_fr_sig_set(insn->r1);
        ia64_gen_fr_nat_from_3(insn->r1, insn->r2, insn->r3, insn->p1);
        break;
    }
    case IA64_OP_XMA_HU: {
        TCGv_i64 lo = tcg_temp_new_i64();
        TCGv_i64 hi = ia64_fr_is_writable(insn->r1) ?
                      cpu_fr[insn->r1] : tcg_temp_new_i64();
        tcg_gen_mulu2_i64(lo, hi, ia64_fr_src(insn->r3),
                          ia64_fr_src(insn->p1));
        tcg_gen_add2_i64(lo, hi, lo, hi, ia64_fr_src(insn->r2),
                         tcg_constant_i64(0));
        ia64_gen_fr_sig_set(insn->r1);
        ia64_gen_fr_nat_from_3(insn->r1, insn->r2, insn->r3, insn->p1);
        break;
    }
    case IA64_OP_XMPY_HU: {
        TCGv_i64 lo = tcg_temp_new_i64();
        TCGv_i64 hi = ia64_fr_is_writable(insn->r1) ?
                      cpu_fr[insn->r1] : tcg_temp_new_i64();
        tcg_gen_mulu2_i64(lo, hi, ia64_fr_src(insn->r3),
                          ia64_fr_src(insn->p1));
        ia64_gen_fr_sig_set(insn->r1);
        ia64_gen_fr_nat_from_2(insn->r1, insn->r3, insn->p1);
        break;
    }
    case IA64_OP_FMIN:
        gen_helper_fmin(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FMAX:
        gen_helper_fmax(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FAMIN:
        gen_helper_famin(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FAMAX:
        gen_helper_famax(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FRCPA:
        gen_helper_frcpa(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->p1),
                         tcg_constant_i32(insn->r2),
                         tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FPRCPA:
        gen_helper_fprcpa(tcg_env, tcg_constant_i32(insn->r1),
                          tcg_constant_i32(insn->p2),
                          tcg_constant_i32(insn->r2),
                          tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FCMP:
        gen_helper_fcmp(tcg_env,
                        tcg_constant_i32(insn->p1),
                        tcg_constant_i32(insn->p2),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3),
                        tcg_constant_i32(insn->imm));
        break;
    case IA64_OP_FMS:
        gen_helper_fms(tcg_env, tcg_constant_i32(insn->r1),
                       tcg_constant_i32(insn->r2),
                       tcg_constant_i32(insn->r3),
                       tcg_constant_i32(insn->p1));
        break;
    case IA64_OP_FNMA:
        gen_helper_fnma4(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->r2),
                         tcg_constant_i32(insn->r3),
                         tcg_constant_i32(insn->p1));
        break;
    case IA64_OP_FSELECT:
        gen_helper_fselect(tcg_env, tcg_constant_i32(insn->r1),
                           tcg_constant_i32(insn->r2),
                           tcg_constant_i32(insn->r3),
                           tcg_constant_i32(insn->p1));
        break;
    case IA64_OP_FNORM:
        gen_helper_fnorm(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->r2),
                         tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FPABS:
        gen_helper_fpabs(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->r2));
        break;
    case IA64_OP_FPNEG:
        gen_helper_fpneg(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->r2));
        break;
    case IA64_OP_FPNEGABS:
        gen_helper_fpnegabs(tcg_env, tcg_constant_i32(insn->r1),
                            tcg_constant_i32(insn->r2));
        break;
    case IA64_OP_FPRSQRTA:
        gen_helper_fprsqrta(tcg_env, tcg_constant_i32(insn->r1),
                            tcg_constant_i32(insn->p2),
                            tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FRSQRTA:
        gen_helper_frsqrta(tcg_env, tcg_constant_i32(insn->r1),
                           tcg_constant_i32(insn->p2),
                           tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FPACK:
        gen_helper_fpack(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->r2),
                         tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FAND:
        gen_helper_flogical_and(tcg_env, tcg_constant_i32(insn->r1),
                                tcg_constant_i32(insn->r2),
                                tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FANDCM:
        gen_helper_flogical_andcm(tcg_env, tcg_constant_i32(insn->r1),
                                  tcg_constant_i32(insn->r2),
                                  tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FOR:
        gen_helper_flogical_or(tcg_env, tcg_constant_i32(insn->r1),
                               tcg_constant_i32(insn->r2),
                               tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FXOR:
        gen_helper_flogical_xor(tcg_env, tcg_constant_i32(insn->r1),
                                tcg_constant_i32(insn->r2),
                                tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FSWAP:
        gen_helper_fswap(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->r2),
                         tcg_constant_i32(insn->r3),
                         tcg_constant_i32(0));
        break;
    case IA64_OP_FSWAP_NL:
        gen_helper_fswap(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->r2),
                         tcg_constant_i32(insn->r3),
                         tcg_constant_i32(1));
        break;
    case IA64_OP_FSWAP_NR:
        gen_helper_fswap(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->r2),
                         tcg_constant_i32(insn->r3),
                         tcg_constant_i32(2));
        break;
    case IA64_OP_FMIX_LR:
        gen_helper_fmix(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3),
                        tcg_constant_i32(0));
        break;
    case IA64_OP_FMIX_R:
        gen_helper_fmix(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3),
                        tcg_constant_i32(1));
        break;
    case IA64_OP_FMIX_L:
        gen_helper_fmix(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3),
                        tcg_constant_i32(2));
        break;
    case IA64_OP_FSXT_R:
        gen_helper_fsxt(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3),
                        tcg_constant_i32(0));
        break;
    case IA64_OP_FSXT_L:
        gen_helper_fsxt(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3),
                        tcg_constant_i32(1));
        break;
    case IA64_OP_FPMERGE:
        gen_helper_fpmerge(tcg_env, tcg_constant_i32(insn->r1),
                           tcg_constant_i32(insn->r2),
                           tcg_constant_i32(insn->r3),
                           tcg_constant_i32(0));
        break;
    case IA64_OP_FPMERGE_S:
        gen_helper_fpmerge(tcg_env, tcg_constant_i32(insn->r1),
                           tcg_constant_i32(insn->r2),
                           tcg_constant_i32(insn->r3),
                           tcg_constant_i32(1));
        break;
    case IA64_OP_FPMERGE_SE:
        gen_helper_fpmerge(tcg_env, tcg_constant_i32(insn->r1),
                           tcg_constant_i32(insn->r2),
                           tcg_constant_i32(insn->r3),
                           tcg_constant_i32(2));
        break;
    case IA64_OP_FPMIN:
        gen_helper_fpminmax(tcg_env, tcg_constant_i32(insn->r1),
                            tcg_constant_i32(insn->r2),
                            tcg_constant_i32(insn->r3),
                            tcg_constant_i32(0),
                            tcg_constant_i32(0));
        break;
    case IA64_OP_FPMAX:
        gen_helper_fpminmax(tcg_env, tcg_constant_i32(insn->r1),
                            tcg_constant_i32(insn->r2),
                            tcg_constant_i32(insn->r3),
                            tcg_constant_i32(1),
                            tcg_constant_i32(0));
        break;
    case IA64_OP_FPAMIN:
        gen_helper_fpminmax(tcg_env, tcg_constant_i32(insn->r1),
                            tcg_constant_i32(insn->r2),
                            tcg_constant_i32(insn->r3),
                            tcg_constant_i32(0),
                            tcg_constant_i32(1));
        break;
    case IA64_OP_FPAMAX:
        gen_helper_fpminmax(tcg_env, tcg_constant_i32(insn->r1),
                            tcg_constant_i32(insn->r2),
                            tcg_constant_i32(insn->r3),
                            tcg_constant_i32(1),
                            tcg_constant_i32(1));
        break;
    case IA64_OP_FPCMP:
        gen_helper_fpcmp(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->r2),
                         tcg_constant_i32(insn->r3),
                         tcg_constant_i32(insn->imm));
        break;
    case IA64_OP_FPCVT:
        gen_helper_fpcvt(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->r2),
                         tcg_constant_i32(insn->imm & 1),
                         tcg_constant_i32((insn->imm >> 1) & 1));
        break;
    case IA64_OP_FPMA:
        gen_helper_fpma(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3),
                        tcg_constant_i32(insn->p1),
                        tcg_constant_i32(0));
        break;
    case IA64_OP_FPMS:
        gen_helper_fpma(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3),
                        tcg_constant_i32(insn->p1),
                        tcg_constant_i32(1));
        break;
    case IA64_OP_FPNMA:
        gen_helper_fpma(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3),
                        tcg_constant_i32(insn->p1),
                        tcg_constant_i32(2));
        break;
    case IA64_OP_FMOV:
        ia64_gen_fr_mov(insn->r1, ia64_fr_src(insn->r2));
        break;
    case IA64_OP_FCVT_XF:
        gen_helper_fcvt_xf(tcg_env, tcg_constant_i32(insn->r1),
                           tcg_constant_i32(insn->r2));
        break;
    case IA64_OP_FCVT_FX:
    case IA64_OP_FCVT_FXU:
        gen_helper_fcvt_fx(tcg_env, tcg_constant_i32(insn->r1),
                           tcg_constant_i32(insn->r2),
                           tcg_constant_i32(insn->opcode == IA64_OP_FCVT_FXU),
                           tcg_constant_i32((insn->imm >> 1) & 1));
        break;
    case IA64_OP_GETF_D:
        if (insn->r1 != 0) {
            tcg_gen_mov_i64(cpu_gr[insn->r1], ia64_fr_src(insn->r2));
            ia64_gen_gr_nat_assign(insn->r1, ia64_gen_fr_nat_read(insn->r2));
        }
        break;
    case IA64_OP_GETF_S:
        if (insn->r1 != 0) {
            tcg_gen_ext32u_i64(cpu_gr[insn->r1], ia64_fr_src(insn->r2));
            ia64_gen_gr_nat_assign(insn->r1, ia64_gen_fr_nat_read(insn->r2));
        }
        break;
    case IA64_OP_GETF_SIG:
        if (insn->r1 != 0) {
            tcg_gen_mov_i64(cpu_gr[insn->r1], ia64_fr_src(insn->r2));
            ia64_gen_gr_nat_assign(insn->r1, ia64_gen_fr_nat_read(insn->r2));
        }
        break;
    case IA64_OP_GETF_EXP: {
        if (insn->r1 != 0) {
            TCGv_i64 leading_zeroes = tcg_temp_new_i64();
            TCGv_i64 exponent = tcg_temp_new_i64();
            TCGv_i64 zero = tcg_constant_i64(0);

            /*
             * The current FR model stores setf.sig payloads as the raw 64-bit
             * significand.  fnorm leaves that payload intact, so synthesize
             * the IA-64 biased exponent from the highest set significand bit.
             */
            tcg_gen_clzi_i64(leading_zeroes, ia64_fr_src(insn->r2), 64);
            tcg_gen_movi_i64(exponent, 0x1003e);
            tcg_gen_sub_i64(exponent, exponent, leading_zeroes);
            tcg_gen_movcond_i64(TCG_COND_EQ, cpu_gr[insn->r1],
                                ia64_fr_src(insn->r2), zero, zero, exponent);
            ia64_gen_gr_nat_assign(insn->r1, ia64_gen_fr_nat_read(insn->r2));
        }
        break;
    }
    case IA64_OP_SETF_D:
        ia64_gen_fr_mov(insn->r1, ia64_gr_src(insn->r2));
        break;
    case IA64_OP_SETF_S: {
        TCGv_i64 val = tcg_temp_new_i64();

        tcg_gen_ext32u_i64(val, ia64_gr_src(insn->r2));
        ia64_gen_fr_mov(insn->r1, val);
        break;
    }
    case IA64_OP_SETF_EXP:
        ia64_gen_fr_mov(insn->r1, ia64_gr_src(insn->r2));
        break;
    case IA64_OP_SETF_SIG:
        ia64_gen_fr_mov_sig(insn->r1, ia64_gr_src(insn->r2));
        break;
    case IA64_OP_TPA:
        if (insn->r1 != 0) {
            TCGv_i64 val = tcg_temp_new_i64();
            gen_helper_tpa(val, tcg_env, ia64_gr_src(insn->r3));
            tcg_gen_mov_i64(cpu_gr[insn->r1], val);
        }
        break;
    case IA64_OP_SYNC_I:
    case IA64_OP_FWB:
        break;
    case IA64_OP_CHK_S:
        if (!insn->check_fp) {
            TCGv_i64 failed = ia64_gen_gr_nat_read(insn->r2);

            ia64_gen_check_branch(failed, insn->address + insn->imm,
                                  insn->address);
        } else {
            ia64_gen_check_branch(ia64_gen_fr_nat_read(insn->r2),
                                  insn->address + insn->imm, insn->address);
        }
        break;
    case IA64_OP_CHK_A:
    case IA64_OP_CHK_A_CLR:
        if (!insn->check_fp && insn->unit == IA64_UNIT_M) {
            const bool clear = insn->opcode == IA64_OP_CHK_A_CLR;
            TCGv_i64 hit = tcg_temp_new_i64();
            TCGv_i64 failed = tcg_temp_new_i64();

            gen_helper_check_load_alat(hit, tcg_env,
                                       tcg_constant_i32(insn->r2),
                                       tcg_constant_i32(clear));
            tcg_gen_xori_i64(failed, hit, 1);
            ia64_gen_check_branch(failed, insn->address + insn->imm,
                                  insn->address);
        } else if (insn->check_fp && insn->unit == IA64_UNIT_M) {
            const bool clear = insn->opcode == IA64_OP_CHK_A_CLR;
            TCGv_i64 hit = tcg_temp_new_i64();
            TCGv_i64 failed = tcg_temp_new_i64();

            gen_helper_check_load_alat_fp(hit, tcg_env,
                                          tcg_constant_i32(insn->r2),
                                          tcg_constant_i32(clear));
            tcg_gen_xori_i64(failed, hit, 1);
            ia64_gen_check_branch(failed, insn->address + insn->imm,
                                  insn->address);
        }
        break;
    case IA64_OP_PROBE_R:
    case IA64_OP_PROBE_W:
    case IA64_OP_PROBE_RW: {
        const bool write_probe = insn->opcode == IA64_OP_PROBE_W ||
                                 insn->opcode == IA64_OP_PROBE_RW;
        TCGv_i64 access_level = insn->probe_imm ?
                                tcg_constant_i64(insn->imm & 3) :
                                ia64_gr_src(insn->r2);
        TCGv_i64 result = tcg_temp_new_i64();
        ia64_gen_check_nat_non_access(insn, insn->r3, write_probe);
        if (insn->probe_fault) {
            gen_helper_probe_fault(tcg_env, ia64_gr_src(insn->r3),
                                   tcg_constant_i32(write_probe),
                                   tcg_constant_i32(insn->opcode ==
                                                    IA64_OP_PROBE_RW),
                                   access_level);
            break;
        }
        gen_helper_probe(result, tcg_env, ia64_gr_src(insn->r3),
                         tcg_constant_i32(write_probe), tcg_constant_i32(0),
                         access_level);
        if (insn->r1 != 0) {
            tcg_gen_mov_i64(cpu_gr[insn->r1], result);
        }
        break;
    }
    case IA64_OP_TAK:
    case IA64_OP_THASH:
    case IA64_OP_TTAG: {
        TCGv_i64 result = tcg_temp_new_i64();
        if (insn->opcode == IA64_OP_TAK) {
            gen_helper_tak(result, tcg_env, ia64_gr_src(insn->r3));
        } else if (insn->opcode == IA64_OP_THASH) {
            gen_helper_thash(result, tcg_env, ia64_gr_src(insn->r3));
        } else {
            gen_helper_ttag(result, tcg_env, ia64_gr_src(insn->r3));
        }
        if (insn->r1 != 0) {
            ia64_gen_gr_write_nat_clear(insn->r1, result);
        }
        break;
    }
    case IA64_OP_FC:
        gen_helper_fc(tcg_env, ia64_gr_src(insn->r3));
        break;
    case IA64_OP_INVALA:
        gen_helper_invala(tcg_env);
        break;
    case IA64_OP_INVALAT: {
        TCGLabel *l_done = gen_new_label();
        TCGv_i64 idx = tcg_temp_new_i64();
        tcg_gen_andi_i64(idx, ia64_gr_src(insn->r3), IA64_ALAT_ENTRIES - 1);
        for (int i = 0; i < IA64_ALAT_ENTRIES; ++i) {
            TCGLabel *l_not_this = gen_new_label();
            tcg_gen_brcondi_i64(TCG_COND_NE, idx, i, l_not_this);
            uint32_t alat_offset =
                offsetof(CPUIA64State, alat) + i * sizeof(IA64AlatEntry);
            tcg_gen_st8_i64(tcg_constant_i64(0), tcg_env, alat_offset);
            tcg_gen_br(l_done);
            gen_set_label(l_not_this);
        }
        gen_set_label(l_done);
        break;
    }
    case IA64_OP_BR_WEXIT:
    case IA64_OP_BR_WTOP:
    case IA64_OP_BR_CEXIT:
    case IA64_OP_BR_CTOP: {
        TCGv_i64 tgt = tcg_temp_new_i64();
        TCGLabel *l_nobr = gen_new_label();
        if (insn->opcode == IA64_OP_BR_WEXIT) {
            gen_helper_br_wexit(tgt, tcg_env,
                tcg_constant_i64(insn->address + insn->imm),
                tcg_constant_i32(insn->qp));
        } else if (insn->opcode == IA64_OP_BR_WTOP) {
            gen_helper_br_wtop(tgt, tcg_env,
                tcg_constant_i64(insn->address + insn->imm),
                tcg_constant_i32(insn->qp));
        } else if (insn->opcode == IA64_OP_BR_CEXIT) {
            gen_helper_br_cexit(tgt, tcg_env,
                tcg_constant_i64(insn->address + insn->imm),
                tcg_constant_i32(insn->b2));
        } else {
            gen_helper_br_ctop(tgt, tcg_env,
                tcg_constant_i64(insn->address + insn->imm),
                tcg_constant_i32(insn->b2));
        }
        tcg_gen_brcondi_i64(TCG_COND_EQ, tgt, 0, l_nobr);
        ia64_gen_note_successful_bundle(insn->address);
        ia64_gen_clear_ri();
        tcg_gen_mov_i64(cpu_ip, tgt);
        tcg_gen_exit_tb(NULL, 0);
        gen_set_label(l_nobr);
        break;
    }
    case IA64_OP_FCLASS:
        gen_helper_fclass(tcg_env, tcg_constant_i32(insn->p1),
                          tcg_constant_i32(insn->p2),
                          tcg_constant_i32(insn->r2),
                          tcg_constant_i32(insn->imm));
        break;
    case IA64_OP_FMERGE:
        gen_helper_fmerge_ns(tcg_env, tcg_constant_i32(insn->r1),
                             tcg_constant_i32(insn->r2),
                             tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FMERGE_S:
        gen_helper_fmerge_s(tcg_env, tcg_constant_i32(insn->r1),
                            tcg_constant_i32(insn->r2),
                            tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FMERGE_SE:
        gen_helper_fmerge_se(tcg_env, tcg_constant_i32(insn->r1),
                             tcg_constant_i32(insn->r2),
                             tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_SRLZ:
        gen_helper_tlb_serialize(tcg_env, tcg_constant_i32(1),
                                 tcg_constant_i32(1));
        ia64_gen_exit_to_slot_completed(insn->address, insn->slot + 1,
                                        insn->address);
        if (skip == NULL) {
            return true;
        }
        break;
    case IA64_OP_SRLZ_D:
        gen_helper_tlb_serialize(tcg_env, tcg_constant_i32(1),
                                 tcg_constant_i32(0));
        ia64_gen_exit_to_slot_completed(insn->address, insn->slot + 1,
                                        insn->address);
        if (skip == NULL) {
            return true;
        }
        break;
    case IA64_OP_MF:
    case IA64_OP_MF_A:
        tcg_gen_mb(TCG_MO_ALL);
        break;
    case IA64_OP_PADD1:
    case IA64_OP_PADD2:
    case IA64_OP_PADD4:
    case IA64_OP_PSUB1:
    case IA64_OP_PSUB2:
    case IA64_OP_PSUB4: {
        int lane_bits;
        int num_lanes;
        if (insn->opcode == IA64_OP_PADD1 || insn->opcode == IA64_OP_PSUB1) {
            lane_bits = 8;
            num_lanes = 8;
        } else if (insn->opcode == IA64_OP_PADD2 || insn->opcode == IA64_OP_PSUB2) {
            lane_bits = 16;
            num_lanes = 4;
        } else {
            lane_bits = 32;
            num_lanes = 2;
        }
        const uint64_t lane_mask = ((uint64_t)1 << lane_bits) - 1;
        bool is_sub = (insn->opcode == IA64_OP_PSUB1 ||
                       insn->opcode == IA64_OP_PSUB2 ||
                       insn->opcode == IA64_OP_PSUB4);
        const unsigned saturation = insn->imm & 3;
        TCGv_i64 result = tcg_temp_new_i64();
        tcg_gen_movi_i64(result, 0);
        for (int i = 0; i < num_lanes; ++i) {
            TCGv_i64 lane_a = tcg_temp_new_i64();
            TCGv_i64 lane_b = tcg_temp_new_i64();
            TCGv_i64 lane_res = tcg_temp_new_i64();
            tcg_gen_extract_i64(lane_a, ia64_gr_src(insn->r2), i * lane_bits, lane_bits);
            tcg_gen_extract_i64(lane_b, ia64_gr_src(insn->r3), i * lane_bits, lane_bits);
            if (saturation == 1) {
                if (lane_bits == 8) {
                    tcg_gen_ext8s_i64(lane_a, lane_a);
                    tcg_gen_ext8s_i64(lane_b, lane_b);
                } else if (lane_bits == 16) {
                    tcg_gen_ext16s_i64(lane_a, lane_a);
                    tcg_gen_ext16s_i64(lane_b, lane_b);
                }
            } else if (saturation == 3) {
                if (lane_bits == 8) {
                    tcg_gen_ext8s_i64(lane_b, lane_b);
                } else if (lane_bits == 16) {
                    tcg_gen_ext16s_i64(lane_b, lane_b);
                }
            }
            if (is_sub) {
                tcg_gen_sub_i64(lane_res, lane_a, lane_b);
            } else {
                tcg_gen_add_i64(lane_res, lane_a, lane_b);
            }
            if (saturation != 0 && lane_bits < 32) {
                int64_t min_value = 0;
                int64_t max_value = lane_mask;
                TCGLabel *ge_min = gen_new_label();
                TCGLabel *le_max = gen_new_label();

                if (saturation == 1) {
                    min_value = -(1LL << (lane_bits - 1));
                    max_value = (1LL << (lane_bits - 1)) - 1;
                }

                tcg_gen_brcondi_i64(TCG_COND_GE, lane_res, min_value,
                                    ge_min);
                tcg_gen_movi_i64(lane_res, min_value);
                gen_set_label(ge_min);
                tcg_gen_brcondi_i64(TCG_COND_LE, lane_res, max_value,
                                    le_max);
                tcg_gen_movi_i64(lane_res, max_value);
                gen_set_label(le_max);
            }
            tcg_gen_andi_i64(lane_res, lane_res, lane_mask);
            tcg_gen_shli_i64(lane_res, lane_res, i * lane_bits);
            tcg_gen_or_i64(result, result, lane_res);
        }
        tcg_gen_mov_i64(cpu_gr[insn->r1], result);
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    }
    case IA64_OP_PSHLADD2: {
        TCGv_i64 result = tcg_temp_new_i64();

        tcg_gen_movi_i64(result, 0);
        for (int i = 0; i < 4; ++i) {
            TCGv_i64 lane_a = tcg_temp_new_i64();
            TCGv_i64 lane_b = tcg_temp_new_i64();
            TCGv_i64 lane_res = tcg_temp_new_i64();

            tcg_gen_extract_i64(lane_a, ia64_gr_src(insn->r2), i * 16, 16);
            tcg_gen_extract_i64(lane_b, ia64_gr_src(insn->r3), i * 16, 16);
            tcg_gen_ext16s_i64(lane_a, lane_a);
            tcg_gen_ext16s_i64(lane_b, lane_b);
            tcg_gen_shli_i64(lane_res, lane_a, insn->imm);
            ia64_gen_saturate_signed_i64(lane_res, 16);
            tcg_gen_add_i64(lane_res, lane_res, lane_b);
            ia64_gen_saturate_signed_i64(lane_res, 16);
            tcg_gen_andi_i64(lane_res, lane_res, 0xffff);
            tcg_gen_shli_i64(lane_res, lane_res, i * 16);
            tcg_gen_or_i64(result, result, lane_res);
        }
        tcg_gen_mov_i64(cpu_gr[insn->r1], result);
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    }
    case IA64_OP_PSHRADD2: {
        TCGv_i64 result = tcg_temp_new_i64();

        tcg_gen_movi_i64(result, 0);
        for (int i = 0; i < 4; ++i) {
            TCGv_i64 lane_a = tcg_temp_new_i64();
            TCGv_i64 lane_b = tcg_temp_new_i64();
            TCGv_i64 lane_res = tcg_temp_new_i64();

            tcg_gen_extract_i64(lane_a, ia64_gr_src(insn->r2), i * 16, 16);
            tcg_gen_extract_i64(lane_b, ia64_gr_src(insn->r3), i * 16, 16);
            tcg_gen_ext16s_i64(lane_a, lane_a);
            tcg_gen_ext16s_i64(lane_b, lane_b);
            tcg_gen_sari_i64(lane_res, lane_a, insn->imm);
            tcg_gen_add_i64(lane_res, lane_res, lane_b);
            ia64_gen_saturate_signed_i64(lane_res, 16);
            tcg_gen_andi_i64(lane_res, lane_res, 0xffff);
            tcg_gen_shli_i64(lane_res, lane_res, i * 16);
            tcg_gen_or_i64(result, result, lane_res);
        }
        tcg_gen_mov_i64(cpu_gr[insn->r1], result);
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    }
    case IA64_OP_PSHR2:
        ia64_gen_pshr(insn, 16, false);
        break;
    case IA64_OP_PSHR2_U:
        ia64_gen_pshr(insn, 16, true);
        break;
    case IA64_OP_PSHR4:
        ia64_gen_pshr(insn, 32, false);
        break;
    case IA64_OP_PSHR4_U:
        ia64_gen_pshr(insn, 32, true);
        break;
    case IA64_OP_XCHG1:
    case IA64_OP_XCHG2:
    case IA64_OP_XCHG4:
    case IA64_OP_XCHG8: {
        MemOp memop = ia64_memop_for_opcode(insn->opcode);
        uint32_t size = ia64_memop_size(memop);

        ia64_gen_check_nat_semaphore(insn, insn->r3, IA64_NAT_NON_ACCESS);
        ia64_gen_check_nat_semaphore(insn, insn->r2, IA64_NAT_ACCESS);
        ia64_gen_check_alignment_access(insn, ia64_gr_src(insn->r3),
                                        size, true,
                                        IA64_ISR_R | IA64_ISR_W);
        gen_helper_check_semaphore_access(tcg_env, ia64_gr_src(insn->r3));
        ia64_gen_memory_release(insn);
        tcg_gen_atomic_xchg_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3),
                                 ia64_gr_src(insn->r2), ctx->mmu_idx, memop);
        ia64_gen_memory_acquire(insn);
        ia64_gen_gr_nat_clear(insn->r1);
        gen_helper_invalidate_alat_store(tcg_env, ia64_gr_src(insn->r3),
                                         tcg_constant_i32(size));
        break;
    }
    case IA64_OP_CMPXCHG1:
    case IA64_OP_CMPXCHG2:
    case IA64_OP_CMPXCHG4:
    case IA64_OP_CMPXCHG8: {
        MemOp memop = ia64_memop_for_opcode(insn->opcode);
        TCGv_i64 ccv = tcg_temp_new_i64();
        ia64_gen_check_nat_semaphore(insn, insn->r3, IA64_NAT_NON_ACCESS);
        ia64_gen_check_nat_semaphore(insn, insn->r2, IA64_NAT_ACCESS);
        ia64_gen_check_alignment_access(insn, ia64_gr_src(insn->r3),
                                        ia64_memop_size(memop), true,
                                        IA64_ISR_R | IA64_ISR_W);
        gen_helper_check_semaphore_access(tcg_env, ia64_gr_src(insn->r3));
        gen_helper_read_ar(ccv, tcg_env, tcg_constant_i32(32));
        ia64_gen_memory_release(insn);
        gen_helper_cmpxchg(cpu_gr[insn->r1], tcg_env,
                            ia64_gr_src(insn->r3), ccv,
                            ia64_gr_src(insn->r2),
                            tcg_constant_i32(ia64_memop_size(memop)));
        ia64_gen_memory_acquire(insn);
        ia64_gen_gr_nat_clear(insn->r1);
        break;
    }
    case IA64_OP_CMP8XCHG16: {
        TCGv_i64 ccv = tcg_temp_new_i64();
        TCGv_i64 csd = tcg_temp_new_i64();

        ia64_gen_check_nat_semaphore(insn, insn->r3, IA64_NAT_NON_ACCESS);
        ia64_gen_check_nat_semaphore(insn, insn->r2, IA64_NAT_ACCESS);
        ia64_gen_check_alignment_access(insn, ia64_gr_src(insn->r3), 8, true,
                                        IA64_ISR_R | IA64_ISR_W);
        gen_helper_check_semaphore_access(tcg_env, ia64_gr_src(insn->r3));
        gen_helper_read_ar(ccv, tcg_env, tcg_constant_i32(32));
        gen_helper_read_ar(csd, tcg_env, tcg_constant_i32(25));
        ia64_gen_memory_release(insn);
        gen_helper_cmp8xchg16(cpu_gr[insn->r1], tcg_env,
                              ia64_gr_src(insn->r3), ccv,
                              ia64_gr_src(insn->r2), csd);
        ia64_gen_memory_acquire(insn);
        ia64_gen_gr_nat_clear(insn->r1);
        break;
    }
    case IA64_OP_FETCHADD4:
    case IA64_OP_FETCHADD8: {
        MemOp memop = ia64_memop_for_opcode(insn->opcode);
        uint32_t size = ia64_memop_size(memop);
        TCGv_i64 addend = insn->imm ?
                           tcg_constant_i64(insn->imm) :
                           ia64_gr_src(insn->r2);
        ia64_gen_check_nat_semaphore(insn, insn->r3, IA64_NAT_NON_ACCESS);
        if (!insn->imm) {
            ia64_gen_check_nat_semaphore(insn, insn->r2, IA64_NAT_ACCESS);
        }
        ia64_gen_check_alignment_access(insn, ia64_gr_src(insn->r3),
                                        size, true,
                                        IA64_ISR_R | IA64_ISR_W);
        gen_helper_check_semaphore_access(tcg_env, ia64_gr_src(insn->r3));
        ia64_gen_memory_release(insn);
        tcg_gen_atomic_fetch_add_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3),
                                     addend, ctx->mmu_idx, memop);
        ia64_gen_memory_acquire(insn);
        ia64_gen_gr_nat_clear(insn->r1);
        gen_helper_invalidate_alat_store(tcg_env, ia64_gr_src(insn->r3),
                                         tcg_constant_i32(size));
        break;
    }
    case IA64_OP_BR_COND:
        ia64_gen_exit_to_completed(insn->address + insn->imm, insn->address);
        if (skip == NULL) {
            return true;
        }
        break;
    case IA64_OP_BR:
        ia64_gen_exit_to_completed(insn->address + insn->imm, insn->address);
        if (skip == NULL) {
            return true;
        }
        break;
    case IA64_OP_BR_CLOOP: {
        TCGv_i64 tgt = tcg_temp_new_i64();
        TCGLabel *l_nobr = gen_new_label();
        gen_helper_br_cloop(tgt, tcg_env,
            tcg_constant_i64(insn->address + insn->imm),
            tcg_constant_i32(insn->b2));
        tcg_gen_brcondi_i64(TCG_COND_EQ, tgt, 0, l_nobr);
        ia64_gen_note_successful_bundle(insn->address);
        ia64_gen_clear_ri();
        tcg_gen_mov_i64(cpu_ip, tgt);
        tcg_gen_exit_tb(NULL, 0);
        gen_set_label(l_nobr);
        break;
    }
    case IA64_OP_BR_IA:
        gen_helper_br_ia_diag(tcg_env, tcg_constant_i32(insn->b2));
        ia64_gen_note_successful_bundle(insn->address);
        ia64_gen_clear_ri();
        tcg_gen_exit_tb(NULL, 0);
        if (skip == NULL) {
            return true;
        }
        break;
    case IA64_OP_BR_CALL: {
        tcg_gen_movi_i64(cpu_ip, insn->address);
        gen_helper_br_call_rse(tcg_env,
                                tcg_constant_i32(insn->b1),
                                tcg_constant_i64(next_ip),
                                tcg_constant_i64(insn->address + insn->imm));
        ia64_gen_note_successful_bundle(insn->address);
        ia64_gen_clear_ri();
        tcg_gen_exit_tb(NULL, 0);
        if (skip == NULL) {
            return true;
        }
        break;
    }
    case IA64_OP_BR_CALL_INDIRECT: {
        TCGv_i64 target = tcg_temp_new_i64();

        tcg_gen_mov_i64(target, cpu_br[insn->b2]);
        tcg_gen_movi_i64(cpu_ip, insn->address);
        gen_helper_br_call_rse(tcg_env,
                                tcg_constant_i32(insn->b1),
                                tcg_constant_i64(next_ip),
                                target);
        ia64_gen_note_successful_bundle(insn->address);
        ia64_gen_clear_ri();
        tcg_gen_exit_tb(NULL, 0);
        if (skip == NULL) {
            return true;
        }
        break;
    }
    case IA64_OP_BRL_COND:
        ia64_gen_exit_to_completed(insn->address + insn->imm, insn->address);
        if (skip == NULL) {
            return true;
        }
        break;
    case IA64_OP_BRL_CALL:
        tcg_gen_movi_i64(cpu_ip, insn->address);
        gen_helper_br_call_rse(tcg_env,
                                tcg_constant_i32(insn->b1),
                                tcg_constant_i64(next_ip),
                                tcg_constant_i64(insn->address + insn->imm));
        ia64_gen_note_successful_bundle(insn->address);
        ia64_gen_clear_ri();
        tcg_gen_exit_tb(NULL, 0);
        if (skip == NULL) {
            return true;
        }
        break;
    case IA64_OP_BR_RET:
        tcg_gen_movi_i64(cpu_ip, insn->address);
        gen_helper_br_ret_rse(tcg_env, tcg_constant_i32(insn->b2));
        ia64_gen_note_successful_bundle(insn->address);
        ia64_gen_clear_ri();
        tcg_gen_exit_tb(NULL, 0);
        if (skip == NULL) {
            return true;
        }
        break;
    case IA64_OP_RFI:
        gen_helper_rfi(tcg_env);
        tcg_gen_exit_tb(NULL, 0);
        if (skip == NULL) {
            return true;
        }
        break;
    case IA64_OP_EPC:
        gen_helper_epc(tcg_env, tcg_constant_i64(insn->address),
                       tcg_constant_i64(insn->raw),
                       tcg_constant_i32(insn->slot));
        if (skip == NULL) {
            ia64_gen_exit_to_completed(next_ip, insn->address);
            return true;
        }
        break;
    case IA64_OP_PAVG1:
    case IA64_OP_PAVG2:
    case IA64_OP_PAVGSUB1:
    case IA64_OP_PAVGSUB2: {
        uint32_t sel;
        if (insn->opcode == IA64_OP_PAVG1) sel = insn->imm ? 4 : 0;
        else if (insn->opcode == IA64_OP_PAVG2) sel = insn->imm ? 5 : 1;
        else if (insn->opcode == IA64_OP_PAVGSUB1) sel = 2;
        else sel = 3;
        gen_helper_simd_pavg(tcg_env, tcg_constant_i32(sel),
                              tcg_constant_i32(insn->r1),
                              tcg_constant_i32(insn->r2),
                              tcg_constant_i32(insn->r3));
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    }
    case IA64_OP_PCMP1_EQ:
    case IA64_OP_PCMP1_GT:
    case IA64_OP_PCMP2_EQ:
    case IA64_OP_PCMP2_GT:
    case IA64_OP_PCMP4_EQ:
    case IA64_OP_PCMP4_GT: {
        uint32_t sel;
        if (insn->opcode == IA64_OP_PCMP1_EQ) sel = 0;
        else if (insn->opcode == IA64_OP_PCMP1_GT) sel = 1;
        else if (insn->opcode == IA64_OP_PCMP2_EQ) sel = 2;
        else if (insn->opcode == IA64_OP_PCMP2_GT) sel = 3;
        else if (insn->opcode == IA64_OP_PCMP4_EQ) sel = 4;
        else sel = 5;
        gen_helper_simd_pcmp(tcg_env, tcg_constant_i32(sel),
                              tcg_constant_i32(insn->r1),
                              tcg_constant_i32(insn->r2),
                              tcg_constant_i32(insn->r3));
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    }
    case IA64_OP_PMAX1_U:
    case IA64_OP_PMAX2:
    case IA64_OP_PMIN1_U:
    case IA64_OP_PMIN2: {
        uint32_t sel;
        if (insn->opcode == IA64_OP_PMAX1_U) sel = 0;
        else if (insn->opcode == IA64_OP_PMIN1_U) sel = 1;
        else if (insn->opcode == IA64_OP_PMAX2) sel = 2;
        else sel = 3;
        gen_helper_simd_pminmax(tcg_env, tcg_constant_i32(sel),
                                 tcg_constant_i32(insn->r1),
                                 tcg_constant_i32(insn->r2),
                                 tcg_constant_i32(insn->r3));
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    }
    case IA64_OP_PMPY2_L:
    case IA64_OP_PMPY2_R:
    case IA64_OP_PMPYSH2:
    case IA64_OP_PMPYSH2_U: {
        uint32_t sel;
        if (insn->opcode == IA64_OP_PMPY2_L) sel = 0;
        else if (insn->opcode == IA64_OP_PMPY2_R) sel = 1;
        else if (insn->opcode == IA64_OP_PMPYSH2) sel = 2;
        else sel = 3;
        gen_helper_simd_pmpy(tcg_env, tcg_constant_i32(sel),
                              tcg_constant_i32(insn->r1),
                              tcg_constant_i32(insn->r2),
                              tcg_constant_i32(insn->r3),
                              tcg_constant_i32(insn->imm));
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    }
    case IA64_OP_PSHL2:
        ia64_gen_pshl(insn, 16);
        break;
    case IA64_OP_PSHL4:
        ia64_gen_pshl(insn, 32);
        break;
    case IA64_OP_PSAD1:
        gen_helper_simd_psad1(tcg_env,
                               tcg_constant_i32(insn->r1),
                               tcg_constant_i32(insn->r2),
                               tcg_constant_i32(insn->r3));
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    case IA64_OP_MUX1:
    case IA64_OP_MUX2:
        gen_helper_simd_mux(tcg_env,
                             tcg_constant_i32(insn->opcode == IA64_OP_MUX1 ? 0 : 1),
                             tcg_constant_i32(insn->r1),
                             tcg_constant_i32(insn->r2),
                             tcg_constant_i32(insn->imm));
        ia64_gen_gr_nat_from_1(insn->r1, insn->r2);
        break;
    case IA64_OP_MIX1_L:
    case IA64_OP_MIX1_R:
    case IA64_OP_MIX2_L:
    case IA64_OP_MIX2_R:
    case IA64_OP_MIX4_L:
    case IA64_OP_MIX4_R: {
        uint32_t sel;
        if (insn->opcode == IA64_OP_MIX1_L) sel = 0;
        else if (insn->opcode == IA64_OP_MIX1_R) sel = 1;
        else if (insn->opcode == IA64_OP_MIX2_L) sel = 2;
        else if (insn->opcode == IA64_OP_MIX2_R) sel = 3;
        else if (insn->opcode == IA64_OP_MIX4_L) sel = 4;
        else sel = 5;
        gen_helper_simd_mix(tcg_env, tcg_constant_i32(sel),
                             tcg_constant_i32(insn->r1),
                             tcg_constant_i32(insn->r2),
                             tcg_constant_i32(insn->r3));
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    }
    case IA64_OP_PACK2_SSS:
    case IA64_OP_PACK2_USS:
    case IA64_OP_PACK4_SSS: {
        uint32_t sel;
        if (insn->opcode == IA64_OP_PACK2_SSS) sel = 0;
        else if (insn->opcode == IA64_OP_PACK2_USS) sel = 1;
        else sel = 2;
        gen_helper_simd_pack(tcg_env, tcg_constant_i32(sel),
                              tcg_constant_i32(insn->r1),
                              tcg_constant_i32(insn->r2),
                              tcg_constant_i32(insn->r3));
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    }
    case IA64_OP_UNPACK1_H:
    case IA64_OP_UNPACK1_L:
    case IA64_OP_UNPACK2_H:
    case IA64_OP_UNPACK2_L:
    case IA64_OP_UNPACK4_H:
    case IA64_OP_UNPACK4_L: {
        uint32_t sel;
        if (insn->opcode == IA64_OP_UNPACK1_H) sel = 0;
        else if (insn->opcode == IA64_OP_UNPACK1_L) sel = 1;
        else if (insn->opcode == IA64_OP_UNPACK2_H) sel = 2;
        else if (insn->opcode == IA64_OP_UNPACK2_L) sel = 3;
        else if (insn->opcode == IA64_OP_UNPACK4_H) sel = 4;
        else sel = 5;
        gen_helper_simd_unpack(tcg_env, tcg_constant_i32(sel),
                                tcg_constant_i32(insn->r1),
                                tcg_constant_i32(insn->r2),
                                tcg_constant_i32(insn->r3));
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    }
    case IA64_OP_SUM:
        gen_helper_simd_sum(tcg_env,
                             tcg_constant_i32(insn->r1),
                             tcg_constant_i32(insn->r2),
                             tcg_constant_i32(insn->r3));
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    case IA64_OP_CZX1_L:
    case IA64_OP_CZX1_R:
    case IA64_OP_CZX2_L:
    case IA64_OP_CZX2_R: {
        uint32_t sel;
        if (insn->opcode == IA64_OP_CZX1_L) sel = 0;
        else if (insn->opcode == IA64_OP_CZX1_R) sel = 1;
        else if (insn->opcode == IA64_OP_CZX2_L) sel = 2;
        else sel = 3;
        gen_helper_simd_czx(tcg_env, tcg_constant_i32(sel),
                             tcg_constant_i32(insn->r1),
                             tcg_constant_i32(insn->r3),
                             tcg_constant_i32(0));
        ia64_gen_gr_nat_from_1(insn->r1, insn->r3);
        break;
    }
    case IA64_OP_ILLEGAL:
        ia64_gen_raise_exception(IA64_EXCP_ILLEGAL, insn->address,
                                  insn->raw, insn->slot);
        if (skip == NULL) {
            return true;
        }
        break;
    }

    ia64_gen_predicate_end(skip);
    ia64_gen_note_successful_bundle(insn->address);
    return false;
}

static void ia64_cpu_set_pc(CPUState *cs, vaddr value)
{
    IA64CPU *cpu = IA64_CPU(cs);

    cpu->env.ip = value;
}

static vaddr ia64_cpu_get_pc(CPUState *cs)
{
    IA64CPU *cpu = IA64_CPU(cs);

    return cpu->env.ip;
}

/* ---- Local SAPIC helpers ---- */

static int sapic_find_isr(CPUIA64State *env);

static bool sapic_vector_active(const uint64_t bitmap[4], int vector)
{
    return bitmap[vector / 64] & (1ULL << (vector % 64));
}

static int sapic_vector_priority(int vector)
{
    if (vector == 2) {
        return 257;
    }
    if (vector == 0) {
        return 256;
    }
    if (vector >= 16) {
        return vector;
    }
    return -1;
}

static bool sapic_vector_unmasked(CPUIA64State *env, int vector)
{
    uint64_t tpr = env->cr[IA64_CR_SAPIC_TPR];
    int isr = sapic_find_isr(env);

    if (sapic_vector_priority(vector) <= sapic_vector_priority(isr)) {
        return false;
    }

    if (vector == 2) {
        return true;
    }
    if (vector == 0) {
        return !(tpr & IA64_TPR_MMI);
    }
    return !(tpr & IA64_TPR_MMI) &&
           ((uint64_t)(vector & 0xF0) > (tpr & IA64_TPR_MIC_MASK));
}

static int sapic_find_irr(CPUIA64State *env)
{
    int i;

    if (sapic_vector_active(env->sapic_irr, 2) &&
        sapic_vector_unmasked(env, 2)) {
        return 2;
    }
    if (sapic_vector_active(env->sapic_irr, 0) &&
        sapic_vector_unmasked(env, 0)) {
        return 0;
    }
    for (i = 255; i >= 16; i--) {
        if (sapic_vector_active(env->sapic_irr, i) &&
            sapic_vector_unmasked(env, i)) {
            return i;
        }
    }
    return IA64_SPURIOUS_VECTOR;
}

static int sapic_find_isr(CPUIA64State *env)
{
    int i;

    if (sapic_vector_active(env->sapic_isr, 2)) {
        return 2;
    }
    if (sapic_vector_active(env->sapic_isr, 0)) {
        return 0;
    }
    for (i = 255; i >= 16; i--) {
        if (sapic_vector_active(env->sapic_isr, i)) {
            return i;
        }
    }
    return IA64_SPURIOUS_VECTOR;
}

void ia64_sapic_update_interrupt(CPUIA64State *env)
{
    CPUState *cs = env_cpu(env);

    if (sapic_find_irr(env) != IA64_SPURIOUS_VECTOR) {
        cpu_set_interrupt(cs, CPU_INTERRUPT_HARD);
        if (!qemu_cpu_is_self(cs)) {
            qemu_cpu_kick(cs);
        }
    } else {
        cpu_reset_interrupt(cs, CPU_INTERRUPT_HARD);
    }
}

bool ia64_sapic_has_pending(CPUIA64State *env)
{
    int vector = sapic_find_irr(env);
    return vector != IA64_SPURIOUS_VECTOR;
}

static uint8_t ia64_itv_vector(CPUIA64State *env)
{
    uint8_t vector = env->cr[IA64_CR_ITV] & 0xFF;

    return vector >= 16 ? vector : IA64_TIMER_VECTOR;
}

static bool ia64_itv_masked(CPUIA64State *env)
{
    return env->cr[IA64_CR_ITV] & IA64_VECTOR_MASKED;
}

static void ia64_sapic_clear_irr(CPUIA64State *env, uint8_t vector)
{
    int idx = vector / 64;
    int bit = vector % 64;

    env->sapic_irr[idx] &= ~(1ULL << bit);
    ia64_sapic_update_interrupt(env);
}

int ia64_sapic_accept(CPUIA64State *env)
{
    int vector = sapic_find_irr(env);
    if (vector != IA64_SPURIOUS_VECTOR) {
        int idx = vector / 64;
        int bit = vector % 64;
        env->sapic_irr[idx] &= ~(1ULL << bit);
        env->sapic_isr[idx] |= (1ULL << bit);
        ia64_sapic_update_interrupt(env);
    }
    return vector;
}

void ia64_sapic_eoi(CPUIA64State *env)
{
    int vector = sapic_find_isr(env);
    if (vector != IA64_SPURIOUS_VECTOR) {
        int idx = vector / 64;
        int bit = vector % 64;
        env->sapic_isr[idx] &= ~(1ULL << bit);
    }
    ia64_sapic_update_interrupt(env);
}

int ia64_sapic_get_ivr(CPUIA64State *env)
{
    return ia64_sapic_accept(env);
}

void ia64_sapic_set_irq(CPUState *cs, uint8_t vector)
{
    IA64CPU *cpu = IA64_CPU(cs);
    int idx = vector / 64;
    int bit = vector % 64;

    cpu->env.sapic_irr[idx] |= (1ULL << bit);
    ia64_sapic_update_interrupt(&cpu->env);
}

static void ia64_itm_raise(CPUIA64State *env, uint64_t itm_value)
{
    IA64CPU *cpu = container_of(env, IA64CPU, env);

    if (env->itm_last_match_valid && env->itm_last_match == itm_value) {
        ia64_sapic_update_interrupt(env);
        return;
    }

    env->itm_last_match = itm_value;
    env->itm_last_match_valid = true;
    ia64_sapic_set_irq(CPU(cpu), ia64_itv_vector(env));
}

static bool ia64_itm_update_pending(CPUIA64State *env, uint64_t itc,
                                    uint64_t itm_value, bool was_armed)
{
    int64_t delta_ticks = (int64_t)(itm_value - itc);

    if (ia64_itv_masked(env)) {
        ia64_sapic_clear_irr(env, ia64_itv_vector(env));
        return true;
    }

    if (delta_ticks > 0) {
        return false;
    }

    /*
     * The architecture raises an interval timer interrupt when ITC equals
     * ITM.  A freshly programmed value already behind the current ITC has
     * missed that equality and must not synthesize an interrupt.  If this
     * value was armed while it was still in the future, a late QEMU timer
     * callback still represents the equality that elapsed in virtual time.
     */
    if (delta_ticks == 0 || was_armed) {
        ia64_itm_raise(env, itm_value);
    }
    return true;
}

static void ia64_itm_timer_cb(void *opaque)
{
    IA64CPU *cpu = opaque;
    uint64_t itc, itm;
    bool was_armed;

    if (!cpu->env.itm_armed) {
        return;
    }
    was_armed = cpu->env.itm_armed;
    cpu->env.itm_armed = false;
    itc = ia64_itc_read(&cpu->env);
    itm = cpu->env.cr[1];

    if (!ia64_itm_update_pending(&cpu->env, itc, itm, was_armed)) {
        ia64_itm_update(&cpu->env, itm);
    }
}

void ia64_itm_update(CPUIA64State *env, uint64_t itm_value)
{
    IA64CPU *cpu = container_of(env, IA64CPU, env);
    uint64_t itc = ia64_itc_read(env);
    int64_t delta_ticks = (int64_t)(itm_value - itc);
    int64_t delay_ns;
    bool was_armed = env->itm_armed && env->itm_armed_value == itm_value;

    timer_del(cpu->itm_timer);
    env->itm_armed = false;

    if (ia64_itm_update_pending(env, itc, itm_value, was_armed)) {
        return;
    }

    if (delta_ticks > INT64_MAX / IA64_ITC_NS_PER_TICK) {
        delay_ns = INT64_MAX;
    } else {
        delay_ns = delta_ticks * IA64_ITC_NS_PER_TICK;
    }
    env->itm_armed = true;
    env->itm_armed_value = itm_value;
    timer_mod(cpu->itm_timer, ia64_itc_clock_ns() + delay_ns);
}

static bool ia64_cpu_has_work(CPUState *cs)
{
    IA64CPU *cpu = IA64_CPU(cs);
    CPUIA64State *env = &cpu->env;
    bool pending_extint;

    if (cs->halted) {
        uint64_t itc = ia64_itc_read(env);
        bool was_armed = env->itm_armed &&
                         env->itm_armed_value == env->cr_itm;

        if (was_armed && (int64_t)(env->cr_itm - itc) <= 0) {
            env->itm_armed = false;
        }
        ia64_itm_update_pending(env, itc, env->cr_itm, was_armed);
    }
    pending_extint = ia64_sapic_has_pending(env);

    return pending_extint && (cs->halted || (env->psr & IA64_PSR_I));
}

static TCGTBCPUState ia64_get_tb_cpu_state(CPUState *cs)
{
    IA64CPU *cpu = IA64_CPU(cs);
    uint32_t flags = 0;

    if (cpu->env.psr & IA64_PSR_DT) {
        flags |= IA64_TB_FLAG_DT;
    }
    if (cpu->env.psr & IA64_PSR_IT) {
        flags |= IA64_TB_FLAG_IT;
    }
    flags |= ((cpu->env.psr & IA64_PSR_RI_MASK) >> IA64_PSR_RI_SHIFT)
             << IA64_TB_FLAG_RI_SHIFT;

    return (TCGTBCPUState) {
        .pc = cpu->env.ip,
        .flags = flags,
    };
}

bool ia64_tlb_match(const IA64TlbEntry *entry, uint64_t va,
                           uint32_t rid, bool is_ifetch)
{
    uint64_t mask;

    (void)is_ifetch;

    if (!entry->valid || entry->ps == 0) {
        return false;
    }
    if (entry->rid != rid) {
        return false;
    }

    mask = entry->ps - 1;
    return (va & ~mask) == (entry->va & ~mask);
}

const IA64TlbEntry *ia64_tlb_find(const IA64TlbEntry *tlb, uint8_t tlb_count,
                                  uint64_t va, uint32_t rid, bool is_ifetch)
{
    uint8_t i;

    for (i = 0; i < tlb_count; i++) {
        if (ia64_tlb_match(&tlb[i], va, rid, is_ifetch)) {
            return &tlb[i];
        }
    }
    return NULL;
}

bool ia64_tlb_lookup(const IA64TlbEntry *tlb, uint8_t tlb_count,
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

static void ia64_cpu_synchronize_from_tb(CPUState *cs,
                                         const TranslationBlock *tb)
{
    IA64CPU *cpu = IA64_CPU(cs);

    tcg_debug_assert(!tcg_cflags_has(cs, CF_PCREL));
    cpu->env.ip = tb->pc;
}

static void ia64_restore_state_to_opc(CPUState *cs,
                                       const TranslationBlock *tb,
                                       const uint64_t *data)
{
    IA64CPU *cpu = IA64_CPU(cs);

    cpu->env.ip = data[0];
}

static int ia64_cpu_mmu_index(CPUState *cs, bool ifetch)
{
    IA64CPU *cpu = IA64_CPU(cs);

    if (cpu->env.psr & (ifetch ? IA64_PSR_IT : IA64_PSR_DT)) {
        return MMU_IDX_VIRT;
    }
    return MMU_PHYS_IDX;
}

#ifndef CONFIG_USER_ONLY
static G_NORETURN void ia64_cpu_do_unaligned_access(CPUState *cs, vaddr addr,
                                                    MMUAccessType access_type,
                                                    int mmu_idx,
                                                    uintptr_t retaddr)
{
    IA64CPU *cpu = IA64_CPU(cs);
    CPUIA64State *env = &cpu->env;

    (void)mmu_idx;
    cpu_restore_state(cs, retaddr);
    env->fault_ip = env->ip;
    env->fault_imm = 0;
    env->cr_ifa = addr;
    env->cr_isr = access_type == MMU_DATA_STORE ? IA64_ISR_W : IA64_ISR_R;
    env->exception = IA64_EXCP_UNALIGNED;
    cs->exception_index = IA64_EXCP_UNALIGNED;
    cpu_loop_exit(cs);
}
#endif

static int ia64_tlb_perm_to_prot(uint8_t perm)
{
    int prot = 0;

    if (perm & IA64_TLB_R) {
        prot |= PAGE_READ;
    }
    if (perm & IA64_TLB_W) {
        prot |= PAGE_WRITE;
    }
    if (perm & IA64_TLB_X) {
        prot |= PAGE_EXEC;
    }
    return prot;
}

static void ia64_tlb_set_entry_page(CPUState *cs, vaddr addr, hwaddr pa,
                                    uint64_t page_size, int prot,
                                    int mmu_idx)
{
    vaddr page = addr & TARGET_PAGE_MASK;

    (void)page_size;
    tlb_set_page(cs, page, pa & TARGET_PAGE_MASK, prot, mmu_idx,
                 TARGET_PAGE_SIZE);
}

static hwaddr ia64_cpu_get_phys_page_debug(CPUState *cs, vaddr addr)
{
    IA64CPU *cpu = IA64_CPU(cs);
    uint64_t pa;
    uint8_t perm;
    uint32_t rid;

    if (!(cpu->env.psr & IA64_PSR_IT)) {
        return addr;
    }

    if (ia64_firmware_identity_pa(addr, &pa)) {
        return pa & TARGET_PAGE_MASK;
    }

    if (ia64_sal_boot_virtual_pa(&cpu->env, addr, &pa)) {
        return pa & TARGET_PAGE_MASK;
    }

    rid = ia64_region_rid(&cpu->env, addr);
    if (ia64_tlb_lookup(cpu->env.tlb_inst, cpu->env.tlb_inst_count,
                        addr, rid, ia64_psr_cpl(cpu->env.psr), true,
                        &pa, &perm)) {
        return pa & TARGET_PAGE_MASK;
    }
    if (ia64_sal_boot_identity_pa(&cpu->env, addr, &pa)) {
        return pa & TARGET_PAGE_MASK;
    }
    return addr;
}

static bool ia64_cpu_tlb_fill(CPUState *cs, vaddr addr, int size,
                              MMUAccessType access_type, int mmu_idx,
                              bool probe, uintptr_t retaddr)
{
    IA64CPU *cpu = IA64_CPU(cs);
    const IA64TlbEntry *tlb;
    uint8_t tlb_count;
    bool is_ifetch = (access_type == MMU_INST_FETCH);
    uint8_t needed = is_ifetch ? IA64_TLB_X :
                     (access_type == MMU_DATA_STORE ? IA64_TLB_W :
                      IA64_TLB_R);
    uint64_t pa;
    uint8_t perm;
    uint32_t rid;
    IA64Exception excp;

    if (mmu_idx == MMU_PHYS_IDX) {
        vaddr page = addr & TARGET_PAGE_MASK;
        tlb_set_page(cs, page, page,
                     PAGE_READ | PAGE_WRITE | PAGE_EXEC,
                     mmu_idx, TARGET_PAGE_SIZE);
        return true;
    }

    if (ia64_firmware_identity_pa(addr, &pa)) {
        vaddr page = addr & TARGET_PAGE_MASK;
        int prot = is_ifetch ? PAGE_EXEC : (PAGE_READ | PAGE_WRITE);

        tlb_set_page(cs, page, pa & TARGET_PAGE_MASK, prot, mmu_idx,
                     TARGET_PAGE_SIZE);
        return true;
    }

    if (ia64_sal_boot_virtual_pa(&cpu->env, addr, &pa)) {
        vaddr page = addr & TARGET_PAGE_MASK;
        int prot = is_ifetch ? PAGE_EXEC : (PAGE_READ | PAGE_WRITE);

        qemu_log_mask(CPU_LOG_MMU,
                      "ia64 firmware identity %c va=0x%016" PRIx64
                      " pa=0x%016" PRIx64 " psr=0x%016" PRIx64 "\n",
                      is_ifetch ? 'i' :
                      (access_type == MMU_DATA_STORE ? 'w' : 'd'),
                      (uint64_t)addr, pa, cpu->env.psr);
        tlb_set_page(cs, page, pa & TARGET_PAGE_MASK, prot, mmu_idx,
                     TARGET_PAGE_SIZE);
        return true;
    }

    rid = ia64_region_rid(&cpu->env, addr);
    if (is_ifetch) {
        tlb = cpu->env.tlb_inst;
        tlb_count = cpu->env.tlb_inst_count;
    } else {
        tlb = cpu->env.tlb_data;
        tlb_count = cpu->env.tlb_data_count;
    }

    {
        const IA64TlbEntry *entry = ia64_tlb_find(tlb, tlb_count, addr, rid,
                                                  is_ifetch);

        if (entry) {
            int prot;
            IA64Exception pte_excp;

            ia64_tlb_entry_translate(entry, addr, ia64_psr_cpl(cpu->env.psr),
                                     &pa, &perm);
            pte_excp = ia64_pte_exception_for_access(
                entry->pte, perm, needed, is_ifetch,
                access_type == MMU_DATA_STORE, cpu->env.psr);
            if (pte_excp != IA64_EXCP_NONE) {
                if (probe) {
                    return false;
                }
                excp = pte_excp;
                goto raise_exception;
            }
            prot = ia64_tlb_perm_to_prot(perm);
            qemu_log_mask(CPU_LOG_MMU,
                          "ia64 tlb hit %c va=0x%016" PRIx64
                          " rid=0x%06" PRIx32 " pa=0x%016" PRIx64
                          " perm=0x%x\n",
                          is_ifetch ? 'i' : 'd', (uint64_t)addr, rid, pa,
                          perm);
            ia64_tlb_set_entry_page(cs, addr, pa, entry->ps, prot, mmu_idx);
            return true;
        }
    }

    if (!is_ifetch &&
        ia64_kernel_direct_data_pa(cpu->env.psr,
                                   cpu->env.rr[ia64_rr_index(addr)],
                                   addr, &pa)) {
        vaddr page = addr & TARGET_PAGE_MASK;
        tlb_set_page(cs, page, pa & TARGET_PAGE_MASK,
                     PAGE_READ | PAGE_WRITE, mmu_idx, TARGET_PAGE_SIZE);
        return true;
    }

    if (!is_ifetch) {
        uint64_t pte = 0;

        if (ia64_vhpt_walk_full(&cpu->env, addr, rid, false, &pa, &perm,
                                &pte)) {
            int prot;
            IA64Exception pte_excp;
            const IA64TlbEntry *new_entry =
                ia64_tlb_find(cpu->env.tlb_data, cpu->env.tlb_data_count,
                              addr, rid, false);
            uint64_t page_size = new_entry ? new_entry->ps : TARGET_PAGE_SIZE;

            pte_excp = ia64_pte_exception_for_access(
                pte, perm, needed, false, access_type == MMU_DATA_STORE,
                cpu->env.psr);
            if (pte_excp != IA64_EXCP_NONE) {
                if (probe) {
                    return false;
                }
                excp = pte_excp;
                goto raise_exception;
            }
            prot = ia64_tlb_perm_to_prot(perm);
            qemu_log_mask(CPU_LOG_MMU,
                          "ia64 vhpt hit d va=0x%016" PRIx64
                          " rid=0x%06" PRIx32 " pa=0x%016" PRIx64
                          " perm=0x%x iha=0x%016" PRIx64 "\n",
                          (uint64_t)addr, rid, pa, perm,
                          ia64_vhpt_hash_address(&cpu->env, addr));
            ia64_tlb_set_entry_page(cs, addr, pa, page_size, prot, mmu_idx);
            return true;
        }
    }

    if (is_ifetch) {
        uint64_t pte = 0;

        if (ia64_vhpt_walk_full(&cpu->env, addr, rid, true, &pa, &perm,
                                &pte)) {
            int prot;
            IA64Exception pte_excp;
            const IA64TlbEntry *new_entry =
                ia64_tlb_find(cpu->env.tlb_inst, cpu->env.tlb_inst_count,
                              addr, rid, true);
            uint64_t page_size = new_entry ? new_entry->ps : TARGET_PAGE_SIZE;

            pte_excp = ia64_pte_exception_for_access(
                pte, perm, needed, true, false, cpu->env.psr);
            if (pte_excp != IA64_EXCP_NONE) {
                if (probe) {
                    return false;
                }
                excp = pte_excp;
                goto raise_exception;
            }
            prot = ia64_tlb_perm_to_prot(perm);
            qemu_log_mask(CPU_LOG_MMU,
                          "ia64 vhpt hit i va=0x%016" PRIx64
                          " rid=0x%06" PRIx32 " pa=0x%016" PRIx64
                          " perm=0x%x iha=0x%016" PRIx64 "\n",
                          (uint64_t)addr, rid, pa, perm,
                          ia64_vhpt_hash_address(&cpu->env, addr));
            ia64_tlb_set_entry_page(cs, addr, pa, page_size, prot, mmu_idx);
            return true;
        }
    }
    if (ia64_sal_boot_identity_pa(&cpu->env, addr, &pa)) {
        vaddr page = addr & TARGET_PAGE_MASK;
        int prot = is_ifetch ? PAGE_EXEC : (PAGE_READ | PAGE_WRITE);

        qemu_log_mask(CPU_LOG_MMU,
                      "ia64 sal boot identity %c va=0x%016" PRIx64
                      " pa=0x%016" PRIx64 " psr=0x%016" PRIx64 "\n",
                      is_ifetch ? 'i' :
                      (access_type == MMU_DATA_STORE ? 'w' : 'd'),
                      (uint64_t)addr, pa, cpu->env.psr);
        tlb_set_page(cs, page, pa & TARGET_PAGE_MASK, prot, mmu_idx,
                     TARGET_PAGE_SIZE);
        return true;
    }
    if (probe) {
        return false;
    }

    {
        uint64_t vhpt_entry_va;
        uint8_t vhpt_size;
        bool vhpt_long_format;
        bool vhpt_enabled = ia64_vhpt_walker_enabled(&cpu->env, addr,
                                                     is_ifetch,
                                                     &vhpt_size,
                                                     &vhpt_long_format);

        if (!is_ifetch && ia64_data_nested_tlb_active(&cpu->env)) {
            excp = IA64_EXCP_DATA_NESTED_TLB;
        } else if (vhpt_enabled &&
                   ia64_vhpt_pte_not_present(&cpu->env, addr, is_ifetch,
                                              &vhpt_entry_va)) {
            excp = IA64_EXCP_PAGE_NOT_PRESENT;
        } else if (!ia64_vhpt_entry_accessible(&cpu->env, addr, is_ifetch,
                                               &vhpt_entry_va)) {
            excp = IA64_EXCP_VHPT_FAULT;
        } else if (vhpt_enabled) {
            excp = is_ifetch ? IA64_EXCP_ITLB_FAULT : IA64_EXCP_DTLB_FAULT;
        } else {
            excp = is_ifetch ? IA64_EXCP_ALT_ITLB : IA64_EXCP_ALT_DTLB;
        }
    }
raise_exception:
    if (cpu->env.psr & IA64_PSR_IC) {
        cpu->env.cr_ifa = addr;
        if (ia64_exception_initializes_iha(excp)) {
            cpu->env.cr_iha = ia64_vhpt_hash_address(&cpu->env, addr);
        }
        cpu->env.cr_itir = ia64_region_itir(
            &cpu->env, excp == IA64_EXCP_VHPT_FAULT ? cpu->env.cr_iha : addr);
    }
    if (excp != IA64_EXCP_DATA_NESTED_TLB) {
        cpu->env.cr_isr = is_ifetch ? IA64_ISR_X :
                          (access_type == MMU_DATA_STORE ? IA64_ISR_W :
                           IA64_ISR_R);
        if (!is_ifetch && ia64_current_code_tlb_ed(&cpu->env)) {
            cpu->env.cr_isr |= IA64_ISR_ED;
        }
    }
    qemu_log_mask(CPU_LOG_MMU,
                  "ia64 tlb miss %c va=0x%016" PRIx64
                  " rid=0x%06" PRIx32 " ps=0x%016" PRIx64
                  " iha=0x%016" PRIx64 " pta=0x%016" PRIx64
                  " isr=0x%016" PRIx64 "\n",
                  is_ifetch ? 'i' :
                  (access_type == MMU_DATA_STORE ? 'w' : 'r'),
                  (uint64_t)addr, rid, cpu->env.cr_itir,
                  cpu->env.cr_iha, cpu->env.cr_pta, cpu->env.cr_isr);
    cs->exception_index = excp;
    cpu_loop_exit_restore(cs, retaddr);
}

static bool ia64_exception_writes_ifa(IA64Exception excp)
{
    switch (excp) {
    case IA64_EXCP_VHPT_FAULT:
    case IA64_EXCP_ITLB_FAULT:
    case IA64_EXCP_DTLB_FAULT:
    case IA64_EXCP_ALT_ITLB:
    case IA64_EXCP_ALT_DTLB:
    case IA64_EXCP_DATA_ACCESS:
    case IA64_EXCP_INST_ACCESS:
    case IA64_EXCP_DATA_DIRTY:
    case IA64_EXCP_INST_ACCESS_BIT:
    case IA64_EXCP_DATA_ACCESS_BIT:
    case IA64_EXCP_NAT_CONSUMPTION:
    case IA64_EXCP_UNALIGNED:
    case IA64_EXCP_PAGE_NOT_PRESENT:
        return true;
    default:
        return false;
    }
}

static void ia64_deliver_exception(CPUState *cs, IA64Exception excp,
                                   uint64_t fault_addr, uint8_t slot)
{
    IA64CPU *cpu = IA64_CPU(cs);
    uint64_t vector;
    uint64_t ifm;
    uint64_t isr_status = 0;
    bool psr_ic_inflight;
    bool collect;
    static unsigned excp_logs;

    if (excp >= IA64_EXCP_MAX || excp == IA64_EXCP_NONE) {
        return;
    }

    vector = ia64_ivt_vectors[excp];
    ifm = IA64_IFS_V |
          cpu->env.cfm_sof |
          ((uint64_t)cpu->env.cfm_sol << IA64_CFM_SOL_SHIFT) |
          ((uint64_t)cpu->env.cfm_sor << IA64_CFM_SOR_SHIFT) |
          ((uint64_t)cpu->env.cfm_rrb_gr << IA64_CFM_RRB_GR_SHIFT);
    switch (excp) {
    case IA64_EXCP_VHPT_FAULT:
    case IA64_EXCP_ITLB_FAULT:
    case IA64_EXCP_DTLB_FAULT:
    case IA64_EXCP_ALT_ITLB:
    case IA64_EXCP_ALT_DTLB:
    case IA64_EXCP_DATA_NESTED_TLB:
    case IA64_EXCP_DATA_ACCESS:
    case IA64_EXCP_INST_ACCESS:
    case IA64_EXCP_DATA_DIRTY:
    case IA64_EXCP_INST_ACCESS_BIT:
    case IA64_EXCP_DATA_ACCESS_BIT:
    case IA64_EXCP_NAT_CONSUMPTION:
    case IA64_EXCP_UNALIGNED:
    case IA64_EXCP_PAGE_NOT_PRESENT:
        isr_status = cpu->env.cr_isr;
        break;
    default:
        break;
    }
    if (excp_logs++ < 32) {
        qemu_log_mask(CPU_LOG_INT,
                      "ia64 exception excp=%u vector=0x%04x ip=0x%016" PRIx64
                      " fault=0x%016" PRIx64 " slot=%u psr=0x%016" PRIx64
                      " ifa=0x%016" PRIx64 " isr=0x%016" PRIx64 "\n",
                      excp, ia64_ivt_vectors[excp], cpu->env.ip, fault_addr,
                      slot, cpu->env.psr, cpu->env.cr_ifa,
                      cpu->env.cr_isr);
    }
    psr_ic_inflight = cpu->env.psr_ic_inflight;
    collect = cpu->env.psr & IA64_PSR_IC;
    if (collect) {
        if (cpu->env.excp_frame_depth < IA64_EXCP_FRAME_MAX) {
            uint32_t depth = cpu->env.excp_frame_depth++;
            IA64ExceptionFrame *frame = &cpu->env.excp_frames[depth];

            memcpy(frame->gr, &cpu->env.gr[32], sizeof(frame->gr));
            memcpy(frame->nat, cpu->env.nat, sizeof(frame->nat));
            frame->ipsr = cpu->env.cr_ipsr;
            frame->iip = cpu->env.cr_iip;
            frame->ifs = cpu->env.cr_ifs;
            frame->ifm = ifm;
            frame->bsp = cpu->env.ar_bsp;
            frame->bspstore = cpu->env.ar_bspstore;
            frame->ifa = cpu->env.cr_ifa;
            frame->isr = cpu->env.cr_isr;
            frame->itir = cpu->env.cr_itir;
            frame->iipa = cpu->env.cr_iipa;
            frame->iim = cpu->env.cr_iim;
            frame->iha = cpu->env.cr_iha;
            frame->interrupted_iip = cpu->env.ip;
            frame->rnat = cpu->env.ar_rnat;
            /*
             * RSE bookkeeping is an emulator cache of stacked frame state.
             * Guest exception handlers may execute loadrs/flushrs/calls, but
             * those operations must not consume the interrupted frame cache.
             */
            frame->rse_cumulative_words = cpu->env.rse_cumulative_words;
            frame->rse_spill_words = cpu->env.rse_spill_words;
            frame->rse_spill_base = cpu->env.rse_spill_base;
            frame->rse_bspstore_switched = cpu->env.rse_bspstore_switched;
            frame->rse_flushed = cpu->env.rse_flushed;
            frame->rse_frame_depth = cpu->env.rse_frame_depth;
            frame->rse_cover_depth = cpu->env.rse_cover_depth;
            memcpy(frame->rse_frame_gr, cpu->env.rse_frame_gr,
                   frame->rse_frame_depth *
                   sizeof(cpu->env.rse_frame_gr[0]));
            memcpy(frame->rse_frame_nat, cpu->env.rse_frame_nat,
                   frame->rse_frame_depth *
                   sizeof(cpu->env.rse_frame_nat[0]));
            memcpy(frame->rse_frame_sof, cpu->env.rse_frame_sof,
                   frame->rse_frame_depth *
                   sizeof(cpu->env.rse_frame_sof[0]));
            memcpy(frame->rse_frame_sol, cpu->env.rse_frame_sol,
                   frame->rse_frame_depth *
                   sizeof(cpu->env.rse_frame_sol[0]));
            memcpy(frame->rse_frame_sor, cpu->env.rse_frame_sor,
                   frame->rse_frame_depth *
                   sizeof(cpu->env.rse_frame_sor[0]));
            memcpy(frame->rse_frame_rrb_gr, cpu->env.rse_frame_rrb_gr,
                   frame->rse_frame_depth *
                   sizeof(cpu->env.rse_frame_rrb_gr[0]));
            memcpy(frame->rse_frame_bsp, cpu->env.rse_frame_bsp,
                   frame->rse_frame_depth *
                   sizeof(cpu->env.rse_frame_bsp[0]));
            memcpy(frame->rse_frame_return_ip, cpu->env.rse_frame_return_ip,
                   frame->rse_frame_depth *
                   sizeof(cpu->env.rse_frame_return_ip[0]));
            memcpy(frame->rse_frame_cumulative_words,
                   cpu->env.rse_frame_cumulative_words,
                   frame->rse_frame_depth *
                   sizeof(cpu->env.rse_frame_cumulative_words[0]));
            memcpy(frame->rse_cover_gr, cpu->env.rse_cover_gr,
                   frame->rse_cover_depth *
                   sizeof(cpu->env.rse_cover_gr[0]));
            memcpy(frame->rse_cover_nat, cpu->env.rse_cover_nat,
                   frame->rse_cover_depth *
                   sizeof(cpu->env.rse_cover_nat[0]));
            memcpy(frame->rse_cover_sof, cpu->env.rse_cover_sof,
                   frame->rse_cover_depth *
                   sizeof(cpu->env.rse_cover_sof[0]));
            memcpy(frame->rse_cover_bsp, cpu->env.rse_cover_bsp,
                   frame->rse_cover_depth *
                   sizeof(cpu->env.rse_cover_bsp[0]));
        }
        cpu->env.cr_ipsr = (cpu->env.psr & ~IA64_PSR_RI_MASK) |
                           (((uint64_t)slot & 3) << IA64_PSR_RI_SHIFT);
        cpu->env.cr_iip = ia64_ip_bundle_addr(cpu->env.ip);
        if (ia64_exception_writes_ifa(excp)) {
            cpu->env.cr_ifa = fault_addr;
        }
        cpu->env.cr_iipa = cpu->env.last_successful_bundle;
        /*
         * A collected interruption records the interrupted IP/PSR and clears
         * IFS.v.  The interrupted frame remains current until the handler
         * executes cover, which then copies CFM into IFS.ifm.
         */
        cpu->env.cr_ifs = 0;

        if (excp == IA64_EXCP_BREAK) {
            cpu->env.cr_iim = cpu->env.fault_imm;
        }
    }

    if (excp != IA64_EXCP_DATA_NESTED_TLB) {
        cpu->env.cr_isr = isr_status;
        if (slot > 0) {
            cpu->env.cr_isr |= ((uint64_t)slot & 3) << IA64_ISR_EI_SHIFT;
        }
        if (!collect || psr_ic_inflight) {
            cpu->env.cr_isr |= IA64_ISR_NI;
        }
    }

    ia64_set_psr(&cpu->env, (cpu->env.psr &
                               ~(IA64_PSR_IC | IA64_PSR_I |
                                 IA64_PSR_CPL_MASK | IA64_PSR_RI_MASK |
                                 IA64_PSR_BN)));
    cpu->env.psr_ic_inflight = false;

    cpu->env.ip = (cpu->env.cr_iva & ~0x7fffULL) | vector;

    cpu->env.exception = 0;
    cpu->env.pending_extint = 0;
}

static bool ia64_debug_read(CPUState *cs, uint64_t addr, void *buf,
                            size_t size)
{
    return cpu_memory_rw_debug(cs, addr, buf, size, false) == 0;
}

static bool ia64_debug_write(CPUState *cs, uint64_t addr, const void *buf,
                             size_t size)
{
    return cpu_memory_rw_debug(cs, addr, (void *)buf, size, true) == 0;
}

static void ia64_resume_after_instruction(CPUIA64State *env, uint64_t ip,
                                          uint8_t slot)
{
    env->psr &= ~IA64_PSR_RI_MASK;
    if (slot >= 2) {
        env->ip = ip + 16;
    } else {
        env->ip = ip;
        env->psr |= (uint64_t)(slot + 1) << IA64_PSR_RI_SHIFT;
    }
}

static void ia64_gr_nat_clear_runtime(CPUIA64State *env, uint8_t reg)
{
    if (reg == 0) {
        return;
    }

    env->nat[reg / 64] &= ~(1ULL << (reg % 64));
}

static bool ia64_gr_nat_get_runtime(CPUIA64State *env, uint8_t reg)
{
    if (reg == 0) {
        return false;
    }

    return (env->nat[reg / 64] >> (reg % 64)) & 1;
}

static void ia64_gr_nat_set_runtime(CPUIA64State *env, uint8_t reg, bool nat)
{
    if (reg == 0) {
        return;
    }

    if (nat) {
        env->nat[reg / 64] |= 1ULL << (reg % 64);
    } else {
        env->nat[reg / 64] &= ~(1ULL << (reg % 64));
    }
}

static void ia64_unaligned_base_update(CPUIA64State *env,
                                       const Ia64Instruction *insn,
                                       uint64_t addr)
{
    if (insn->r3 == 0) {
        return;
    }

    if (insn->reg_base_update) {
        bool base_nat = ia64_gr_nat_get_runtime(env, insn->r3);
        bool inc_nat = ia64_gr_nat_get_runtime(env, insn->r2);

        env->gr[insn->r3] = addr + env->gr[insn->r2];
        ia64_gr_nat_set_runtime(env, insn->r3, base_nat || inc_nat);
    } else if (insn->imm != 0) {
        env->gr[insn->r3] = addr + insn->imm;
    }
}

static bool ia64_try_emulate_firmware_unaligned(CPUState *cs,
                                                uint64_t fault_addr,
                                                uint8_t fault_slot)
{
    IA64CPU *cpu = IA64_CPU(cs);
    CPUIA64State *env = &cpu->env;
    uint8_t bundle[16];
    uint8_t data[16];
    uint64_t low, high;
    uint8_t template_code;
    const IA64TemplateInfo *template_info;
    Ia64Instruction insn;
    uint64_t slots[3];
    uint64_t addr;
    MemOp memop;
    uint32_t size;

    /*
     * Model the SAL/firmware IVT's unaligned assist only before the guest has
     * installed its own IVA.  Page-spanning and semaphore references remain
     * architectural faults.
     */
    if (env->cr_iva != IA64_FIRMWARE_IVT_BASE ||
        !(env->psr & IA64_PSR_IC) ||
        (env->cr_isr & IA64_ISR_SP) ||
        fault_slot > 2) {
        return false;
    }

    if (!ia64_debug_read(cs, env->fault_ip, bundle, sizeof(bundle))) {
        return false;
    }

    low = ldq_le_p(bundle);
    high = ldq_le_p(bundle + 8);
    template_code = ia64_bundle_template_code(low);
    template_info = ia64_template_info(template_code);
    if (!template_info->defined) {
        return false;
    }

    slots[0] = ia64_bundle_slot(low, high, 0);
    slots[1] = ia64_bundle_slot(low, high, 1);
    slots[2] = ia64_bundle_slot(low, high, 2);
    insn = ia64_decode_insn((Ia64SlotUnit)template_info->units[fault_slot],
                            slots[fault_slot], env->fault_ip, fault_slot);
    if (!insn.valid) {
        return false;
    }

    if (ia64_opcode_has_firmware_unaligned_load_assist(insn.opcode)) {
        memop = ia64_memop_for_opcode(insn.opcode);
        size = ia64_memop_size(memop);
        addr = env->gr[insn.r3];
        if (addr != fault_addr ||
            ((addr & 0xfff) + size - 1) > 0xfff ||
            size > sizeof(data) ||
            !ia64_debug_read(cs, addr, data, size)) {
            return false;
        }

        if (insn.r1 != 0) {
            env->gr[insn.r1] = ldm_p(data, memop);
            if (ia64_opcode_is_fill_load(insn.opcode)) {
                uint64_t nat = (env->ar_unat >> ((addr >> 3) & 0x3f)) & 1;

                if (nat) {
                    ia64_gr_nat_set_runtime(env, insn.r1, true);
                } else {
                    ia64_gr_nat_clear_runtime(env, insn.r1);
                }
            } else {
                ia64_gr_nat_clear_runtime(env, insn.r1);
                if (ia64_opcode_is_advanced_load(insn.opcode)) {
                    helper_set_alat(env, insn.r1, addr, size);
                }
            }
        }
        ia64_unaligned_base_update(env, &insn, addr);
        ia64_resume_after_instruction(env, env->fault_ip, fault_slot);
        env->exception = IA64_EXCP_NONE;
        return true;
    }

    if (ia64_opcode_has_firmware_unaligned_store_assist(insn.opcode)) {
        memop = ia64_memop_for_opcode(insn.opcode);
        size = ia64_memop_size(memop);
        addr = env->gr[insn.r3];
        if (addr != fault_addr ||
            ((addr & 0xfff) + size - 1) > 0xfff ||
            size > sizeof(data)) {
            return false;
        }

        stm_p(data, memop, env->gr[insn.r2]);
        if (!ia64_debug_write(cs, addr, data, size)) {
            return false;
        }
        helper_invalidate_alat_store(env, addr, size);
        if (insn.opcode == IA64_OP_ST8SPILL) {
            helper_st_spill_unat(env, insn.r2, addr);
        }
        ia64_unaligned_base_update(env, &insn, addr);
        ia64_resume_after_instruction(env, env->fault_ip, fault_slot);
        env->exception = IA64_EXCP_NONE;
        return true;
    }

    return false;
}

static bool ia64_exception_is_translation_fault(IA64Exception excp)
{
    switch (excp) {
    case IA64_EXCP_VHPT_FAULT:
    case IA64_EXCP_ITLB_FAULT:
    case IA64_EXCP_DTLB_FAULT:
    case IA64_EXCP_ALT_ITLB:
    case IA64_EXCP_ALT_DTLB:
    case IA64_EXCP_DATA_NESTED_TLB:
        return true;
    default:
        return false;
    }
}

static bool ia64_exception_uses_psr_ri_slot(IA64Exception excp, uint64_t isr)
{
    switch (excp) {
    case IA64_EXCP_EXTINT:
    case IA64_EXCP_VHPT_FAULT:
    case IA64_EXCP_ITLB_FAULT:
    case IA64_EXCP_DTLB_FAULT:
    case IA64_EXCP_ALT_ITLB:
    case IA64_EXCP_ALT_DTLB:
    case IA64_EXCP_DATA_NESTED_TLB:
    case IA64_EXCP_INST_ACCESS:
    case IA64_EXCP_INST_ACCESS_BIT:
        return true;
    case IA64_EXCP_PAGE_NOT_PRESENT:
        return isr & IA64_ISR_X;
    default:
        return false;
    }
}

static void ia64_cpu_do_interrupt(CPUState *cs)
{
    IA64CPU *cpu = IA64_CPU(cs);
    int excp = cs->exception_index;
    uint64_t fault_addr;
    uint8_t slot;

    if (excp == IA64_EXCP_NONE) {
        return;
    }

    if (!(cpu->env.psr & IA64_PSR_IC) &&
        !ia64_exception_is_translation_fault(excp) &&
        cpu->env.cr_iva == 0 &&
        (excp == IA64_EXCP_BREAK ||
         excp == IA64_EXCP_ILLEGAL ||
         excp == IA64_EXCP_RESERVED_TEMPLATE)) {
        /*
         * Bare loader tests have no IVT.  Keep decoder/sentinel faults at
         * the faulting bundle for inspection, and use break as a monitor stop.
         * Other faults may deliberately target a handler at IVA-relative
         * vectors, even when IVA is zero.
         */
        if (excp == IA64_EXCP_BREAK) {
            cs->halted = 1;
            cs->exception_index = IA64_EXCP_NONE;
        } else {
            cpu->env.ip = cpu->env.fault_ip;
        }
        return;
    }

    fault_addr = cpu->env.cr_ifa;
    switch (excp) {
    case IA64_EXCP_BREAK:
    case IA64_EXCP_ILLEGAL:
    case IA64_EXCP_RESERVED_TEMPLATE:
        fault_addr = cpu->env.fault_ip;
        break;
    case IA64_EXCP_EXTINT:
        break;
    default:
        break;
    }
    slot = cpu->env.fault_slot;
    if (ia64_exception_uses_psr_ri_slot(excp, cpu->env.cr_isr)) {
        slot = (cpu->env.psr & IA64_PSR_RI_MASK) >> IA64_PSR_RI_SHIFT;
    }

    if (excp == IA64_EXCP_UNALIGNED &&
        ia64_try_emulate_firmware_unaligned(cs, fault_addr, slot)) {
        cs->exception_index = IA64_EXCP_NONE;
        return;
    }

    if (excp == IA64_EXCP_EXTINT) {
        if (sapic_find_irr(&cpu->env) != IA64_SPURIOUS_VECTOR) {
            ia64_deliver_exception(cs, excp, fault_addr, slot);
            cpu->env.pending_extint = 0;
        }
    } else {
        ia64_deliver_exception(cs, excp, fault_addr, slot);
    }
    cs->exception_index = IA64_EXCP_NONE;
}

static bool ia64_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
    IA64CPU *cpu = IA64_CPU(cs);

    if ((interrupt_request & CPU_INTERRUPT_HARD) &&
        (cpu->env.psr & IA64_PSR_I) &&
        ia64_sapic_has_pending(&cpu->env)) {
        cs->exception_index = IA64_EXCP_EXTINT;
        ia64_cpu_do_interrupt(cs);
        return true;
    }
    return false;
}

static void ia64_cpu_reset_hold(Object *obj, ResetType type)
{
    IA64CPUClass *icc = IA64_CPU_GET_CLASS(obj);
    IA64CPU *cpu = IA64_CPU(obj);

    if (icc->parent_phases.hold) {
        icc->parent_phases.hold(obj, type);
    }

    memset(&cpu->env, 0, sizeof(cpu->env));
    cpu->env.fr[1] = IA64_FR_ONE;
    cpu->env.pr[0] = 1;
    cpu->env.psr = 0;
    cpu->env.ar_rsc = 0;
    cpu->env.cr_iva = 0;
    ia64_itc_write(&cpu->env, 0);
    set_float_2nan_prop_rule(float_2nan_prop_ab, &cpu->env.fp_status);
    set_float_3nan_prop_rule(float_3nan_prop_abc, &cpu->env.fp_status);
    set_float_infzeronan_rule(float_infzeronan_dnan_never, &cpu->env.fp_status);
    set_float_default_nan_pattern(0b01000000, &cpu->env.fp_status);
    cpu->env.cr[IA64_CR_SAPIC_LID] = 0;
    cpu->env.cr[IA64_CR_SAPIC_TPR] = 0;
    cpu->env.cr[IA64_CR_ITV] = IA64_VECTOR_MASKED;
    cpu->env.pal_proc_copy_valid = false;
    cpu->env.pal_proc_copy_addr = 0;
    cpu->env.pal_interrupt_block_addr = IA64_LOCAL_SAPIC_PA;
    cpu->env.pal_io_block_addr = IA64_PAL_IO_BLOCK_PA;
}

static ObjectClass *ia64_cpu_class_by_name(const char *cpu_model)
{
    ObjectClass *oc = object_class_by_name(cpu_model);
    char *typename;

    if (oc != NULL && object_class_dynamic_cast(oc, TYPE_IA64_CPU) != NULL) {
        return oc;
    }

    typename = g_strdup_printf(IA64_CPU_TYPE_NAME("%s"), cpu_model);
    oc = object_class_by_name(typename);
    g_free(typename);
    return oc;
}

static void ia64_cpu_realize(DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    IA64CPU *cpu = IA64_CPU(dev);
    IA64CPUClass *icc = IA64_CPU_GET_CLASS(dev);
    Error *local_err = NULL;

    cpu_exec_realizefn(cs, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return;
    }

    cpu->itm_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, ia64_itm_timer_cb, cpu);

    qemu_init_vcpu(cs);
    cpu_reset(cs);

    icc->parent_realize(dev, errp);
}

static void ia64_dump_tlb(FILE *f, const char *name, const IA64TlbEntry *tlb,
                          uint8_t count)
{
    uint8_t i;

    for (i = 0; i < count; i++) {
        const IA64TlbEntry *entry = &tlb[i];

        if (!entry->valid) {
            continue;
        }
        qemu_fprintf(f, "%s[%u]%s va=0x%016" PRIx64
                     " pa=0x%016" PRIx64 " ps=0x%016" PRIx64
                     " rid=0x%06" PRIx32 " key=0x%06" PRIx32
                     " ar=%u pl=%u perm=0x%x\n",
                     name, i, entry->is_tr ? " TR" : " TC",
                     entry->va, entry->pa, entry->ps, entry->rid,
                     entry->key, entry->ar, entry->pl, entry->perm);
    }
}

static void ia64_cpu_dump_state(CPUState *cs, FILE *f, int flags)
{
    IA64CPU *cpu = IA64_CPU(cs);
    int i;

    qemu_fprintf(f, "IP: 0x%016" PRIx64 "  PSR: 0x%016" PRIx64 "\n",
                 cpu->env.ip, cpu->env.psr);
    qemu_fprintf(f, "exception: %" PRIu32 " fault_ip: 0x%016" PRIx64
                 " fault_imm: 0x%016" PRIx64 " fault_tmpl: 0x%016" PRIx64 "\n",
                 cpu->env.exception, cpu->env.fault_ip,
                 cpu->env.fault_imm, cpu->env.fault_tmpl);
    for (i = 0; i < IA64_GR_COUNT; i += 4) {
        qemu_fprintf(f,
                     "r%-3d 0x%016" PRIx64 " r%-3d 0x%016" PRIx64
                     " r%-3d 0x%016" PRIx64 " r%-3d 0x%016" PRIx64 "\n",
                     i, cpu->env.gr[i], i + 1, cpu->env.gr[i + 1],
                     i + 2, cpu->env.gr[i + 2], i + 3,
                     cpu->env.gr[i + 3]);
    }
    for (i = 0; i < 16; i += 4) {
        qemu_fprintf(f,
                     "p%d: %" PRIu64 " p%d: %" PRIu64
                     " p%d: %" PRIu64 " p%d: %" PRIu64 "\n",
                     i, cpu->env.pr[i], i + 1, cpu->env.pr[i + 1],
                     i + 2, cpu->env.pr[i + 2], i + 3,
                     cpu->env.pr[i + 3]);
    }
    qemu_fprintf(f, "b0: 0x%016" PRIx64 " b1: 0x%016" PRIx64
                 " b2: 0x%016" PRIx64 " b3: 0x%016" PRIx64 "\n",
                 cpu->env.br[0], cpu->env.br[1],
                 cpu->env.br[2], cpu->env.br[3]);
    qemu_fprintf(f, "b4: 0x%016" PRIx64 " b5: 0x%016" PRIx64
                 " b6: 0x%016" PRIx64 " b7: 0x%016" PRIx64 "\n",
                 cpu->env.br[4], cpu->env.br[5],
                 cpu->env.br[6], cpu->env.br[7]);
    qemu_fprintf(f, "AR.ITC: 0x%016" PRIx64 " AR.LC: 0x%016" PRIx64
                 " AR.EC: 0x%016" PRIx64 "\n",
                 ia64_itc_read(&cpu->env),
                 cpu->env.ar_lc, cpu->env.ar_ec);
    qemu_fprintf(f, "CR.ITM: 0x%016" PRIx64 " ITV: 0x%016" PRIx64
                 " TPR: 0x%016" PRIx64 " EOI: 0x%016" PRIx64 "\n",
                 cpu->env.cr_itm, cpu->env.cr[IA64_CR_ITV],
                 cpu->env.cr[IA64_CR_SAPIC_TPR],
                 cpu->env.cr[IA64_CR_SAPIC_EOI]);
    qemu_fprintf(f, "SAPIC IRR: %016" PRIx64 " %016" PRIx64
                 " %016" PRIx64 " %016" PRIx64 "\n",
                 cpu->env.sapic_irr[0], cpu->env.sapic_irr[1],
                 cpu->env.sapic_irr[2], cpu->env.sapic_irr[3]);
    qemu_fprintf(f, "SAPIC ISR: %016" PRIx64 " %016" PRIx64
                 " %016" PRIx64 " %016" PRIx64 "\n",
                 cpu->env.sapic_isr[0], cpu->env.sapic_isr[1],
                 cpu->env.sapic_isr[2], cpu->env.sapic_isr[3]);
    qemu_fprintf(f, "IIP: 0x%016" PRIx64 " IFA: 0x%016" PRIx64
                 " IPSR: 0x%016" PRIx64 "\n",
                 cpu->env.cr_iip, cpu->env.cr_ifa, cpu->env.cr_ipsr);
    qemu_fprintf(f, "ISR: 0x%016" PRIx64 " IFS: 0x%016" PRIx64
                 " IIM: 0x%016" PRIx64 "\n",
                 cpu->env.cr_isr, cpu->env.cr_ifs, cpu->env.cr_iim);
    qemu_fprintf(f, "IVA: 0x%016" PRIx64 " IIPA: 0x%016" PRIx64
                 " ITIR: 0x%016" PRIx64 "\n",
                 cpu->env.cr_iva, cpu->env.cr_iipa, cpu->env.cr_itir);
    qemu_fprintf(f, "IHA: 0x%016" PRIx64 " PTA: 0x%016" PRIx64
                 " RR0: 0x%016" PRIx64 " RR5: 0x%016" PRIx64
                 " RR6: 0x%016" PRIx64 " RR7: 0x%016" PRIx64 "\n",
                 cpu->env.cr_iha, cpu->env.cr_pta, cpu->env.rr[0],
                 cpu->env.rr[5], cpu->env.rr[6], cpu->env.rr[7]);
    qemu_fprintf(f, "PKR0: 0x%016" PRIx64 " PKR1: 0x%016" PRIx64
                 " PKR2: 0x%016" PRIx64 " PKR3: 0x%016" PRIx64 "\n",
                 cpu->env.pkr[0], cpu->env.pkr[1],
                 cpu->env.pkr[2], cpu->env.pkr[3]);
    if (cpu->env.excp_frame_depth > 0) {
        const IA64ExceptionFrame *frame =
            &cpu->env.excp_frames[cpu->env.excp_frame_depth - 1];

        qemu_fprintf(f, "EXCP frame %u IIP: 0x%016" PRIx64
                     " IPSR: 0x%016" PRIx64 " IFA: 0x%016" PRIx64
                     " ISR: 0x%016" PRIx64 "\n",
                     cpu->env.excp_frame_depth - 1, frame->iip, frame->ipsr,
                     frame->ifa, frame->isr);
        qemu_fprintf(f, "EXCP IIPA: 0x%016" PRIx64
                     " ITIR: 0x%016" PRIx64 " IHA: 0x%016" PRIx64 "\n",
                     frame->iipa, frame->itir, frame->iha);
        qemu_fprintf(f, "EXCP gr32: 0x%016" PRIx64
                     " gr33: 0x%016" PRIx64 " gr34: 0x%016" PRIx64
                     " gr35: 0x%016" PRIx64 "\n",
                     frame->gr[0], frame->gr[1], frame->gr[2],
                     frame->gr[3]);
        qemu_fprintf(f, "EXCP gr36: 0x%016" PRIx64
                     " gr37: 0x%016" PRIx64 " gr38: 0x%016" PRIx64
                     " gr39: 0x%016" PRIx64 "\n",
                     frame->gr[4], frame->gr[5], frame->gr[6],
                     frame->gr[7]);
    }
    qemu_fprintf(f, "CFM: sof=%u sol=%u sor=%u rrb.gr=%u AR.PFS=0x%016"
                 PRIx64 " BSP=0x%016" PRIx64 " BSPSTORE=0x%016" PRIx64 "\n",
                 cpu->env.cfm_sof, cpu->env.cfm_sol,
                 cpu->env.cfm_sor, cpu->env.cfm_rrb_gr,
                 cpu->env.ar_pfs, cpu->env.ar_bsp, cpu->env.ar_bspstore);
    ia64_dump_tlb(f, "ITLB", cpu->env.tlb_inst, cpu->env.tlb_inst_count);
    ia64_dump_tlb(f, "DTLB", cpu->env.tlb_data, cpu->env.tlb_data_count);
}

static int ia64_cpu_gdb_read_register(CPUState *cs, GByteArray *buf, int reg)
{
    IA64CPU *cpu = IA64_CPU(cs);
    CPUIA64State *env = &cpu->env;
    uint64_t val = 0;

    if (reg < IA64_GR_COUNT) {
        val = env->gr[reg];
    } else if (reg < 128 + IA64_FR_COUNT) {
        uint32_t freg = reg - 128;
        if (freg == 1) {
            val = IA64_FR_ONE;
        } else if (freg != 0) {
            val = env->fr[freg];
        }
    } else if (reg < 256 + IA64_BR_COUNT) {
        val = env->br[reg - 256];
    } else if (reg < 264 + IA64_PR_COUNT) {
        val = env->pr[reg - 264];
    } else {
        switch (reg) {
        case 328:
            val = env->ip;
            break;
        case 329:
            val = env->psr;
            break;
        case 330:
            val = env->cfm_sof | ((uint64_t)env->cfm_sol << 7)
                | ((uint64_t)env->cfm_sor << 14)
                | ((uint64_t)env->cfm_rrb_gr << 18);
            break;
        default:
            if (reg >= 340 && reg < 340 + IA64_AR_COUNT) {
                val = env->ar[reg - 340];
            } else if (reg >= 468 && reg < 468 + IA64_CR_COUNT) {
                val = env->cr[reg - 468];
            }
            break;
        }
    }

    return gdb_get_reg64(buf, val);
}

static int ia64_cpu_gdb_write_register(CPUState *cs, uint8_t *buf, int reg)
{
    IA64CPU *cpu = IA64_CPU(cs);
    CPUIA64State *env = &cpu->env;
    uint64_t val = ldq_p(buf);

    if (reg < IA64_GR_COUNT) {
        env->gr[reg] = val;
    } else if (reg < 128 + IA64_FR_COUNT) {
        uint32_t freg = reg - 128;
        if (freg > 1) {
            env->fr[freg] = val;
        }
    } else if (reg < 256 + IA64_BR_COUNT) {
        env->br[reg - 256] = val;
    } else if (reg < 264 + IA64_PR_COUNT) {
        env->pr[reg - 264] = val != 0;
    } else {
        switch (reg) {
        case 328:
            env->ip = val;
            break;
        case 329:
            env->psr = val;
            break;
        case 330: {
            uint64_t cfm = val;
            env->cfm_sof = cfm & 0x7f;
            env->cfm_sol = (cfm >> 7) & 0x7f;
            env->cfm_sor = (cfm >> 14) & 0x0f;
            env->cfm_rrb_gr = (cfm >> 18) & 0x0f;
            break;
        }
        default:
            if (reg >= 340 && reg < 340 + IA64_AR_COUNT) {
                env->ar[reg - 340] = val;
            } else if (reg >= 468 && reg < 468 + IA64_CR_COUNT) {
                env->cr[reg - 468] = val;
            }
            break;
        }
    }

    return 8;
}

static const struct SysemuCPUOps ia64_sysemu_ops = {
    .has_work = ia64_cpu_has_work,
    .get_phys_page_debug = ia64_cpu_get_phys_page_debug,
};

static void ia64_cpu_tcg_init(void)
{
    static const char * const gr_names[IA64_GR_COUNT] = {
        "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
        "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31",
        "r32", "r33", "r34", "r35", "r36", "r37", "r38", "r39",
        "r40", "r41", "r42", "r43", "r44", "r45", "r46", "r47",
        "r48", "r49", "r50", "r51", "r52", "r53", "r54", "r55",
        "r56", "r57", "r58", "r59", "r60", "r61", "r62", "r63",
        "r64", "r65", "r66", "r67", "r68", "r69", "r70", "r71",
        "r72", "r73", "r74", "r75", "r76", "r77", "r78", "r79",
        "r80", "r81", "r82", "r83", "r84", "r85", "r86", "r87",
        "r88", "r89", "r90", "r91", "r92", "r93", "r94", "r95",
        "r96", "r97", "r98", "r99", "r100", "r101", "r102", "r103",
        "r104", "r105", "r106", "r107", "r108", "r109", "r110",
        "r111", "r112", "r113", "r114", "r115", "r116", "r117",
        "r118", "r119", "r120", "r121", "r122", "r123", "r124",
        "r125", "r126", "r127",
    };
    static const char * const pr_names[IA64_PR_COUNT] = {
        "p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7",
        "p8", "p9", "p10", "p11", "p12", "p13", "p14", "p15",
        "p16", "p17", "p18", "p19", "p20", "p21", "p22", "p23",
        "p24", "p25", "p26", "p27", "p28", "p29", "p30", "p31",
        "p32", "p33", "p34", "p35", "p36", "p37", "p38", "p39",
        "p40", "p41", "p42", "p43", "p44", "p45", "p46", "p47",
        "p48", "p49", "p50", "p51", "p52", "p53", "p54", "p55",
        "p56", "p57", "p58", "p59", "p60", "p61", "p62", "p63",
    };
    static const char * const br_names[IA64_BR_COUNT] = {
        "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7",
    };
    int i;

    for (i = 0; i < IA64_GR_COUNT; ++i) {
        cpu_gr[i] = tcg_global_mem_new_i64(tcg_env,
                                           offsetof(CPUIA64State, gr[i]),
                                           gr_names[i]);
    }
    for (i = 0; i < IA64_PR_COUNT; ++i) {
        cpu_pr[i] = tcg_global_mem_new_i64(tcg_env,
                                           offsetof(CPUIA64State, pr[i]),
                                           pr_names[i]);
    }
    for (i = 0; i < IA64_BR_COUNT; ++i) {
        cpu_br[i] = tcg_global_mem_new_i64(tcg_env,
                                           offsetof(CPUIA64State, br[i]),
                                           br_names[i]);
    }
    cpu_ip = tcg_global_mem_new_i64(tcg_env, offsetof(CPUIA64State, ip), "ip");
    cpu_psr = tcg_global_mem_new_i64(tcg_env, offsetof(CPUIA64State, psr),
                                     "psr");
    for (i = 0; i < IA64_FR_COUNT; ++i) {
        cpu_fr[i] = tcg_global_mem_new_i64(tcg_env,
                                           offsetof(CPUIA64State, fr[i]),
                                           "fr");
    }
    for (i = 0; i < 2; ++i) {
        cpu_nat[i] = tcg_global_mem_new_i64(tcg_env,
                                           offsetof(CPUIA64State, nat[i]),
                                           "nat");
        cpu_fr_nat[i] = tcg_global_mem_new_i64(tcg_env,
                                               offsetof(CPUIA64State,
                                                        fr_nat[i]),
                                               "fr_nat");
        cpu_fr_sig[i] = tcg_global_mem_new_i64(tcg_env,
                                               offsetof(CPUIA64State,
                                                        fr_sig[i]),
                                               "fr_sig");
    }
}

static void ia64_tr_init_disas_context(DisasContextBase *db, CPUState *cs)
{
    DisasContext *ctx = container_of(db, DisasContext, base);

    ctx->env = cpu_env(cs);
    ctx->base.max_insns = 32;
    ctx->mmu_idx = ia64_cpu_mmu_index(cs, false);
    ctx->start_slot = (ctx->base.tb->flags & IA64_TB_FLAG_RI_MASK) >>
                      IA64_TB_FLAG_RI_SHIFT;
    if (ctx->start_slot > 2) {
        ctx->start_slot = 0;
    }
}

static void ia64_tr_tb_start(DisasContextBase *db, CPUState *cs)
{
}

static void ia64_tr_insn_start(DisasContextBase *db, CPUState *cs)
{
    tcg_gen_insn_start(db->pc_next, 0, 0);
}

static void ia64_tr_translate_insn(DisasContextBase *db, CPUState *cs)
{
    DisasContext *ctx = container_of(db, DisasContext, base);
    const uint64_t bundle_ip = db->pc_next;
    const uint64_t low = translator_ldq_end(ctx->env, db, bundle_ip, MO_LE);
    const uint64_t high = translator_ldq_end(ctx->env, db, bundle_ip + 8,
                                              MO_LE);
    const uint8_t template_code = ia64_bundle_template_code(low);
    const IA64TemplateInfo *template_info = ia64_template_info(template_code);
    uint64_t slots[3];
    int slot;

    db->pc_next = bundle_ip + 16;

    if (!template_info->defined) {
        ia64_gen_raise_exception(IA64_EXCP_RESERVED_TEMPLATE, bundle_ip,
                                  template_code, 0);
        db->is_jmp = DISAS_NORETURN;
        return;
    }

    slots[0] = ia64_bundle_slot(low, high, 0);
    slots[1] = ia64_bundle_slot(low, high, 1);
    slots[2] = ia64_bundle_slot(low, high, 2);

    bool skip_x_slot = false;
    for (slot = ctx->start_slot; slot < 3; ++slot) {
        if (skip_x_slot && slot == 2) {
            continue;
        }

        Ia64Instruction insn = ia64_decode_insn(
            (Ia64SlotUnit)template_info->units[slot], slots[slot], bundle_ip,
            slot);

        ia64_apply_mlx_long_fixup(template_code, slots, slot, &insn,
                                  &skip_x_slot);
        {
            TCGv_i64 suppression = tcg_temp_new_i64();

            tcg_gen_andi_i64(suppression, cpu_psr,
                             IA64_PSR_FAULT_SUPPRESS_MASK);
            tcg_gen_st_i64(suppression, tcg_env,
                           offsetof(CPUIA64State,
                                    psr_suppression_before_insn));
        }
        ia64_gen_set_ri(slot);
        ia64_gen_set_fault_slot(slot);
        if (ia64_gen_insn(ctx, &insn)) {
            db->is_jmp = DISAS_NORETURN;
            return;
        }
    }

    db->is_jmp = DISAS_EXIT;
}

static void ia64_tr_tb_stop(DisasContextBase *db, CPUState *cs)
{
    switch (db->is_jmp) {
    case DISAS_EXIT:
    case DISAS_TOO_MANY:
        ia64_gen_clear_ri();
        tcg_gen_movi_i64(cpu_ip, db->pc_next);
        tcg_gen_exit_tb(NULL, 0);
        break;
    case DISAS_NORETURN:
        break;
    case DISAS_NEXT:
    default:
        g_assert_not_reached();
    }
}

static const char *ia64_unit_log_name(Ia64SlotUnit unit)
{
    switch (unit) {
    case IA64_UNIT_M:
        return "M";
    case IA64_UNIT_I:
        return "I";
    case IA64_UNIT_B:
        return "B";
    case IA64_UNIT_F:
        return "F";
    case IA64_UNIT_L:
        return "L";
    case IA64_UNIT_X:
        return "X";
    case IA64_UNIT_RESERVED:
    default:
        return "reserved";
    }
}

static bool ia64_tr_disas_log(const DisasContextBase *db, CPUState *cs,
                              FILE *logfile)
{
    const DisasContext *ctx = container_of(db, DisasContext, base);
    vaddr bundle_ip = db->pc_first;
    size_t size = translator_st_len(db);
    int start_slot = ctx->start_slot;

    fprintf(logfile, "QEMU-IA64-DECODE: pc=0x%016" PRIx64
            " size=%zu\n", (uint64_t)db->pc_first, size);

    while (size >= 16) {
        uint8_t bundle[16];
        uint64_t low;
        uint64_t high;
        uint8_t template_code;
        const IA64TemplateInfo *template_info;
        uint64_t slots[3];
        bool skip_x_slot = false;
        int slot;

        if (!translator_st(db, bundle, bundle_ip, sizeof(bundle))) {
            fprintf(logfile,
                    "QEMU-IA64-DECODE: read-failed pc=0x%016" PRIx64 "\n",
                    (uint64_t)bundle_ip);
            break;
        }

        low = ldq_le_p(bundle);
        high = ldq_le_p(bundle + 8);
        template_code = ia64_bundle_template_code(low);
        template_info = ia64_template_info(template_code);
        slots[0] = ia64_bundle_slot(low, high, 0);
        slots[1] = ia64_bundle_slot(low, high, 1);
        slots[2] = ia64_bundle_slot(low, high, 2);

        fprintf(logfile,
                "QEMU-IA64-DECODE: bundle=0x%016" PRIx64
                " template=0x%02x name=%s defined=%u\n",
                (uint64_t)bundle_ip, template_code, template_info->name,
                template_info->defined ? 1 : 0);

        if (template_info->defined) {
            for (slot = start_slot; slot < 3; ++slot) {
                Ia64SlotUnit unit;
                Ia64Instruction insn;

                if (skip_x_slot && slot == 2) {
                    continue;
                }

                unit = (Ia64SlotUnit)template_info->units[slot];
                insn = ia64_decode_insn(unit, slots[slot], bundle_ip, slot);
                ia64_apply_mlx_long_fixup(template_code, slots, slot, &insn,
                                          &skip_x_slot);
                fprintf(logfile,
                        "QEMU-IA64-DECODE: slot=%d unit=%s opcode=%u"
                        " valid=%u qp=%u raw=0x%010" PRIx64 "\n",
                        slot, ia64_unit_log_name(insn.unit),
                        (unsigned)insn.opcode, insn.valid ? 1 : 0,
                        insn.qp, insn.raw);
            }
        }

        bundle_ip += 16;
        size -= 16;
        start_slot = 0;
    }

    return false;
}

static void ia64_cpu_translate_code(CPUState *cs, TranslationBlock *tb,
                                    int *max_insns, vaddr pc, void *host_pc)
{
    DisasContext ctx = {};
    static const TranslatorOps ia64_tr_ops = {
        .init_disas_context = ia64_tr_init_disas_context,
        .tb_start = ia64_tr_tb_start,
        .insn_start = ia64_tr_insn_start,
        .translate_insn = ia64_tr_translate_insn,
        .tb_stop = ia64_tr_tb_stop,
        .disas_log = ia64_tr_disas_log,
    };

    translator_loop(cs, tb, max_insns, pc, host_pc, &ia64_tr_ops, &ctx.base,
                    TCG_TYPE_VA);
}

static const TCGCPUOps ia64_tcg_ops = {
    .guest_default_memory_order = TCG_MO_ALL,
    .mttcg_supported = false,
    .initialize = ia64_cpu_tcg_init,
    .translate_code = ia64_cpu_translate_code,
    .get_tb_cpu_state = ia64_get_tb_cpu_state,
    .synchronize_from_tb = ia64_cpu_synchronize_from_tb,
    .restore_state_to_opc = ia64_restore_state_to_opc,
    .mmu_index = ia64_cpu_mmu_index,
    .tlb_fill = ia64_cpu_tlb_fill,
    .pointer_wrap = cpu_pointer_wrap_notreached,
#ifndef CONFIG_USER_ONLY
    .do_unaligned_access = ia64_cpu_do_unaligned_access,
#endif
    .cpu_exec_interrupt = ia64_cpu_exec_interrupt,
    .cpu_exec_halt = ia64_cpu_has_work,
    .cpu_exec_reset = cpu_reset,
    .do_interrupt = ia64_cpu_do_interrupt,
};

static void ia64_cpu_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    CPUClass *cc = CPU_CLASS(oc);
    IA64CPUClass *icc = IA64_CPU_CLASS(oc);
    ResettableClass *rc = RESETTABLE_CLASS(oc);

    device_class_set_parent_realize(dc, ia64_cpu_realize,
                                    &icc->parent_realize);
    resettable_class_set_parent_phases(rc, NULL, ia64_cpu_reset_hold, NULL,
                                       &icc->parent_phases);

    cc->class_by_name = ia64_cpu_class_by_name;
    cc->dump_state = ia64_cpu_dump_state;
    cc->set_pc = ia64_cpu_set_pc;
    cc->get_pc = ia64_cpu_get_pc;
    cc->sysemu_ops = &ia64_sysemu_ops;
    cc->gdb_read_register = ia64_cpu_gdb_read_register;
    cc->gdb_write_register = ia64_cpu_gdb_write_register;
    cc->tcg_ops = &ia64_tcg_ops;
}

static const TypeInfo ia64_cpu_type_info[] = {
    {
        .name = TYPE_IA64_CPU,
        .parent = TYPE_CPU,
        .instance_size = sizeof(IA64CPU),
        .instance_align = __alignof__(IA64CPU),
        .class_size = sizeof(IA64CPUClass),
        .class_init = ia64_cpu_class_init,
    },
    {
        .name = IA64_CPU_TYPE_NAME("itanium2"),
        .parent = TYPE_IA64_CPU,
    },
};

DEFINE_TYPES(ia64_cpu_type_info)
