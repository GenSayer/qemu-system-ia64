/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "ia64-test.h"

#define TEST_SAL_SET_VECTORS           0x01000000ULL
#define TEST_SAL_VECTOR_BOOT_RENDEZ     2U
#define TEST_SAL_SUCCESS                0ULL
#define TEST_LOCAL_SAPIC_BASE           0x00000000fee00000ULL
#define TEST_AP_WAKE_VECTOR             0xffU
#define TEST_PROCESSOR_COUNT             4U
#define TEST_RENDEZVOUS_ROUNDS           8U
#define TEST_ATOMIC_INCREMENTS          128U
#define TEST_WAIT_TICKS        1000000000ULL
#define TEST_RETURN_TICKS        10000000ULL
#define TEST_ATOMIC_HIGH 0xa5a55a5af00f0ff0ULL

typedef struct {
    UINT64 Status;
    UINT64 Value0;
    UINT64 Value1;
    UINT64 Value2;
} TEST_SAL_RETURN;

typedef TEST_SAL_RETURN (*TEST_SAL_PROC)(UINT64, UINT64, UINT64, UINT64,
                                        UINT64, UINT64, UINT64, UINT64);

static UINT8 sal_guid[16] = IA64_GUID_SAL;
/* Each AP updates its own slot; the BSP observes the slots after an mf. */
static volatile UINT64 ap_rendezvous_count[TEST_PROCESSOR_COUNT];
/* All processors contend on this naturally aligned semaphore datum. */
static struct {
    volatile UINT64 Low;
    volatile UINT64 High;
} atomic_pair __attribute__((aligned(16)));

static UINT64 cmp8xchg16(volatile UINT64 *Address, UINT64 Compare,
                         UINT64 Low, UINT64 High)
{
    UINT64 old;

    __asm__ volatile (
        "mov ar.ccv=%2\n\t"
        "mov ar.csd=%4;;\n\t"
        "cmp8xchg16.acq %0=[%1],%3;;"
        : "=r"(old)
        : "r"(Address), "r"(Compare), "r"(Low), "r"(High)
        : "memory");
    return old;
}

static UINT64 cmp8xchg16_big_endian(volatile UINT64 *Address, UINT64 Compare,
                                    UINT64 Low, UINT64 High)
{
    UINT64 old;

    __asm__ volatile (
        "sum 2;;\n\t"
        "srlz.d;;\n\t"
        "mov ar.ccv=%2\n\t"
        "mov ar.csd=%4;;\n\t"
        "cmp8xchg16.acq %0=[%1],%3;;\n\t"
        "rum 2;;\n\t"
        "srlz.d;;"
        : "=r"(old)
        : "r"(Address), "r"(Compare), "r"(Low), "r"(High)
        : "memory");
    return old;
}

static VOID atomic_increment_pair(VOID)
{
    UINT64 compare = atomic_pair.Low;

    for (;;) {
        UINT64 old = cmp8xchg16(&atomic_pair.Low, compare, compare + 1,
                                TEST_ATOMIC_HIGH);

        if (old == compare) {
            return;
        }
        compare = old;
    }
}

static VOID atomic_increment_batch(VOID)
{
    UINTN i;

    for (i = 0; i < TEST_ATOMIC_INCREMENTS; i++) {
        atomic_increment_pair();
    }
}

static VOID *find_config_table(EFI_SYSTEM_TABLE *SystemTable,
                               const UINT8 *Guid)
{
    UINTN i;

    for (i = 0; i < SystemTable->NumberOfTableEntries; i++) {
        if (ia64_bytes_equal(SystemTable->ConfigurationTable[i].VendorGuid,
                             Guid, 16)) {
            return (VOID *)(UINTN)
                SystemTable->ConfigurationTable[i].VendorTable;
        }
    }
    return NULL;
}

static UINT16 get_u16(const VOID *Address)
{
    const UINT8 *p = (const UINT8 *)Address;

    return (UINT16)p[0] | ((UINT16)p[1] << 8);
}

static UINT32 get_u32(const VOID *Address)
{
    const UINT8 *p = (const UINT8 *)Address;

    return (UINT32)p[0] | ((UINT32)p[1] << 8) |
           ((UINT32)p[2] << 16) | ((UINT32)p[3] << 24);
}

static UINT64 get_u64(const VOID *Address)
{
    const UINT8 *p = (const UINT8 *)Address;

    return (UINT64)get_u32(p) | ((UINT64)get_u32(p + 4) << 32);
}

static UINTN sal_descriptor_size(UINT8 Type)
{
    switch (Type) {
    case 0:
        return 48U;
    case 1:
        return 32U;
    case 2:
        return 16U;
    case 3:
        return 32U;
    case 4:
    case 5:
        return 16U;
    default:
        return 0;
    }
}

static BOOLEAN find_sal_descriptors(UINT8 *Sal, UINT64 *Procedure,
                                    UINT64 *Gp, UINT64 *WakeVector)
{
    UINT32 length;
    UINT16 entries;
    UINTN offset = 96U;
    UINTN i;
    BOOLEAN entrypoint = 0;
    BOOLEAN wake = 0;

    if (Sal == NULL || get_u32(Sal) != 0x5f545353U) {
        return 0;
    }
    length = get_u32(Sal + 4U);
    entries = get_u16(Sal + 10U);
    if (length < 96U || length > 4096U || ia64_checksum8(Sal, length) != 0) {
        return 0;
    }
    for (i = 0; i < entries; i++) {
        UINTN size;

        if (offset >= length) {
            return 0;
        }
        size = sal_descriptor_size(Sal[offset]);
        if (size == 0 || size > length - offset) {
            return 0;
        }
        if (Sal[offset] == 0) {
            *Procedure = get_u64(Sal + offset + 16U);
            *Gp = get_u64(Sal + offset + 24U);
            entrypoint = *Procedure != 0;
        } else if (Sal[offset] == 5 && Sal[offset + 1U] == 0) {
            *WakeVector = get_u64(Sal + offset + 8U);
            wake = *WakeVector >= 0x10U && *WakeVector <= 0xffU;
        }
        offset += size;
    }
    return offset == length && entrypoint && wake;
}

static UINT64 read_lid(void)
{
    UINT64 lid;

    __asm__ volatile ("mov %0 = cr.lid;;" : "=r"(lid) : : "memory");
    return lid;
}

static UINT64 read_itc(void)
{
    UINT64 itc;

    __asm__ volatile ("mov %0 = ar.itc;;" : "=r"(itc) : : "memory");
    return itc;
}

static VOID ap_rendezvous(void)
{
    UINTN id = (read_lid() >> 24) & 0xffU;
    UINT64 masked = 1ULL << 16;

    if (id > 0 && id < TEST_PROCESSOR_COUNT) {
        atomic_increment_batch();
        ap_rendezvous_count[id]++;
        __asm__ volatile ("mf;;" : : : "memory");
        /* TPR is scratch on return; firmware must reopen the wake vector. */
        __asm__ volatile ("mov cr.tpr = %0;;\n\tsrlz.d;;"
                          : : "r"(masked) : "memory");
    }
}

static VOID send_wake_ipi(UINTN Id, UINT64 Vector)
{
    /* The target address is an architected memory-mapped interrupt register. */
    volatile UINT64 *ipi = (volatile UINT64 *)(UINTN)
        (TEST_LOCAL_SAPIC_BASE + (Id << 12));

    __asm__ volatile ("mf;;" : : : "memory");
    *ipi = Vector;
}

static BOOLEAN wait_for_round(UINT64 Round)
{
    UINT64 deadline = read_itc() + TEST_WAIT_TICKS;

    for (;;) {
        UINTN id;
        BOOLEAN complete = 1;

        __asm__ volatile ("mf;;" : : : "memory");
        for (id = 1; id < TEST_PROCESSOR_COUNT; id++) {
            if (ap_rendezvous_count[id] < Round) {
                complete = 0;
            }
        }
        if (complete) {
            return 1;
        }
        if ((INTN)(read_itc() - deadline) >= 0) {
            return 0;
        }
        __asm__ volatile ("hint @pause" : : : "memory");
    }
}

static VOID wait_for_rendezvous_return(VOID)
{
    UINT64 deadline = read_itc() + TEST_RETURN_TICKS;

    /*
     * A counter update precedes the handler return.  Leave enough time for
     * every AP to reach PAL_HALT_LIGHT before reusing the same SAPIC vector;
     * an interrupt request bit intentionally coalesces duplicate writes.
     */
    while ((INTN)(read_itc() - deadline) < 0) {
        __asm__ volatile ("hint @pause" : : : "memory");
    }
}

EFI_STATUS efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    IA64_TEST_CONTEXT context = {
        .SystemTable = SystemTable,
        .Suite = "smp",
        .Passed = 0,
        .Failed = 0,
        .DirectUart = 0,
    };
    UINT8 *sal = (UINT8 *)find_config_table(SystemTable, sal_guid);
    UINT64 sal_descriptor[2] __attribute__((aligned(16)));
    UINT64 *handler_descriptor = (UINT64 *)(UINTN)ap_rendezvous;
    UINT64 wake_vector = 0;
    TEST_SAL_PROC sal_proc;
    TEST_SAL_RETURN result;
    UINTN id;
    UINT64 round;
    BOOLEAN descriptors;
    BOOLEAN first_round = 0;
    BOOLEAN repeat_rounds = 0;
    BOOLEAN atomic_semantics;
    BOOLEAN big_endian_atomic;

    (void)ImageHandle;
    atomic_pair.Low = 0;
    atomic_pair.High = TEST_ATOMIC_HIGH;
    descriptors = find_sal_descriptors(sal, &sal_descriptor[0],
                                       &sal_descriptor[1], &wake_vector);
    ia64_test_check(&context, "sal-ap-wake", descriptors &&
                    wake_vector == TEST_AP_WAKE_VECTOR,
                    EFI_DEVICE_ERROR, "missing-rendezvous-descriptor");
    if (descriptors) {
        sal_proc = (TEST_SAL_PROC)(UINTN)sal_descriptor;
        result = sal_proc(TEST_SAL_SET_VECTORS,
                          TEST_SAL_VECTOR_BOOT_RENDEZ,
                          handler_descriptor[0], handler_descriptor[1],
                          0, 0, 0, 0);
        if (result.Status == TEST_SAL_SUCCESS) {
            for (id = 1; id < TEST_PROCESSOR_COUNT; id++) {
                send_wake_ipi(id, wake_vector);
            }
            atomic_increment_batch();
            first_round = wait_for_round(1);
            if (first_round) {
                repeat_rounds = 1;
                wait_for_rendezvous_return();
                for (round = 2; round <= TEST_RENDEZVOUS_ROUNDS; round++) {
                    for (id = 1; id < TEST_PROCESSOR_COUNT; id++) {
                        send_wake_ipi(id, wake_vector);
                    }
                    atomic_increment_batch();
                    if (!wait_for_round(round)) {
                        repeat_rounds = 0;
                        break;
                    }
                    wait_for_rendezvous_return();
                }
            }
        }
    }
    ia64_test_check(&context, "four-processor-rendezvous", first_round,
                    EFI_TIMEOUT, "secondary-start-timeout");
    ia64_test_check(&context, "repeat-rendezvous", repeat_rounds,
                    EFI_TIMEOUT, "secondary-return-timeout");
    atomic_semantics = repeat_rounds &&
        atomic_pair.Low == TEST_RENDEZVOUS_ROUNDS * TEST_PROCESSOR_COUNT *
                           TEST_ATOMIC_INCREMENTS &&
        atomic_pair.High == TEST_ATOMIC_HIGH;
    ia64_test_check(&context, "atomic-16-byte-semaphore", atomic_semantics,
                    EFI_DEVICE_ERROR, "semaphore-contention-failed");
    atomic_pair.Low = __builtin_bswap64(0x0123456789abcdefULL);
    atomic_pair.High = __builtin_bswap64(0xfedcba9876543210ULL);
    __asm__ volatile ("mf;;" : : : "memory");
    big_endian_atomic =
        cmp8xchg16_big_endian(&atomic_pair.High,
                              0xfedcba9876543210ULL,
                              0x1111222233334444ULL,
                              0x5555666677778888ULL) ==
                              0xfedcba9876543210ULL &&
        atomic_pair.Low == __builtin_bswap64(0x1111222233334444ULL) &&
        atomic_pair.High == __builtin_bswap64(0x5555666677778888ULL);
    ia64_test_check(&context, "big-endian-16-byte-semaphore",
                    big_endian_atomic, EFI_DEVICE_ERROR,
                    "big-endian-semaphore-failed");
    ia64_test_done(&context);
    return context.Failed == 0 ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}

EFI_STATUS (*efi_entry_descriptor_reference)(EFI_HANDLE, EFI_SYSTEM_TABLE *)
    __attribute__((used)) = efi_main;
