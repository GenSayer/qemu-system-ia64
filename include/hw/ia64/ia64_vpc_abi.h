/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * IA-64 virtual PC ABI shared by QEMU and its freestanding firmware.
 *
 * This header must remain usable with -nostdinc.  Do not include QEMU or
 * hosted C library headers here; use compiler built-in types only.
 */

#ifndef HW_IA64_VPC_ABI_H
#define HW_IA64_VPC_ABI_H

#define IA64_FW_HANDOFF_ADDR          0x00000000000ff000ULL
#define IA64_FW_HANDOFF_MAGIC         0x4d41523436414951ULL /* "QIA64RAM" */
#define IA64_FW_HANDOFF_VERSION       10ULL

#define IA64_FW_CONSOLE_SERIAL        0ULL
#define IA64_FW_CONSOLE_VGA           1ULL
#define IA64_FW_DEBUG_PORT_PRESENT    1ULL

#define IA64_UART_BASE                0x00000047f0000000ULL
#define IA64_DEBUG_UART_BASE          0x00000047f0001000ULL
#define IA64_UART_MMIO_SIZE           0x0000000000002000ULL

#define IA64_PCI_MMIO_BASE            0x00000000c1000000ULL
#define IA64_PCI_MMIO_SIZE            0x0000000010000000ULL

typedef struct __attribute__((packed)) IA64VpcHandoff {
    unsigned long long Magic;
    unsigned long long Version;
    unsigned long long RamSize;
    unsigned long long ConsolePolicy;
    unsigned long long IdeDmaEnabled;
    unsigned long long DebugPortFlags;
    unsigned long long DebugPortBase;
    unsigned long long I8042Enabled;
    unsigned long long ProcessorCount;
    unsigned long long NvramPersistent;
    unsigned long long SocketCount;
    unsigned long long CoresPerSocket;
    unsigned long long ThreadsPerCore;
} IA64VpcHandoff;

#endif /* HW_IA64_VPC_ABI_H */
