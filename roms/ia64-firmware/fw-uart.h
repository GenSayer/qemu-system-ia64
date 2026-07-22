/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef IA64_FIRMWARE_FW_UART_H
#define IA64_FIRMWARE_FW_UART_H

#include "fw-device-path.h"

typedef enum {
    DefaultParity,
    NoParity,
    EvenParity,
    OddParity,
    MarkParity,
    SpaceParity
} EFI_PARITY_TYPE;

typedef enum {
    DefaultStopBits,
    OneStopBit,
    OneFiveStopBits,
    TwoStopBits
} EFI_STOP_BITS_TYPE;

typedef struct {
    FW_DEVICE_PATH_NODE Header;
    UINT32 Reserved;
    UINT64 BaudRate;
    UINT8 DataBits;
    UINT8 Parity;
    UINT8 StopBits;
} __attribute__((packed)) FW_UART_DEVICE_PATH_NODE;

#endif /* IA64_FIRMWARE_FW_UART_H */
