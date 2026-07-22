/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef IA64_FIRMWARE_FW_DEVICE_PATH_H
#define IA64_FIRMWARE_FW_DEVICE_PATH_H

#include "fw-base.h"

typedef struct {
    UINT8 Type;
    UINT8 SubType;
    UINT16 Length;
} __attribute__((packed)) FW_DEVICE_PATH_NODE;

typedef struct {
    FW_DEVICE_PATH_NODE Header;
    UINT32 Hid;
    UINT32 Uid;
} __attribute__((packed)) FW_ACPI_HID_DEVICE_PATH_NODE;

typedef struct {
    FW_DEVICE_PATH_NODE Header;
    UINT8 Function;
    UINT8 Device;
} __attribute__((packed)) FW_PCI_DEVICE_PATH_NODE;

#endif /* IA64_FIRMWARE_FW_DEVICE_PATH_H */
