/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Internal interface to the EFI 1.10 decompression protocol module.
 */

#ifndef IA64_FIRMWARE_FW_DECOMPRESS_H
#define IA64_FIRMWARE_FW_DECOMPRESS_H

#include "fw-base.h"

typedef struct _FW_EFI_DECOMPRESS_PROTOCOL FW_EFI_DECOMPRESS_PROTOCOL;

extern FW_EFI_DECOMPRESS_PROTOCOL fw_decompress_protocol;
extern const UINT8 fw_decompress_protocol_guid[16];

BOOLEAN fw_decompress_selftest(void);

#endif /* IA64_FIRMWARE_FW_DECOMPRESS_H */
