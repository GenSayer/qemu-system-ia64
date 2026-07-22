/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef IA64_FIRMWARE_FW_POINTER_H
#define IA64_FIRMWARE_FW_POINTER_H

#include "fw-base.h"

BOOLEAN fw_pointer_install(void);
BOOLEAN fw_pointer_selftest(void);
void fw_pointer_consume_byte(UINT8 byte);

#endif /* IA64_FIRMWARE_FW_POINTER_H */
