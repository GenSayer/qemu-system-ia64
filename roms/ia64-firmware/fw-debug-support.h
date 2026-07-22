/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * EFI Debug Support protocol module interface.
 */

#ifndef IA64_FIRMWARE_FW_DEBUG_SUPPORT_H
#define IA64_FIRMWARE_FW_DEBUG_SUPPORT_H

#include "fw-base.h"

BOOLEAN fw_debug_support_install(VOID);
VOID fw_debug_support_exit_boot_services(VOID);
BOOLEAN fw_debug_support_selftest(VOID);

#endif /* IA64_FIRMWARE_FW_DEBUG_SUPPORT_H */
