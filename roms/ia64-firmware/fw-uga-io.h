/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * EFI UGA I/O protocol module interface.
 */

#ifndef IA64_FIRMWARE_FW_UGA_IO_H
#define IA64_FIRMWARE_FW_UGA_IO_H

#include "fw-base.h"

BOOLEAN fw_uga_io_install(VOID);
BOOLEAN fw_uga_io_selftest(VOID);

#endif /* IA64_FIRMWARE_FW_UGA_IO_H */
