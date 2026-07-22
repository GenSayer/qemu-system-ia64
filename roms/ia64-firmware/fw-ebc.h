/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * EFI Byte Code interpreter module interface.
 */

#ifndef IA64_FIRMWARE_FW_EBC_H
#define IA64_FIRMWARE_FW_EBC_H

#include "fw-base.h"

EFI_STATUS fw_ebc_create_image_thunk(EFI_HANDLE image_handle,
                                     VOID *ebc_entry_point, VOID **thunk);
EFI_STATUS fw_ebc_unload_for_image(EFI_HANDLE image_handle);
BOOLEAN fw_ebc_install_protocol(VOID);
BOOLEAN fw_ebc_selftest(VOID);

#endif /* IA64_FIRMWARE_FW_EBC_H */
