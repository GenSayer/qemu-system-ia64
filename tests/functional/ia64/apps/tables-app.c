/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "common/services.h"

EFI_STATUS efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    return ia64_services_main(ImageHandle, SystemTable, 1);
}

EFI_STATUS (*efi_entry_descriptor_reference)(EFI_HANDLE, EFI_SYSTEM_TABLE *)
    __attribute__((used)) = efi_main;
