/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "ia64-test.h"

static UINT8 loaded_image_guid[16] = IA64_GUID_LOADED_IMAGE;
static UINT8 device_path_guid[16] = IA64_GUID_DEVICE_PATH;

static BOOLEAN system_table_crc_valid(EFI_SYSTEM_TABLE *SystemTable)
{
    UINT8 copy[256];
    UINT32 crc = 0;
    UINT32 expected;
    UINTN size;

    if (SystemTable == NULL || SystemTable->BootServices == NULL ||
        SystemTable->BootServices->CalculateCrc32 == NULL ||
        SystemTable->Hdr.HeaderSize > sizeof(copy) ||
        SystemTable->Hdr.HeaderSize < sizeof(EFI_TABLE_HEADER)) {
        return 0;
    }
    size = SystemTable->Hdr.HeaderSize;
    expected = SystemTable->Hdr.CRC32;
    ia64_copy(copy, SystemTable, size);
    ((EFI_TABLE_HEADER *)copy)->CRC32 = 0;
    return SystemTable->BootServices->CalculateCrc32(copy, size, &crc) ==
               EFI_SUCCESS &&
           crc == expected;
}

EFI_STATUS efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    IA64_TEST_CONTEXT context = {
        .SystemTable = SystemTable,
        .Suite = "smoke",
        .Passed = 0,
        .Failed = 0,
        .DirectUart = 0,
    };
    EFI_LOADED_IMAGE_PROTOCOL *loaded = NULL;
    VOID *device_path = NULL;
    EFI_STATUS status;

    ia64_test_pass(&context, "entry");
    ia64_test_check(
        &context, "system-table",
        SystemTable != NULL &&
            SystemTable->Hdr.Signature == EFI_SYSTEM_TABLE_SIGNATURE &&
            SystemTable->BootServices != NULL &&
            SystemTable->BootServices->Hdr.Signature ==
                EFI_BOOT_SERVICES_SIGNATURE &&
            SystemTable->RuntimeServices != NULL &&
            SystemTable->RuntimeServices->Hdr.Signature ==
                EFI_RUNTIME_SERVICES_SIGNATURE &&
            system_table_crc_valid(SystemTable),
        EFI_DEVICE_ERROR, "signature-or-crc");

    status = SystemTable->BootServices->HandleProtocol(
        ImageHandle, loaded_image_guid, (VOID **)&loaded);
    ia64_test_check(&context, "loaded-image",
                    status == EFI_SUCCESS && loaded != NULL &&
                        loaded->DeviceHandle != NULL &&
                        loaded->ImageBase != NULL && loaded->ImageSize != 0,
                    status, "handle-protocol");

    if (loaded != NULL && loaded->DeviceHandle != NULL) {
        status = SystemTable->BootServices->HandleProtocol(
            loaded->DeviceHandle, device_path_guid, &device_path);
    } else {
        status = EFI_NOT_FOUND;
    }
    ia64_test_check(&context, "device-path",
                    status == EFI_SUCCESS && device_path != NULL,
                    status, "device-path-protocol");

    ia64_test_check(&context, "console-output",
                    SystemTable != NULL && SystemTable->ConOut != NULL &&
                        SystemTable->ConOut->OutputString != NULL,
                    EFI_DEVICE_ERROR, "missing-conout");
    ia64_test_done(&context);
    return context.Failed == 0 ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}

EFI_STATUS (*efi_entry_descriptor_reference)(EFI_HANDLE, EFI_SYSTEM_TABLE *)
    __attribute__((used)) = efi_main;
