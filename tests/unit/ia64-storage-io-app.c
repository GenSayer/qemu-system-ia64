/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Minimal IA-64 EFI application used by the firmware storage tests. */

typedef unsigned char UINT8;
typedef unsigned int UINT32;
typedef unsigned long UINT64;
typedef unsigned long UINTN;
typedef unsigned short CHAR16;
typedef UINT64 EFI_STATUS;
typedef void VOID;
typedef VOID *EFI_HANDLE;

#define EFI_SUCCESS 0
#define EFI_DEVICE_ERROR (0x8000000000000000ULL | 7U)
#define EFI_LOADER_DATA 2U
#define TEST_BLOCKS 256U

typedef struct {
    UINT64 Signature;
    UINT32 Revision;
    UINT32 HeaderSize;
    UINT32 Crc32;
    UINT32 Reserved;
} EFI_TABLE_HEADER;

typedef struct _EFI_SIMPLE_TEXT_OUT_PROTOCOL EFI_SIMPLE_TEXT_OUT_PROTOCOL;
struct _EFI_SIMPLE_TEXT_OUT_PROTOCOL {
    EFI_STATUS (*Reset)(EFI_SIMPLE_TEXT_OUT_PROTOCOL *This,
                        UINT8 ExtendedVerification);
    EFI_STATUS (*OutputString)(EFI_SIMPLE_TEXT_OUT_PROTOCOL *This,
                               CHAR16 *String);
    VOID *TestString;
    VOID *QueryMode;
    VOID *SetMode;
    VOID *SetAttribute;
    VOID *ClearScreen;
    VOID *SetCursorPosition;
    VOID *EnableCursor;
    VOID *Mode;
};

typedef struct _EFI_BOOT_SERVICES EFI_BOOT_SERVICES;
struct _EFI_BOOT_SERVICES {
    EFI_TABLE_HEADER Hdr;
    VOID *RaiseTpl;
    VOID *RestoreTpl;
    VOID *AllocatePages;
    VOID *FreePages;
    VOID *GetMemoryMap;
    EFI_STATUS (*AllocatePool)(UINT32 PoolType, UINTN Size, VOID **Buffer);
    EFI_STATUS (*FreePool)(VOID *Buffer);
    VOID *CreateEvent;
    VOID *SetTimer;
    VOID *WaitForEvent;
    VOID *SignalEvent;
    VOID *CloseEvent;
    VOID *CheckEvent;
    VOID *InstallProtocolInterface;
    VOID *ReinstallProtocolInterface;
    VOID *UninstallProtocolInterface;
    EFI_STATUS (*HandleProtocol)(EFI_HANDLE Handle, VOID *Protocol,
                                 VOID **Interface);
};

typedef struct {
    EFI_TABLE_HEADER Hdr;
    CHAR16 *FirmwareVendor;
    UINT32 FirmwareRevision;
    EFI_HANDLE ConsoleInHandle;
    VOID *ConIn;
    EFI_HANDLE ConsoleOutHandle;
    EFI_SIMPLE_TEXT_OUT_PROTOCOL *ConOut;
    EFI_HANDLE StandardErrorHandle;
    VOID *StdErr;
    VOID *RuntimeServices;
    EFI_BOOT_SERVICES *BootServices;
    UINTN NumberOfTableEntries;
    VOID *ConfigurationTable;
} EFI_SYSTEM_TABLE;

typedef struct {
    UINT32 Revision;
    EFI_HANDLE ParentHandle;
    EFI_SYSTEM_TABLE *SystemTable;
    EFI_HANDLE DeviceHandle;
    VOID *FilePath;
    VOID *Reserved;
    UINT32 LoadOptionsSize;
    VOID *LoadOptions;
    VOID *ImageBase;
    UINT64 ImageSize;
    UINT32 ImageCodeType;
    UINT32 ImageDataType;
    EFI_STATUS (*Unload)(EFI_HANDLE ImageHandle);
} EFI_LOADED_IMAGE_PROTOCOL;

typedef struct {
    UINT32 MediaId;
    UINT8 RemovableMedia;
    UINT8 MediaPresent;
    UINT8 LogicalPartition;
    UINT8 ReadOnly;
    UINT8 WriteCaching;
    UINT32 BlockSize;
    UINT32 IoAlign;
    UINT64 LastBlock;
} EFI_BLOCK_IO_MEDIA;

typedef struct _EFI_BLOCK_IO_PROTOCOL EFI_BLOCK_IO_PROTOCOL;
struct _EFI_BLOCK_IO_PROTOCOL {
    UINT64 Revision;
    EFI_BLOCK_IO_MEDIA *Media;
    EFI_STATUS (*Reset)(EFI_BLOCK_IO_PROTOCOL *This,
                        UINT8 ExtendedVerification);
    EFI_STATUS (*ReadBlocks)(EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId,
                             UINT64 Lba, UINTN BufferSize, VOID *Buffer);
    EFI_STATUS (*WriteBlocks)(EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId,
                              UINT64 Lba, UINTN BufferSize, VOID *Buffer);
    EFI_STATUS (*FlushBlocks)(EFI_BLOCK_IO_PROTOCOL *This);
};

static UINT8 loaded_image_guid[16] = {
    0xa1, 0x31, 0x1b, 0x5b, 0x62, 0x95, 0xd2, 0x11,
    0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
};

static UINT8 block_io_guid[16] = {
    0x21, 0x5b, 0x4e, 0x96, 0x59, 0x64, 0xd2, 0x11,
    0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
};

static CHAR16 success_message[] = {
    'I', 'A', '6', '4', ' ', 'S', 'T', 'O', 'R', 'A', 'G', 'E', ' ',
    'I', 'O', ':', ' ', 'r', 'e', 'a', 'd', '/', 'w', 'r', 'i', 't', 'e',
    ' ', 'v', 'e', 'r', 'i', 'f', 'i', 'e', 'd', '\r', '\n', 0,
};

static CHAR16 failure_message[] = {
    'I', 'A', '6', '4', ' ', 'S', 'T', 'O', 'R', 'A', 'G', 'E', ' ',
    'I', 'O', ':', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '\r', '\n', 0,
};

static void output(EFI_SYSTEM_TABLE *system_table, CHAR16 *message)
{
    if (system_table != (VOID *)0 && system_table->ConOut != (VOID *)0) {
        system_table->ConOut->OutputString(system_table->ConOut, message);
    }
}

static UINT8 test_byte(UINTN index)
{
    return (UINT8)(((index * 37U) + (index >> 8) + 0x5aU) & 0xffU);
}

EFI_STATUS efi_main(EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *system_table)
{
    EFI_BOOT_SERVICES *boot_services;
    EFI_LOADED_IMAGE_PROTOCOL *loaded_image = (VOID *)0;
    EFI_BLOCK_IO_PROTOCOL *block_io = (VOID *)0;
    EFI_BLOCK_IO_MEDIA *media;
    UINT8 *original = (VOID *)0;
    UINT8 *buffer = (VOID *)0;
    UINTN size;
    UINT64 start_lba;
    UINTN index;
    EFI_STATUS status = EFI_DEVICE_ERROR;
    UINT8 wrote_test_data = 0;

    if (system_table == (VOID *)0 || system_table->BootServices == (VOID *)0) {
        return EFI_DEVICE_ERROR;
    }
    boot_services = system_table->BootServices;
    if (boot_services->HandleProtocol(image_handle, loaded_image_guid,
                                      (VOID **)&loaded_image) != EFI_SUCCESS ||
        loaded_image == (VOID *)0 || loaded_image->DeviceHandle == (VOID *)0 ||
        boot_services->HandleProtocol(loaded_image->DeviceHandle, block_io_guid,
                                      (VOID **)&block_io) != EFI_SUCCESS ||
        block_io == (VOID *)0 || block_io->Media == (VOID *)0) {
        goto out;
    }

    media = block_io->Media;
    if (!media->MediaPresent || media->ReadOnly || media->BlockSize != 512U ||
        media->LastBlock + 1U < TEST_BLOCKS) {
        goto out;
    }
    size = TEST_BLOCKS * media->BlockSize;
    start_lba = media->LastBlock + 1U - TEST_BLOCKS;

    if (boot_services->AllocatePool(EFI_LOADER_DATA, size,
                                    (VOID **)&original) != EFI_SUCCESS ||
        boot_services->AllocatePool(EFI_LOADER_DATA, size,
                                    (VOID **)&buffer) != EFI_SUCCESS) {
        goto out;
    }
    if (block_io->ReadBlocks(block_io, media->MediaId, start_lba, size,
                             original) != EFI_SUCCESS) {
        goto out;
    }
    for (index = 0; index < size; index++) {
        buffer[index] = test_byte(index);
    }
    wrote_test_data = 1;
    if (block_io->WriteBlocks(block_io, media->MediaId, start_lba, size,
                              buffer) != EFI_SUCCESS) {
        goto out;
    }
    for (index = 0; index < size; index++) {
        buffer[index] = 0;
    }
    if (block_io->ReadBlocks(block_io, media->MediaId, start_lba, size,
                             buffer) != EFI_SUCCESS) {
        goto out;
    }
    for (index = 0; index < size; index++) {
        if (buffer[index] != test_byte(index)) {
            goto out;
        }
    }
    status = EFI_SUCCESS;

out:
    if (wrote_test_data && original != (VOID *)0 && block_io != (VOID *)0) {
        if (block_io->WriteBlocks(block_io, block_io->Media->MediaId, start_lba,
                                  size, original) != EFI_SUCCESS ||
            block_io->FlushBlocks(block_io) != EFI_SUCCESS) {
            status = EFI_DEVICE_ERROR;
        }
    }
    if (buffer != (VOID *)0) {
        boot_services->FreePool(buffer);
    }
    if (original != (VOID *)0) {
        boot_services->FreePool(original);
    }
    output(system_table,
           status == EFI_SUCCESS ? success_message : failure_message);
    return status;
}

/* Force emission of the IA-64 function descriptor required by PE/COFF. */
EFI_STATUS (*efi_entry_descriptor_reference)(EFI_HANDLE, EFI_SYSTEM_TABLE *)
    __attribute__((used)) = efi_main;
