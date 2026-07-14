/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "ia64-test.h"

#define MAX_TEST_BLOCKS 256U
#define EFI_MEDIA_CHANGED EFIERR(13)

static UINT8 loaded_image_guid[16] = IA64_GUID_LOADED_IMAGE;
static UINT8 block_io_guid[16] = IA64_GUID_BLOCK_IO;
static UINT8 disk_io_guid[16] = IA64_GUID_DISK_IO;
static UINT8 simple_fs_guid[16] = IA64_GUID_SIMPLE_FILE_SYSTEM;
static CHAR16 boot_app_path[] = {
    '\\', 'E', 'F', 'I', '\\', 'B', 'O', 'O', 'T', '\\',
    'B', 'O', 'O', 'T', 'I', 'A', '6', '4', '.', 'E', 'F', 'I', 0,
};

static UINT8 pattern_byte(UINTN Index)
{
    return (UINT8)(((Index * 37U) + (Index >> 8) + 0x5aU) & 0xffU);
}

static UINT8 fixture_byte(UINTN Index)
{
    return (UINT8)((Index * 19U + 0x31U) & 0xffU);
}

static UINT16 get_u16(const UINT8 *Buffer)
{
    return (UINT16)Buffer[0] | ((UINT16)Buffer[1] << 8);
}

static UINT32 get_u32(const UINT8 *Buffer)
{
    return (UINT32)Buffer[0] | ((UINT32)Buffer[1] << 8) |
           ((UINT32)Buffer[2] << 16) | ((UINT32)Buffer[3] << 24);
}

static UINT64 get_u64(const UINT8 *Buffer)
{
    return (UINT64)get_u32(Buffer) | ((UINT64)get_u32(Buffer + 4) << 32);
}

static BOOLEAN bytes_equal(const UINT8 *Left, const UINT8 *Right, UINTN Size)
{
    UINTN index;

    for (index = 0; index < Size; index++) {
        if (Left[index] != Right[index]) {
            return 0;
        }
    }
    return 1;
}

static BOOLEAN fat_boot_sector_valid(const UINT8 *Sector, UINTN SectorSize,
                                     UINT64 *VolumeBlocks)
{
    UINT32 blocks;

    if (SectorSize < 512U || Sector[0] != 0xebU || Sector[1] != 0x3cU ||
        Sector[2] != 0x90U || !bytes_equal(Sector + 3,
                                          (const UINT8 *)"QEMUIA64", 8) ||
        get_u16(Sector + 11) != 512U || Sector[13] == 0 ||
        Sector[16] == 0 || Sector[510] != 0x55U || Sector[511] != 0xaaU) {
        return 0;
    }
    blocks = get_u16(Sector + 19);
    if (blocks == 0) {
        blocks = get_u32(Sector + 32);
    }
    if (blocks == 0) {
        return 0;
    }
    *VolumeBlocks = blocks;
    return 1;
}

static BOOLEAN find_fat_test_region(EFI_BLOCK_IO_PROTOCOL *Block,
                                    EFI_BLOCK_IO_MEDIA *Media, UINT8 *Sector,
                                    UINT64 *StartLba, UINT64 *BlockCount)
{
    static const UINT8 esp_guid[16] = {
        0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11,
        0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
    };
    UINT64 volume_start = 0;
    UINT64 volume_blocks = 0;
    EFI_STATUS status;
    UINTN index;

    status = Block->ReadBlocks(Block, Media->MediaId, 0, Media->BlockSize,
                               Sector);
    if (status != EFI_SUCCESS) {
        return 0;
    }
    if (!fat_boot_sector_valid(Sector, Media->BlockSize, &volume_blocks)) {
        UINTN selected = 4U;

        if (Media->BlockSize != 512U || Sector[510] != 0x55U ||
            Sector[511] != 0xaaU) {
            return 0;
        }
        for (index = 0; index < 4U; index++) {
            const UINT8 *entry = Sector + 446U + index * 16U;

            if (entry[4] == 0xefU) {
                selected = index;
                break;
            }
            if (selected == 4U && entry[4] != 0 && entry[4] != 0xeeU) {
                selected = index;
            }
        }
        if (Sector[446U + 4U] == 0xeeU) {
            UINT64 entries_lba;
            UINT32 entry_size;

            status = Block->ReadBlocks(Block, Media->MediaId, 1,
                                       Media->BlockSize, Sector);
            if (status != EFI_SUCCESS ||
                !bytes_equal(Sector, (const UINT8 *)"EFI PART", 8)) {
                return 0;
            }
            entries_lba = get_u64(Sector + 72);
            entry_size = get_u32(Sector + 84);
            if (entries_lba > Media->LastBlock || entry_size < 128U ||
                entry_size > Media->BlockSize) {
                return 0;
            }
            status = Block->ReadBlocks(Block, Media->MediaId, entries_lba,
                                       Media->BlockSize, Sector);
            if (status != EFI_SUCCESS ||
                !bytes_equal(Sector, esp_guid, sizeof(esp_guid))) {
                return 0;
            }
            volume_start = get_u64(Sector + 32);
            volume_blocks = get_u64(Sector + 40);
            if (volume_blocks < volume_start) {
                return 0;
            }
            volume_blocks = volume_blocks - volume_start + 1U;
        } else {
            const UINT8 *entry;

            if (selected == 4U) {
                return 0;
            }
            entry = Sector + 446U + selected * 16U;
            volume_start = get_u32(entry + 8);
            volume_blocks = get_u32(entry + 12);
        }

        if (volume_blocks == 0 || volume_start > Media->LastBlock ||
            volume_blocks - 1U > Media->LastBlock - volume_start) {
            return 0;
        }
        status = Block->ReadBlocks(Block, Media->MediaId, volume_start,
                                   Media->BlockSize, Sector);
        if (status != EFI_SUCCESS) {
            return 0;
        }
        {
            UINT64 fat_blocks;

            if (!fat_boot_sector_valid(Sector, Media->BlockSize,
                                       &fat_blocks) ||
                fat_blocks != volume_blocks) {
                return 0;
            }
        }
    }

    if (volume_blocks == 0 || volume_start > Media->LastBlock ||
        volume_blocks - 1U > Media->LastBlock - volume_start) {
        return 0;
    }
    *BlockCount = volume_blocks > MAX_TEST_BLOCKS ?
        MAX_TEST_BLOCKS : volume_blocks;
    *StartLba = volume_start + volume_blocks - *BlockCount;
    return 1;
}

static BOOLEAN original_fixture_data_valid(const UINT8 *Buffer, UINTN Size)
{
    UINTN index;

    for (index = 0; index < Size; index++) {
        if (Buffer[index] != fixture_byte(index)) {
            return 0;
        }
    }
    return 1;
}

/*
 * The El Torito boot image has its own FAT SimpleFS handle.  A UDF bridge
 * additionally exposes the raw optical handle.  Opening the application from
 * a handle other than the loaded image's handle proves that the native UDF
 * directory tree, not merely the El Torito FAT image, was parsed correctly.
 */
static BOOLEAN probe_native_optical_filesystem(EFI_BOOT_SERVICES *bs,
                                                EFI_HANDLE loaded_handle)
{
    EFI_HANDLE *handles = NULL;
    UINTN handle_count = 0;
    UINTN index;
    EFI_STATUS status;
    BOOLEAN found = 0;

    status = bs->LocateHandleBuffer(EFI_LOCATE_BY_PROTOCOL, simple_fs_guid,
                                    NULL, &handle_count, &handles);
    if (status != EFI_SUCCESS || handles == NULL) {
        return 0;
    }
    for (index = 0; index < handle_count; index++) {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = NULL;
        EFI_BLOCK_IO_PROTOCOL *raw_block = NULL;
        EFI_FILE_PROTOCOL *root = NULL;
        EFI_FILE_PROTOCOL *file = NULL;
        UINT8 signature[2] = { 0, 0 };
        UINTN size = sizeof(signature);

        if (handles[index] == loaded_handle ||
            bs->HandleProtocol(handles[index], block_io_guid,
                               (VOID **)&raw_block) != EFI_SUCCESS ||
            raw_block == NULL || raw_block->Media == NULL ||
            !raw_block->Media->MediaPresent ||
            !raw_block->Media->RemovableMedia ||
            !raw_block->Media->ReadOnly ||
            raw_block->Media->LogicalPartition ||
            raw_block->Media->BlockSize != 2048U ||
            bs->HandleProtocol(handles[index], simple_fs_guid,
                               (VOID **)&fs) != EFI_SUCCESS ||
            fs == NULL || fs->OpenVolume(fs, &root) != EFI_SUCCESS ||
            root == NULL) {
            continue;
        }
        status = root->Open(root, &file, boot_app_path,
                            EFI_FILE_MODE_READ, 0);
        if (status == EFI_SUCCESS && file != NULL &&
            file->Read(file, &size, signature) == EFI_SUCCESS && size == 2 &&
            signature[0] == 'M' && signature[1] == 'Z') {
            found = 1;
        }
        if (file != NULL) {
            (void)file->Close(file);
        }
        (void)root->Close(root);
        if (found) {
            break;
        }
    }
    (void)bs->FreePool(handles);
    return found;
}

EFI_STATUS efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    IA64_TEST_CONTEXT context = {
        .SystemTable = SystemTable,
        .Suite = "storage",
        .Passed = 0,
        .Failed = 0,
        .DirectUart = 0,
    };
    EFI_BOOT_SERVICES *bs = SystemTable->BootServices;
    EFI_LOADED_IMAGE_PROTOCOL *loaded = NULL;
    EFI_BLOCK_IO_PROTOCOL *block = NULL;
    EFI_DISK_IO_PROTOCOL *disk = NULL;
    EFI_BLOCK_IO_MEDIA *media = NULL;
    UINT8 *original = NULL;
    UINT8 *buffer = NULL;
    UINT8 disk_probe[31];
    UINT64 block_count;
    UINT64 start_lba = 0;
    UINT64 disk_offset;
    UINT64 media_bytes;
    UINTN allocation_size = 0;
    UINTN size = 0;
    UINTN index;
    EFI_STATUS status;
    EFI_STATUS restore_status;
    UINT32 invalid_media_id;
    BOOLEAN layout_valid;
    BOOLEAN error_contracts_valid;
    BOOLEAN bulk_content_valid;
    BOOLEAN disk_content_valid;
    BOOLEAN restore_verified;
    BOOLEAN wrote = 0;
    BOOLEAN write_ok = 0;

    status = bs->HandleProtocol(ImageHandle, loaded_image_guid,
                                (VOID **)&loaded);
    if (status == EFI_SUCCESS && loaded != NULL &&
        loaded->DeviceHandle != NULL) {
        status = bs->HandleProtocol(loaded->DeviceHandle, block_io_guid,
                                    (VOID **)&block);
    }
    if (status == EFI_SUCCESS && loaded != NULL) {
        status = bs->HandleProtocol(loaded->DeviceHandle, disk_io_guid,
                                    (VOID **)&disk);
    }
    ia64_test_check(&context, "loaded-protocols",
                    status == EFI_SUCCESS && block != NULL && disk != NULL,
                    status, "loaded-device-protocols");
    if (loaded != NULL &&
        probe_native_optical_filesystem(bs, loaded->DeviceHandle)) {
        ia64_test_pass(&context, "udf-filesystem");
    }
    if (block == NULL || disk == NULL || block->Media == NULL) {
        ia64_test_done(&context);
        return EFI_DEVICE_ERROR;
    }

    media = block->Media;
    block_count = media->LastBlock + 1U;
    ia64_test_check(
        &context, "block-media",
        media->MediaPresent && media->BlockSize >= 512U &&
            media->BlockSize <= 4096U && block_count != 0,
        EFI_DEVICE_ERROR, "invalid-media");
    if (!media->MediaPresent || media->BlockSize < 512U ||
        media->BlockSize > 4096U || block_count == 0) {
        ia64_test_done(&context);
        return EFI_DEVICE_ERROR;
    }

    if (block_count > MAX_TEST_BLOCKS) {
        block_count = MAX_TEST_BLOCKS;
    }
    allocation_size = (UINTN)block_count * media->BlockSize;
    if (bs->AllocatePool(EfiLoaderData, allocation_size, (VOID **)&original) !=
            EFI_SUCCESS ||
        bs->AllocatePool(EfiLoaderData, allocation_size, (VOID **)&buffer) !=
            EFI_SUCCESS) {
        ia64_test_fail(&context, "bulk-read", EFI_OUT_OF_RESOURCES,
                       "buffer-allocation");
        goto out;
    }

    layout_valid = find_fat_test_region(block, media, buffer, &start_lba,
                                        &block_count);
    ia64_test_check(&context, "media-layout", layout_valid,
                    EFI_DEVICE_ERROR, "fat-test-region");
    if (!layout_valid) {
        goto out;
    }
    size = (UINTN)block_count * media->BlockSize;
    status = block->ReadBlocks(block, media->MediaId, start_lba, size,
                               original);
    bulk_content_valid = status == EFI_SUCCESS &&
        (media->ReadOnly || original_fixture_data_valid(original, size));
    ia64_test_check(&context, "bulk-read", bulk_content_valid,
                    status, "read-blocks");
    if (status != EFI_SUCCESS) {
        goto out;
    }

    invalid_media_id = media->MediaId ^ 1U;
    error_contracts_valid =
        block->ReadBlocks(block, invalid_media_id, start_lba,
                          media->BlockSize, buffer) == EFI_MEDIA_CHANGED &&
        block->ReadBlocks(block, media->MediaId, media->LastBlock + 1U,
                          media->BlockSize, buffer) == EFI_INVALID_PARAMETER &&
        block->ReadBlocks(block, media->MediaId, start_lba,
                          media->BlockSize - 1U,
                          buffer) == EFI_BAD_BUFFER_SIZE &&
        block->ReadBlocks(block, media->MediaId, start_lba,
                          media->BlockSize, NULL) == EFI_INVALID_PARAMETER;
    if (error_contracts_valid && media->IoAlign > 1U) {
        error_contracts_valid =
            block->ReadBlocks(block, media->MediaId, start_lba,
                              media->BlockSize, buffer + 1) ==
                EFI_INVALID_PARAMETER;
    }
    media_bytes = (media->LastBlock + 1U) * (UINT64)media->BlockSize;
    error_contracts_valid = error_contracts_valid &&
        disk->ReadDisk(disk, invalid_media_id, 0, 1,
                       disk_probe) == EFI_MEDIA_CHANGED &&
        disk->ReadDisk(disk, media->MediaId, media_bytes, 1,
                       disk_probe) == EFI_INVALID_PARAMETER;
    ia64_test_check(&context, "block-error-contracts", error_contracts_valid,
                    EFI_DEVICE_ERROR, "media-id-range-size-alignment");

    disk_offset = start_lba * (UINT64)media->BlockSize + 3U;
    status = disk->ReadDisk(disk, media->MediaId, disk_offset,
                            sizeof(disk_probe), disk_probe);
    disk_content_valid = status == EFI_SUCCESS &&
        bytes_equal(disk_probe, original + 3U, sizeof(disk_probe));
    ia64_test_check(&context, "disk-read", disk_content_valid,
                    status, "read-disk-content");

    if (media->ReadOnly) {
        status = block->WriteBlocks(block, media->MediaId, start_lba, size,
                                    original);
        ia64_test_check(&context, "read-only-media",
                        status == EFI_WRITE_PROTECTED, status,
                        "write-blocks-status");
        goto out;
    }

    for (index = 0; index < size; index++) {
        buffer[index] = pattern_byte(index);
    }
    /* A failing transfer is not required to be atomic; always restore it. */
    wrote = 1;
    status = block->WriteBlocks(block, media->MediaId, start_lba, size,
                                buffer);
    if (status != EFI_SUCCESS) {
        goto write_done;
    }
    for (index = 0; index < size; index++) {
        buffer[index] = 0;
    }
    status = block->ReadBlocks(block, media->MediaId, start_lba, size,
                               buffer);
    if (status != EFI_SUCCESS) {
        goto write_done;
    }
    for (index = 0; index < size; index++) {
        if (buffer[index] != pattern_byte(index)) {
            status = EFI_DEVICE_ERROR;
            goto write_done;
        }
    }
    status = block->WriteBlocks(block, media->MediaId, start_lba, size,
                                original);
    if (status == EFI_SUCCESS) {
        status = block->FlushBlocks(block);
    }
    if (status == EFI_SUCCESS) {
        status = block->ReadBlocks(block, media->MediaId, start_lba, size,
                                   buffer);
    }
    restore_verified = status == EFI_SUCCESS &&
        bytes_equal(buffer, original, size);
    if (restore_verified) {
        wrote = 0;
        write_ok = 1;
    }

write_done:
    if (wrote) {
        restore_status = block->WriteBlocks(block, media->MediaId, start_lba,
                                            size, original);
        if (restore_status == EFI_SUCCESS) {
            restore_status = block->FlushBlocks(block);
        }
        if (restore_status == EFI_SUCCESS) {
            restore_status = block->ReadBlocks(block, media->MediaId,
                                               start_lba, size, buffer);
        }
        if (restore_status == EFI_SUCCESS &&
            bytes_equal(buffer, original, size)) {
            wrote = 0;
        } else {
            status = restore_status;
        }
    }
    ia64_test_check(&context, "write-read-restore",
                    write_ok && !wrote, status, "block-restore");

out:
    if (buffer != NULL) {
        (void)bs->FreePool(buffer);
    }
    if (original != NULL) {
        (void)bs->FreePool(original);
    }
    ia64_test_done(&context);
    return context.Failed == 0 ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}

EFI_STATUS (*efi_entry_descriptor_reference)(EFI_HANDLE, EFI_SYSTEM_TABLE *)
    __attribute__((used)) = efi_main;
