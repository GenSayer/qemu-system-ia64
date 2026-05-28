#!/usr/bin/env python3
#
# IA-64 firmware UDF Bridge CD-ROM test.
# Builds a small ECMA-167/UDF 2.01 optical image with an ISO9660 El Torito
# boot record and verifies that the raw optical Simple File System path
# accepts the UDF volume descriptors and root directory ICB.

import os
import select
import struct
import subprocess
import sys
import tempfile
import time


ISO_SECTOR_SIZE = 2048
FAT_SECTOR_SIZE = 512
TOTAL_SECTORS = 544
CATALOG_LBA = 23
BOOT_LBA = 32
FAT_SECTORS = 64
MAIN_VDS_LBA = 257
PARTITION_START = 304
PARTITION_LENGTH = 64
PARTITION_NUMBER = 2989
PARTITION_REFERENCE = 0
ROOT_ICB = 2
EFI_ICB = 3
BOOT_ICB = 4

UDF_TAG_ANCHOR_VOLUME_DESCRIPTOR_POINTER = 2
UDF_TAG_PARTITION_DESCRIPTOR = 5
UDF_TAG_LOGICAL_VOLUME_DESCRIPTOR = 6
UDF_TAG_TERMINATING_DESCRIPTOR = 8
UDF_TAG_FILE_SET_DESCRIPTOR = 256
UDF_TAG_FILE_IDENTIFIER_DESCRIPTOR = 257
UDF_TAG_FILE_ENTRY = 261
UDF_FILE_TYPE_DIRECTORY = 4
UDF_FID_CHAR_DIRECTORY = 0x02
UDF_FID_CHAR_PARENT = 0x08
UDF_ICB_AD_INLINE = 3


def decode_output(output):
    return output.decode("utf-8", errors="replace")


def sector(image, lba):
    start = lba * ISO_SECTOR_SIZE
    return memoryview(image)[start:start + ISO_SECTOR_SIZE]


def udf_crc16(data):
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def finish_udf_tag(buf, tag_id, location, crc_len):
    struct.pack_into("<H", buf, 0, tag_id)
    struct.pack_into("<H", buf, 2, 3)
    buf[4] = 0
    buf[5] = 0
    struct.pack_into("<H", buf, 6, 1)
    struct.pack_into("<H", buf, 8, udf_crc16(buf[16:16 + crc_len]))
    struct.pack_into("<H", buf, 10, crc_len)
    struct.pack_into("<I", buf, 12, location)

    checksum = 0
    for i in range(16):
        if i != 4:
            checksum = (checksum + buf[i]) & 0xFF
    buf[4] = checksum


def write_regid(buf, offset, identifier):
    encoded = identifier.encode("ascii")
    buf[offset] = 0
    buf[offset + 1:offset + 1 + len(encoded)] = encoded


def write_long_ad(buf, offset, length, location, partition_reference):
    struct.pack_into("<I", buf, offset, length)
    struct.pack_into("<I", buf, offset + 4, location)
    struct.pack_into("<H", buf, offset + 8, partition_reference)


def make_fat_image(sectors):
    image = bytearray(sectors * FAT_SECTOR_SIZE)

    image[0:3] = b"\xeb\x3c\x90"
    image[3:11] = b"QEMU    "
    struct.pack_into("<H", image, 11, FAT_SECTOR_SIZE)
    image[13] = 1
    struct.pack_into("<H", image, 14, 1)
    image[16] = 1
    struct.pack_into("<H", image, 17, 16)
    struct.pack_into("<H", image, 19, sectors)
    image[21] = 0xF8
    struct.pack_into("<H", image, 22, 1)
    struct.pack_into("<H", image, 24, 1)
    struct.pack_into("<H", image, 26, 1)
    image[38] = 0x29
    image[510:512] = b"\x55\xaa"
    return image


def write_iso9660_el_torito(image):
    pvd = sector(image, 16)
    pvd[0] = 1
    pvd[1:6] = b"CD001"
    pvd[6] = 1
    struct.pack_into("<I", pvd, 80, TOTAL_SECTORS)
    struct.pack_into(">I", pvd, 84, TOTAL_SECTORS)

    boot_record = sector(image, 17)
    boot_record[0] = 0
    boot_record[1:6] = b"CD001"
    boot_record[6] = 1
    boot_record[7:30] = b"EL TORITO SPECIFICATION"
    struct.pack_into("<I", boot_record, 71, CATALOG_LBA)

    terminator = sector(image, 18)
    terminator[0] = 0xFF
    terminator[1:6] = b"CD001"
    terminator[6] = 1

    catalog = sector(image, CATALOG_LBA)
    catalog[0] = 1
    catalog[0x1E] = 0x55
    catalog[0x1F] = 0xAA
    catalog[0x20] = 0x88
    struct.pack_into("<H", catalog, 0x26, 1)
    struct.pack_into("<I", catalog, 0x28, BOOT_LBA)

    fat = make_fat_image(FAT_SECTORS)
    start = BOOT_LBA * ISO_SECTOR_SIZE
    image[start:start + len(fat)] = fat


def write_udf_vrs(image):
    for lba, ident in [(19, b"BEA01"), (20, b"NSR02"), (21, b"TEA01")]:
        desc = sector(image, lba)
        desc[0] = 0
        desc[1:6] = ident
        desc[6] = 1


def write_anchor(image, lba):
    desc = sector(image, lba)
    struct.pack_into("<I", desc, 16, 3 * ISO_SECTOR_SIZE)
    struct.pack_into("<I", desc, 20, MAIN_VDS_LBA)
    finish_udf_tag(desc, UDF_TAG_ANCHOR_VOLUME_DESCRIPTOR_POINTER, lba, 496)


def write_logical_volume_descriptor(image):
    desc = sector(image, MAIN_VDS_LBA)
    struct.pack_into("<I", desc, 212, ISO_SECTOR_SIZE)
    write_regid(desc, 216, "*OSTA UDF Compliant")
    write_long_ad(desc, 248, ISO_SECTOR_SIZE, 0, PARTITION_REFERENCE)
    struct.pack_into("<I", desc, 264, 6)
    struct.pack_into("<I", desc, 268, 1)
    desc[440] = 1
    desc[441] = 6
    struct.pack_into("<H", desc, 442, 1)
    struct.pack_into("<H", desc, 444, PARTITION_NUMBER)
    finish_udf_tag(desc, UDF_TAG_LOGICAL_VOLUME_DESCRIPTOR, MAIN_VDS_LBA, 430)


def write_partition_descriptor(image):
    desc = sector(image, MAIN_VDS_LBA + 1)
    struct.pack_into("<I", desc, 16, 1)
    struct.pack_into("<H", desc, 22, PARTITION_NUMBER)
    write_regid(desc, 24, "+NSR02")
    struct.pack_into("<I", desc, 188, PARTITION_START)
    struct.pack_into("<I", desc, 192, PARTITION_LENGTH)
    finish_udf_tag(desc, UDF_TAG_PARTITION_DESCRIPTOR, MAIN_VDS_LBA + 1, 496)


def write_terminating_descriptor(image):
    desc = sector(image, MAIN_VDS_LBA + 2)
    finish_udf_tag(desc, UDF_TAG_TERMINATING_DESCRIPTOR, MAIN_VDS_LBA + 2, 496)


def make_fid(name, characteristics, icb, parent_icb):
    name_bytes = b"" if not name else bytes([8]) + name.encode("ascii")
    total = (38 + len(name_bytes) + 3) & ~3
    fid = bytearray(total)

    struct.pack_into("<H", fid, 16, 1)
    fid[18] = characteristics
    fid[19] = len(name_bytes)
    write_long_ad(fid, 20, ISO_SECTOR_SIZE, icb, PARTITION_REFERENCE)
    struct.pack_into("<I", fid, 30, parent_icb)
    struct.pack_into("<H", fid, 36, 0)
    fid[38:38 + len(name_bytes)] = name_bytes
    finish_udf_tag(
        fid,
        UDF_TAG_FILE_IDENTIFIER_DESCRIPTOR,
        parent_icb,
        22 + len(name_bytes),
    )
    return bytes(fid)


def write_file_entry(image, icb, parent_icb, data):
    desc = sector(image, PARTITION_START + icb)

    struct.pack_into("<H", desc, 20, 4)
    desc[27] = UDF_FILE_TYPE_DIRECTORY
    struct.pack_into("<I", desc, 28, parent_icb)
    struct.pack_into("<H", desc, 32, PARTITION_REFERENCE)
    struct.pack_into("<H", desc, 34, UDF_ICB_AD_INLINE)
    struct.pack_into("<H", desc, 52, 1)
    struct.pack_into("<Q", desc, 56, len(data))
    struct.pack_into("<I", desc, 112, 1)
    struct.pack_into("<Q", desc, 120, icb + 1)
    struct.pack_into("<I", desc, 168, 0)
    struct.pack_into("<I", desc, 172, len(data))
    desc[176:176 + len(data)] = data
    finish_udf_tag(desc, UDF_TAG_FILE_ENTRY, icb, 160 + len(data))


def write_file_set_descriptor(image):
    desc = sector(image, PARTITION_START)
    write_long_ad(desc, 400, ISO_SECTOR_SIZE, ROOT_ICB, PARTITION_REFERENCE)
    finish_udf_tag(desc, UDF_TAG_FILE_SET_DESCRIPTOR, 0, 496)


def write_udf_filesystem(image):
    write_udf_vrs(image)
    write_anchor(image, 256)
    write_anchor(image, TOTAL_SECTORS - 1)
    write_logical_volume_descriptor(image)
    write_partition_descriptor(image)
    write_terminating_descriptor(image)
    write_file_set_descriptor(image)

    root_data = b"".join([
        make_fid("", UDF_FID_CHAR_DIRECTORY | UDF_FID_CHAR_PARENT,
                 ROOT_ICB, ROOT_ICB),
        make_fid("EFI", UDF_FID_CHAR_DIRECTORY, EFI_ICB, ROOT_ICB),
    ])
    efi_data = b"".join([
        make_fid("", UDF_FID_CHAR_DIRECTORY | UDF_FID_CHAR_PARENT,
                 ROOT_ICB, EFI_ICB),
        make_fid("BOOT", UDF_FID_CHAR_DIRECTORY, BOOT_ICB, EFI_ICB),
    ])
    boot_data = make_fid("", UDF_FID_CHAR_DIRECTORY | UDF_FID_CHAR_PARENT,
                         EFI_ICB, BOOT_ICB)

    write_file_entry(image, ROOT_ICB, ROOT_ICB, root_data)
    write_file_entry(image, EFI_ICB, ROOT_ICB, efi_data)
    write_file_entry(image, BOOT_ICB, EFI_ICB, boot_data)


def make_udf_bridge_iso(path):
    image = bytearray(TOTAL_SECTORS * ISO_SECTOR_SIZE)
    write_iso9660_el_torito(image)
    write_udf_filesystem(image)
    with open(path, "wb") as f:
        f.write(image)


def run_qemu(qemu, firmware, disk):
    args = [
        qemu,
        "-machine", "ia64-vpc",
        "-smp", "1",
        "-bios", firmware,
        "-display", "none",
        "-serial", "stdio",
        "-monitor", "none",
        "-drive", f"file={disk},if=ide,format=raw,media=cdrom,readonly=on",
    ]
    proc = subprocess.Popen(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    output_parts = []
    deadline = time.monotonic() + 8.0
    try:
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            readable, _, _ = select.select([proc.stdout], [], [], 0.1)
            if readable:
                chunk = os.read(proc.stdout.fileno(), 4096)
                if not chunk:
                    break
                output_parts.append(chunk)
                output = decode_output(b"".join(output_parts))
                if "UDF root verified" in output:
                    break
        returncode = proc.poll()
        if returncode is None:
            proc.terminate()
            try:
                output, _ = proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                output, _ = proc.communicate(timeout=2)
        else:
            output, _ = proc.communicate(timeout=2)
        output_parts.append(output)
        return returncode, decode_output(b"".join(output_parts))
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2)


def main():
    if len(sys.argv) != 3:
        print(
            "Bail out! usage: test-ia64-fw-udf-cdrom.py "
            "QEMU_SYSTEM_IA64 IA64_FIRMWARE_BIN"
        )
        return 1

    qemu = sys.argv[1]
    firmware = sys.argv[2]

    print("TAP version 13")
    print("1..1")

    if not os.path.exists(qemu):
        print(f"not ok 1 - qemu exists ({qemu})")
        return 1
    if not os.path.exists(firmware):
        print(f"not ok 1 - firmware exists ({firmware})")
        return 1

    with tempfile.TemporaryDirectory() as tmpdir:
        disk = os.path.join(tmpdir, "udf-bridge.iso")
        make_udf_bridge_iso(disk)
        returncode, output = run_qemu(qemu, firmware, disk)

    required = [
        "IDE device:           ATAPI primary master",
        "Block I/O: El Torito FAT image mapped",
        "Optical SimpleFS:     UDF root verified",
    ]
    missing = [sig for sig in required if sig not in output]
    if returncode is not None:
        print("not ok 1 - qemu exited during UDF CD-ROM test")
        for line in output.splitlines():
            print(f"# {line}")
        return 1
    if missing:
        print("not ok 1 - UDF CD-ROM signatures")
        for sig in missing:
            print(f"# missing signature: {sig}")
        for line in output.splitlines():
            print(f"# {line}")
        return 1

    print("ok 1 - IA-64 firmware accepts UDF optical SimpleFS media")
    return 0


if __name__ == "__main__":
    sys.exit(main())
