#!/usr/bin/env python3
#
# IA-64 firmware storage acceptance and Block I/O test.
# Boots an EFI application from an explicitly requested CMD646 controller in
# PIO/DMA modes and from the default SCSI disk.  The application performs a
# 128 KiB write/read/restore cycle through Block I/O.

import os
import select
import struct
import subprocess
import sys
import tempfile
import time
import uuid
import zlib


SECTOR_SIZE = 512
DISK_SECTORS = 16384
FAT_SECTORS = 64
ROOT_ENTRIES = 512
ROOT_SECTORS = ROOT_ENTRIES * 32 // SECTOR_SIZE
DATA_START = 1 + FAT_SECTORS + ROOT_SECTORS
TEST_BLOCKS = 256
GPT_ESP_START = 63
MBR_ESP_START = 63
SUCCESS_SIGNATURE = "IA64 STORAGE IO: read/write verified"
FAILURE_SIGNATURE = "IA64 STORAGE IO: failed"


def decode_output(output):
    return output.decode("utf-8", errors="replace")


def run_command(args):
    result = subprocess.run(
        args,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "command failed: " + " ".join(args) + "\n" + result.stdout
        )


def build_efi_application(source_root, output_dir):
    source = os.path.join(source_root, "tests/unit/ia64-storage-io-app.c")
    linker_script = os.path.join(
        source_root, "tests/unit/ia64-storage-io-app.lds"
    )
    obj = os.path.join(output_dir, "ia64-storage-io-app.o")
    elf = os.path.join(output_dir, "ia64-storage-io-app.elf")
    efi = os.path.join(output_dir, "BOOTIA64.EFI")

    run_command([
        "ia64-linux-gnu-gcc",
        "-O2",
        "-fno-builtin",
        "-ffreestanding",
        "-nostdinc",
        "-nostdlib",
        "-mno-sdata",
        "-fno-stack-protector",
        "-fno-common",
        "-Wall",
        "-Wextra",
        "-c",
        "-o", obj,
        source,
    ])
    run_command([
        "ia64-linux-gnu-ld",
        "-nostdlib",
        "-static",
        "-T", linker_script,
        "-o", elf,
        obj,
    ])
    run_command([
        "ia64-linux-gnu-objcopy",
        "-R", ".comment",
        "-O", "pei-ia64",
        "--image-base=0x4000000",
        "--subsystem=10",
        elf,
        efi,
    ])
    return efi


def set_fat_entry(fat, cluster, value):
    struct.pack_into("<H", fat, cluster * 2, value)


def directory_entry(name, attributes, cluster, size=0):
    if len(name) != 11:
        raise ValueError("FAT short name must contain exactly 11 bytes")
    entry = bytearray(32)
    entry[0:11] = name
    entry[11] = attributes
    struct.pack_into("<H", entry, 26, cluster)
    struct.pack_into("<I", entry, 28, size)
    return entry


def make_storage_disk(path, efi_path, layout="whole"):
    with open(efi_path, "rb") as f:
        efi_image = f.read()

    image = bytearray(DISK_SECTORS * SECTOR_SIZE)
    image[0:3] = b"\xeb\x3c\x90"
    image[3:11] = b"QEMUIA64"
    struct.pack_into("<H", image, 11, SECTOR_SIZE)
    image[13] = 1
    struct.pack_into("<H", image, 14, 1)
    image[16] = 1
    struct.pack_into("<H", image, 17, ROOT_ENTRIES)
    struct.pack_into("<H", image, 19, DISK_SECTORS)
    image[21] = 0xF8
    struct.pack_into("<H", image, 22, FAT_SECTORS)
    struct.pack_into("<H", image, 24, 32)
    struct.pack_into("<H", image, 26, 64)
    image[38] = 0x29
    image[43:54] = b"IA64 IOTEST"
    image[54:62] = b"FAT16   "
    image[510:512] = b"\x55\xaa"

    fat_start = SECTOR_SIZE
    fat = memoryview(image)[
        fat_start:fat_start + FAT_SECTORS * SECTOR_SIZE
    ]
    set_fat_entry(fat, 0, 0xFFF8)
    set_fat_entry(fat, 1, 0xFFFF)
    set_fat_entry(fat, 2, 0xFFFF)
    set_fat_entry(fat, 3, 0xFFFF)

    file_clusters = (len(efi_image) + SECTOR_SIZE - 1) // SECTOR_SIZE
    first_file_cluster = 4
    last_file_cluster = first_file_cluster + file_clusters - 1
    if DATA_START + last_file_cluster - 2 >= DISK_SECTORS - TEST_BLOCKS:
        raise RuntimeError("EFI test application overlaps the I/O test region")
    for cluster in range(first_file_cluster, last_file_cluster + 1):
        next_cluster = 0xFFFF if cluster == last_file_cluster else cluster + 1
        set_fat_entry(fat, cluster, next_cluster)

    root_start = (1 + FAT_SECTORS) * SECTOR_SIZE
    image[root_start:root_start + 32] = directory_entry(
        b"EFI        ", 0x10, 2
    )

    efi_dir_start = DATA_START * SECTOR_SIZE
    image[efi_dir_start:efi_dir_start + 32] = directory_entry(
        b"BOOT       ", 0x10, 3
    )
    boot_dir_start = (DATA_START + 1) * SECTOR_SIZE
    image[boot_dir_start:boot_dir_start + 32] = directory_entry(
        b"BOOTIA64EFI", 0x20, first_file_cluster, len(efi_image)
    )

    file_start = (DATA_START + first_file_cluster - 2) * SECTOR_SIZE
    image[file_start:file_start + len(efi_image)] = efi_image

    if layout == "gpt":
        total_sectors = GPT_ESP_START + DISK_SECTORS + 33
        raw = bytearray(total_sectors * SECTOR_SIZE)
        raw[446 + 4] = 0xEE
        struct.pack_into("<I", raw, 446 + 8, 1)
        struct.pack_into("<I", raw, 446 + 12, total_sectors - 1)
        raw[510:512] = b"\x55\xaa"

        entries = bytearray(128 * 128)
        entries[0:16] = uuid.UUID(
            "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
        ).bytes_le
        entries[16:32] = uuid.UUID(
            "12345678-9abc-def0-1234-56789abcdef0"
        ).bytes_le
        struct.pack_into(
            "<QQ", entries, 32,
            GPT_ESP_START, GPT_ESP_START + DISK_SECTORS - 1,
        )
        name = "EFI system partition".encode("utf-16le")
        entries[56:56 + len(name)] = name
        entries_crc = zlib.crc32(entries) & 0xFFFFFFFF

        def make_gpt_header(current, backup, entries_lba):
            header = bytearray(SECTOR_SIZE)
            header[0:8] = b"EFI PART"
            struct.pack_into("<I", header, 8, 0x00010000)
            struct.pack_into("<I", header, 12, 92)
            struct.pack_into("<QQQQ", header, 24, current, backup,
                             34, total_sectors - 34)
            header[56:72] = uuid.UUID(
                "0fedcba9-8765-4321-fedc-ba9876543210"
            ).bytes_le
            struct.pack_into("<QIII", header, 72, entries_lba,
                             128, 128, entries_crc)
            struct.pack_into(
                "<I", header, 16,
                zlib.crc32(header[:92]) & 0xFFFFFFFF,
            )
            return header

        backup_entries_lba = total_sectors - 33
        raw[2 * SECTOR_SIZE:34 * SECTOR_SIZE] = entries
        raw[backup_entries_lba * SECTOR_SIZE:
            (backup_entries_lba + 32) * SECTOR_SIZE] = entries
        raw[SECTOR_SIZE:2 * SECTOR_SIZE] = make_gpt_header(
            1, total_sectors - 1, 2
        )
        raw[(total_sectors - 1) * SECTOR_SIZE:] = make_gpt_header(
            total_sectors - 1, 1, backup_entries_lba
        )
        raw[GPT_ESP_START * SECTOR_SIZE:
            (GPT_ESP_START + DISK_SECTORS) * SECTOR_SIZE] = image
        image = raw
    elif layout in ("mbr", "mbr-fallback"):
        total_sectors = MBR_ESP_START + DISK_SECTORS
        raw = bytearray(total_sectors * SECTOR_SIZE)
        partition_entry = 446
        if layout == "mbr-fallback":
            raw[partition_entry] = 0x80
            raw[partition_entry + 4] = 0x0B
            struct.pack_into("<I", raw, partition_entry + 8, 1)
            struct.pack_into(
                "<I", raw, partition_entry + 12, MBR_ESP_START - 1
            )
            partition_entry += 16
            raw[partition_entry] = 0x7F
            raw[partition_entry + 4] = 0xEF
        else:
            raw[partition_entry] = 0x80
            raw[partition_entry + 4] = 0x0B
        struct.pack_into(
            "<I", raw, partition_entry + 8, MBR_ESP_START
        )
        struct.pack_into("<I", raw, partition_entry + 12, DISK_SECTORS)
        raw[510:512] = b"\x55\xaa"
        raw[MBR_ESP_START * SECTOR_SIZE:] = image
        image = raw
    elif layout != "whole":
        raise ValueError(f"unknown disk layout: {layout}")

    test_start = len(image) - TEST_BLOCKS * SECTOR_SIZE
    test_size = TEST_BLOCKS * SECTOR_SIZE
    if layout == "whole":
        for index in range(test_size):
            image[test_start + index] = (index * 19 + 0x31) & 0xff
    original_test_region = bytes(image[test_start:test_start + test_size])

    with open(path, "wb") as f:
        f.write(image)
    return original_test_region


def run_qemu(qemu, firmware, disk, machine, interface, trace_ide_dma):
    args = [
        qemu,
        "-machine", machine,
        "-smp", "1",
        "-bios", firmware,
        "-display", "none",
        "-serial", "stdio",
        "-monitor", "none",
    ]
    if interface == "ide":
        args += [
            "-drive", f"file={disk},format=raw,if=none,id=storage-disk",
            "-device", "cmd646-ide,id=ide,secondary=1,addr=0",
            "-device", "ide-hd,drive=storage-disk,bus=ide.0,unit=0",
        ]
    else:
        args += ["-drive", f"file={disk},format=raw,if={interface}"]
    if trace_ide_dma:
        args += ["-trace", "enable=bmdma_cmd_writeb"]
    proc = subprocess.Popen(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    output_parts = []
    deadline = time.monotonic() + 20.0
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
                if SUCCESS_SIGNATURE in output or FAILURE_SIGNATURE in output:
                    break

        returncode = proc.poll()
        if returncode is None:
            proc.terminate()
            try:
                tail, _ = proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                tail, _ = proc.communicate(timeout=2)
        else:
            tail, _ = proc.communicate(timeout=2)
        output_parts.append(tail)
        return returncode, decode_output(b"".join(output_parts))
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2)


def check_restored_region(disk, expected):
    with open(disk, "rb") as f:
        f.seek(-len(expected), os.SEEK_END)
        actual = f.read(len(expected))
    return actual == expected


def main():
    if len(sys.argv) != 4:
        print(
            "Bail out! usage: test-ia64-fw-storage.py "
            "SOURCE_ROOT QEMU_SYSTEM_IA64 IA64_FIRMWARE_BIN"
        )
        return 1

    source_root, qemu, firmware = sys.argv[1:]
    print("TAP version 13")
    print("1..6")

    for path in [qemu, firmware]:
        if not os.path.exists(path):
            print(f"Bail out! missing input: {path}")
            return 1

    scenarios = [
        (
            "IDE bus-master DMA read/write",
            "ia64-vpc",
            "ide",
            [
                "IDE device:           ATA primary master",
                "Block I/O Protocol:   installed "
                "(ATA DMA-capable, primary IDE)",
            ],
            "dma",
            "whole",
        ),
        (
            "IDE PIO read/write",
            "ia64-vpc,firmware-ide-dma=off",
            "ide",
            [
                "IDE device:           ATA primary master",
                "Block I/O Protocol:   installed (ATA PIO, primary IDE)",
            ],
            "pio",
            "whole",
        ),
        (
            "LSI SCSI read/write",
            "ia64-vpc",
            "scsi",
            [
                "SCSI device:          target 0000000000000000 disk media",
                "Block I/O Protocol:   installed (SCSI disk, LSI53C895A)",
            ],
            None,
            "whole",
        ),
        (
            "GPT EFI system partition",
            "ia64-vpc",
            "scsi",
            [
                "SCSI device:          target 0000000000000000 disk media",
                "Block I/O Protocol:   installed (SCSI disk, LSI53C895A)",
            ],
            None,
            "gpt",
        ),
        (
            "MBR FAT system partition",
            "ia64-vpc",
            "scsi",
            [
                "SCSI device:          target 0000000000000000 disk media",
                "Block I/O Protocol:   installed (SCSI disk, LSI53C895A)",
            ],
            None,
            "mbr",
        ),
        (
            "MBR EFI partition ignores legacy boot indicator",
            "ia64-vpc",
            "scsi",
            [
                "SCSI device:          target 0000000000000000 disk media",
                "Block I/O Protocol:   installed (SCSI disk, LSI53C895A)",
            ],
            None,
            "mbr-fallback",
        ),
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            efi_app = build_efi_application(source_root, tmpdir)
        except Exception as exc:
            print("Bail out! failed to build IA-64 EFI storage application")
            for line in str(exc).splitlines():
                print(f"# {line}")
            return 1

        status = 0
        for index, scenario in enumerate(scenarios, 1):
            name, machine, interface, signatures, ide_mode, layout = scenario
            disk = os.path.join(tmpdir, f"storage-{index}.img")
            expected_region = make_storage_disk(
                disk, efi_app, layout=layout
            )
            returncode, output = run_qemu(
                qemu, firmware, disk, machine, interface,
                trace_ide_dma=ide_mode is not None,
            )
            required = [
                "Boot Manager:        trying Boot0000000000000000",
                SUCCESS_SIGNATURE,
            ] + signatures
            missing = [
                signature for signature in required
                if signature not in output
            ]
            if ide_mode == "dma":
                for signature in [
                    "bmdma_cmd_writeb val: 0x00000009",
                    "bmdma_cmd_writeb val: 0x00000001",
                ]:
                    if signature not in output:
                        missing.append(signature)
            unexpected_dma = (
                ide_mode == "pio" and "bmdma_cmd_writeb" in output
            )
            restored = check_restored_region(disk, expected_region)

            if (returncode is not None or missing or unexpected_dma or
                    not restored):
                status = 1
                print(f"not ok {index} - {name}")
                if returncode is not None:
                    print(f"# qemu exited with status {returncode}")
                for signature in missing:
                    print(f"# missing signature: {signature}")
                if unexpected_dma:
                    print("# IDE PIO scenario issued a bus-master DMA command")
                if not restored:
                    print("# EFI application did not restore the test region")
                for line in output.splitlines():
                    print(f"# {line}")
            else:
                print(f"ok {index} - {name}")

    return status


if __name__ == "__main__":
    sys.exit(main())
