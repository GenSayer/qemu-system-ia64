#!/usr/bin/env python3
#
# IA-64 firmware El Torito CD-ROM boot-path test.
# Verifies that the firmware maps El Torito no-emulation FAT images with the
# correct logical size for both EFI Platform ID entries and older FAT images.

import os
import select
import struct
import subprocess
import sys
import tempfile
import time


ISO_SECTOR_SIZE = 2048
FAT_SECTOR_SIZE = 512


def decode_output(output):
    return output.decode("utf-8", errors="replace")


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


def make_el_torito_iso(path, platform_id, catalog_sector_count, fat_sectors):
    iso_sectors = 512
    boot_lba = 64
    catalog_lba = 19
    image = bytearray(iso_sectors * ISO_SECTOR_SIZE)

    pvd = memoryview(image)[16 * ISO_SECTOR_SIZE:(17 * ISO_SECTOR_SIZE)]
    pvd[0] = 1
    pvd[1:6] = b"CD001"
    pvd[6] = 1
    struct.pack_into("<I", pvd, 80, iso_sectors)
    struct.pack_into(">I", pvd, 84, iso_sectors)

    boot_record = memoryview(image)[17 * ISO_SECTOR_SIZE:(18 * ISO_SECTOR_SIZE)]
    boot_record[0] = 0
    boot_record[1:6] = b"CD001"
    boot_record[6] = 1
    boot_record[7:30] = b"EL TORITO SPECIFICATION"
    struct.pack_into("<I", boot_record, 71, catalog_lba)

    terminator = memoryview(image)[18 * ISO_SECTOR_SIZE:(19 * ISO_SECTOR_SIZE)]
    terminator[0] = 0xFF
    terminator[1:6] = b"CD001"
    terminator[6] = 1

    catalog = memoryview(image)[catalog_lba * ISO_SECTOR_SIZE:
                                (catalog_lba + 1) * ISO_SECTOR_SIZE]
    catalog[0] = 1
    catalog[1] = platform_id
    catalog[0x1E] = 0x55
    catalog[0x1F] = 0xAA
    catalog[0x20] = 0x88
    struct.pack_into("<H", catalog, 0x26, catalog_sector_count)
    struct.pack_into("<I", catalog, 0x28, boot_lba)

    fat = make_fat_image(fat_sectors)
    boot_start = boot_lba * ISO_SECTOR_SIZE
    image[boot_start:boot_start + len(fat)] = fat

    with open(path, "wb") as f:
        f.write(image)


def make_blank_disk(path):
    with open(path, "wb") as f:
        f.truncate(16 * 1024 * 1024)


def run_qemu(qemu, firmware, disk, target_disk):
    args = [
        qemu,
        "-machine", "ia64-vpc",
        "-smp", "1",
        "-bios", firmware,
        "-display", "none",
        "-serial", "stdio",
        "-monitor", "none",
        "-drive", f"file={disk},if=ide,index=0,format=raw,media=cdrom,readonly=on",
        "-drive", f"file={target_disk},if=ide,index=1,format=raw,media=disk",
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
                if "Block I/O: BOOTIA64.EFI not found" in output:
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
            "Bail out! usage: test-ia64-fw-cdrom-boot-path.py "
            "QEMU_SYSTEM_IA64 IA64_FIRMWARE_BIN"
        )
        return 1

    qemu = sys.argv[1]
    firmware = sys.argv[2]

    print("TAP version 13")
    print("1..2")

    if not os.path.exists(qemu):
        print(f"not ok 1 - qemu exists ({qemu})")
        return 1
    if not os.path.exists(firmware):
        print(f"not ok 1 - firmware exists ({firmware})")
        return 1

    scenarios = [
        ("legacy BPB-sized no-emulation FAT image", 0x00, 4, 64),
        ("EFI sector-count no-emulation FAT image", 0xef, 1, 64),
    ]

    required = [
        "IDE controller:       PCI BAR primary data=0x0000800010000800",
        "IDE device:           ATAPI primary master",
        "IDE device:           ATA primary slave",
        "Block I/O: El Torito FAT image mapped",
        "El Torito Mapping:    partition verified",
        "Windows Setup Boot Option: CD boot path verified",
        "Optical Raw Device Path: whole-media ATAPI path verified",
        "Console Out Test:     text output contracts verified",
        "Console Handles:      graphics output handle verified",
        "Loaded Image Options: type and ownership contracts verified",
        "Block I/O Read Test:  media ID/range/bulk reads verified",
        "Disk Block I/O Test:  primary ATA read/zero-write verified",
        "Block I/O: locating \\EFI\\BOOT\\BOOTIA64.EFI...",
        "Block I/O: BOOTIA64.EFI not found",
    ]

    for index, (name, platform_id, catalog_count, fat_sectors) in enumerate(
        scenarios, 1
    ):
        with tempfile.TemporaryDirectory() as tmpdir:
            disk = os.path.join(tmpdir, "eltorito.iso")
            target_disk = os.path.join(tmpdir, "target.raw")
            make_el_torito_iso(disk, platform_id, catalog_count, fat_sectors)
            make_blank_disk(target_disk)
            returncode, output = run_qemu(qemu, firmware, disk, target_disk)

        missing = [sig for sig in required if sig not in output]
        if returncode is not None:
            print(f"not ok {index} - qemu exited during {name}")
            for line in output.splitlines():
                print(f"# {line}")
            return 1
        if missing:
            print(f"not ok {index} - El Torito signatures for {name}")
            for sig in missing:
                print(f"# missing signature: {sig}")
            for line in output.splitlines():
                print(f"# {line}")
            return 1

        print(f"ok {index} - IA-64 firmware maps {name}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
