#!/usr/bin/env python3
#
# IA-64 firmware ATA Block I/O smoke test.
# Builds a tiny FAT boot sector on an IDE disk image and verifies that the
# firmware probes the device as ATA rather than assuming ATAPI CD-ROM media.

import os
import select
import struct
import subprocess
import sys
import tempfile
import time


def decode_output(output):
    return output.decode("utf-8", errors="replace")


def make_fat_disk(path):
    sectors = 64
    image = bytearray(sectors * 512)

    image[0:3] = b"\xeb\x3c\x90"
    image[3:11] = b"QEMU    "
    struct.pack_into("<H", image, 11, 512)  # bytes per sector
    image[13] = 1                            # sectors per cluster
    struct.pack_into("<H", image, 14, 1)     # reserved sectors
    image[16] = 1                            # FAT count
    struct.pack_into("<H", image, 17, 16)    # root directory entries
    struct.pack_into("<H", image, 19, sectors)
    image[21] = 0xF8                         # fixed disk media
    struct.pack_into("<H", image, 22, 1)     # sectors per FAT
    struct.pack_into("<H", image, 24, 1)     # sectors per track
    struct.pack_into("<H", image, 26, 1)     # heads
    image[38] = 0x29                         # extended boot signature
    image[510:512] = b"\x55\xaa"

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
        "-drive", f"file={disk},if=ide,format=raw",
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
            "Bail out! usage: test-ia64-fw-ata-block.py "
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
        disk = os.path.join(tmpdir, "fat.img")
        make_fat_disk(disk)
        returncode, output = run_qemu(qemu, firmware, disk)

    required = [
        "SAL PCI Config:       read/write verified",
        "SAL Proc Dispatch:    function ID mask verified",
        "SAL Update PAL:       error path verified",
        "SAL MC Rendezvous:    idle path verified",
        "SAL MC Params:        argument checks verified",
        "SAL Physical IDs:     argument checks verified",
        "SAL Cache Services:   argument checks verified",
        "SAL Set Vectors:      argument checks verified",
        "SAL Frequency Base:   optional clocks verified",
        "SAL State Info:       no-log paths verified",
        "ACPI Table Checks:    checksums verified",
        "Console Out Test:     text output contracts verified",
        "Console In:           Serial/PS2/USB WaitForKey ready",
        "Console In Buffer:    WaitForKey preserves keystrokes",
        "USB Keyboard Test:    HID boot report decode verified",
        "GOP SetMode Test:     BGRx framebuffer cleared",
        "Protocol Notify:      LocateProtocol registration verified",
        "Protocol Database:    NULL interface markers verified",
        "PCI Root Bridge Test: config/resources verified",
        "PCI I/O Protocol:    controllers verified",
        "FPSWA Protocol:       published (visibility fallback)",
        "NVRAM Variable Test:  contract checks verified",
        "IDE controller:       PCI BAR primary data=0x0000800010000800",
        "IDE device:           ATA primary master",
        "Block I/O Read Test:  media ID/range/bulk reads verified",
        "Block I/O: locating \\EFI\\BOOT\\BOOTIA64.EFI...",
        "Block I/O: BOOTIA64.EFI not found",
    ]
    missing = [sig for sig in required if sig not in output]
    if returncode is not None:
        print("not ok 1 - qemu exited during ATA Block I/O smoke")
        for line in output.splitlines():
            print(f"# {line}")
        return 1
    if missing:
        print("not ok 1 - ATA Block I/O signatures")
        for sig in missing:
            print(f"# missing signature: {sig}")
        for line in output.splitlines():
            print(f"# {line}")
        return 1

    print("ok 1 - IA-64 firmware probes ATA Block I/O")
    return 0


if __name__ == "__main__":
    sys.exit(main())
