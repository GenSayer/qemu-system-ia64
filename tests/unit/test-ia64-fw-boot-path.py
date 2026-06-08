#!/usr/bin/env python3
#
# IA-64 firmware boot-path scaffold test.
# Verifies BOOTIA64 candidate scan helpers exist in firmware ELF.

import os
import subprocess
import sys


def main():
    if len(sys.argv) != 2:
        print("Bail out! usage: test-ia64-fw-boot-path.py IA64_FIRMWARE_BIN")
        return 1

    firmware = sys.argv[1]
    print("TAP version 13")
    print("1..1")

    if not os.path.exists(firmware):
        print(f"not ok 1 - firmware exists ({firmware})")
        return 1

    elf_path = os.path.splitext(firmware)[0] + ".elf"
    if not os.path.exists(elf_path):
        print(f"not ok 1 - firmware ELF exists ({elf_path})")
        return 1

    strings = subprocess.run(
        ["strings", "-a", elf_path],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if strings.returncode != 0:
        print("not ok 1 - strings on firmware ELF")
        for line in strings.stdout.splitlines():
            print(f"# {line}")
        return 1

    required = [
        "ACPI MADT (SAPIC):    published",
        "ACPI SRAT/SLIT:       published",
        "ACPI MCFG (PCIe):     published",
        "ACPI HCDP/PCDP:       published",
        "ACPI Table Checks:",
        "PCI Root Bridge I/O:  published",
        "PCI Root Bridge Test:",
        "PCI I/O Protocol:",
        "Console Out Test:",
        "Console In:",
        "FPSWA Protocol:",
        "NVRAM Variable Test:",
        "SAL PCI Config:",
        "SAL Proc Dispatch:",
        "SAL Update PAL:",
        "SAL MC Rendezvous:",
        "SAL MC Params:",
        "SAL Physical IDs:",
        "SAL Cache Services:",
        "SAL Set Vectors:",
        "SAL Frequency Base:",
        "SAL State Info:",
        "Loaded Image Options:",
        "Boot Manager:        trying Boot",
        "BootOrder boot failed",
        "BOOT path:            ATA/ATAPI Block I/O + FAT resolver",
        "BOOTIA64.EFI",
        "PlatformLangCodes",
        "ConOutDev",
    ]
    missing = [tok for tok in required if tok not in strings.stdout]
    if missing:
        print("not ok 1 - BOOTIA64 path scaffold tokens")
        for tok in missing:
            print(f"# missing token: {tok}")
        return 1

    print("ok 1 - BOOTIA64 path scaffold tokens present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
