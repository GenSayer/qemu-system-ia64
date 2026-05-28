#!/usr/bin/env python3
#
# IA-64 machine device inventory smoke test.

import re
import subprocess
import sys


def main():
    if len(sys.argv) != 2:
        print("Bail out! usage: test-ia64-device-inventory.py QEMU_SYSTEM_IA64")
        return 1

    qemu = sys.argv[1]
    proc = subprocess.run(
        [
            qemu,
            "-machine",
            "ia64-vpc",
            "-display",
            "none",
            "-serial",
            "none",
            "-monitor",
            "stdio",
            "-S",
        ],
        input=(
            "info pci\n"
            "info mtree\n"
            "xp /1wx 0x7ff0000000\n"
            "xp /5wx 0x7ff0000010\n"
            "xp /1wx 0x7ff0008000\n"
            "xp /2wx 0x7ff0008020\n"
            "xp /1wx 0x7ff0010000\n"
            "xp /1wx 0x7ff0010010\n"
            "xp /1wx 0x7ff0018000\n"
            "xp /1wx 0x7ff0018020\n"
            "xp /1wx 0x7ff0020000\n"
            "xp /3wx 0x7ff0020010\n"
            "quit\n"
        ),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=10,
        check=False,
    )

    print("TAP version 13")
    print("1..1")

    if proc.returncode != 0:
        print("not ok 1 - ia64-vpc starts for PCI inventory")
        for line in proc.stdout.splitlines():
            print(f"# {line}")
        return 1

    required = {
        "CMD646 IDE": r"IDE controller: PCI device 1095:0646",
        "CMD646 IDE INTx": r"IDE controller: PCI device 1095:0646[\s\S]*?IRQ 0, pin A",
        "ICH9 AHCI": r"SATA controller: PCI device 8086:2922",
        "ICH9 AHCI INTx": r"SATA controller: PCI device 8086:2922[\s\S]*?IRQ 1, pin A",
        "OHCI USB": r"USB controller: PCI device 106b:003f",
        "OHCI USB INTx": r"USB controller: PCI device 106b:003f[\s\S]*?IRQ 2, pin A",
        "UHCI USB": r"USB controller: PCI device 8086:7020",
        "UHCI USB INTx": r"USB controller: PCI device 8086:7020[\s\S]*?IRQ 2, pin D",
        "VGA": r"VGA controller: PCI device 1234:1111",
        "SAL PCI config aperture": r"ia64-pci-config",
        "SAL PCI config IDE read": r"7ff0000000:\s+0x06461095",
        "SAL PCI config IDE BARs": (
            r"7ff0000010:\s+0x00000801\s+0x00000809\s+"
            r"0x00000811\s+0x00000819"
        ),
        "SAL PCI config IDE bus-master BAR": r"7ff0000020:\s+0x0000c001",
        "SAL PCI config AHCI read": r"7ff0008000:\s+0x29228086",
        "SAL PCI config AHCI BARs": (
            r"7ff0008020:\s+0x0000c101\s+0x00020000"
        ),
        "SAL PCI config OHCI read": r"7ff0010000:\s+0x003f106b",
        "SAL PCI config OHCI BAR": r"7ff0010010:\s+0x00010000",
        "SAL PCI config UHCI read": r"7ff0018000:\s+0x70208086",
        "SAL PCI config UHCI BAR": r"7ff0018020:\s+0x0000c121",
        "SAL PCI config VGA read": r"7ff0020000:\s+0x11111234",
        "SAL PCI config VGA BARs": (
            r"7ff0020010:\s+0x01000008\s+0x00000000\s+0x02000000"
        ),
    }
    missing = [
        name for name, pattern in required.items()
        if re.search(pattern, proc.stdout) is None
    ]
    if missing:
        print("not ok 1 - ia64-vpc PCI inventory")
        for name in missing:
            print(f"# missing {name}")
        for line in proc.stdout.splitlines():
            print(f"# {line}")
        return 1

    print("ok 1 - ia64-vpc exposes PCI devices and SAL config aperture")
    return 0


if __name__ == "__main__":
    sys.exit(main())
