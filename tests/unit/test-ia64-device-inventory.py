#!/usr/bin/env python3
#
# IA-64 machine device inventory smoke test.

import re
import subprocess
import sys


def run_inventory(qemu, extra_args=(), machine="ia64-vpc"):
    return subprocess.run(
        [
            qemu,
            "-machine",
            machine,
        ] + list(extra_args) + [
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
            "info qtree\n"
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
            "xp /1wx 0x7ff0028000\n"
            "xp /3wx 0x7ff0028010\n"
            "xp /1hx 0x800010801004\n"
            "quit\n"
        ),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=10,
        check=False,
    )


def main():
    if len(sys.argv) != 2:
        print("Bail out! usage: test-ia64-device-inventory.py QEMU_SYSTEM_IA64")
        return 1

    qemu = sys.argv[1]
    proc = run_inventory(qemu)

    print("TAP version 13")
    print("1..1")

    if proc.returncode != 0:
        print("not ok 1 - ia64-vpc starts for PCI inventory")
        for line in proc.stdout.splitlines():
            print(f"# {line}")
        return 1

    required = {
        "ICH9 AHCI": r"SATA controller: PCI device 8086:2922",
        "ICH9 AHCI INTx": r"SATA controller: PCI device 8086:2922[\s\S]*?IRQ 17, pin A",
        "OHCI USB": r"USB controller: PCI device 106b:003f",
        "OHCI USB INTx": r"USB controller: PCI device 106b:003f[\s\S]*?IRQ 18, pin A",
        "UHCI USB": r"USB controller: PCI device 8086:7020",
        "UHCI USB INTx": r"USB controller: PCI device 8086:7020[\s\S]*?IRQ 18, pin D",
        "LSI SCSI": r"SCSI controller: PCI device 1000:0012",
        "LSI SCSI INTx": (
            r"SCSI controller: PCI device 1000:0012[\s\S]*?IRQ 16, pin A"
        ),
        "VGA": r"VGA controller: PCI device 1002:5046",
        "SAL PCI config aperture": r"ia64-pci-config",
        "empty PCI slot 0": r"7ff0000000:\s+0xffffffff",
        "SAL PCI config AHCI read": r"7ff0008000:\s+0x29228086",
        "SAL PCI config AHCI BARs": (
            r"7ff0008020:\s+0x0000c101\s+0xc1020000"
        ),
        "SAL PCI config OHCI read": r"7ff0010000:\s+0x003f106b",
        "SAL PCI config OHCI BAR": r"7ff0010010:\s+0xc1010000",
        "SAL PCI config UHCI read": r"7ff0018000:\s+0x70208086",
        "SAL PCI config UHCI BAR": r"7ff0018020:\s+0x0000c121",
        "SAL PCI config LSI read": r"7ff0020000:\s+0x00121000",
        "SAL PCI config LSI BARs": (
            r"7ff0020010:\s+0x0000c201\s+0xc1030000\s+0xc1032000"
        ),
        "SAL PCI config VGA read": r"7ff0028000:\s+0x50461002",
        "SAL PCI config VGA BARs": (
            r"7ff0028010:\s+0xc4000008\s+0x0000c301\s+0xc8000000"
        ),
        "sparse PM1 control SCI_EN": r"800010801004:\s+0x0001",
    }
    missing = [
        name for name, pattern in required.items()
        if re.search(pattern, proc.stdout) is None
    ]
    unexpected = []
    if re.search(r"IDE controller: PCI device", proc.stdout):
        unexpected.append("default IDE controller")
    if re.search(r"dev: scsi-cd,", proc.stdout):
        unexpected.append("default empty SCSI CD-ROM")

    explicit = run_inventory(
        qemu, ("-device", "cmd646-ide,secondary=1,addr=0")
    )
    if explicit.returncode != 0:
        unexpected.append("explicit CMD646 failed to start")
    if re.search(r"IDE controller: PCI device 1095:0646", explicit.stdout) is None:
        unexpected.append("explicit CMD646 controller")
    if re.search(r"7ff0000000:\s+0x06461095", explicit.stdout) is None:
        unexpected.append("explicit CMD646 SAL config read")

    usb_input = run_inventory(
        qemu, ("-usb",), machine="ia64-vpc,i8042=off"
    )
    if usb_input.returncode != 0:
        unexpected.append("default USB input failed to start")
    for device in ("usb-kbd", "usb-mouse"):
        if re.search(
                rf"dev: {re.escape(device)},"
                rf"(?:(?!\n\s*dev: )[\s\S])*?msos-desc = false",
                usb_input.stdout) is None:
            unexpected.append(f"{device} Microsoft OS descriptors enabled")

    if missing or unexpected:
        print("not ok 1 - ia64-vpc PCI inventory")
        for name in missing:
            print(f"# missing {name}")
        for name in unexpected:
            print(f"# unexpected/missing explicit case: {name}")
        for line in proc.stdout.splitlines():
            print(f"# {line}")
        if unexpected:
            print("# explicit CMD646 output:")
            for line in explicit.stdout.splitlines():
                print(f"# {line}")
            print("# default USB input output:")
            for line in usb_input.stdout.splitlines():
                print(f"# {line}")
        return 1

    print("ok 1 - ia64-vpc PCI and USB compatibility defaults")
    return 0


if __name__ == "__main__":
    sys.exit(main())
