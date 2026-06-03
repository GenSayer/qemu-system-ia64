#!/usr/bin/env python3
#
# IA-64 firmware platform-table build-level test.
# Verifies SAL/ACPI scaffold artifacts exist in the firmware ELF.

import os
import subprocess
import sys


def main():
    if len(sys.argv) != 2:
        print("Bail out! usage: test-ia64-fw-platform-tables.py IA64_FIRMWARE_BIN")
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

    symbols = subprocess.run(
        ["ia64-linux-gnu-objdump", "-t", elf_path],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if symbols.returncode != 0:
        print("not ok 1 - objdump symbol table")
        for line in symbols.stdout.splitlines():
            print(f"# {line}")
        return 1

    required_symbols = [
        "mSalSystemTable",
        "mRsdp",
        "mXsdt",
        "mRsdt",
        "mFadt",
        "mSsdt",
        "mMcfg",
        "mMadt",
        "mSrat",
        "mSlit",
        "mHcdp",
        "sal_set_vectors",
        "sal_set_vectors_selftest",
        "sal_freq_base",
        "sal_freq_base_selftest",
        "sal_get_state_info",
        "sal_get_state_info_size",
        "sal_clear_state_info",
        "sal_state_info_selftest",
        "sal_cache_flush",
        "sal_cache_init",
        "sal_cache_services_selftest",
        "sal_mc_rendez",
        "sal_mc_rendez_selftest",
        "sal_physical_id_info",
        "sal_register_physical_addr",
        "sal_update_pal",
        "sal_update_pal_selftest",
        "sal_pci_config_read",
        "sal_pci_config_write",
        "sal_pci_config_decode",
        "sal_pci_config_selftest",
        "sal_proc_dispatch_selftest",
        "pci_config_ecam_addr",
        "acpi_table_integrity_selftest",
        "pal_proc_entry",
        "mSalPalProcPhysicalAddress",
        "mGraphicsDevicePath",
        "mPciRootBridgeIoProto",
        "mConfigTables",
    ]
    missing = [sym for sym in required_symbols if sym not in symbols.stdout]
    if missing:
        print("not ok 1 - SAL/ACPI scaffold symbols in firmware")
        for sym in missing:
            print(f"# missing symbol: {sym}")
        return 1

    def symbol_size(name):
        line = next(
            (line for line in symbols.stdout.splitlines() if line.endswith(f" {name}")),
            "",
        )
        fields = line.split()
        return int(fields[-2], 16) if len(fields) >= 2 else 0

    def symbol_addr(name):
        line = next(
            (line for line in symbols.stdout.splitlines() if line.endswith(f" {name}")),
            "",
        )
        fields = line.split()
        return int(fields[0], 16) if fields else 0

    def symbol_bytes(name):
        addr = symbol_addr(name)
        size = symbol_size(name)
        dump = subprocess.run(
            [
                "ia64-linux-gnu-objdump", "-s",
                f"--start-address=0x{addr:x}",
                f"--stop-address=0x{addr + size:x}",
                elf_path,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        data = bytearray()
        for line in dump.stdout.splitlines():
            fields = line.split()
            if len(fields) < 2 or not fields[0].isalnum():
                continue
            for word in fields[1:]:
                if (
                    len(word) == 0 or len(word) > 8 or len(word) % 2 != 0 or
                    any(c not in "0123456789abcdefABCDEF" for c in word)
                ):
                    break
                data.extend(bytes.fromhex(word))
        return bytes(data[:size])

    pal_proc_addr = symbol_addr("pal_proc_entry")
    if pal_proc_addr != 0x100060:
        print("not ok 1 - PAL proc entry fixed offset")
        print(f"# expected pal_proc_entry at 0x100060, got 0x{pal_proc_addr:x}")
        return 1

    madt_size = symbol_size("mMadt")
    if madt_size != 0x48:
        print("not ok 1 - IA-64 MADT layout size")
        print(f"# expected mMadt size 0x48, got 0x{madt_size:x}")
        return 1

    hcdp_size = symbol_size("mHcdp")
    if hcdp_size != 0x81:
        print("not ok 1 - IA-64 HCDP/PCDP layout size")
        print(f"# expected mHcdp size 0x81, got 0x{hcdp_size:x}")
        return 1

    dsdt_size = symbol_size("mDsdt")
    if dsdt_size != 0x1e7:
        print("not ok 1 - IA-64 DSDT layout size")
        print(f"# expected mDsdt size 0x1e7, got 0x{dsdt_size:x}")
        return 1

    ssdt_size = symbol_size("mSsdt")
    if ssdt_size != 0x91:
        print("not ok 1 - IA-64 SSDT serial layout size")
        print(f"# expected mSsdt size 0x91, got 0x{ssdt_size:x}")
        return 1

    mcfg_size = symbol_size("mMcfg")
    if mcfg_size != 0x3c:
        print("not ok 1 - ACPI MCFG layout size")
        print(f"# expected mMcfg size 0x3c, got 0x{mcfg_size:x}")
        return 1

    xsdt_size = symbol_size("mXsdt")
    if xsdt_size != 0x5c:
        print("not ok 1 - ACPI XSDT layout size")
        print(f"# expected mXsdt size 0x5c, got 0x{xsdt_size:x}")
        return 1

    rsdt_size = symbol_size("mRsdt")
    if rsdt_size != 0x40:
        print("not ok 1 - ACPI RSDT layout size")
        print(f"# expected mRsdt size 0x40, got 0x{rsdt_size:x}")
        return 1

    config_tables_size = symbol_size("mConfigTables")
    if config_tables_size < 0x180:
        print("not ok 1 - UEFI configuration table capacity")
        print(
            "# expected mConfigTables to hold at least 16 entries, "
            f"got size 0x{config_tables_size:x}"
        )
        return 1

    graphics_path = symbol_bytes("mGraphicsDevicePath")
    if len(graphics_path) != 0x16 or graphics_path[0x11] != 4:
        print("not ok 1 - GOP device path PCI slot")
        print("# expected GOP PCI device path to reference bus 0 device 4")
        return 1

    dsdt = symbol_bytes("mDsdt")
    for token in [b"_S5_", b"PCI0", b"PNP0A08", b"PNP0A03", b"_CRS", b"_PRT"]:
        if token not in dsdt:
            print("not ok 1 - DSDT PCI root bridge AML")
            print(f"# missing AML token: {token.decode('ascii')}")
            return 1

    ssdt = symbol_bytes("mSsdt")
    if b"\x5b\x83\x0bCPU0\x00\x00\x00\x00\x00\x00" not in ssdt:
        print("not ok 1 - SSDT processor AML")
        print("# missing ACPI Processor CPU0 declaration")
        return 1
    for token in [b"UAR0", b"PNP0501", b"_CRS"]:
        if token not in ssdt:
            print("not ok 1 - SSDT serial AML")
            print(f"# missing AML token: {token.decode('ascii')}")
            return 1
    for value, label in [
        ((0x47F0000000).to_bytes(8, "little"), "UART MMIO base"),
        ((0x47F0000007).to_bytes(8, "little"), "UART MMIO limit"),
        ((8).to_bytes(8, "little"), "UART MMIO length"),
        (b"\x8a\x2b\x00\x00\x0d\x01", "UART QWordMemory consumer descriptor"),
        (b"\x22\x10\x00\x79\x00", "UART IRQ4 descriptor and EndTag"),
    ]:
        if value not in ssdt:
            print("not ok 1 - SSDT serial AML")
            print(f"# missing {label}")
            return 1

    print("ok 1 - SAL/ACPI scaffold symbols present in firmware ELF")
    return 0


if __name__ == "__main__":
    sys.exit(main())
