#!/usr/bin/env python3
#
# IA-64 firmware UEFI services build-level test.
# Verifies the cross-built firmware ELF contains minimum UEFI service symbols.

import os
import re
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        print(
            "Bail out! usage: test-ia64-fw-uefi-services.py "
            "QEMU_SYSTEM_IA64 IA64_FIRMWARE_BIN"
        )
        return 1

    qemu = sys.argv[1]
    firmware = sys.argv[2]

    print("TAP version 13")
    print("1..8")

    if not os.path.exists(firmware):
        print(f"not ok 1 - firmware exists ({firmware})")
        print("not ok 2 - firmware entry ABI and GP fixup")
        print("not ok 3 - firmware StartImage/Exit nonlocal handoff")
        print("not ok 4 - firmware StartImage config table compatibility")
        print("not ok 5 - firmware RAM handoff memory map")
        print("not ok 6 - firmware GOP multi-mode table")
        print("not ok 7 - firmware EFI input scan tables")
        print("not ok 8 - firmware EFI event notification core")
        return 1

    elf_path = os.path.splitext(firmware)[0] + ".elf"
    if not os.path.exists(elf_path):
        print(f"not ok 1 - firmware ELF exists ({elf_path})")
        print("not ok 2 - firmware entry ABI and GP fixup")
        print("not ok 3 - firmware StartImage/Exit nonlocal handoff")
        print("not ok 4 - firmware StartImage config table compatibility")
        print("not ok 5 - firmware RAM handoff memory map")
        print("not ok 6 - firmware GOP multi-mode table")
        print("not ok 7 - firmware EFI input scan tables")
        print("not ok 8 - firmware EFI event notification core")
        return 1

    objdump = subprocess.run(
        ["ia64-linux-gnu-objdump", "-t", elf_path],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if objdump.returncode != 0:
        print("not ok 1 - objdump symbol table")
        for line in objdump.stdout.splitlines():
            print(f"# {line}")
        print("not ok 2 - firmware entry ABI and GP fixup")
        print("not ok 3 - firmware StartImage/Exit nonlocal handoff")
        print("not ok 4 - firmware StartImage config table compatibility")
        print("not ok 5 - firmware RAM handoff memory map")
        print("not ok 6 - firmware GOP multi-mode table")
        print("not ok 7 - firmware EFI input scan tables")
        return 1

    required_symbols = [
        "bs_allocate_pages",
        "bs_free_pages",
        "bs_get_memory_map",
        "bs_unload_image",
        "efi_coalesce_memory_map",
        "bs_allocate_pool",
        "mPoolAllocations",
        "bs_load_image",
        "bs_start_image",
        "bs_exit_boot_services",
        "rs_get_time",
        "mRuntimeTimeBase",
        "mRuntimeTimeBaseItc",
        "rs_get_wakeup_time",
        "rs_set_wakeup_time",
        "mWakeupTime",
        "uefi_time_services_selftest",
        "rs_set_virtual_address_map",
        "rs_convert_pointer",
        "mVirtualAddressMap",
        "mVirtualAddressMapApplied",
        "rs_get_variable",
        "rs_set_variable",
        "rs_get_next_var_name",
        "rs_get_next_high_monotonic_count",
        "rs_query_variable_info",
        "runtime_variable_selftest",
        "mFirmwareVariables",
        "fw_device_path_size",
        "loaded_image_file_path_selftest",
        "disk_read",
        "disk_write",
        "mBlockDiskIoProto",
        "mRawDiskIoProto",
        "mDiskBlockIoProto",
        "mDiskIoProto",
        "mDiskBlockDevicePath",
        "ide_probe_primary_devices",
        "mWindowsSetupOsOptions",
        "mWindowsSetupLoaderDevicePath",
        "fw_iso_init",
        "fw_iso_lookup",
        "fw_iso_read_extent",
        "fw_udf_init",
        "fw_udf_lookup",
        "fw_udf_tag_valid",
        "fw_udf_parse_file_meta",
        "fw_udf_read_file_bytes",
        "mUdfVolume",
        "mUdfRootFile",
        "mOpticalSimpleFsProto",
        "fat_file_read",
        "bs_install_configuration_table",
        "mFacs",
        "mDsdt",
        "graphics_select_mode",
        "graphics_gop_set_mode_selftest",
        "mGopModeInfo",
        "uefi_conout_selftest",
        "mPs2ExtendedEfiScanMap",
        "mPs2Set1EfiScanMap",
        "mPs2Set2EfiScanMap",
        "mPs2Translated",
        "ps2_shift_scan_code",
        "uefi_conin_wait_key_selftest",
        "uefi_ps2_scancode_selftest",
        "mConInExProtocolGuid",
        "mConInExProto",
        "mConInKeyNotifyRecords",
        "conin_ex_read_key",
        "conin_ex_set_state",
        "conin_ex_register_key_notify",
        "conin_ex_unregister_key_notify",
        "uefi_conin_ex_selftest",
        "fw_event_type_valid",
        "fw_event_queue_notify",
        "fw_dispatch_event_notifications",
        "fw_signal_event_group",
        "fw_cancel_all_timers",
        "gEfiEventGroupExitBootServicesGuid",
        "gEfiEventGroupVirtualAddressChangeGuid",
        "uefi_event_services_selftest",
        "bs_open_protocol",
        "bs_close_protocol",
        "bs_open_protocol_information",
        "add_open_protocol_record",
        "mOpenProtocolRecords",
        "pci_root_bridge_io_selftest",
        "pci_io_protocol_selftest",
        "mPciIdeIoProto",
        "mPciAhciIoProto",
        "mPciOhciIoProto",
        "mPciUhciIoProto",
        "mPciVgaIoProto",
        "mPciIoDevices",
        "fpswa_protocol_selftest",
        "fpswa_visibility_fallback",
        "mFpswaProto",
        "bs_register_protocol_notify",
        "fw_protocol_notify_next_handle",
        "protocol_notify_selftest",
        "protocol_notify_selftest_callback",
        "mProtocolNotifyRecords",
        "mProtocolNotifyLog",
        "uefi_memory_map_selftest",
    ]
    missing = [sym for sym in required_symbols if sym not in objdump.stdout]
    if missing:
        print("not ok 1 - firmware contains minimum UEFI service symbols")
        for sym in missing:
            print(f"# missing symbol: {sym}")
        print("not ok 2 - firmware entry ABI and GP fixup")
        print("not ok 3 - firmware StartImage/Exit nonlocal handoff")
        print("not ok 4 - firmware StartImage config table compatibility")
        print("not ok 5 - firmware RAM handoff memory map")
        print("not ok 6 - firmware GOP multi-mode table")
        print("not ok 7 - firmware EFI input scan tables")
        print("not ok 8 - firmware EFI event notification core")
        return 1

    print("ok 1 - firmware contains minimum UEFI service symbols")

    disasm = subprocess.run(
        ["ia64-linux-gnu-objdump", "-d", elf_path],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if disasm.returncode != 0:
        print("not ok 2 - firmware entry ABI and GP fixup")
        for line in disasm.stdout.splitlines():
            print(f"# {line}")
        print("not ok 3 - firmware StartImage/Exit nonlocal handoff")
        print("not ok 4 - firmware StartImage config table compatibility")
        print("not ok 5 - firmware RAM handoff memory map")
        print("not ok 6 - firmware GOP multi-mode table")
        print("not ok 7 - firmware EFI input scan tables")
        print("not ok 8 - firmware EFI event notification core")
        return 1

    text = disasm.stdout
    gp_symbol = re.search(r"([0-9a-fA-F]+)\s+g\s+.*\b__gp\b",
                          objdump.stdout)
    gp_block = re.search(r"<_start>:(?:.|\n)*?movl r1=0x([0-9a-fA-F]+)",
                         text)
    gp_value = int(gp_symbol.group(1), 16) if gp_symbol else 0
    gp_immediate = int(gp_block.group(1), 16) if gp_block else 0

    checks = [
        (gp_symbol is not None, "missing __gp symbol"),
        (gp_block is not None, "missing _start GP load"),
        (gp_value != 0 and gp_immediate == gp_value,
         "GP load immediate does not match __gp"),
        ("alloc r2=ar.pfs,16,13,0" in text, "alloc calling convention is incorrect"),
        ("mov r45=r1" in text and "mov r46=r12" in text and "mov r47=r3" in text,
         "firmware_main argument setup is incorrect"),
    ]
    failed = [msg for ok, msg in checks if not ok]
    if failed:
        print("not ok 2 - firmware entry ABI and GP fixup")
        for msg in failed:
            print(f"# {msg}")
        print("not ok 3 - firmware StartImage/Exit nonlocal handoff")
        print("not ok 4 - firmware StartImage config table compatibility")
        print("not ok 5 - firmware RAM handoff memory map")
        print("not ok 6 - firmware GOP multi-mode table")
        print("not ok 7 - firmware EFI input scan tables")
        print("not ok 8 - firmware EFI event notification core")
        return 1

    print("ok 2 - firmware entry ABI and GP fixup")

    handoff_checks = [
        ("bs_exit" in objdump.stdout, "missing bs_exit symbol"),
        ("__ia64_save_stack_nonlocal" in objdump.stdout,
         "missing IA-64 nonlocal stack save helper"),
        ("__ia64_nonlocal_goto" in objdump.stdout,
         "missing IA-64 nonlocal goto helper"),
    ]
    handoff_failed = [msg for ok, msg in handoff_checks if not ok]
    if handoff_failed:
        print("not ok 3 - firmware StartImage/Exit nonlocal handoff")
        for msg in handoff_failed:
            print(f"# {msg}")
        print("not ok 4 - firmware StartImage config table compatibility")
        print("not ok 5 - firmware RAM handoff memory map")
        print("not ok 6 - firmware GOP multi-mode table")
        print("not ok 7 - firmware EFI input scan tables")
        print("not ok 8 - firmware EFI event notification core")
        return 1

    print("ok 3 - firmware StartImage/Exit nonlocal handoff")

    compat_checks = [
        ("fw_push_image_config_tables" in objdump.stdout,
         "missing StartImage config table push helper"),
        ("fw_pop_image_config_tables" in objdump.stdout,
         "missing StartImage config table pop helper"),
    ]
    compat_failed = [msg for ok, msg in compat_checks if not ok]
    if compat_failed:
        print("not ok 4 - firmware StartImage config table compatibility")
        for msg in compat_failed:
            print(f"# {msg}")
        print("not ok 5 - firmware RAM handoff memory map")
        print("not ok 6 - firmware GOP multi-mode table")
        print("not ok 7 - firmware EFI input scan tables")
        print("not ok 8 - firmware EFI event notification core")
        return 1

    print("ok 4 - firmware StartImage config table compatibility")

    proc = subprocess.Popen(
        [
            qemu,
            "-machine", "ia64-vpc",
            "-smp", "1",
            "-m", "1024",
            "-bios", firmware,
            "-display", "none",
            "-serial", "stdio",
            "-monitor", "none",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        console, _ = proc.communicate(timeout=6)
    except subprocess.TimeoutExpired:
        proc.kill()
        console, _ = proc.communicate()

    expected_lines = [
        "Memory Map:           low RAM end=0x0000000040000000",
        "I/O Port Space:       0x0000800010000000-0x0000800013FFFFFF",
        "Memory Map Test:      descriptor boundaries verified",
        "UEFI Time Services:   GetTime/SetTime/GetWakeupTime verified",
        "Loaded Image Paths:   protocol storage verified",
    ]
    missing_lines = [line for line in expected_lines if line not in console]
    if missing_lines:
        print("not ok 5 - firmware RAM handoff memory map")
        for line in missing_lines:
            print(f"# missing console line: {line}")
        for line in console.splitlines()[-20:]:
            print(f"# {line}")
        print("not ok 6 - firmware GOP multi-mode table")
        print("not ok 7 - firmware EFI input scan tables")
        return 1

    try:
        mtree = subprocess.run(
            [
                qemu,
                "-machine", "ia64-vpc",
                "-smp", "1",
                "-m", "1024",
                "-bios", firmware,
                "-display", "none",
                "-serial", "none",
                "-monitor", "stdio",
            ],
            input="info mtree\nquit\n",
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=6,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        mtree = exc
        mtree.returncode = -1
        mtree.stdout = stdout
    mtree_checks = [
        ("0000000080110000-0000000080111fff" in mtree.stdout and
         "iosapic" in mtree.stdout,
         "IOSAPIC aperture is not two EFI pages"),
        ("0000000080112000-0000000080113fff" in mtree.stdout and
         "ia64-acpi-pm" in mtree.stdout,
         "ACPI PM aperture is not two EFI pages"),
    ]
    mtree_failed = [msg for ok, msg in mtree_checks if not ok]
    if mtree.returncode != 0 or mtree_failed:
        print("not ok 5 - firmware RAM handoff memory map")
        if mtree.returncode != 0:
            print("# qemu monitor mtree command failed")
        for msg in mtree_failed:
            print(f"# {msg}")
        for line in mtree.stdout.splitlines()[-20:]:
            print(f"# {line}")
        print("not ok 6 - firmware GOP multi-mode table")
        print("not ok 7 - firmware EFI input scan tables")
        return 1

    readelf = subprocess.run(
        ["ia64-linux-gnu-readelf", "-SW", elf_path],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    runtime_data_match = re.search(
        r"^([0-9a-fA-F]+)\s+g\s+.*\s__runtime_data_start$",
        objdump.stdout,
        re.MULTILINE,
    )
    runtime_data_start = (
        int(runtime_data_match.group(1), 16) if runtime_data_match else 0
    )
    sections = {}
    for line in readelf.stdout.splitlines():
        match = re.match(
            r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-fA-F]+)\s+",
            line,
        )
        if match:
            sections[match.group(1)] = int(match.group(2), 16)
    runtime_data_sections = [
        ".rodata",
        ".opd",
        ".IA_64.unwind_info",
        ".IA_64.unwind",
        ".data",
        ".got",
        ".bss",
    ]
    layout_failed = []
    if readelf.returncode != 0:
        layout_failed.append("readelf section table failed")
    if runtime_data_start == 0:
        layout_failed.append("missing __runtime_data_start symbol")
    if sections.get(".text", runtime_data_start) >= runtime_data_start:
        layout_failed.append(".text is not before runtime data")
    for section in runtime_data_sections:
        if sections.get(section, 0) < runtime_data_start:
            layout_failed.append(
                f"{section} starts before __runtime_data_start"
            )
    if layout_failed:
        print("not ok 5 - firmware RAM handoff memory map")
        for msg in layout_failed:
            print(f"# {msg}")
        print("not ok 6 - firmware GOP multi-mode table")
        print("not ok 7 - firmware EFI input scan tables")
        return 1

    print("ok 5 - firmware RAM handoff memory map")

    def symbol_size(name):
        line = next(
            (line for line in objdump.stdout.splitlines() if line.endswith(f" {name}")),
            "",
        )
        fields = line.split()
        return int(fields[-2], 16) if len(fields) >= 2 else 0

    gop_size = symbol_size("mGopModeInfo")
    strings = subprocess.run(
        ["strings", "-a", elf_path],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    expected_banner = (
        "Graphics Output:      GOP/UGA stdvga BGRx PixelBitMask "
        "640x400x32, 640x480x32, 800x600x32, 1024x768x32, "
        "1280x1024x32 @ 0xc2000000"
    )
    expected_setmode = "GOP SetMode Test:"
    if (strings.returncode != 0 or gop_size != 0xb4 or
            expected_banner not in strings.stdout or
            expected_setmode not in strings.stdout):
        print("not ok 6 - firmware GOP multi-mode table")
        if strings.returncode != 0:
            print("# strings failed for firmware ELF")
        if gop_size != 0xb4:
            print(f"# expected mGopModeInfo size 0xb4, got 0x{gop_size:x}")
        if expected_banner not in strings.stdout:
            print(f"# missing banner: {expected_banner}")
        if expected_setmode not in strings.stdout:
            print(f"# missing banner token: {expected_setmode}")
        return 1

    print("ok 6 - firmware GOP multi-mode table")

    extended_scan_size = symbol_size("mPs2ExtendedEfiScanMap")
    set1_scan_size = symbol_size("mPs2Set1EfiScanMap")
    set2_scan_size = symbol_size("mPs2Set2EfiScanMap")
    conin_ex_size = symbol_size("mConInExProto")
    ps2_scan_enable_size = symbol_size("ps2_keyboard_enable_scanning")
    input_ex_tokens = [
        "PS/2 Scancode Test:",
        "translated set1/set2 decode verified",
        "Console In Ex:",
        "SimpleTextInputEx ready",
    ]
    if (extended_scan_size != 0x50 or set1_scan_size != 0x30 or
            set2_scan_size != 0x30 or conin_ex_size != 0x30 or
            ps2_scan_enable_size == 0 or
            any(token not in strings.stdout for token in input_ex_tokens)):
        print("not ok 7 - firmware EFI input scan tables")
        if extended_scan_size != 0x50:
            print(
                "# expected mPs2ExtendedEfiScanMap size 0x50, "
                f"got 0x{extended_scan_size:x}"
            )
        if set1_scan_size != 0x30:
            print(
                "# expected mPs2Set1EfiScanMap size 0x30, "
                f"got 0x{set1_scan_size:x}"
            )
        if set2_scan_size != 0x30:
            print(
                "# expected mPs2Set2EfiScanMap size 0x30, "
                f"got 0x{set2_scan_size:x}"
            )
        if conin_ex_size != 0x30:
            print(
                "# expected mConInExProto size 0x30, "
                f"got 0x{conin_ex_size:x}"
            )
        if ps2_scan_enable_size == 0:
            print("# missing non-empty PS/2 keyboard scan-enable helper")
        for token in input_ex_tokens:
            if token not in strings.stdout:
                print(f"# missing banner token: {token}")
        return 1

    print("ok 7 - firmware EFI input scan tables")

    event_checks = [
        ("fw_event_type_valid" in objdump.stdout,
         "missing event type validation helper"),
        ("fw_event_queue_notify" in objdump.stdout,
         "missing event notification queue helper"),
        ("fw_dispatch_event_notifications" in objdump.stdout,
         "missing event notification dispatcher"),
        ("fw_signal_event_group" in objdump.stdout,
         "missing event group signaling helper"),
        ("fw_cancel_all_timers" in objdump.stdout,
         "missing ExitBootServices timer cancellation helper"),
        ("gEfiEventGroupExitBootServicesGuid" in objdump.stdout,
         "missing ExitBootServices event group GUID"),
        ("gEfiEventGroupVirtualAddressChangeGuid" in objdump.stdout,
         "missing virtual-address-change event group GUID"),
    ]
    event_failed = [msg for ok, msg in event_checks if not ok]
    if event_failed:
        print("not ok 8 - firmware EFI event notification core")
        for msg in event_failed:
            print(f"# {msg}")
        return 1

    print("ok 8 - firmware EFI event notification core")
    return 0


if __name__ == "__main__":
    sys.exit(main())
