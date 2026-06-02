#!/usr/bin/env python3
#
# IA-64 standard-derived golden execution tests.
#
# This test is intentionally separate from test-ia64-standard-goldens.py.  The
# latter checks that every docs/ia64 inventory row has a standard-derived golden
# specification.  This file executes those contracts against QEMU and the IA-64
# firmware image.

import csv
import importlib.util
import os
import re
import select
import struct
import subprocess
import sys
import tempfile
import time


CSV_FILES = {
    "instructions": "docs/ia64/implemented-instructions.csv",
    "efi": "docs/ia64/implemented-efi.csv",
    "pal": "docs/ia64/implemented-pal.csv",
    "sal": "docs/ia64/implemented-sal.csv",
    "acpi": "docs/ia64/implemented-acpi.csv",
}

FAT_SECTOR_SIZE = 512
EFI_PAGE_SIZE = 4096
EFI_IA64_RUNTIME_DESCRIPTOR_ALIGN = 8192

RSDP_SIGNATURE = b"RSD PTR "
ACPI_RECLAIM_BASE = 0x00800000
ACPI_RECLAIM_END = 0x00820000
ACPI_PM_BASE = 0x80112000
ACPI_SCI_IRQ = 9
ACPI_FADT_FLAG_WBINVD = 1 << 0
ACPI_FADT_FLAG_PWR_BUTTON = 1 << 4
ACPI_FADT_FLAG_SLP_BUTTON = 1 << 5
ACPI_FADT_FLAG_TMR_VAL_EXT = 1 << 8
ACPI_FADT_EXPECTED_FLAGS = (
    ACPI_FADT_FLAG_WBINVD |
    ACPI_FADT_FLAG_PWR_BUTTON |
    ACPI_FADT_FLAG_SLP_BUTTON |
    ACPI_FADT_FLAG_TMR_VAL_EXT
)
PCI_CONFIG_ECAM_BASE = 0x7FF0000000
PCI_MMIO_BASE = 0xC1000000
PCI_MMIO_SIZE = 0x10000000
PCI_IO_SIZE = 0x1000000
PCI_IO_SPARSE_SIZE = 0x4000000
LEGACY_IO_BASE = 0x800010000000
PCI_IO_TRANSLATION_OFFSET = (-LEGACY_IO_BASE) & ((1 << 64) - 1)
PCI_INTX_GSI_BASE = 16
PCI_INTX_LINES = 4
IOSAPIC_BASE = 0x80110000
IOSAPIC_RTE_DELIVERY_STATUS = 1 << 12
IOSAPIC_RTE_REMOTE_IRR = 1 << 14
IOSAPIC_RTE_TRIGGER_LEVEL = 1 << 15
IOSAPIC_RTE_MASKED = 1 << 16
UART_BASE = 0x47F0000000
UART_BAUD = 115200
HCDP_UART_IRQ = 4
HCDP_UART_PRIMARY_CONSOLE = 1 << 2
HCDP_DEVICE_PRIMARY_CONSOLE = 1
HCDP_PCI_TRANSLATE_IOPORT = 1 << 1
VGA_VENDOR_ID = 0x1234
VGA_DEVICE_ID = 0x1111
EFI_RUNTIME_SERVICES_DATA = 6
EFI_ACPI_RECLAIM_MEMORY = 9
EFI_MEMORY_MAPPED_IO = 11
EFI_MEMORY_MAPPED_IO_PORT_SPACE = 12
EFI_MEMORY_UC = 0x1
EFI_MEMORY_RUNTIME = 0x8000000000000000
EFI_MEMORY_WB = 0x8
EFI_ACPI20_TABLE_GUID = bytes.fromhex(
    "71 e8 68 88 f1 e4 d3 11 bc 22 00 80 c7 3c 88 81"
)
EFI_ACPI10_TABLE_GUID = bytes.fromhex(
    "30 2d 9d eb 88 2d d3 11 9a 16 00 90 27 3f c1 4d"
)
EFI_SAL_SYSTEM_TABLE_GUID = bytes.fromhex(
    "32 2d 9d eb 88 2d d3 11 9a 16 00 90 27 3f c1 4d"
)
EFI_HCDP_TABLE_GUID = bytes.fromhex(
    "8d 93 51 f9 0b 62 ef 42 82 79 a8 4b 79 61 78 98"
)


def load_csv(root, domain):
    with open(os.path.join(root, CSV_FILES[domain]), newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def decode_output(output):
    return output.decode("utf-8", errors="replace")


def checksum8(data):
    return sum(data) & 0xff


def u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def gas_address(data, off):
    return u32(data, off + 4) | (u32(data, off + 8) << 32)


def aml_pkg_length(data, off):
    lead = data[off]
    follow = lead >> 6
    if follow == 0:
        return lead & 0x3f, 1

    length = lead & 0x0f
    for index in range(follow):
        length |= data[off + 1 + index] << (4 + index * 8)
    return length, 1 + follow


def aml_integer(data, off):
    op = data[off]
    if op == 0x00:
        return 0, off + 1
    if op == 0x01:
        return 1, off + 1
    if op == 0x0a:
        return data[off + 1], off + 2
    if op == 0x0b:
        return u16(data, off + 1), off + 3
    if op == 0x0c:
        return u32(data, off + 1), off + 5
    if op == 0x0e:
        return u64(data, off + 1), off + 9
    raise RuntimeError(f"unsupported AML integer opcode 0x{op:02x}")


def aml_package(data, off):
    if data[off] != 0x12:
        raise RuntimeError(f"expected AML PackageOp at 0x{off:x}")
    length, length_bytes = aml_pkg_length(data, off + 1)
    count_off = off + 1 + length_bytes
    end = off + 1 + length
    return data[count_off], count_off + 1, end


def dsdt_prt_entries(dsdt):
    name_off = dsdt.index(b"_PRT")
    if name_off == 0 or dsdt[name_off - 1] != 0x08:
        raise RuntimeError("DSDT _PRT must be a NameOp")

    count, off, end = aml_package(dsdt, name_off + 4)
    entries = []
    while off < end:
        entry_count, entry_off, entry_end = aml_package(dsdt, off)
        values = []
        for _ in range(entry_count):
            value, entry_off = aml_integer(dsdt, entry_off)
            values.append(value)
        if entry_off != entry_end:
            raise RuntimeError("DSDT _PRT package has trailing AML")
        entries.append(values)
        off = entry_end

    if len(entries) != count or off != end:
        raise RuntimeError("DSDT _PRT package length/count mismatch")
    return entries


def aml_named_buffer_resource_bytes(data, name, label):
    name_off = data.index(name)
    if name_off == 0 or data[name_off - 1] != 0x08:
        raise RuntimeError(f"{label} must be a NameOp")

    off = name_off + 4
    if data[off] != 0x11:
        raise RuntimeError(f"{label} must be a BufferOp")
    length, length_bytes = aml_pkg_length(data, off + 1)
    buffer_len_off = off + 1 + length_bytes
    end = off + 1 + length
    buffer_len, resource_off = aml_integer(data, buffer_len_off)
    if resource_off + buffer_len != end:
        raise RuntimeError(f"{label} buffer length mismatch")
    return data[resource_off:end]


def dsdt_crs_resource_bytes(dsdt):
    return aml_named_buffer_resource_bytes(dsdt, b"_CRS", "DSDT _CRS")


def qword_address_descriptors(resources, label):
    descriptors = []
    off = 0
    while off < len(resources):
        tag = resources[off]
        if tag == 0x79:
            if off + 2 != len(resources):
                raise RuntimeError(f"{label} end tag has trailing data")
            break
        if (tag & 0x80) == 0:
            off += 1 + (tag & 0x07)
            continue

        length = u16(resources, off + 1)
        if off + 3 + length > len(resources):
            raise RuntimeError(f"{label} large resource length overflow")
        if tag == 0x8a:
            desc = resources[off:off + 3 + length]
            if len(desc) != 46:
                raise RuntimeError(f"{label} QWordAddress length mismatch")
            descriptors.append({
                "resource_type": desc[3],
                "general_flags": desc[4],
                "type_flags": desc[5],
                "granularity": u64(desc, 6),
                "minimum": u64(desc, 14),
                "maximum": u64(desc, 22),
                "translation": u64(desc, 30),
                "length": u64(desc, 38),
            })
        off += 3 + length
    return descriptors


def dsdt_qword_address_descriptors(dsdt):
    return qword_address_descriptors(dsdt_crs_resource_bytes(dsdt), "DSDT _CRS")


def run_named_tests(qemu, tests, label):
    failures = []
    start = time.monotonic()
    for index, (name, func) in enumerate(tests, start=1):
        try:
            func(qemu)
        except Exception as exc:
            failures.append((name, str(exc)))
            if len(failures) >= 20:
                break
        if index % 50 == 0:
            print(f"# {label}: executed {index} golden programs")
    elapsed = time.monotonic() - start
    print(f"# {label}: executed {len(tests)} golden programs in {elapsed:.1f}s")
    return failures


def make_fat_disk(path):
    sectors = 64
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

    with open(path, "wb") as f:
        f.write(image)


def run_firmware(qemu, firmware):
    with tempfile.TemporaryDirectory() as tmpdir:
        disk = os.path.join(tmpdir, "fat.img")
        make_fat_disk(disk)
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
        deadline = time.monotonic() + 12.0
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
                    text = decode_output(b"".join(output_parts))
                    if "Block I/O: BOOTIA64.EFI not found" in text:
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


def objdump_symbols(elf_path):
    result = subprocess.run(
        ["ia64-linux-gnu-objdump", "-t", elf_path],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stdout)
    symbols = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 6:
            name = fields[-1]
            try:
                addr = int(fields[0], 16)
                size = int(fields[-2], 16)
            except ValueError:
                continue
            symbols[name] = (addr, size)
    return symbols


def symbol_bytes(elf_path, symbols, name):
    if name not in symbols:
        raise RuntimeError(f"missing firmware symbol {name}")
    addr, size = symbols[name]
    result = subprocess.run(
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
    if result.returncode != 0:
        raise RuntimeError(result.stdout)
    data = bytearray()
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        try:
            int(fields[0], 16)
        except ValueError:
            continue
        for word in fields[1:]:
            if len(word) > 8 or len(word) % 2 != 0:
                break
            if any(c not in "0123456789abcdefABCDEF" for c in word):
                break
            data.extend(bytes.fromhex(word))
    return bytes(data[:size])


def qemu_physical_bytes(qemu, firmware, ranges, machine="ia64-vpc"):
    commands = []
    for addr, size in ranges.values():
        commands.append(f"xp /{size}xb 0x{addr:x}")
    input_text = "\n".join(commands + ["quit", ""])

    proc = subprocess.Popen(
        [
            qemu,
            "-machine", machine,
            "-smp", "1",
            "-bios", firmware,
            "-display", "none",
            "-serial", "none",
            "-monitor", "stdio",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        time.sleep(2.0)
        proc.stdin.write(input_text)
        proc.stdin.flush()
        output, _ = proc.communicate(timeout=8)
    except Exception:
        proc.kill()
        output, _ = proc.communicate()
        raise RuntimeError("qemu monitor memory dump failed\n" + output)

    if proc.returncode != 0:
        raise RuntimeError("qemu monitor exited nonzero\n" + output)

    result = {}
    lines = output.splitlines()
    for name, (addr, size) in ranges.items():
        wanted = addr
        data = bytearray()
        for line in lines:
            match = re.search(r"\b([0-9a-fA-F]{6,16}):\s+(.+)$", line)
            if not match:
                continue
            line_addr = int(match.group(1), 16)
            if not (addr <= line_addr < addr + size):
                continue
            if line_addr != wanted:
                continue
            bytes_in_line = [
                int(value, 16)
                for value in re.findall(r"0x([0-9a-fA-F]{2})", match.group(2))
            ]
            data.extend(bytes_in_line)
            wanted += len(bytes_in_line)
            if len(data) >= size:
                break
        if len(data) != size:
            raise RuntimeError(
                f"could not read runtime bytes for {name}: got {len(data)} of {size}\n"
                + output
            )
        result[name] = bytes(data)
    return result


def qemu_runtime_symbol_bytes(qemu, firmware, symbols, names):
    ranges = {}
    for name in names:
        if name not in symbols:
            raise RuntimeError(f"missing firmware symbol {name}")
        ranges[name] = symbols[name]
    return qemu_physical_bytes(qemu, firmware, ranges)


def parse_efi_memory_map(data, entries):
    descriptors = []
    for index in range(entries):
        off = index * 40
        descriptors.append({
            "type": u32(data, off),
            "physical_start": u64(data, off + 8),
            "virtual_start": u64(data, off + 16),
            "pages": u64(data, off + 24),
            "attribute": u64(data, off + 32),
        })
    return descriptors


def efi_descriptor_contains(desc, addr, size):
    start = desc["physical_start"]
    end = start + desc["pages"] * EFI_PAGE_SIZE
    return addr >= start and addr + size <= end


def ia64_sparse_io_offset(port):
    return ((port & 0xfffc) << 10) | (port & 0xfff)


def c_define_integer(source, name):
    pattern = r"^#define\s+" + re.escape(name) + r"\s+([0-9A-Fa-fxX]+)ULL"
    match = re.search(pattern, source, re.MULTILINE)
    if not match:
        raise RuntimeError(f"missing C integer define {name}")
    return int(match.group(1), 0)


def sdt_name(data):
    return data[:4].decode("ascii")


def validate_sdt(name, data, expected_signature, min_revision=1):
    if sdt_name(data) != expected_signature:
        raise RuntimeError(f"{name}: expected signature {expected_signature}")
    length = u32(data, 4)
    if length != len(data):
        raise RuntimeError(f"{name}: length field {length} != symbol size {len(data)}")
    if data[8] < min_revision:
        raise RuntimeError(f"{name}: revision {data[8]} < {min_revision}")
    if checksum8(data) != 0:
        raise RuntimeError(f"{name}: checksum is not zero")
    if data[36:length] == b"":
        raise RuntimeError(f"{name}: missing body")


def test_inputs(root, qemu, firmware):
    missing = []
    for path in CSV_FILES.values():
        if not os.path.exists(os.path.join(root, path)):
            missing.append(path)
    for path in [qemu, firmware, os.path.splitext(firmware)[0] + ".elf"]:
        if not os.path.exists(path):
            missing.append(path)
    if missing:
        raise RuntimeError("missing inputs: " + ", ".join(missing))
    if LEGACY_IO_BASE & (PCI_IO_SPARSE_SIZE - 1):
        raise RuntimeError("legacy PCI I/O base must be aligned for sparse I/O")
    for port in [0x60, 0x1f0, 0x3f6, 0x800, 0x80a, 0xc000, 0xffff]:
        sparse = ia64_sparse_io_offset(port)
        if sparse >= PCI_IO_SPARSE_SIZE:
            raise RuntimeError(f"sparse I/O port 0x{port:x} exceeds aperture")
        if (LEGACY_IO_BASE | sparse) != LEGACY_IO_BASE + sparse:
            raise RuntimeError(f"sparse I/O port 0x{port:x} aliases base bits")

    with open(os.path.join(root, "hw/ia64/ia64_iosapic.c"),
              encoding="utf-8") as f:
        iosapic_source = f.read()
    iosapic_rte_bits = {
        "RTE_DELIVERY_STATUS": IOSAPIC_RTE_DELIVERY_STATUS,
        "RTE_REMOTE_IRR": IOSAPIC_RTE_REMOTE_IRR,
        "RTE_TRIGGER_LEVEL": IOSAPIC_RTE_TRIGGER_LEVEL,
        "RTE_MASKED": IOSAPIC_RTE_MASKED,
    }
    for name, expected in iosapic_rte_bits.items():
        actual = c_define_integer(iosapic_source, name)
        if actual != expected:
            raise RuntimeError(
                f"I/O SAPIC {name} 0x{actual:x} != standard bit 0x{expected:x}"
            )
    for required in [
        "#define RTE_RO_BITS          (RTE_DELIVERY_STATUS | RTE_REMOTE_IRR)",
        "s->rte[pin] = (s->rte[pin] & ~RTE_RO_BITS) | ro_bits;",
        "s->rte[pin] |= RTE_REMOTE_IRR;",
        "s->rte[pin] &= ~RTE_REMOTE_IRR;",
        "iosapic_update(s, pin);",
    ]:
        if required not in iosapic_source:
            raise RuntimeError(
                f"I/O SAPIC level-triggered Remote IRR contract missing: {required}"
            )


def test_csv_rows_are_bound_to_execution(root, qemu1, qemu2):
    rows = {domain: load_csv(root, domain) for domain in CSV_FILES}
    qemu1_names = {
        name[5:] for name in dir(qemu1)
        if name.startswith("test_") and callable(getattr(qemu1, name))
    }
    qemu2_names = set(qemu2.TEST_NAMES)
    pal_names = {name for name in qemu2_names if name.startswith("pal_")}
    problems = []

    instruction_group_tests = {
        "bundle": {"exception_reserved_template", "mlx_long_nop_x_imm_decode",
                   "exception_break_x"},
        "branch_or_hint": {"arithmetic_and_branch", "br_many",
                           "brl_call_mlx_decode", "br_call_indirect_completers_decode",
                           "br_ctop_rotating_pipeline"},
        "integer": {"alu_immediate_ops", "register_shifts", "deposit_immediate",
                    "extract_immediate", "dep_decode", "popcnt_decode"},
        "predicate": {"predicate_register_moves", "predicate_rot_immediate",
                      "predication"},
        "predicate_compare": {"cmp_eq_and_decode", "cmp_ge_or_decode",
                              "cmp4_eq_imm_decode", "cmp_same_pred_illegal"},
        "memory": {"memory_load_store", "ld16_loads_gr_and_csd",
                   "st16_stores_gr_and_csd", "store_invalidates_advanced_load",
                   "semaphore_ops_invalidate_advanced_loads"},
        "nat": {"nat_consumption_sets_ifa_isr", "integer_nat_propagates_and_clears",
                "speculative_load_defers_nat_base"},
        "simd_integer": {"pmpy2_decode", "mix_decode", "unpack2_l_decode",
                         "pavg_decode", "pcmp1_eq_decode"},
        "floating_point": {"windows_fp_decode", "xmpy_hu", "fselect_decode",
                           "fp_logical_and_swap_decode", "fpsr_status_field_controls"},
        "system_or_translation": {"pal_version", "itc_d_preserves_24bit_key",
                                  "ptc_l_m_unit_decode",
                                  "ptr_d_purge_completes_on_srlz_d",
                                  "rfi_restores_interrupted_bsp_after_cover",
                                  "pmc_pmd_registers_are_independent"},
    }
    available = qemu1_names | qemu2_names
    for category, tests in instruction_group_tests.items():
        missing = tests - available
        if missing:
            problems.append(f"instruction category {category}: missing {sorted(missing)}")

    for row in rows["instructions"]:
        if row["category"] not in instruction_group_tests:
            problems.append(f"instruction row lacks execution group: {row}")

    for row in rows["pal"]:
        if not pal_names:
            problems.append("PAL execution suite is empty")
            break
        name = row["name"].lower()
        required = None
        if row["entry_type"] == "function":
            required = "pal_" + re.sub(r"^pal_", "", name).replace("_", "_")
            required = required.replace("pal_halt_light", "pal_halt_light_wakes_on_due_itm")
        elif "reserved" in name:
            required = "pal_version_reserved_arg"
        elif "cache_flush" in name:
            required = "pal_cache_flush_bad_type"
        elif "cache_info" in name:
            required = "pal_cache_info_l0_data"
        elif "cache_init" in name:
            required = "pal_cache_init"
        elif "platform_addr" in name:
            required = "pal_platform_addr_interrupt"
        elif "mc_expected" in name:
            required = "pal_mc_expected"
        elif "mc_error_info" in name:
            required = "pal_mc_error_info_structure_empty"
        elif "mc_resume" in name:
            required = "pal_mc_resume_no_context"
        elif "copy_info" in name:
            required = "pal_copy_info"
        elif "copy_pal" in name:
            required = "pal_copy_pal_entry_callable"
        elif "vm_tr_read" in name:
            required = "pal_vm_tr_read_dtr"
        else:
            required = "pal_unknown"
        if required not in pal_names:
            alternatives = [
                candidate for candidate in pal_names
                if candidate.startswith(required + "_") or required in candidate
            ]
            if alternatives:
                continue
            problems.append(f"PAL row {row['name']}: missing execution test {required}")

    # SAL, EFI, and ACPI rows are bound to the firmware boot contract and the
    # binary table verifier below.  Their exact row count is asserted so adding
    # a new CSV function requires extending this execution test deliberately.
    expected_counts = {
        "efi": 147,
        "sal": 28,
        "acpi": 24,
    }
    for domain, count in expected_counts.items():
        if len(rows[domain]) != count:
            problems.append(f"{domain}: expected {count} rows, got {len(rows[domain])}")

    if problems:
        raise RuntimeError("\n".join(problems[:80]))


def test_instruction_execution_suite(qemu, qemu1, qemu2):
    qemu1_tests = sorted(
        (name[5:], getattr(qemu1, name))
        for name in dir(qemu1)
        if name.startswith("test_") and callable(getattr(qemu1, name))
    )
    qemu2_tests = sorted(
        (name, func)
        for name, func in qemu2.TEST_NAMES.items()
        if not name.startswith("pal_")
    )
    failures = run_named_tests(qemu, qemu1_tests + qemu2_tests,
                               "IA-64 instruction/system")
    if failures:
        lines = [f"{name}: {error}" for name, error in failures]
        raise RuntimeError("\n".join(lines))


def test_pal_execution_suite(qemu, qemu2):
    pal_tests = sorted(
        (name, func)
        for name, func in qemu2.TEST_NAMES.items()
        if name.startswith("pal_")
    )
    if len(pal_tests) < 90:
        raise RuntimeError(f"PAL suite too small: {len(pal_tests)} tests")
    failures = run_named_tests(qemu, pal_tests, "PAL")
    if failures:
        lines = [f"{name}: {error}" for name, error in failures]
        raise RuntimeError("\n".join(lines))


def test_sal_efi_firmware_boot_contract(qemu, firmware):
    returncode, output = run_firmware(qemu, firmware)
    required = [
        "UEFI Time Services:   GetTime/SetTime/GetWakeupTime verified",
        "Memory Map Test:      descriptor boundaries verified",
        "Console Out Test:     text output contracts verified",
        "Console In:           Serial/PS2 WaitForKey ready",
        "Console In Buffer:    WaitForKey preserves keystrokes",
        "UEFI Event Services:  contract checks verified",
        "Protocol Notify:      LocateProtocol registration verified",
        "Protocol Database:    NULL interface markers verified",
        "PCI Root Bridge Test: config/resources verified",
        "PCI I/O Protocol:    controllers verified",
        "FPSWA Protocol:       published (visibility fallback)",
        "NVRAM Variable Test:  contract checks verified",
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
        "ACPI RSDP/RSDT/XSDT/FADT: published",
        "ACPI MADT (SAPIC):    published",
        "ACPI SRAT/SLIT:       published",
        "ACPI MCFG (PCIe):     published",
        "ACPI HCDP/PCDP:       published",
        "ACPI SSDT (serial):   published",
        "ACPI Table Checks:    checksums verified",
        "Block I/O Read Test:  media ID/range/bulk reads verified",
        "Block I/O: BOOTIA64.EFI not found",
    ]
    missing = [token for token in required if token not in output]
    if returncode is not None:
        raise RuntimeError("firmware exited during boot contract test\n" + output)
    if missing:
        raise RuntimeError(
            "missing firmware standard-contract output:\n" +
            "\n".join(missing) + "\n" + output
        )


def test_acpi_efi_sal_binary_tables(qemu, firmware):
    elf_path = os.path.splitext(firmware)[0] + ".elf"
    symbols = objdump_symbols(elf_path)
    runtime_names = [
        "mSystemTable", "mConfigTables", "mSalSystemTable",
        "mMemoryMapEntries", "mMemoryMap",
    ]
    runtime = qemu_runtime_symbol_bytes(qemu, firmware, symbols, runtime_names)
    memory_map = parse_efi_memory_map(
        runtime["mMemoryMap"], u64(runtime["mMemoryMapEntries"], 0)
    )

    system_table = runtime["mSystemTable"]
    config_count = u64(system_table, 104)
    config_ptr = u64(system_table, 112)
    if config_ptr != symbols["mConfigTables"][0]:
        raise RuntimeError("EFI system table configuration pointer mismatch")

    config_tables = runtime["mConfigTables"]
    config = {}
    for off in range(0, min(config_count * 24, len(config_tables)), 24):
        config[config_tables[off:off + 16]] = u64(config_tables, off + 16)

    rsdp_addr = config.get(EFI_ACPI20_TABLE_GUID)
    if rsdp_addr is None:
        raise RuntimeError("missing EFI ACPI 2.0 configuration table")
    if config.get(EFI_ACPI10_TABLE_GUID) != rsdp_addr:
        raise RuntimeError("EFI ACPI 1.0 and 2.0 GUIDs must both reference RSDP")
    if config.get(EFI_SAL_SYSTEM_TABLE_GUID) != symbols["mSalSystemTable"][0]:
        raise RuntimeError("EFI configuration table does not reference SAL table")

    def find_efi_descriptor(name, memory_type, addr, size,
                            required_attr=0):
        for desc in memory_map:
            if (desc["type"] == memory_type and
                    (desc["attribute"] & required_attr) == required_attr and
                    efi_descriptor_contains(desc, addr, size)):
                return desc
        raise RuntimeError(f"{name} is not covered by the expected EFI memory type")

    runtime_data_attr = EFI_MEMORY_WB | EFI_MEMORY_RUNTIME
    find_efi_descriptor(
        "EFI system table", EFI_RUNTIME_SERVICES_DATA,
        symbols["mSystemTable"][0], symbols["mSystemTable"][1],
        runtime_data_attr,
    )
    find_efi_descriptor(
        "EFI configuration table", EFI_RUNTIME_SERVICES_DATA,
        symbols["mConfigTables"][0], symbols["mConfigTables"][1],
        runtime_data_attr,
    )
    find_efi_descriptor(
        "PCI MMIO window", EFI_MEMORY_MAPPED_IO,
        PCI_MMIO_BASE, PCI_MMIO_SIZE, EFI_MEMORY_UC,
    )
    find_efi_descriptor(
        "PCI sparse I/O port window", EFI_MEMORY_MAPPED_IO_PORT_SPACE,
        LEGACY_IO_BASE + EFI_PAGE_SIZE,
        PCI_IO_SPARSE_SIZE - EFI_PAGE_SIZE, EFI_MEMORY_UC,
    )
    find_efi_descriptor(
        "runtime reset I/O port page", EFI_MEMORY_MAPPED_IO_PORT_SPACE,
        LEGACY_IO_BASE, EFI_PAGE_SIZE, EFI_MEMORY_UC | EFI_MEMORY_RUNTIME,
    )
    find_efi_descriptor(
        "runtime ACPI PM window", EFI_MEMORY_MAPPED_IO,
        ACPI_PM_BASE, 0x2000, EFI_MEMORY_UC | EFI_MEMORY_RUNTIME,
    )

    def require_acpi_reclaim(name, addr, size, align=8):
        reclaim_desc = find_efi_descriptor(
            name, EFI_ACPI_RECLAIM_MEMORY, addr, size, EFI_MEMORY_WB
        )
        if (reclaim_desc["physical_start"] % EFI_IA64_RUNTIME_DESCRIPTOR_ALIGN or
                (reclaim_desc["pages"] * EFI_PAGE_SIZE) %
                EFI_IA64_RUNTIME_DESCRIPTOR_ALIGN):
            raise RuntimeError(f"{name} ACPI reclaim descriptor alignment mismatch")
        if addr < ACPI_RECLAIM_BASE or addr + size > ACPI_RECLAIM_END:
            raise RuntimeError(f"{name} is not in EFI ACPI Reclaim memory")
        if addr % align != 0:
            raise RuntimeError(f"{name} alignment mismatch")

    require_acpi_reclaim("RSDP", rsdp_addr, symbols["mRsdp"][1], 16)
    rsdp = qemu_physical_bytes(
        qemu, firmware, {"RSDP": (rsdp_addr, symbols["mRsdp"][1])}
    )["RSDP"]
    if len(rsdp) != 36 or rsdp[:8] != RSDP_SIGNATURE:
        raise RuntimeError("RSDP signature/length mismatch")
    if checksum8(rsdp[:20]) != 0 or checksum8(rsdp) != 0:
        raise RuntimeError("RSDP checksum mismatch")
    if rsdp[15] != 2 or u32(rsdp, 20) != 36:
        raise RuntimeError("RSDP must be ACPI 2.0 revision 2 length 36")

    rsdt_addr = u32(rsdp, 16)
    xsdt_addr = u64(rsdp, 24)
    require_acpi_reclaim("RSDT", rsdt_addr, symbols["mRsdt"][1])
    require_acpi_reclaim("XSDT", xsdt_addr, symbols["mXsdt"][1])
    roots = qemu_physical_bytes(qemu, firmware, {
        "mXsdt": (xsdt_addr, symbols["mXsdt"][1]),
        "mRsdt": (rsdt_addr, symbols["mRsdt"][1]),
    })
    xsdt = roots["mXsdt"]
    rsdt = roots["mRsdt"]
    validate_sdt("mXsdt", xsdt, "XSDT", 1)
    validate_sdt("mRsdt", rsdt, "RSDT", 1)

    xsdt_entries = [u64(xsdt, off) for off in range(36, u32(xsdt, 4), 8)]
    rsdt_entries = [u32(rsdt, off) for off in range(36, u32(rsdt, 4), 4)]
    expected_xsdt_symbols = [
        "mFadt", "mMadt", "mSrat", "mSlit", "mHcdp", "mMcfg", "mSsdt",
    ]
    if len(xsdt_entries) != len(expected_xsdt_symbols):
        raise RuntimeError("XSDT entry count mismatch")
    if rsdt_entries != [addr & 0xffffffff for addr in xsdt_entries]:
        raise RuntimeError("RSDT entries do not match XSDT low addresses")

    table_addrs = dict(zip(expected_xsdt_symbols, xsdt_entries))
    for name, addr in table_addrs.items():
        require_acpi_reclaim(name, addr, symbols[name][1])

    tables = {
        "mFadt": ("FACP", 3),
        "mSsdt": ("SSDT", 2),
        "mMadt": ("APIC", 2),
        "mMcfg": ("MCFG", 1),
        "mSrat": ("SRAT", 1),
        "mSlit": ("SLIT", 1),
        "mHcdp": ("HCDP", 3),
    }
    table_data = qemu_physical_bytes(qemu, firmware, {
        name: (table_addrs[name], symbols[name][1])
        for name in tables
    })
    for symbol, (signature, min_revision) in tables.items():
        data = table_data[symbol]
        validate_sdt(symbol, data, signature, min_revision)

    if config.get(EFI_HCDP_TABLE_GUID) != table_addrs["mHcdp"]:
        raise RuntimeError("EFI configuration table does not reference HCDP")

    fadt = table_data["mFadt"]
    facs_addr = u64(fadt, 132)
    dsdt_addr = u64(fadt, 140)
    if (u32(fadt, 36) != (facs_addr & 0xffffffff) or
            u32(fadt, 40) != (dsdt_addr & 0xffffffff)):
        raise RuntimeError("FADT legacy FACS/DSDT pointers mismatch")
    require_acpi_reclaim("FACS", facs_addr, symbols["mFacs"][1], 64)
    require_acpi_reclaim("DSDT", dsdt_addr, symbols["mDsdt"][1])
    if fadt[45] != 4 or u16(fadt, 46) != ACPI_SCI_IRQ:
        raise RuntimeError("FADT IA-64 profile or SCI IRQ mismatch")
    if u32(fadt, 112) != ACPI_FADT_EXPECTED_FLAGS:
        raise RuntimeError("FADT fixed feature flags mismatch")
    if fadt[149] != 32 or gas_address(fadt, 148) != ACPI_PM_BASE:
        raise RuntimeError("FADT X_PM1a_EVT_BLK address mismatch")
    if fadt[173] != 16 or gas_address(fadt, 172) != ACPI_PM_BASE + 4:
        raise RuntimeError("FADT X_PM1a_CNT_BLK address mismatch")
    if fadt[209] != 32 or gas_address(fadt, 208) != ACPI_PM_BASE + 8:
        raise RuntimeError("FADT X_PM_TMR_BLK address mismatch")

    fadt_children = qemu_physical_bytes(qemu, firmware, {
        "mFacs": (facs_addr, symbols["mFacs"][1]),
        "mDsdt": (dsdt_addr, symbols["mDsdt"][1]),
    })
    dsdt = fadt_children["mDsdt"]
    validate_sdt("mDsdt", dsdt, "DSDT", 2)
    for token in [b"PCI0", b"PNP0A08", b"PNP0A03", b"_CRS", b"_PRT"]:
        if token not in dsdt:
            raise RuntimeError(f"DSDT PCI namespace missing {token!r}")
    expected_prt = []
    for slot in range(5):
        for pin in range(PCI_INTX_LINES):
            expected_prt.append([
                (slot << 16) | 0xffff,
                pin,
                0,
                PCI_INTX_GSI_BASE + ((slot + pin) % PCI_INTX_LINES),
            ])
    if dsdt_prt_entries(dsdt) != expected_prt:
        raise RuntimeError("DSDT _PRT PCI INTx to IOSAPIC GSI routing mismatch")
    qword_crs = dsdt_qword_address_descriptors(dsdt)
    io_crs = next((desc for desc in qword_crs if desc["resource_type"] == 1), None)
    mem_crs = next((desc for desc in qword_crs if desc["resource_type"] == 0), None)
    if (io_crs is None or io_crs["granularity"] != 0 or
            io_crs["minimum"] != 0 or
            io_crs["maximum"] != PCI_IO_SIZE - 1 or
            io_crs["translation"] != PCI_IO_TRANSLATION_OFFSET or
            io_crs["length"] != PCI_IO_SIZE):
        raise RuntimeError("DSDT _CRS PCI I/O translation window mismatch")
    if (mem_crs is None or mem_crs["granularity"] != 0 or
            mem_crs["minimum"] != PCI_MMIO_BASE or
            mem_crs["maximum"] != PCI_MMIO_BASE + PCI_MMIO_SIZE - 1 or
            mem_crs["translation"] != 0 or
            mem_crs["length"] != PCI_MMIO_SIZE):
        raise RuntimeError("DSDT _CRS PCI MMIO identity window mismatch")

    ssdt = table_data["mSsdt"]
    if b"\x5b\x83\x0bCPU0\x00\x00\x00\x00\x00\x00" not in ssdt:
        raise RuntimeError("SSDT Processor CPU0 declaration missing")
    for token in [b"UAR0", b"PNP0501", b"_CRS"]:
        if token not in ssdt:
            raise RuntimeError(f"SSDT UART namespace missing {token!r}")
    ssdt_resources = aml_named_buffer_resource_bytes(ssdt, b"_CRS", "SSDT _CRS")
    ssdt_qword_crs = qword_address_descriptors(ssdt_resources, "SSDT _CRS")
    uart_crs = next((desc for desc in ssdt_qword_crs
                     if desc["resource_type"] == 0), None)
    if (uart_crs is None or uart_crs["general_flags"] != 0x0d or
            uart_crs["type_flags"] != 0x01 or
            uart_crs["granularity"] != 0 or
            uart_crs["minimum"] != UART_BASE or
            uart_crs["maximum"] != UART_BASE + 7 or
            uart_crs["translation"] != 0 or
            uart_crs["length"] != 8):
        raise RuntimeError("SSDT UART QWordMemory resource mismatch")
    if struct.pack("<Q", UART_BASE) not in ssdt:
        raise RuntimeError("SSDT UART QWordMemory base mismatch")
    if struct.pack("<Q", UART_BASE + 7) not in ssdt:
        raise RuntimeError("SSDT UART QWordMemory limit mismatch")
    if struct.pack("<Q", 8) not in ssdt:
        raise RuntimeError("SSDT UART QWordMemory length mismatch")
    if not ssdt_resources.endswith(b"\x22\x10\x00\x79\x00"):
        raise RuntimeError("SSDT UART IRQ descriptor mismatch")

    facs = fadt_children["mFacs"]
    if facs[:4] != b"FACS" or u32(facs, 4) != 64:
        raise RuntimeError("FACS signature/length mismatch")
    if u32(facs, 8) != 0 or u32(facs, 16) != 0 or u64(facs, 24) != 0:
        raise RuntimeError("FACS must publish zero wake vectors/global lock")
    if facs[32] != 1:
        raise RuntimeError("FACS version must be 1")

    madt = table_data["mMadt"]
    if u32(madt, 36) != 0xFEE00000 or u32(madt, 40) != 0:
        raise RuntimeError("MADT local SAPIC address/flags mismatch")
    if madt[44] != 7 or madt[45] != 12 or u32(madt, 52) != 1:
        raise RuntimeError("MADT Local SAPIC entry mismatch")
    if madt[56] != 6 or madt[57] != 16 or u32(madt, 60) != 0:
        raise RuntimeError("MADT I/O SAPIC entry mismatch")
    if u64(madt, 64) != IOSAPIC_BASE:
        raise RuntimeError("MADT I/O SAPIC address mismatch")

    mcfg = table_data["mMcfg"]
    if u64(mcfg, 44) != PCI_CONFIG_ECAM_BASE:
        raise RuntimeError("MCFG ECAM base mismatch")
    if u16(mcfg, 52) != 0 or mcfg[54] != 0 or mcfg[55] != 255:
        raise RuntimeError("MCFG segment/bus range mismatch")

    srat = table_data["mSrat"]
    if u32(srat, 36) != 1:
        raise RuntimeError("SRAT table revision mismatch")
    if srat[48] != 1 or srat[49] != 40 or u32(srat, 76) != 1:
        raise RuntimeError("SRAT memory affinity entry mismatch")
    if srat[88] != 0 or srat[89] != 16 or u32(srat, 92) != 1:
        raise RuntimeError("SRAT processor affinity entry mismatch")

    slit = table_data["mSlit"]
    if u64(slit, 36) != 1 or slit[44] != 10:
        raise RuntimeError("SLIT one-locality distance mismatch")

    hcdp = table_data["mHcdp"]
    if u32(hcdp, 36) != 2:
        raise RuntimeError("HCDP entry count mismatch")
    if hcdp[40] != 0 or hcdp[41] != 8 or hcdp[43] != 1:
        raise RuntimeError("HCDP UART 8n1 descriptor mismatch")
    if u32(hcdp, 48) != UART_BAUD or u32(hcdp, 72) != HCDP_UART_IRQ:
        raise RuntimeError("HCDP UART baud/IRQ mismatch")
    if hcdp[81] != 0 or hcdp[89] != HCDP_DEVICE_PRIMARY_CONSOLE:
        raise RuntimeError("HCDP default VGA primary console flags mismatch")
    if hcdp[88] != 10 or hcdp[90] != 41:
        raise RuntimeError("HCDP VGA console descriptor mismatch")
    if u16(hcdp, 102) != VGA_DEVICE_ID or u16(hcdp, 104) != VGA_VENDOR_ID:
        raise RuntimeError("HCDP VGA PCI identity mismatch")
    if (u64(hcdp, 110) != 0 or u64(hcdp, 118) != LEGACY_IO_BASE or
            hcdp[126] != 0 or hcdp[127] != HCDP_PCI_TRANSLATE_IOPORT):
        raise RuntimeError("HCDP VGA PCI translation flags mismatch")
    serial_hcdp = qemu_physical_bytes(
        qemu, firmware,
        {"mHcdp": (table_addrs["mHcdp"], symbols["mHcdp"][1])},
        machine="ia64-vpc,firmware-console=serial",
    )["mHcdp"]
    if (serial_hcdp[81] != HCDP_UART_PRIMARY_CONSOLE or
            serial_hcdp[89] != 0):
        raise RuntimeError("HCDP serial console override flags mismatch")

    sal = runtime["mSalSystemTable"]
    if sal[:4] != b"SST_" or u32(sal, 4) != len(sal):
        raise RuntimeError("SAL table signature/length mismatch")
    if checksum8(sal) != 0:
        raise RuntimeError("SAL table checksum mismatch")
    if u16(sal, 8) != 0x0330 or u16(sal, 10) != 2:
        raise RuntimeError("SAL revision or descriptor count mismatch")
    if sal[24:28] != b"QEMU" or sal[56:61] != b"IA-64":
        raise RuntimeError("SAL OEM/product identifiers mismatch")
    if sal[96] != 0 or sal[144] != 2:
        raise RuntimeError("SAL descriptor type sequence mismatch")


def main():
    if len(sys.argv) != 4:
        print(
            "Bail out! usage: test-ia64-standard-execution.py "
            "SOURCE_ROOT QEMU_SYSTEM_IA64 IA64_FIRMWARE_BIN"
        )
        return 1

    root, qemu, firmware = sys.argv[1:]
    print("TAP version 13")
    print("1..6")

    qemu1 = None
    qemu2 = None
    status = 0

    tests = []
    try:
        test_inputs(root, qemu, firmware)
        qemu1 = load_module(os.path.join(root, "tests/unit/test-ia64-qemu-tcg.py"),
                            "ia64_qemu_tcg_goldens")
        qemu2 = load_module(os.path.join(root, "tests/unit/test-ia64-qemu-tcg-2.py"),
                            "ia64_qemu_tcg_2_goldens")
        tests = [
            ("standard inputs and imported execution suites are available", None),
            ("all CSV rows are bound to executable standard goldens",
             lambda: test_csv_rows_are_bound_to_execution(root, qemu1, qemu2)),
            ("IA-64 instruction and system-operation goldens",
             lambda: test_instruction_execution_suite(qemu, qemu1, qemu2)),
            ("PAL procedure goldens", lambda: test_pal_execution_suite(qemu, qemu2)),
            ("SAL and EFI firmware boot-service/runtime/protocol goldens",
             lambda: test_sal_efi_firmware_boot_contract(qemu, firmware)),
            ("ACPI, EFI configuration, and SAL binary table goldens",
             lambda: test_acpi_efi_sal_binary_tables(qemu, firmware)),
        ]
        print("ok 1 - " + tests[0][0])
    except Exception as exc:
        print("not ok 1 - standard inputs and imported execution suites are available")
        print(f"# {exc}")
        return 1

    for index, (name, fn) in enumerate(tests[1:], start=2):
        try:
            fn()
            print(f"ok {index} - {name}")
        except Exception as exc:
            status = 1
            print(f"not ok {index} - {name}")
            for line in str(exc).splitlines():
                print(f"# {line}")
    return status


if __name__ == "__main__":
    sys.exit(main())
