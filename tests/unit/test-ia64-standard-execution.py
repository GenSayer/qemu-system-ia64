#!/usr/bin/env python3
#
# IA-64 standard-derived golden execution tests.
#
# This test is intentionally separate from test-ia64-standard-goldens.py.  The
# latter checks that every docs/ia64 inventory row has a standard-derived golden
# specification.  This file executes those contracts against QEMU and the IA-64
# firmware image.

import calendar
import csv
import importlib.util
import os
import re
import select
import socket
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
ACPI_PM_IO_BASE = 0x2000
ACPI_PM_RESET_OFFSET = 0x0c
ACPI_PM_RESET_VALUE = 0x01
ACPI_GAS_SYSTEM_MEMORY = 0
ACPI_GAS_SYSTEM_IO = 1
ACPI_SCI_IRQ = 9
ACPI_FADT_FLAG_WBINVD = 1 << 0
ACPI_FADT_FLAG_PWR_BUTTON = 1 << 4
ACPI_FADT_FLAG_SLP_BUTTON = 1 << 5
ACPI_FADT_FLAG_RESET_REG_SUP = 1 << 10
ACPI_FADT_FLAG_SW_CPU_SLP = 1 << 13
ACPI_FADT_EXPECTED_FLAGS = (
    ACPI_FADT_FLAG_WBINVD |
    ACPI_FADT_FLAG_SLP_BUTTON |
    ACPI_FADT_FLAG_RESET_REG_SUP |
    ACPI_FADT_FLAG_SW_CPU_SLP
)
PCI_CONFIG_ECAM_BASE = 0x7FF0000000
PCI_MMIO_BASE = 0xC1000000
PCI_MMIO_SIZE = 0x10000000
FW_HIGH_RAM_BASE = 0x80200000
FW_HIGH_RAM_AFTER_PCI_BASE = PCI_MMIO_BASE + PCI_MMIO_SIZE
FW_FIRMWARE_ADDRESS_SPACE_BASE = 0xFF000000
FW_FIRMWARE_ADDRESS_SPACE_SIZE = 0x01000000
FW_RTC_BASE = 0xFFEF0000
FW_RTC_SIZE = 0x00002000
FW_NVRAM_BASE = 0xFFF00000
FW_NVRAM_SIZE = 0x00010000
FW_NVRAM_RTC_OFFSET = 0x0000F000
FW_RTC_STATE_MAGIC = 0x54464F3436545249
PCI_IO_SIZE = 0x1000000
PCI_IO_SPARSE_SIZE = 0x4000000
LEGACY_IO_BASE = 0x800010000000
PCI_IO_TRANSLATION_OFFSET = 0
PCI_INTX_GSI_BASE = 16
PCI_INTX_LINES = 4
IOSAPIC_BASE = 0x80110000
LOCAL_SAPIC_BASE = 0xFEE00000
LOCAL_SAPIC_SIZE = 0x00200000
IOSAPIC_RTE_DELIVERY_STATUS = 1 << 12
IOSAPIC_RTE_REMOTE_IRR = 1 << 14
IOSAPIC_RTE_TRIGGER_LEVEL = 1 << 15
IOSAPIC_RTE_MASKED = 1 << 16
UART_BASE = 0x47F0000000
DEBUG_UART_BASE = 0x47F0001000
UART_MMIO_SIZE = 0x2000
UART_BAUD = 115200
HCDP_UART_IRQ = 4
HCDP_UART_PRIMARY_CONSOLE = 1 << 2
HCDP_DEVICE_PRIMARY_CONSOLE = 1
HCDP_PCI_TRANSLATE_IOPORT = 1 << 1
HCDP_VGA_PCI_DEVICE = 5
VGA_VENDOR_ID = 0x1002
VGA_DEVICE_ID = 0x5046
EFI_RUNTIME_SERVICES_CODE = 5
EFI_ACPI_RECLAIM_MEMORY = 9
EFI_MEMORY_MAPPED_IO = 11
EFI_MEMORY_MAPPED_IO_PORT_SPACE = 12
EFI_RESERVED_MEMORY_TYPE = 0
EFI_BOOT_SERVICES_DATA = 4
EFI_CONVENTIONAL_MEMORY = 7
EFI_MEMORY_UC = 0x1
EFI_MEMORY_RUNTIME = 0x8000000000000000
EFI_MEMORY_WB = 0x8
SAL_REVISION = 0x0340
SAL_HANDOFF_PSR = (1 << 3) | (1 << 13) | (1 << 44)
SAL_DCR_LC = 1 << 2
SAL_IVT_BASE = 0x10000
SAL_PTA_DISABLED_VALUE = 15 << 2
SAL_TR_PAGE_SHIFT = 22
SAL_TR_ITIR = SAL_TR_PAGE_SHIFT << 2
SAL_RR_FIRST_RID = 0x1000
FW_BOOT_STACK_SIZE = 0x00400000
IA64_EFI_MIN_STACK_BYTES = 0x20000
IA64_EFI_MIN_BACKING_BYTES = 0x4000
SAL_BACKING_STORE_BASE = 0x80000
SAL_BACKING_STORE_END = 0xA0000
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
EFI_SMBIOS_TABLE_GUID = bytes.fromhex(
    "31 2d 9d eb 88 2d d3 11 9a 16 00 90 27 3f c1 4d"
)
EFI_DEBUG_IMAGE_INFO_TABLE_GUID = bytes.fromhex(
    "77 2e 15 49 da 1a 64 47 b7 a2 7a fe fe d9 5e 8b"
)
EFI_LOADED_IMAGE_PROTOCOL_GUID = bytes.fromhex(
    "a1 31 1b 5b 62 95 d2 11 8e 3f 00 a0 c9 69 72 3b"
)
EFI_DEVICE_PATH_PROTOCOL_GUID = bytes.fromhex(
    "91 6e 57 09 3f 6d d2 11 8e 39 00 a0 c9 69 72 3b"
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
            "-drive", f"file={disk},format=raw",
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


def qemu_physical_bytes(qemu, firmware, ranges, machine="ia64-vpc",
                        memory_mib=None, extra_args=None):
    commands = []
    for addr, size in ranges.values():
        commands.append(f"xp /{size}xb 0x{addr:x}")
    input_text = "\n".join(commands + ["quit", ""])

    args = [
        qemu,
        "-machine", machine,
        "-smp", "1",
    ]
    if memory_mib is not None:
        args += ["-m", f"{memory_mib}M"]
    args += [
        "-bios", firmware,
        "-display", "none",
        "-serial", "none",
        "-monitor", "stdio",
    ]
    if extra_args:
        args += extra_args

    proc = subprocess.Popen(
        args,
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


def qemu_monitor_output(qemu, firmware, command, delay=4.0):
    proc = subprocess.Popen(
        [
            qemu,
            "-machine", "ia64-vpc",
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
        time.sleep(delay)
        proc.stdin.write(command + "\nquit\n")
        proc.stdin.flush()
        output, _ = proc.communicate(timeout=8)
    except Exception:
        proc.kill()
        output, _ = proc.communicate()
        raise RuntimeError("qemu monitor command failed\n" + output)
    if proc.returncode != 0:
        raise RuntimeError("qemu monitor exited nonzero\n" + output)
    return output


def qemu_runtime_symbol_bytes(qemu, firmware, symbols, names, memory_mib=None):
    ranges = {}
    for name in names:
        if name not in symbols:
            raise RuntimeError(f"missing firmware symbol {name}")
        ranges[name] = symbols[name]
    return qemu_physical_bytes(qemu, firmware, ranges,
                               memory_mib=memory_mib)


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


def parse_fw_ram_ranges(data, count):
    return [(u64(data, index * 16), u64(data, index * 16 + 8))
            for index in range(count)]


def efi_descriptor_contains(desc, addr, size):
    start = desc["physical_start"]
    end = start + desc["pages"] * EFI_PAGE_SIZE
    return addr >= start and addr + size <= end


def efi_range_has_type(memory_map, memory_type, addr, size, required_attr=0):
    cursor = addr
    end = addr + size

    for desc in memory_map:
        desc_start = desc["physical_start"]
        desc_end = desc_start + desc["pages"] * EFI_PAGE_SIZE

        if desc_end <= cursor:
            continue
        if desc_start > cursor:
            return False
        if (desc["type"] != memory_type or
                (desc["attribute"] & required_attr) != required_attr):
            return False
        cursor = min(desc_end, end)
        if cursor == end:
            return True
    return False


def ia64_sparse_io_offset(port):
    return ((port & 0xfffc) << 10) | (port & 0xfff)


def ia64_sparse_io_port(encoded):
    group = encoded >> 12
    low = encoded & 0xfff

    if (group & 0x3ff) == (low >> 2):
        return (group << 2) | (low & 3)
    return encoded


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
    if length > len(data):
        raise RuntimeError(f"{name}: length field {length} > bytes read {len(data)}")
    if data[8] < min_revision:
        raise RuntimeError(f"{name}: revision {data[8]} < {min_revision}")
    if checksum8(data[:length]) != 0:
        raise RuntimeError(f"{name}: checksum is not zero")
    if data[36:length] == b"":
        raise RuntimeError(f"{name}: missing body")


def validate_dbgp(data):
    validate_sdt("mDbgp", data, "DBGP", 1)
    if u32(data, 4) != 52:
        raise RuntimeError("DBGP length mismatch")
    if data[36] != 0 or data[37:40] != b"\0\0\0":
        raise RuntimeError("DBGP interface type/reserved fields mismatch")
    if (data[40] != ACPI_GAS_SYSTEM_MEMORY or data[41] != 8 or
            data[42] != 0 or data[43] != 0 or
            gas_address(data, 40) != DEBUG_UART_BASE):
        raise RuntimeError("DBGP base address GAS mismatch")


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

    result = subprocess.run(
        [
            qemu,
            "-machine", "none",
            "-display", "none",
            "-monitor", "none",
            "-serial", "none",
            "-debug-port", "none",
            "-debug-port", "none",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=8,
    )
    if (result.returncode == 0 or
            "only one -debug-port option is supported" not in result.stdout):
        raise RuntimeError("-debug-port must reject multiple instances\n" +
                           result.stdout)

    try:
        result = subprocess.run(
            [
                qemu,
                "-machine", "none",
                "-nographic",
                "-debug-port", "stdio",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=1,
        )
    except subprocess.TimeoutExpired:
        result = None
    if result is not None:
        if ("cannot use stdio by multiple character devices" in
                result.stdout):
            raise RuntimeError("-debug-port stdio must own nographic stdio\n" +
                               result.stdout)
        if result.returncode != 0:
            raise RuntimeError("-debug-port stdio failed under -nographic\n" +
                               result.stdout)

    probe = socket.socket()
    try:
        probe.bind(("127.0.0.1", 0))
        tcp_port = probe.getsockname()[1]
    finally:
        probe.close()
    proc = subprocess.Popen(
        [
            qemu,
            "-machine", "none",
            "-display", "none",
            "-monitor", "none",
            "-serial", "none",
            "-debug-port", f"tcp::{tcp_port},server=on,wait=off",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    connected = False
    output = ""
    try:
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                output, _ = proc.communicate(timeout=1)
                break
            try:
                with socket.create_connection(("127.0.0.1", tcp_port),
                                              timeout=0.2):
                    connected = True
                    break
            except OSError:
                time.sleep(0.05)
        if not connected:
            if not output:
                proc.terminate()
                try:
                    output, _ = proc.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    output, _ = proc.communicate(timeout=2)
            raise RuntimeError("-debug-port tcp server did not accept\n" +
                               output)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)

    if LEGACY_IO_BASE & (PCI_IO_SPARSE_SIZE - 1):
        raise RuntimeError("legacy PCI I/O base must be aligned for sparse I/O")
    for port in [
            0x60, 0x1f0, 0x3f6, 0x800, 0x80a,
            ACPI_PM_IO_BASE, ACPI_PM_IO_BASE + 4, ACPI_PM_IO_BASE + 8,
            0xc000, 0xffff]:
        sparse = ia64_sparse_io_offset(port)
        if sparse >= PCI_IO_SPARSE_SIZE:
            raise RuntimeError(f"sparse I/O port 0x{port:x} exceeds aperture")
        if (LEGACY_IO_BASE | sparse) != LEGACY_IO_BASE + sparse:
            raise RuntimeError(f"sparse I/O port 0x{port:x} aliases base bits")
        if ia64_sparse_io_port(sparse) != port:
            raise RuntimeError(f"sparse I/O port 0x{port:x} does not decode")
    if ia64_sparse_io_port(ACPI_PM_IO_BASE + 4) != ACPI_PM_IO_BASE + 4:
        raise RuntimeError("runtime ACPI PM1 control address needs dense fallback")

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
                           "brl_call_mlx_decode",
                           "brl_call_mlx_no_stop_decode",
                           "brl_cond_mlx_no_stop_decode",
                           "br_call_indirect_completers_decode",
                           "br_ctop_rotating_pipeline"},
        "integer": {"alu_immediate_ops", "register_shifts", "deposit_immediate",
                    "extract_immediate", "dep_decode", "popcnt_decode",
                    "clz_decode", "mpyshl4_decode"},
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
                                  "future_itm_rearm_preserves_pended_timer_irr",
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
        "efi": 158,
        "sal": 28,
        "acpi": 29,
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
        "Memory Map Test:      descriptor and pool placement verified",
        "Console Out Test:     text output contracts verified",
        "Console In:           Serial/PS2/USB WaitForKey ready",
        "Console In Buffer:    WaitForKey preserves keystrokes",
        "USB Keyboard Test:    HID boot report decode verified",
        "UEFI Event Services:  contract checks verified",
        "Protocol Notify:      LocateProtocol registration verified",
        "Protocol Database:    NULL interface markers verified",
        "PCI Root Bridge Test: config/resources/polling verified",
        "PCI I/O Protocol:    controllers/polling verified",
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
        "SAL Loader Handoff:   registers/stack/TR verified",
        "SMBIOS Table:         published",
        "SMBIOS Table Checks:  entry point verified",
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
    rtc_before = int(time.time())
    rtc_output = qemu_monitor_output(
        qemu, firmware, f"xp /1gx 0x{FW_RTC_BASE:x}", delay=1.0
    )
    rtc_after = int(time.time())
    rtc_match = re.search(
        rf"\b{FW_RTC_BASE:x}:\s+0x([0-9a-fA-F]{{16}})", rtc_output
    )
    if rtc_match is None:
        raise RuntimeError(
            "could not read IA-64 host-backed RTC\n" + rtc_output
        )
    rtc_seconds = int(rtc_match.group(1), 16)
    if not rtc_before - 2 <= rtc_seconds <= rtc_after + 2:
        raise RuntimeError(
            f"IA-64 RTC is not tracking host time: rtc={rtc_seconds} "
            f"host={rtc_before}..{rtc_after}"
        )

    nvram_image = bytearray(FW_NVRAM_SIZE)
    struct.pack_into(
        "<QIIqIhBB", nvram_image, FW_NVRAM_RTC_OFFSET,
        FW_RTC_STATE_MAGIC, 1, 0, 86400, 0, 0, 0, 0,
    )
    with tempfile.NamedTemporaryFile() as nvram:
        nvram.write(nvram_image)
        nvram.flush()
        offset_before = int(time.time())
        persisted = qemu_physical_bytes(
            qemu, firmware,
            {"mWakeupTime": symbols["mWakeupTime"]},
            machine=f"ia64-vpc,nvram={nvram.name}",
        )["mWakeupTime"]
        offset_after = int(time.time())
    persisted_epoch = calendar.timegm((
        u16(persisted, 0), persisted[2], persisted[3], persisted[4],
        persisted[5], persisted[6], 0, 0, 0,
    ))
    if not offset_before + 86400 - 2 <= persisted_epoch <= \
            offset_after + 86400 + 2:
        raise RuntimeError(
            "EFI GetTime did not apply the persistent RTC offset: "
            f"guest={persisted_epoch} host={offset_before}..{offset_after}"
        )
    runtime_names = [
        "mSystemTable", "mConfigTables", "mSalSystemTable",
        "mSalHandoffProbe",
        "mDebugImageInfoHeader",
        "mSmbiosEntryPoint", "mSmbiosTable", "mSmbiosTableLength",
        "mSmbiosStructureCount", "mSmbiosMaxStructureSize",
        "mMemoryMapEntries", "mMemoryMap",
        "mBootStackBase", "mBootStackTop", "mGuestRamSize",
        "mGuestLowRamEnd", "mGuestHighRam", "mGuestHighRamCount",
        "mAcpiSrat", "mRuntimeRtc", "mRuntimeRtcState",
    ]
    runtime = qemu_runtime_symbol_bytes(qemu, firmware, symbols, runtime_names)
    memory_map = parse_efi_memory_map(
        runtime["mMemoryMap"], u64(runtime["mMemoryMapEntries"], 0)
    )
    guest_ram_size = u64(runtime["mGuestRamSize"], 0)
    guest_low_ram_end = u64(runtime["mGuestLowRamEnd"], 0)
    guest_high_ranges = parse_fw_ram_ranges(
        runtime["mGuestHighRam"], u64(runtime["mGuestHighRamCount"], 0)
    )
    boot_stack_base = u64(runtime["mBootStackBase"], 0)
    boot_stack_top = u64(runtime["mBootStackTop"], 0)
    if u64(runtime["mRuntimeRtc"], 0) != FW_RTC_BASE:
        raise RuntimeError("EFI runtime RTC pointer mismatch")
    if not (FW_NVRAM_BASE <= u64(runtime["mRuntimeRtcState"], 0) <
            FW_NVRAM_BASE + FW_NVRAM_SIZE):
        raise RuntimeError("EFI persistent RTC state pointer mismatch")
    if (guest_ram_size != 0x80000000 or guest_high_ranges or
            boot_stack_top != guest_low_ram_end or
            boot_stack_top - boot_stack_base != FW_BOOT_STACK_SIZE):
        raise RuntimeError("default-RAM EFI boot stack placement mismatch")
    if any(
            memory_map[index - 1]["physical_start"] >
            memory_map[index]["physical_start"]
            for index in range(1, len(memory_map))):
        raise RuntimeError("EFI memory map is not sorted by physical address")

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
    if config.get(EFI_SMBIOS_TABLE_GUID) != symbols["mSmbiosEntryPoint"][0]:
        raise RuntimeError("EFI configuration table does not reference SMBIOS")
    if (config.get(EFI_DEBUG_IMAGE_INFO_TABLE_GUID) !=
            symbols["mDebugImageInfoHeader"][0]):
        raise RuntimeError("EFI configuration table does not reference debug image info")
    for guid_name, guid in (
            ("Loaded Image Protocol", EFI_LOADED_IMAGE_PROTOCOL_GUID),
            ("Device Path Protocol", EFI_DEVICE_PATH_PROTOCOL_GUID)):
        if guid in config:
            raise RuntimeError(f"{guid_name} GUID must not be an EFI configuration table")

    def find_efi_descriptor_in(target_map, name, memory_type, addr, size,
                               required_attr=0):
        for desc in target_map:
            if (desc["type"] == memory_type and
                    (desc["attribute"] & required_attr) == required_attr and
                    efi_descriptor_contains(desc, addr, size)):
                return desc
        raise RuntimeError(f"{name} is not covered by the expected EFI memory type")

    def find_efi_descriptor(name, memory_type, addr, size,
                            required_attr=0):
        return find_efi_descriptor_in(memory_map, name, memory_type, addr,
                                      size, required_attr)

    runtime_image_attr = EFI_MEMORY_WB | EFI_MEMORY_RUNTIME
    find_efi_descriptor(
        "EFI system table", EFI_RUNTIME_SERVICES_CODE,
        symbols["mSystemTable"][0], symbols["mSystemTable"][1],
        runtime_image_attr,
    )
    find_efi_descriptor(
        "EFI configuration table", EFI_RUNTIME_SERVICES_CODE,
        symbols["mConfigTables"][0], symbols["mConfigTables"][1],
        runtime_image_attr,
    )
    find_efi_descriptor(
        "SMBIOS entry point", EFI_RUNTIME_SERVICES_CODE,
        symbols["mSmbiosEntryPoint"][0], symbols["mSmbiosEntryPoint"][1],
        runtime_image_attr,
    )
    find_efi_descriptor(
        "SMBIOS structure table", EFI_RUNTIME_SERVICES_CODE,
        symbols["mSmbiosTable"][0], symbols["mSmbiosTable"][1],
        runtime_image_attr,
    )
    find_efi_descriptor(
        "PCI MMIO window", EFI_MEMORY_MAPPED_IO,
        PCI_MMIO_BASE, PCI_MMIO_SIZE, EFI_MEMORY_UC,
    )
    find_efi_descriptor(
        "platform UART MMIO", EFI_MEMORY_MAPPED_IO,
        UART_BASE, UART_MMIO_SIZE, EFI_MEMORY_UC,
    )
    find_efi_descriptor(
        "PAL/SAL firmware address space below RTC", EFI_MEMORY_MAPPED_IO,
        FW_FIRMWARE_ADDRESS_SPACE_BASE,
        FW_RTC_BASE - FW_FIRMWARE_ADDRESS_SPACE_BASE,
        EFI_MEMORY_UC,
    )
    find_efi_descriptor(
        "runtime RTC", EFI_MEMORY_MAPPED_IO,
        FW_RTC_BASE, FW_RTC_SIZE,
        EFI_MEMORY_UC | EFI_MEMORY_RUNTIME,
    )
    find_efi_descriptor(
        "PAL/SAL firmware address space between RTC and NVRAM",
        EFI_MEMORY_MAPPED_IO, FW_RTC_BASE + FW_RTC_SIZE,
        FW_NVRAM_BASE - (FW_RTC_BASE + FW_RTC_SIZE), EFI_MEMORY_UC,
    )
    find_efi_descriptor(
        "runtime NVRAM", EFI_MEMORY_MAPPED_IO,
        FW_NVRAM_BASE, FW_NVRAM_SIZE,
        EFI_MEMORY_UC | EFI_MEMORY_RUNTIME,
    )
    find_efi_descriptor(
        "PAL/SAL firmware address space above NVRAM", EFI_MEMORY_MAPPED_IO,
        FW_NVRAM_BASE + FW_NVRAM_SIZE,
        FW_FIRMWARE_ADDRESS_SPACE_BASE + FW_FIRMWARE_ADDRESS_SPACE_SIZE -
        (FW_NVRAM_BASE + FW_NVRAM_SIZE),
        EFI_MEMORY_UC,
    )
    io_port_descs = [
        desc for desc in memory_map
        if desc["type"] == EFI_MEMORY_MAPPED_IO_PORT_SPACE
    ]
    if len(io_port_descs) != 1:
        raise RuntimeError("IA-64 EFI memory map must expose one I/O port space")
    io_port_desc = io_port_descs[0]
    if (io_port_desc["physical_start"] != LEGACY_IO_BASE or
            io_port_desc["pages"] * EFI_PAGE_SIZE != PCI_IO_SPARSE_SIZE or
            (io_port_desc["attribute"] &
             (EFI_MEMORY_UC | EFI_MEMORY_RUNTIME)) !=
             (EFI_MEMORY_UC | EFI_MEMORY_RUNTIME)):
        raise RuntimeError("PCI sparse I/O port window descriptor mismatch")
    acpi_pm_cpu_address = LEGACY_IO_BASE + ACPI_PM_IO_BASE
    io_port_end = (io_port_desc["physical_start"] +
                   io_port_desc["pages"] * EFI_PAGE_SIZE)
    if not (io_port_desc["physical_start"] <= acpi_pm_cpu_address and
            acpi_pm_cpu_address + 12 <= io_port_end):
        raise RuntimeError("ACPI PM ports are outside the EFI I/O port window")
    find_efi_descriptor(
        "runtime SAL PCI configuration window", EFI_MEMORY_MAPPED_IO,
        PCI_CONFIG_ECAM_BASE, 0x10000000,
        EFI_MEMORY_UC | EFI_MEMORY_RUNTIME,
    )
    find_efi_descriptor(
        "EFI boot stack", EFI_BOOT_SERVICES_DATA,
        boot_stack_base,
        boot_stack_top - boot_stack_base,
        EFI_MEMORY_WB,
    )

    smbios_ep = runtime["mSmbiosEntryPoint"]
    if (len(smbios_ep) != 31 or smbios_ep[:4] != b"_SM_" or
            smbios_ep[5] != 0x1f or smbios_ep[6] != 2 or
            smbios_ep[7] != 7 or smbios_ep[0x10:0x15] != b"_DMI_" or
            smbios_ep[0x1e] != 0x27):
        raise RuntimeError("SMBIOS 2.7 entry point signature/version mismatch")
    if checksum8(smbios_ep[:smbios_ep[5]]) != 0:
        raise RuntimeError("SMBIOS entry point checksum mismatch")
    if checksum8(smbios_ep[0x10:0x1f]) != 0:
        raise RuntimeError("SMBIOS intermediate checksum mismatch")
    smbios_table_len = u16(smbios_ep, 0x16)
    smbios_table_addr = u32(smbios_ep, 0x18)
    smbios_struct_count = u16(smbios_ep, 0x1c)
    smbios_max_struct_size = u16(smbios_ep, 0x08)
    if smbios_table_addr != symbols["mSmbiosTable"][0]:
        raise RuntimeError("SMBIOS entry point table address mismatch")
    if smbios_table_len != u16(runtime["mSmbiosTableLength"], 0):
        raise RuntimeError("SMBIOS entry point table length mismatch")
    if smbios_struct_count != u16(runtime["mSmbiosStructureCount"], 0):
        raise RuntimeError("SMBIOS entry point structure count mismatch")
    if smbios_max_struct_size != u16(runtime["mSmbiosMaxStructureSize"], 0):
        raise RuntimeError("SMBIOS entry point maximum structure size mismatch")

    def smbios_structures(table):
        off = 0
        structures = []
        while off < len(table):
            if off + 4 > len(table):
                raise RuntimeError("SMBIOS truncated structure header")
            formatted_len = table[off + 1]
            if formatted_len < 4 or off + formatted_len > len(table):
                raise RuntimeError("SMBIOS invalid formatted structure length")
            end = off + formatted_len
            while end + 1 < len(table):
                if table[end] == 0 and table[end + 1] == 0:
                    end += 2
                    break
                end += 1
            else:
                raise RuntimeError("SMBIOS structure missing double-NUL terminator")
            structures.append(table[off:end])
            if table[off] == 127 and end != len(table):
                raise RuntimeError("SMBIOS end-of-table is not the last structure")
            off = end
        return structures

    def smbios_strings(structure):
        text = structure[structure[1]:-2]
        if not text:
            return []
        return text.split(b"\0")

    smbios_table = runtime["mSmbiosTable"][:smbios_table_len]
    smbios = smbios_structures(smbios_table)
    if len(smbios) != smbios_struct_count:
        raise RuntimeError("SMBIOS parsed structure count mismatch")
    if max(len(entry) for entry in smbios) != smbios_max_struct_size:
        raise RuntimeError("SMBIOS parsed maximum structure size mismatch")
    smbios_by_type = {}
    for entry in smbios:
        smbios_by_type.setdefault(entry[0], []).append(entry)
    required_smbios_types = {0, 1, 2, 3, 4, 16, 17, 19, 32, 127}
    if set(smbios_by_type) != required_smbios_types:
        raise RuntimeError("SMBIOS required type set mismatch")
    for single_type in required_smbios_types - {19}:
        if len(smbios_by_type[single_type]) != 1:
            raise RuntimeError(f"SMBIOS Type {single_type} count mismatch")

    def smbios_type19_range(entry):
        if (entry[1] != 0x1f or u16(entry, 0x0c) != 0x1000 or
                entry[0x0e] != 1):
            raise RuntimeError("SMBIOS Type 19 memory array mapping mismatch")
        if u32(entry, 4) != 0xffffffff or u32(entry, 8) != 0xffffffff:
            return (u32(entry, 4) * 1024, (u32(entry, 8) + 1) * 1024)
        return (u64(entry, 0x0f), u64(entry, 0x17) + 1)

    t0 = smbios_by_type[0][0]
    if (t0[1] != 0x18 or t0[4] != 1 or t0[5] != 2 or
            t0[8] != 3 or u64(t0, 0x0a) != 0x08 or t0[0x13] != 0x18):
        raise RuntimeError("SMBIOS Type 0 BIOS information mismatch")
    if smbios_strings(t0) != [b"QEMU", b"ia64-firmware", b"01/01/2026"]:
        raise RuntimeError("SMBIOS Type 0 string set mismatch")

    t1 = smbios_by_type[1][0]
    if t1[1] != 0x1b or t1[0x18] != 0x06:
        raise RuntimeError("SMBIOS Type 1 system information mismatch")
    if smbios_strings(t1)[:2] != [b"QEMU", b"IA-64 Virtual Platform"]:
        raise RuntimeError("SMBIOS Type 1 identity strings mismatch")

    t4 = smbios_by_type[4][0]
    if (t4[1] != 0x2a or t4[5] != 0x03 or t4[6] != 0x82 or
            t4[0x18] != 0x41 or u16(t4, 0x28) != 0x0082 or
            u16(t4, 0x26) != 0x0004):
        raise RuntimeError("SMBIOS Type 4 IA-64 processor fields mismatch")

    t16 = smbios_by_type[16][0]
    if (t16[1] != 0x17 or t16[4] != 0x03 or t16[5] != 0x03 or
            t16[6] != 0x03 or u16(t16, 0x0b) != 0xfffe or
            u16(t16, 0x0d) != 1 or
            u32(t16, 7) != guest_ram_size // 1024):
        raise RuntimeError("SMBIOS Type 16 physical memory array mismatch")

    t17 = smbios_by_type[17][0]
    if (t17[1] != 0x22 or u16(t17, 4) != 0x1000 or
            u16(t17, 6) != 0xfffe or u16(t17, 8) != 64 or
            u16(t17, 0x0a) != 64 or t17[0x0e] != 0x09 or
            t17[0x12] != 0x07 or u16(t17, 0x13) != 0x0002):
        raise RuntimeError("SMBIOS Type 17 memory device mismatch")
    guest_ram_mb = (guest_ram_size + 0xfffff) >> 20
    if guest_ram_mb < 0x7fff:
        if u16(t17, 0x0c) != guest_ram_mb or u32(t17, 0x1c) != 0:
            raise RuntimeError("SMBIOS Type 17 memory device size mismatch")
    elif u16(t17, 0x0c) != 0x7fff or u32(t17, 0x1c) != guest_ram_mb:
        raise RuntimeError("SMBIOS Type 17 memory device size mismatch")

    t19_ranges = [smbios_type19_range(entry)
                  for entry in smbios_by_type[19]]
    expected_t19_ranges = [(0, guest_low_ram_end)] + guest_high_ranges
    if t19_ranges != expected_t19_ranges:
        raise RuntimeError("SMBIOS Type 19 memory array ranges mismatch")

    t32 = smbios_by_type[32][0]
    if t32[1] != 0x0b or t32[4:10] != b"\0" * 6 or t32[0x0a] != 0:
        raise RuntimeError("SMBIOS Type 32 boot status mismatch")
    if smbios_by_type[127][0][1] != 4:
        raise RuntimeError("SMBIOS Type 127 end-of-table mismatch")

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
    if "mDbgp" in table_addrs:
        raise RuntimeError("DBGP must not be present without -debug-port")

    debug_rsdp = qemu_physical_bytes(
        qemu, firmware,
        {"RSDP": (ACPI_RECLAIM_BASE, symbols["mRsdp"][1])},
        extra_args=["-debug-port", "null"],
    )["RSDP"]
    debug_rsdt_addr = u32(debug_rsdp, 16)
    debug_xsdt_addr = u64(debug_rsdp, 24)
    debug_roots = qemu_physical_bytes(
        qemu, firmware,
        {
            "mXsdt": (debug_xsdt_addr, symbols["mXsdt"][1]),
            "mRsdt": (debug_rsdt_addr, symbols["mRsdt"][1]),
        },
        extra_args=["-debug-port", "null"],
    )
    debug_xsdt = debug_roots["mXsdt"]
    debug_rsdt = debug_roots["mRsdt"]
    validate_sdt("debug-port mXsdt", debug_xsdt, "XSDT", 1)
    validate_sdt("debug-port mRsdt", debug_rsdt, "RSDT", 1)
    debug_xsdt_entries = [
        u64(debug_xsdt, off) for off in range(36, u32(debug_xsdt, 4), 8)
    ]
    debug_rsdt_entries = [
        u32(debug_rsdt, off) for off in range(36, u32(debug_rsdt, 4), 4)
    ]
    if (len(debug_xsdt_entries) != len(expected_xsdt_symbols) + 1 or
            debug_rsdt_entries !=
            [addr & 0xffffffff for addr in debug_xsdt_entries]):
        raise RuntimeError("debug-port RSDT/XSDT entry set mismatch")
    debug_dbgp_addr = debug_xsdt_entries[-1]
    debug_dbgp = qemu_physical_bytes(
        qemu, firmware,
        {"mDbgp": (debug_dbgp_addr, symbols["mDbgp"][1])},
        extra_args=["-debug-port", "null"],
    )["mDbgp"]
    require_acpi_reclaim("DBGP", debug_dbgp_addr, symbols["mDbgp"][1])
    validate_dbgp(debug_dbgp)

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
    for off in (56, 60, 64, 68, 72, 76, 80, 84):
        if u32(fadt, off) != 0:
            raise RuntimeError("FADT legacy fixed register fields must be zero")
    expected_pm_gas = [
        (148, 32, ACPI_PM_IO_BASE, "X_PM1a_EVT_BLK"),
        (172, 16, ACPI_PM_IO_BASE + 4, "X_PM1a_CNT_BLK"),
        (208, 32, ACPI_PM_IO_BASE + 8, "X_PM_TMR_BLK"),
    ]
    for off, width, address, label in expected_pm_gas:
        if (fadt[off] != ACPI_GAS_SYSTEM_IO or fadt[off + 1] != width or
                fadt[off + 2] != 0 or fadt[off + 3] != 0 or
                gas_address(fadt, off) != address):
            raise RuntimeError(f"FADT {label} System I/O GAS mismatch")
    if (fadt[116] != ACPI_GAS_SYSTEM_IO or fadt[117] != 8 or
            fadt[118] != 0 or fadt[119] != 0 or
            gas_address(fadt, 116) != ACPI_PM_IO_BASE + ACPI_PM_RESET_OFFSET or
            fadt[128] != ACPI_PM_RESET_VALUE):
        raise RuntimeError("FADT reset register System I/O GAS mismatch")

    fadt_children = qemu_physical_bytes(qemu, firmware, {
        "mFacs": (facs_addr, symbols["mFacs"][1]),
        "mDsdt": (dsdt_addr, symbols["mDsdt"][1]),
    })
    dsdt = fadt_children["mDsdt"]
    validate_sdt("mDsdt", dsdt, "DSDT", 2)
    for token in [b"_S5_", b"PCI0", b"PNP0A08", b"PNP0A03", b"_CRS", b"_PRT"]:
        if token not in dsdt:
            raise RuntimeError(f"DSDT PCI namespace missing {token!r}")
    s5_name_off = dsdt.index(b"_S5_")
    if s5_name_off == 0 or dsdt[s5_name_off - 1] != 0x08:
        raise RuntimeError("DSDT _S5 must be a NameOp")
    s5_count, s5_off, s5_end = aml_package(dsdt, s5_name_off + 4)
    s5_values = []
    while s5_off < s5_end:
        value, s5_off = aml_integer(dsdt, s5_off)
        s5_values.append(value)
    if s5_count != 4 or s5_values != [0, 0, 0, 0] or s5_off != s5_end:
        raise RuntimeError("DSDT _S5 package mismatch")
    expected_prt = []
    for slot in range(6):
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
    for token in [b"UAR0", b"PNP0501", b"P2EN", b"_STA", b"_CRS"]:
        if token not in ssdt:
            raise RuntimeError(f"SSDT UART namespace missing {token!r}")
    ps2_enabled_off = ssdt.index(b"P2EN") + len(b"P2EN")
    if (ssdt[ps2_enabled_off:ps2_enabled_off + 2] != b"\x0a\x0f" or
            ssdt.count(b"_STA") != 2):
        raise RuntimeError("SSDT enabled PS/2 status policy mismatch")

    disabled_ssdt = qemu_physical_bytes(
        qemu,
        firmware,
        {"mSsdt": (table_addrs["mSsdt"], symbols["mSsdt"][1])},
        machine="ia64-vpc,i8042=off",
    )["mSsdt"]
    validate_sdt("mSsdt (i8042=off)", disabled_ssdt, "SSDT", 2)
    disabled_ps2_enabled_off = disabled_ssdt.index(b"P2EN") + len(b"P2EN")
    if (disabled_ssdt[
            disabled_ps2_enabled_off:disabled_ps2_enabled_off + 2
            ] != b"\x0a\x00" or disabled_ssdt.count(b"_STA") != 2):
        raise RuntimeError("SSDT disabled PS/2 status policy mismatch")
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
    srat_memory_entries = []
    for index in range(4):
        off = 48 + index * 40
        if srat[off] != 1 or srat[off + 1] != 40:
            raise RuntimeError("SRAT memory affinity entry mismatch")
        base = u32(srat, off + 8) | (u32(srat, off + 12) << 32)
        length = u32(srat, off + 16) | (u32(srat, off + 20) << 32)
        flags = u32(srat, off + 28)
        srat_memory_entries.append((base, base + length, flags))
    expected_srat_ranges = [(0, guest_low_ram_end)] + guest_high_ranges
    for index, entry in enumerate(srat_memory_entries):
        if index < len(expected_srat_ranges):
            if entry != (*expected_srat_ranges[index], 1):
                raise RuntimeError("SRAT memory affinity range mismatch")
        elif entry != (0, 0, 0):
            raise RuntimeError("SRAT disabled memory affinity mismatch")
    processor_off = 48 + 4 * 40
    if (srat[processor_off] != 0 or srat[processor_off + 1] != 16 or
            u32(srat, processor_off + 4) != 1):
        raise RuntimeError("SRAT processor affinity entry mismatch")

    high_runtime = qemu_runtime_symbol_bytes(
        qemu, firmware, symbols, runtime_names, memory_mib=4096
    )
    high_memory_map = parse_efi_memory_map(
        high_runtime["mMemoryMap"],
        u64(high_runtime["mMemoryMapEntries"], 0),
    )
    high_guest_ram_size = u64(high_runtime["mGuestRamSize"], 0)
    high_low_ram_end = u64(high_runtime["mGuestLowRamEnd"], 0)
    high_guest_ranges = parse_fw_ram_ranges(
        high_runtime["mGuestHighRam"],
        u64(high_runtime["mGuestHighRamCount"], 0),
    )
    expected_high_ranges = [
        (FW_HIGH_RAM_BASE, PCI_MMIO_BASE),
        (FW_HIGH_RAM_AFTER_PCI_BASE, LOCAL_SAPIC_BASE),
        (FW_FIRMWARE_ADDRESS_SPACE_BASE + FW_FIRMWARE_ADDRESS_SPACE_SIZE,
         0x111400000),
    ]
    if (high_guest_ram_size != 0x100000000 or
            high_low_ram_end != 0x80000000 or
            high_guest_ranges != expected_high_ranges):
        raise RuntimeError("4 GiB guest RAM range split mismatch")
    if (high_low_ram_end + sum(end - start for start, end in
                              high_guest_ranges) != high_guest_ram_size):
        raise RuntimeError("4 GiB EFI RAM ranges lose installed memory")
    for start, end in expected_high_ranges:
        find_efi_descriptor_in(
            high_memory_map, "4 GiB high conventional memory",
            EFI_CONVENTIONAL_MEMORY, start, end - start, EFI_MEMORY_WB,
        )
    find_efi_descriptor_in(
        high_memory_map, "4 GiB PCI MMIO window",
        EFI_MEMORY_MAPPED_IO, PCI_MMIO_BASE, PCI_MMIO_SIZE, EFI_MEMORY_UC,
    )
    find_efi_descriptor_in(
        high_memory_map, "4 GiB local SAPIC window",
        EFI_MEMORY_MAPPED_IO, LOCAL_SAPIC_BASE, LOCAL_SAPIC_SIZE,
        EFI_MEMORY_UC,
    )
    find_efi_descriptor_in(
        high_memory_map, "4 GiB PAL/SAL firmware space below RTC",
        EFI_MEMORY_MAPPED_IO,
        FW_FIRMWARE_ADDRESS_SPACE_BASE,
        FW_RTC_BASE - FW_FIRMWARE_ADDRESS_SPACE_BASE,
        EFI_MEMORY_UC,
    )
    find_efi_descriptor_in(
        high_memory_map, "4 GiB runtime RTC", EFI_MEMORY_MAPPED_IO,
        FW_RTC_BASE, FW_RTC_SIZE, EFI_MEMORY_UC | EFI_MEMORY_RUNTIME,
    )
    find_efi_descriptor_in(
        high_memory_map, "4 GiB firmware space between RTC and NVRAM",
        EFI_MEMORY_MAPPED_IO, FW_RTC_BASE + FW_RTC_SIZE,
        FW_NVRAM_BASE - (FW_RTC_BASE + FW_RTC_SIZE), EFI_MEMORY_UC,
    )
    find_efi_descriptor_in(
        high_memory_map, "4 GiB runtime NVRAM", EFI_MEMORY_MAPPED_IO,
        FW_NVRAM_BASE, FW_NVRAM_SIZE,
        EFI_MEMORY_UC | EFI_MEMORY_RUNTIME,
    )
    find_efi_descriptor_in(
        high_memory_map, "4 GiB PAL/SAL firmware space above NVRAM",
        EFI_MEMORY_MAPPED_IO,
        FW_NVRAM_BASE + FW_NVRAM_SIZE,
        FW_FIRMWARE_ADDRESS_SPACE_BASE + FW_FIRMWARE_ADDRESS_SPACE_SIZE -
        (FW_NVRAM_BASE + FW_NVRAM_SIZE),
        EFI_MEMORY_UC,
    )

    high_srat_addr = u64(high_runtime["mAcpiSrat"], 0)
    high_srat = qemu_physical_bytes(
        qemu, firmware,
        {"mSrat": (high_srat_addr, symbols["mSrat"][1])},
        memory_mib=4096,
    )["mSrat"]
    validate_sdt("4 GiB mSrat", high_srat, "SRAT", 1)
    for index, (start, end) in enumerate(
            [(0, high_low_ram_end)] + expected_high_ranges):
        off = 48 + index * 40
        if (high_srat[off] != 1 or high_srat[off + 1] != 40 or
                (u32(high_srat, off + 8) |
                 (u32(high_srat, off + 12) << 32)) != start or
                (u32(high_srat, off + 16) |
                 (u32(high_srat, off + 20) << 32)) != end - start or
                u32(high_srat, off + 28) != 1):
            raise RuntimeError("4 GiB SRAT memory affinity range mismatch")

    high_smbios_ep = high_runtime["mSmbiosEntryPoint"]
    high_smbios_len = u16(high_smbios_ep, 0x16)
    high_smbios_count = u16(high_smbios_ep, 0x1c)
    high_smbios = smbios_structures(
        high_runtime["mSmbiosTable"][:high_smbios_len]
    )
    if len(high_smbios) != high_smbios_count:
        raise RuntimeError("4 GiB SMBIOS structure count mismatch")
    high_smbios_by_type = {}
    for entry in high_smbios:
        high_smbios_by_type.setdefault(entry[0], []).append(entry)
    high_type19_ranges = [
        smbios_type19_range(entry)
        for entry in high_smbios_by_type.get(19, [])
    ]
    if high_type19_ranges != [(0, high_low_ram_end)] + expected_high_ranges:
        raise RuntimeError("4 GiB SMBIOS Type 19 ranges mismatch")
    high_t16 = high_smbios_by_type.get(16, [b""])[0]
    high_t17 = high_smbios_by_type.get(17, [b""])[0]
    if (len(high_t16) < 0x17 or u32(high_t16, 7) !=
            high_guest_ram_size // 1024):
        raise RuntimeError("4 GiB SMBIOS Type 16 capacity mismatch")
    if (len(high_t17) < 0x22 or u16(high_t17, 0x0c) !=
            high_guest_ram_size >> 20 or u32(high_t17, 0x1c) != 0):
        raise RuntimeError("4 GiB SMBIOS Type 17 size mismatch")

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
    if (hcdp[98] != 0 or hcdp[99] != 0 or
            hcdp[100] != HCDP_VGA_PCI_DEVICE or hcdp[101] != 0):
        raise RuntimeError("HCDP VGA PCI location mismatch")
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
    if u16(sal, 8) != SAL_REVISION or u16(sal, 10) != 3:
        raise RuntimeError("SAL revision or descriptor count mismatch")
    if sal[24:28] != b"QEMU" or sal[56:61] != b"IA-64":
        raise RuntimeError("SAL OEM/product identifiers mismatch")
    if sal[96] != 0 or sal[144] != 2 or sal[160] != 3:
        raise RuntimeError("SAL descriptor type sequence mismatch")
    if (sal[161] != 0 or sal[162] != 0 or sal[163:168] != b"\0" * 5 or
            u64(sal, 168) != 0 or u64(sal, 176) != SAL_TR_ITIR or
            u64(sal, 184) != 0):
        raise RuntimeError("SAL ITR0 descriptor mismatch")

    probe = runtime["mSalHandoffProbe"]
    sp = u64(probe, 40)
    if (u64(probe, 0) != SAL_HANDOFF_PSR or
            u64(probe, 8) != 0 or
            u64(probe, 16) != SAL_DCR_LC or
            u64(probe, 24) != SAL_IVT_BASE or
            u64(probe, 32) != SAL_PTA_DISABLED_VALUE or
            sp < boot_stack_base + IA64_EFI_MIN_STACK_BYTES or
            sp >= boot_stack_top):
        raise RuntimeError("SAL loader PSR/RSC/CR/stack handoff mismatch")
    bsp = u64(probe, 48)
    bspstore = u64(probe, 56)
    if (bsp < SAL_BACKING_STORE_BASE or
            bsp + IA64_EFI_MIN_BACKING_BYTES > SAL_BACKING_STORE_END or
            bspstore < SAL_BACKING_STORE_BASE or bspstore > bsp):
        raise RuntimeError("SAL loader backing store handoff mismatch")
    find_efi_descriptor(
        "SAL backing store", EFI_RESERVED_MEMORY_TYPE,
        bsp, IA64_EFI_MIN_BACKING_BYTES, EFI_MEMORY_WB,
    )
    for index in range(8):
        expected_rr = ((SAL_RR_FIRST_RID + index) << 8) | (12 << 2)
        if u64(probe, 64 + index * 8) != expected_rr:
            raise RuntimeError(f"SAL loader RR{index} handoff mismatch")
    if any(u64(probe, 128 + index * 8) != 0 for index in range(16)):
        raise RuntimeError("SAL loader PKR handoff mismatch")

    sparse_pm_timer = LEGACY_IO_BASE + ia64_sparse_io_offset(
        ACPI_PM_IO_BASE + 8
    )
    registers = qemu_monitor_output(
        qemu, firmware,
        f"xp /1wx 0x{sparse_pm_timer:x}\n"
        f"xp /1wx 0x{sparse_pm_timer:x}\n"
        "info registers",
    )
    pm_timer_values = [
        int(value, 16) for value in re.findall(
            rf"(?m)^{sparse_pm_timer:x}: 0x([0-9a-f]+)$", registers
        )
    ]
    if len(pm_timer_values) != 2:
        raise RuntimeError(
            f"ACPI PM timer reads missing at CPU address 0x{sparse_pm_timer:x}"
        )
    if any(value > 0xffffff for value in pm_timer_values):
        raise RuntimeError("ACPI PM timer must return a 24-bit counter")
    if ((pm_timer_values[1] - pm_timer_values[0]) & 0xffffff) >= 0x100000:
        raise RuntimeError("ACPI PM timer did not advance monotonically")

    tr_lines = [line for line in registers.splitlines() if " TR " in line]
    expected_itr0 = (
        "ITLB[0] TR va=0x0000000000000000 pa=0x0000000000000000 "
        "ps=0x0000000000400000 rid=0x001000 key=0x000000 "
        "ar=3 pl=0 perm=0x7 pte=0x0000000000000661"
    )
    if tr_lines != [expected_itr0]:
        raise RuntimeError("SAL loader must expose only the specified ITR0\n" +
                           "\n".join(tr_lines))
    for token in [
            "CR.DCR: 0x0000000000000004",
            "IVA: 0x0000000000010000",
            "PTA: 0x000000000000003c",
            "RR0: 0x0000000000100030",
            "RR5: 0x0000000000100530",
            "RR6: 0x0000000000100630",
            "RR7: 0x0000000000100730",
            "ITIR: 0x0000000000000058"]:
        if token not in registers:
            raise RuntimeError(f"SAL loader runtime state missing: {token}")

    if not efi_range_has_type(
            memory_map, EFI_BOOT_SERVICES_DATA,
            boot_stack_base, FW_BOOT_STACK_SIZE, EFI_MEMORY_WB):
        raise RuntimeError("2 GiB EFI boot stack descriptor mismatch")
    if not efi_range_has_type(
            memory_map, EFI_CONVENTIONAL_MEMORY,
            0x04000000, 0x04000000, EFI_MEMORY_WB):
        raise RuntimeError(
            "64-128 MiB loader image window is not conventional memory"
        )


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
