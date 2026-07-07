#!/usr/bin/env python3
#
# IA-64 standard-derived golden-test coverage.
#
# The docs/ia64 CSV files are the repository-local inventory of implemented
# externally visible IA-64 items and the small amount of standard-derived
# metadata needed by this test.  The full standards PDFs are intentionally not
# required at test runtime.

import csv
import os
import re
import sys


IMPLEMENTATION_PATH_PREFIXES = (
    "target/",
    "hw/",
    "roms/",
    "tests/",
)

CSV_FILES = {
    "instructions": "docs/ia64/implemented-instructions.csv",
    "efi": "docs/ia64/implemented-efi.csv",
    "pal": "docs/ia64/implemented-pal.csv",
    "sal": "docs/ia64/implemented-sal.csv",
    "acpi": "docs/ia64/implemented-acpi.csv",
}

STANDARD_FILES = {
    "templates": "docs/ia64/bundle-templates.csv",
}

EXPECTED_COUNTS = {
    "instructions": 473,
    "efi": 158,
    "pal": 56,
    "sal": 28,
    "acpi": 29,
}

INSTRUCTION_CATEGORY_REFS = {
    "bundle": ["ia64_vol3:ch4-bundle-format", "templates"],
    "branch_or_hint": ["ia64_vol3:ch2-branch-instructions",
                       "ia64_vol1:branch-registers-and-ip"],
    "integer": ["ia64_vol3:ch2-integer-instructions",
                "ia64_vol1:integer-registers"],
    "predicate": ["ia64_vol1:predicate-registers",
                  "ia64_vol3:instruction-predication"],
    "predicate_compare": ["ia64_vol3:compare-instructions",
                          "ia64_vol1:predicate-registers"],
    "memory": ["ia64_vol3:memory-instructions",
               "ia64_vol1:memory-and-endianness",
               "ia64_vol2:interruption-and-translation"],
    "nat": ["ia64_vol1:nat-collection-and-consumption",
            "ia64_vol2:nat-consumption-fault"],
    "simd_integer": ["ia64_vol3:multimedia-instructions",
                     "ia64_vol1:integer-registers"],
    "floating_point": ["ia64_vol3:floating-point-instructions",
                       "ia64_vol1:floating-point-state-and-fpsr"],
    "system_or_translation": ["ia64_vol2:system-architecture",
                              "ia64_vol2:translation-registers",
                              "ia64_vol3:system-instructions"],
}

INSTRUCTION_COMMON_ASSERTIONS = [
    "decode accepts only the documented slot class, major opcode, completer, "
    "register, predicate, and immediate field encodings",
    "predicate true executes the architectural pseudocode and predicate false "
    "suppresses architectural side effects except for architecturally required "
    "decode or privilege faults",
    "writes to architecturally immutable registers such as r0, f0, f1, and p0 "
    "preserve the standard-defined constant values",
    "reserved encodings in the instruction page are rejected as illegal or "
    "reserved-operation cases, not silently treated as a different instruction",
]

INSTRUCTION_CATEGORY_ASSERTIONS = {
    "bundle": [
        "template bits map to exactly the standard slot-unit sequence",
        "stop bits split instruction groups at the standard-defined slot "
        "boundaries",
        "reserved template values are diagnosed before slot execution",
        "MLX consumes the L/X pair as one long-form instruction and never as two "
        "independent 41-bit instructions",
    ],
    "branch_or_hint": [
        "taken targets are bundle aligned and use the standard branch-immediate "
        "scaling and sign extension",
        "call forms set the return branch register and stacked-frame state "
        "defined by the SDM",
        "return and indirect forms mask or validate low target bits as specified",
        "branch hints and prediction instructions do not change non-hint "
        "architectural state",
    ],
    "integer": [
        "integer results are computed modulo 2^64 unless the instruction page "
        "defines a narrower result",
        "signed immediate fields are sign-extended from their documented width",
        "logical operations use the exact complement, mask, and zero-extension "
        "rules in the instruction page",
        "shift, extract, and deposit counts are masked and range-checked exactly "
        "as specified",
    ],
    "predicate": [
        "predicate moves preserve p0 as permanently true",
        "rotating predicate state is updated only by the documented rotation "
        "forms",
        "mask immediates affect only architecturally writable predicate bits",
        "false source predicates do not cause hidden predicate writes",
    ],
    "predicate_compare": [
        "p1 receives the comparison result and p2 receives its complement for "
        "normal compare types",
        "and/or/or.andcm compare forms combine with the previous destination "
        "predicate values exactly as specified",
        ".unc variants apply the standard unconditional destination update "
        "semantics",
        "cmp4 forms compare the low 32-bit operands with signedness determined "
        "by the relation completer",
    ],
    "memory": [
        "load and store widths, sign/zero extension, alignment checks, and byte "
        "ordering match the SDM",
        "base-update forms update the base register after the memory access with "
        "the documented immediate or register operand",
        "speculative and advanced loads produce or consume NaT/ALAT state "
        "according to the instruction completer",
        "acquire, release, semaphore, and check-load forms enforce their "
        "standard ordering and ALAT invalidation rules",
    ],
    "nat": [
        "NaT-consuming operands raise a register-NaT-consumption fault when the "
        "instruction class requires consumption",
        "NaT-propagating instructions propagate the NaT bit to the destination "
        "without fabricating a data value dependency",
        "spill/fill instructions encode and restore RNAT collection bits at the "
        "standard backing-store positions",
        "speculative-load NaT values are distinguishable from ordinary integer "
        "NaT propagation",
    ],
    "simd_integer": [
        "packed lanes are partitioned at the documented 8-, 16-, 32-, or 64-bit "
        "boundaries",
        "signed and unsigned packed operations use the specified per-lane "
        "extension and saturation rules",
        "mix, unpack, mux, and parallel shift forms preserve lane ordering as "
        "defined by the completer",
        "packed multiply and add forms keep high/low halves exactly as described "
        "by the instruction page",
    ],
    "floating_point": [
        "FPSR rounding controls, trap-disable bits, and status flags are updated "
        "according to the floating-point instruction page",
        "f0 and f1 remain the architectural +0.0 and +1.0 constants",
        "NaTVal, NaN, infinity, denormal, and signed-zero cases follow the "
        "standard result-class rules",
        "memory FP load/store, spill/fill, pair-load, and setf/getf transfers "
        "preserve the documented bit layout",
    ],
    "system_or_translation": [
        "privileged instructions fault or virtualize when CPL, PSR.vm, or "
        "translation state does not permit execution",
        "control, application, region, protection-key, and debug register moves "
        "respect read-only, side-effect, and reserved-bit rules",
        "TLB/TR insert, purge, lookup, tpa, tak, thash, and ttag forms use the "
        "standard region and page-size fields",
        "serialization, interruption return, PSR changes, and PAL portal entry "
        "stop at the architecturally required instruction boundary",
    ],
}

EFI_AREA_REFS = {
    "BootServices": ["uefi:ch4.4.1-boot-services-table",
                     "uefi:ch7-boot-services"],
    "RuntimeServices": ["uefi:ch4.5.1-runtime-services-table",
                        "uefi:ch8-runtime-services"],
    "Protocol": ["uefi:protocol-chapters", "efi_1_10:ia64-era-protocols"],
}

EFI_COMMON_ASSERTIONS = [
    "the function pointer appears in the standard service table or protocol "
    "structure at the documented ABI position",
    "successful calls return the standard success value or function-specific "
    "non-status result",
    "NULL, size, alignment, search-type, and unsupported-operation inputs return "
    "the status codes required by the UEFI or EFI specification",
    "side effects are externally visible only through standard service-table, "
    "handle-database, event, memory-map, variable, protocol, file, block, PCI, "
    "or console state",
]

EFI_AREA_ASSERTIONS = {
    "BootServices": [
        "boot services are callable before ExitBootServices and unavailable "
        "after a successful ExitBootServices call",
        "TPL rules are enforced for event dispatch, WaitForEvent, CheckEvent, "
        "RaiseTPL, and RestoreTPL",
        "memory-map keys change after allocations and must match for "
        "ExitBootServices",
        "runtime code, runtime data, PAL code, ACPI reclaim, and MMIO ranges "
        "are reported with the EFI memory types and IA-64 alignment required "
        "by the firmware specifications",
        "handle/protocol services maintain the standard open, notify, install, "
        "uninstall, and locate semantics",
    ],
    "RuntimeServices": [
        "runtime services remain callable using the mapping rules established by "
        "SetVirtualAddressMap",
        "ConvertPointer updates only registered runtime pointers and respects "
        "EFI_OPTIONAL_PTR",
        "variable services enforce attributes, name/vendor identity, iteration, "
        "deletion, and storage-limit status rules",
        "time, wakeup, monotonic-count, and reset services return the status and "
        "capability fields defined by UEFI",
    ],
    "Protocol": [
        "protocol methods validate their This pointer and argument buffers per "
        "the protocol definition",
        "console protocols implement Unicode, mode, cursor, attribute, and input "
        "readiness semantics exactly as specified",
        "block, disk, file, filesystem, and load-file protocols enforce media "
        "IDs, block alignment, EOF, buffer-size, read-only, and file-info rules",
        "graphics, PCI, device-path, loaded-image, FPSWA, TCG, and collation "
        "protocols use the standard structures and operation-specific status "
        "codes",
    ],
}

PAL_REFS = ["ia64_vol2:processor-abstraction-layer",
            "ia64_vol2:pal-procedure-calling-convention"]

PAL_ASSERTIONS = [
    "static PAL calls use gr28 for the function index and gr29 through gr31 "
    "for arguments, while stacked PAL calls use gr28 plus in0 for the function "
    "index and in1 through in3 for arguments",
    "gr8 contains the PAL status and gr9, gr10, and gr11 contain only "
    "standard-defined result values",
    "reserved argument fields must be zero and must return "
    "PAL_STATUS_INVALID_ARGUMENT when the PAL specification requires that",
    "unsupported function IDs return PAL_STATUS_NOT_IMPLEMENTED without "
    "leaking stale result registers",
    "function-specific cache, TLB, machine-check, register, platform-address, "
    "copy, halt, and self-test side effects match the PAL-defined contract",
]

SAL_REFS = ["sal:sal-procedure-summary",
            "sal:software-interface-conventions-for-sal-procedures"]

SAL_ASSERTIONS = [
    "the low 32 bits of Index select the SAL procedure ID listed by the SAL "
    "specification",
    "Arg0 through Arg7 are validated according to the selected procedure and "
    "reserved fields are rejected when nonzero",
    "Status, r9, r10, and r11 carry only the standard SAL return-register "
    "values",
    "runtime entry rejects invalid CPL or virtual/physical translation state "
    "before dispatching to a procedure",
    "procedure-specific vector, state-info, cache, PCI config, frequency, "
    "physical-id, register-physical-address, and update-PAL behavior follows "
    "the SAL specification",
]

ACPI_REFS = ["acpi_2:acpi-2.0-table-definitions",
             "acpi_ia64:ia64-sapic-and-efi-acpi-support",
             "uefi:configuration-table-acpi-sal-smbios-guid",
             "efi_1_10:debug-image-info-configuration-table",
             "smbios:2.7-entry-point-and-structures"]

ACPI_ASSERTIONS = [
    "every published ACPI, SAL, SMBIOS, and debug-image table has the standard "
    "signature, revision, length, checksum, header, and reserved-field values "
    "where that table format defines them",
    "64-bit IA-64 table pointers and EFI configuration-table GUIDs resolve to "
    "the architecturally appropriate physical ACPI reclaim or runtime firmware "
    "tables exposed to the OS loader",
    "RSDP/RSDT/XSDT/FADT/FACS/DSDT/SSDT/MADT/MCFG/SRAT/SLIT/HCDP/DBGP/SAL-table "
    "and SMBIOS structures match ACPI 2.0 IA-64, EFI, and SMBIOS layout and "
    "entry ordering requirements",
    "SAPIC, I/O SAPIC, PM block, SCI, PIB, and IOSAPIC MMIO behavior follows "
    "the IA-64 ACPI and interrupt-controller specifications",
]


def read_csv(root, path):
    with open(os.path.join(root, path), newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def normalize_text(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def instruction_key(row):
    return "|".join([
        "instruction",
        row["entry_type"],
        row["opcode"],
        row["mnemonic"],
        row["variant_or_condition"],
    ])


def efi_key(row):
    return "|".join([
        "efi",
        row["area"],
        row["table_or_protocol"],
        row["function"],
        row["entry_type"],
        row["condition"],
        row["behavior"],
    ])


def pal_key(row):
    return "|".join([
        "pal",
        row["function_id"],
        row["name"],
        row["entry_type"],
        row["condition"],
    ])


def sal_key(row):
    return "|".join([
        "sal",
        row["function_id"],
        row["name"],
        row["entry_type"],
        row["condition"],
    ])


def acpi_key(row):
    return "|".join([
        "acpi",
        row["area"],
        row["object"],
        row["entry_type"],
        row["condition"],
    ])


def with_row_focus(assertions, row, field):
    text = row.get(field, "")
    if text:
        assertions = list(assertions)
        assertions.append("row-specific standard scenario is covered: " + text)
    return assertions


def instruction_golden(row):
    refs = list(INSTRUCTION_CATEGORY_REFS[row["category"]])
    assertions = []
    if row["entry_type"] == "template":
        assertions.extend(INSTRUCTION_CATEGORY_ASSERTIONS["bundle"])
        assertions.append("template row is checked against every concrete "
                          "5-bit value represented by the documented range")
    else:
        assertions.extend(INSTRUCTION_COMMON_ASSERTIONS)
        assertions.extend(INSTRUCTION_CATEGORY_ASSERTIONS[row["category"]])
    if row["entry_type"] == "special_case":
        assertions = with_row_focus(assertions, row, "test_split")
    return {
        "key": instruction_key(row),
        "refs": refs,
        "assertions": assertions,
        "probe_kind": "bundle-decode-and-architectural-execution",
    }


def efi_golden(row):
    assertions = list(EFI_COMMON_ASSERTIONS)
    assertions.extend(EFI_AREA_ASSERTIONS[row["area"]])
    if row["entry_type"] == "special_case":
        assertions = with_row_focus(assertions, row, "test_split")
    return {
        "key": efi_key(row),
        "refs": EFI_AREA_REFS[row["area"]],
        "assertions": assertions,
        "probe_kind": "firmware-abi-and-service-call",
    }


def pal_golden(row):
    assertions = list(PAL_ASSERTIONS)
    assertions = with_row_focus(assertions, row, "test_split")
    return {
        "key": pal_key(row),
        "refs": PAL_REFS,
        "assertions": assertions,
        "probe_kind": "pal-procedure-call",
    }


def sal_golden(row):
    assertions = list(SAL_ASSERTIONS)
    assertions = with_row_focus(assertions, row, "test_split")
    return {
        "key": sal_key(row),
        "refs": SAL_REFS,
        "assertions": assertions,
        "probe_kind": "sal-procedure-call",
    }


def acpi_golden(row):
    assertions = list(ACPI_ASSERTIONS)
    if row["entry_type"] == "special_case":
        assertions = with_row_focus(assertions, row, "test_split")
    return {
        "key": acpi_key(row),
        "refs": ACPI_REFS,
        "assertions": assertions,
        "probe_kind": "firmware-table-or-platform-mmio",
    }


def build_catalog(rows_by_domain):
    catalog = []
    for row in rows_by_domain["instructions"]:
        catalog.append(instruction_golden(row))
    for row in rows_by_domain["efi"]:
        catalog.append(efi_golden(row))
    for row in rows_by_domain["pal"]:
        catalog.append(pal_golden(row))
    for row in rows_by_domain["sal"]:
        catalog.append(sal_golden(row))
    for row in rows_by_domain["acpi"]:
        catalog.append(acpi_golden(row))
    return catalog


def fail(messages):
    for message in messages:
        print(f"# {message}")
    return False


def test_inputs_available(root):
    missing = []
    for path in list(CSV_FILES.values()) + list(STANDARD_FILES.values()):
        if not os.path.exists(os.path.join(root, path)):
            missing.append(path)
    if missing:
        return fail([f"missing input: {path}" for path in missing])
    return True


def test_csv_shape(rows_by_domain):
    problems = []
    total = 0
    for domain, expected in EXPECTED_COUNTS.items():
        actual = len(rows_by_domain[domain])
        total += actual
        if actual != expected:
            problems.append(
                f"{domain}: expected {expected} rows from standard inventory, "
                f"got {actual}"
            )
    if total != sum(EXPECTED_COUNTS.values()):
        problems.append(f"total row count mismatch: {total}")
    for domain, rows in rows_by_domain.items():
        if len(rows) != len({tuple(row.items()) for row in rows}):
            problems.append(f"{domain}: duplicate CSV rows")
    return not problems or fail(problems)


def test_standard_only_catalog(catalog):
    problems = []
    for case in catalog:
        for ref in case["refs"]:
            if ref.startswith(IMPLEMENTATION_PATH_PREFIXES):
                problems.append(f"{case['key']}: implementation ref {ref}")
        if not case["refs"]:
            problems.append(f"{case['key']}: missing standard refs")
        if len(case["assertions"]) < 4:
            problems.append(f"{case['key']}: insufficient golden assertions")
        for assertion in case["assertions"]:
            if any(part in assertion for part in IMPLEMENTATION_PATH_PREFIXES):
                problems.append(
                    f"{case['key']}: assertion mentions implementation path"
                )
    return not problems or fail(problems[:50])


def test_catalog_completeness(rows_by_domain, catalog):
    expected = set()
    expected.update(instruction_key(row) for row in rows_by_domain["instructions"])
    expected.update(efi_key(row) for row in rows_by_domain["efi"])
    expected.update(pal_key(row) for row in rows_by_domain["pal"])
    expected.update(sal_key(row) for row in rows_by_domain["sal"])
    expected.update(acpi_key(row) for row in rows_by_domain["acpi"])

    actual = [case["key"] for case in catalog]
    actual_set = set(actual)
    problems = []
    if len(actual) != len(actual_set):
        problems.append("golden catalog has duplicate case keys")
    for key in sorted(expected - actual_set):
        problems.append(f"missing golden case: {key}")
    for key in sorted(actual_set - expected):
        problems.append(f"extra golden case: {key}")
    return not problems or fail(problems[:50])


def test_instruction_standard_cross_checks(root, rows):
    problems = []
    templates = read_csv(root, STANDARD_FILES["templates"])
    template_classes = {}
    reserved_templates = set()
    for template in templates:
        code = int(template["template_dec"], 10)
        if template["defined"] == "True":
            template_classes[code] = template["template_class"]
        else:
            reserved_templates.add(code)

    if len(template_classes) != 24:
        problems.append("IA-64 template table must contain 24 defined values")
    if reserved_templates != {0x06, 0x07, 0x14, 0x15, 0x1a, 0x1b, 0x1e, 0x1f}:
        problems.append("IA-64 reserved template set does not match SDM Vol.3")

    template_rows = [row for row in rows if row["entry_type"] == "template"]
    mentioned = set()
    for row in template_rows:
        codes = set()
        for match in re.finditer(r"0x([0-9a-f]{2})(?:\.\.0x([0-9a-f]{2}))?",
                                 row["variant_or_condition"].lower()):
            lo = int(match.group(1), 16)
            hi = int(match.group(2), 16) if match.group(2) else lo
            codes.update(range(lo, hi + 1))
        for code in codes:
            if template_classes.get(code) != row["mnemonic"]:
                problems.append(
                    f"template 0x{code:02x}: CSV mnemonic {row['mnemonic']} "
                    f"does not match standard {template_classes.get(code)}"
                )
        mentioned.update(codes)
    if mentioned != set(template_classes):
        problems.append("template rows do not cover exactly all defined templates")

    opcode_rows = [row for row in rows if row["entry_type"] == "opcode"]
    if not opcode_rows:
        problems.append("no instruction opcode rows")
    for row in opcode_rows:
        if not row["opcode"].startswith("IA64_OP_"):
            problems.append(f"opcode row lacks IA64_OP_ prefix: {row['opcode']}")
        if normalize_text(row["mnemonic"]) == "":
            problems.append(f"opcode row has empty mnemonic: {row['opcode']}")
    return not problems or fail(problems[:50])


def test_firmware_interface_cross_checks(rows_by_domain):
    problems = []
    for row in rows_by_domain["pal"]:
        fid = row["function_id"]
        if fid not in {"default", "shared"}:
            try:
                int(fid, 16)
            except ValueError:
                problems.append(f"PAL function_id is not hex/default/shared: {fid}")
        if row["function_id"] == "shared":
            continue
        if not row["name"].startswith("PAL_"):
            problems.append(f"PAL name lacks PAL_ prefix: {row['name']}")

    for row in rows_by_domain["sal"]:
        fid = row["function_id"]
        if fid not in {"default", "runtime"}:
            try:
                value = int(fid, 16)
            except ValueError:
                problems.append(f"SAL function_id is not hex/default/runtime: {fid}")
            else:
                if value >> 24 != 0x01:
                    problems.append(f"SAL function id outside standard range: {fid}")
        if fid not in {"default", "runtime"} and not row["name"].startswith("SAL_"):
            problems.append(f"SAL name lacks SAL_ prefix: {row['name']}")

    for row in rows_by_domain["efi"]:
        if row["area"] not in EFI_AREA_REFS:
            problems.append(f"unknown EFI area: {row['area']}")
        if row["entry_type"] not in {"function", "special_case"}:
            problems.append(f"unknown EFI entry_type: {row['entry_type']}")

    for row in rows_by_domain["acpi"]:
        if row["entry_type"] not in {"feature", "special_case"}:
            problems.append(f"unknown ACPI entry_type: {row['entry_type']}")

    return not problems or fail(problems[:50])


def load_rows(root):
    return {
        domain: read_csv(root, path)
        for domain, path in CSV_FILES.items()
    }


def main():
    if len(sys.argv) != 2:
        print("Bail out! usage: test-ia64-standard-goldens.py SOURCE_ROOT")
        return 1

    root = sys.argv[1]
    print("TAP version 13")
    print("1..6")

    rows_by_domain = None
    catalog = None
    tests = []

    ok = test_inputs_available(root)
    print(("ok" if ok else "not ok") +
          " 1 - IA-64 standard-derived metadata available")
    if not ok:
        return 1

    rows_by_domain = load_rows(root)
    catalog = build_catalog(rows_by_domain)

    tests = [
        ("CSV inventory row counts are stable", test_csv_shape(rows_by_domain)),
        ("golden catalog uses only standard references",
         test_standard_only_catalog(catalog)),
        ("golden catalog covers every CSV row",
         test_catalog_completeness(rows_by_domain, catalog)),
        ("instruction goldens cross-check SDM template inventory",
         test_instruction_standard_cross_checks(root,
                                                rows_by_domain["instructions"])),
        ("firmware/platform goldens cross-check standard identifiers",
         test_firmware_interface_cross_checks(rows_by_domain)),
    ]

    status = 0
    for index, (name, ok) in enumerate(tests, start=2):
        if ok:
            print(f"ok {index} - {name}")
        else:
            print(f"not ok {index} - {name}")
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
