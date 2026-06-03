#!/usr/bin/env python3
#
# IA-64 firmware TPM/TCG publication test.
# The ia64-vpc machine does not model a TPM device.  If the firmware publishes
# the legacy EFI TCG protocol for old boot managers, it must report that no TPM
# is present, provide the specified SHA-1 HashAll service, and avoid dummy
# success for TPM-dependent commands.

import os
import subprocess
import sys
import tempfile


def main():
    if len(sys.argv) != 2:
        print("Bail out! usage: test-ia64-fw-no-fake-tcg.py IA64_FIRMWARE_BIN")
        return 1

    firmware = sys.argv[1]

    print("TAP version 13")
    print("1..3")

    if not os.path.exists(firmware):
        print(f"not ok 1 - firmware exists ({firmware})")
        return 1

    elf_path = os.path.splitext(firmware)[0] + ".elf"
    if not os.path.exists(elf_path):
        print(f"not ok 1 - firmware ELF exists ({elf_path})")
        return 1

    objdump = subprocess.run(
        ["ia64-linux-gnu-objdump", "-t", elf_path],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    with tempfile.NamedTemporaryFile() as raw_file:
        objcopy = subprocess.run(
            ["ia64-linux-gnu-objcopy", "-O", "binary", elf_path, raw_file.name],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        raw_file.seek(0)
        raw = raw_file.read() if objcopy.returncode == 0 else b""
    if objdump.returncode != 0 or objcopy.returncode != 0:
        print("not ok 1 - inspect firmware ELF")
        for line in objdump.stdout.splitlines():
            print(f"# {line}")
        for line in objcopy.stdout.decode("utf-8", errors="replace").splitlines():
            print(f"# {line}")
        print("not ok 2 - EFI TCG protocol GUID and no-TPM capability")
        print("not ok 3 - SHA-1 golden digests")
        return 1

    required_symbols = [
        "mTcgProtocolGuid",
        "mTcgProto",
        "mTcgCapability",
        "tcg_status_check",
        "tcg_hash_all",
        "tcg_log_event",
        "tcg_pass_through_to_tpm",
        "tcg_hash_log_extend_event",
        "tcg_protocol_selftest",
        "fw_sha1_hash",
        "fw_sha1_transform",
    ]
    forbidden_symbols = [
        "mTcgEventLog",
    ]
    missing_symbols = [sym for sym in required_symbols if sym not in objdump.stdout]
    found_forbidden = [sym for sym in forbidden_symbols if sym in objdump.stdout]

    if missing_symbols or found_forbidden:
        print("not ok 1 - firmware publishes truthful no-TPM TCG protocol")
        for sym in missing_symbols:
            print(f"# missing symbol: {sym}")
        for sym in found_forbidden:
            print(f"# unexpected symbol: {sym}")
        print("not ok 2 - EFI TCG protocol GUID and no-TPM capability")
        print("not ok 3 - SHA-1 golden digests")
        return 1

    print("ok 1 - firmware publishes truthful no-TPM TCG protocol")

    tcg_guid = bytes.fromhex("6d7941f52ea65449a7759584f61b9cdd")
    no_tpm_capability = bytes([
        12, 1, 2, 0, 0, 1, 2, 0, 0, 1, 0, 0
    ])
    if tcg_guid not in raw or no_tpm_capability not in raw:
        print("not ok 2 - EFI TCG protocol GUID and no-TPM capability")
        if tcg_guid not in raw:
            print("# missing EFI_TCG_PROTOCOL_GUID bytes")
        if no_tpm_capability not in raw:
            print("# missing TCG capability bytes for SHA-1, TPM not present")
        print("not ok 3 - SHA-1 golden digests")
        return 1

    print("ok 2 - EFI TCG protocol GUID and no-TPM capability")

    sha1_empty = bytes.fromhex("da39a3ee5e6b4b0d3255bfef95601890afd80709")
    sha1_abc = bytes.fromhex("a9993e364706816aba3e25717850c26c9cd0d89d")
    if sha1_empty not in raw or sha1_abc not in raw:
        print("not ok 3 - SHA-1 golden digests")
        if sha1_empty not in raw:
            print("# missing SHA-1 empty-string digest selftest vector")
        if sha1_abc not in raw:
            print("# missing SHA-1 abc digest selftest vector")
        return 1

    print("ok 3 - SHA-1 golden digests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
