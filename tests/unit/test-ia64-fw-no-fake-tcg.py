#!/usr/bin/env python3
#
# IA-64 firmware TPM/TCG publication test.
# The ia64-vpc machine does not model a TPM device.  The firmware must not
# publish a fake EFI TCG protocol that reports a present TPM and returns dummy
# success for TPM commands.

import os
import subprocess
import sys


def main():
    if len(sys.argv) != 2:
        print("Bail out! usage: test-ia64-fw-no-fake-tcg.py IA64_FIRMWARE_BIN")
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

    objdump = subprocess.run(
        ["ia64-linux-gnu-objdump", "-t", elf_path],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    strings = subprocess.run(
        ["strings", "-a", elf_path],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if objdump.returncode != 0 or strings.returncode != 0:
        print("not ok 1 - inspect firmware ELF")
        for line in (objdump.stdout + strings.stdout).splitlines():
            print(f"# {line}")
        return 1

    forbidden_symbols = [
        "mTcgHandle",
        "mTcgProtocolGuid",
        "mTcgProto",
        "mTcgEventLog",
        "tcg_status_check",
        "tcg_pass_through",
        "tcg_hash_log_extend_event",
    ]
    forbidden_strings = [
        "TCG: StatusCheck",
        "TCG: PassThrough",
        "TCG: HashLogExtendEvent",
    ]
    found_symbols = [sym for sym in forbidden_symbols if sym in objdump.stdout]
    found_strings = [text for text in forbidden_strings if text in strings.stdout]

    if found_symbols or found_strings:
        print("not ok 1 - firmware omits fake TCG protocol")
        for sym in found_symbols:
            print(f"# unexpected symbol: {sym}")
        for text in found_strings:
            print(f"# unexpected string: {text}")
        return 1

    print("ok 1 - firmware omits fake TCG protocol")
    return 0


if __name__ == "__main__":
    sys.exit(main())
