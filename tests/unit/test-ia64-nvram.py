#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# IA-64 machine persistent NVRAM test.

import os
import re
import subprocess
import sys
import tempfile


NVRAM_BASE = 0xFFF00000
NVRAM_SIZE = 64 * 1024
NVRAM_COMMIT_OFFSET = NVRAM_SIZE - 8
NVRAM_COMMIT_MAGIC = 0x54494D4D4F43564E
TEST_VALUE = 0x1122334455667788


def run_qemu(qemu, nvram, extra_args=(), monitor_input="quit\n"):
    return subprocess.run(
        [
            qemu,
            "-machine", f"ia64-vpc,nvram={nvram}",
            "-S",
            "-display", "none",
            "-serial", "none",
            "-monitor", "stdio",
        ] + list(extra_args),
        input=monitor_input,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=10,
        check=False,
    )


def main():
    if len(sys.argv) != 2:
        print("Bail out! usage: test-ia64-nvram.py QEMU_SYSTEM_IA64")
        return 1

    qemu = sys.argv[1]
    print("TAP version 13")
    print("1..1")

    with tempfile.TemporaryDirectory(prefix="ia64-nvram-") as tempdir:
        nvram = os.path.join(tempdir, "nvram")
        first = run_qemu(qemu, nvram, (
            "-device",
            f"loader,data=0x{TEST_VALUE:x},addr=0x{NVRAM_BASE:x},data-len=8",
            "-device",
            f"loader,data=0x{NVRAM_COMMIT_MAGIC:x},"
            f"addr=0x{NVRAM_BASE + NVRAM_COMMIT_OFFSET:x},data-len=8",
        ))
        if first.returncode != 0 or not os.path.exists(nvram):
            print("not ok 1 - IA-64 NVRAM commit creates backing file")
            for line in first.stdout.splitlines():
                print(f"# {line}")
            return 1
        with open(nvram, "rb") as stream:
            contents = stream.read()
        if (len(contents) != NVRAM_SIZE or
                int.from_bytes(contents[:8], "little") != TEST_VALUE):
            print("not ok 1 - IA-64 NVRAM backing file contents")
            print(f"# size={len(contents)} value={contents[:8].hex()}")
            return 1

        second = run_qemu(
            qemu, nvram,
            monitor_input=f"xp /1gx 0x{NVRAM_BASE:x}\nquit\n",
        )
        expected = rf"{NVRAM_BASE:x}:\s+0x{TEST_VALUE:016x}"
        if (second.returncode != 0 or
                re.search(expected, second.stdout, re.IGNORECASE) is None):
            print("not ok 1 - IA-64 NVRAM survives QEMU restart")
            for line in second.stdout.splitlines():
                print(f"# {line}")
            return 1

    print("ok 1 - IA-64 NVRAM persists across QEMU restart")
    return 0


if __name__ == "__main__":
    sys.exit(main())
