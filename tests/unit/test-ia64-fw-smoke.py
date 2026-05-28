#!/usr/bin/env python3
#
# IA-64 firmware wiring smoke test.
# Ensures qemu-system-ia64 can boot with the generated IA-64 firmware image
# and stay alive long enough to indicate successful machine+firmware wiring.

import os
import subprocess
import sys
import time


def main():
    if len(sys.argv) != 3:
        print("Bail out! usage: test-ia64-fw-smoke.py QEMU_SYSTEM_IA64 IA64_FIRMWARE_BIN")
        return 1

    qemu = sys.argv[1]
    firmware = sys.argv[2]

    if not os.path.exists(firmware):
        print("TAP version 13")
        print("1..1")
        print(f"not ok 1 - firmware exists ({firmware})")
        return 1

    args = [
        qemu,
        "-machine",
        "ia64-vpc",
        "-smp",
        "1",
        "-bios",
        firmware,
        "-display",
        "none",
        "-serial",
        "none",
        "-monitor",
        "none",
    ]

    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        time.sleep(1.0)
        rc = proc.poll()
        print("TAP version 13")
        print("1..1")
        if rc is None:
            print("ok 1 - qemu boots with generated ia64 firmware")
            return 0
        output, _ = proc.communicate(timeout=2)
        print("not ok 1 - qemu exited early with generated ia64 firmware")
        for line in output.splitlines():
            print(f"# {line}")
        return 1
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)


if __name__ == "__main__":
    sys.exit(main())
