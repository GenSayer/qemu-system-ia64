#!/usr/bin/env python3
#
# IA-64 firmware wiring smoke test.
# Ensures qemu-system-ia64 can boot with the generated IA-64 firmware image
# and stay alive long enough to indicate successful machine+firmware wiring.

import json
import os
import subprocess
import sys
import tempfile
import time


def wait_for_count(path, marker, count, proc, timeout):
    deadline = time.monotonic() + timeout
    output = ""

    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                output = f.read()
        except FileNotFoundError:
            pass
        if output.count(marker) >= count:
            return True, output
        time.sleep(0.05)
    return False, output


def qmp_read(proc):
    while True:
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError("QMP connection closed")
        response = json.loads(line)
        if "return" in response or "error" in response or "QMP" in response:
            return response


def qmp_command(proc, command):
    proc.stdin.write(json.dumps({"execute": command}) + "\n")
    proc.stdin.flush()
    while True:
        response = qmp_read(proc)
        if "return" in response:
            return
        if "error" in response:
            raise RuntimeError(str(response["error"]))


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

    marker = "No bootable image found. System halted."
    with tempfile.TemporaryDirectory() as tmpdir:
        serial_path = os.path.join(tmpdir, "serial.log")
        args = [
            qemu,
            "-machine", "ia64-vpc",
            "-smp", "1",
            "-m", "256M",
            "-bios", firmware,
            "-display", "none",
            "-serial", f"file:{serial_path}",
            "-monitor", "none",
            "-qmp", "stdio",
        ]

        proc = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        output = ""
        failure = None
        try:
            qmp_read(proc)
            qmp_command(proc, "qmp_capabilities")
            first, output = wait_for_count(
                serial_path, marker, 1, proc, 6.0
            )
            if not first:
                failure = "firmware did not complete its initial boot"
            else:
                qmp_command(proc, "system_reset")
                second, output = wait_for_count(
                    serial_path, marker, 2, proc, 6.0
                )
                if not second:
                    failure = "firmware did not complete after system reset"
        except Exception as exc:
            failure = str(exc)
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)

        print("TAP version 13")
        print("1..1")
        if failure is None:
            print("ok 1 - firmware completes cold boot and system reset")
            return 0
        print(f"not ok 1 - {failure}")
        for line in output.splitlines():
            print(f"# {line}")
        stderr = proc.stderr.read()
        for line in stderr.splitlines():
            print(f"# {line}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
