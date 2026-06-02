#!/usr/bin/env python3
#
# IA-64 staged OS boot smoke harness.
# If IA64_BOOT_SMOKE_DISK is provided, boots with that disk image and checks
# optional signatures from IA64_BOOT_SMOKE_SIGNATURES (comma-separated).
# Without a disk image, validates framework health by ensuring firmware boot
# stays alive for a short interval.

import os
import select
import shlex
import subprocess
import sys
import time


def decode_output(output):
    return output.decode("utf-8", errors="replace")


def decode_input(value):
    return value.encode("utf-8").decode("unicode_escape").encode("latin1")


def parse_float_env(name, default):
    value = os.getenv(name, "").strip()
    if not value:
        return default
    try:
        return float(value)
    except ValueError:
        raise ValueError(f"{name} must be a number")


def main():
    if len(sys.argv) != 3:
        print("Bail out! usage: test-ia64-os-boot-smoke.py QEMU_SYSTEM_IA64 IA64_FIRMWARE_BIN")
        return 1

    qemu = sys.argv[1]
    firmware = sys.argv[2]
    disk = os.getenv("IA64_BOOT_SMOKE_DISK", "").strip()
    memory = os.getenv("IA64_BOOT_SMOKE_MEMORY", "").strip()
    signatures = [s.strip() for s in os.getenv("IA64_BOOT_SMOKE_SIGNATURES", "").split(",") if s.strip()]
    boot_seconds = parse_float_env("IA64_BOOT_SMOKE_SECONDS", 2.0)
    input_delay = parse_float_env("IA64_BOOT_SMOKE_INPUT_DELAY", 0.0)
    boot_input = decode_input(os.getenv("IA64_BOOT_SMOKE_INPUT", ""))
    extra_args = shlex.split(os.getenv("IA64_BOOT_SMOKE_EXTRA_ARGS", ""))

    print("TAP version 13")
    print("1..1")

    if not os.path.exists(firmware):
        print(f"not ok 1 - firmware exists ({firmware})")
        return 1
    if disk and not os.path.exists(disk):
        print(f"not ok 1 - smoke disk exists ({disk})")
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
        "stdio",
        "-monitor",
        "none",
    ]
    args += extra_args
    if memory:
        args += ["-m", memory]
    if disk:
        drive_opts = f"file={disk},if=ide,format=raw"
        if disk.lower().endswith(".iso"):
            drive_opts += ",media=cdrom,readonly=on"
        args += ["-drive", drive_opts]

    proc = subprocess.Popen(
        args,
        stdin=subprocess.PIPE if boot_input else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    output_parts = []
    try:
        started = time.monotonic()
        deadline = started + boot_seconds
        input_sent = not boot_input

        while time.monotonic() < deadline:
            now = time.monotonic()
            if not input_sent and now - started >= input_delay:
                try:
                    proc.stdin.write(boot_input)
                    proc.stdin.flush()
                except BrokenPipeError:
                    pass
                input_sent = True

            if proc.poll() is not None:
                break

            readable, _, _ = select.select([proc.stdout], [], [], 0.1)
            if readable:
                chunk = os.read(proc.stdout.fileno(), 4096)
                if not chunk:
                    break
                output_parts.append(chunk)
                if signatures:
                    output_so_far = decode_output(b"".join(output_parts))
                    if all(sig in output_so_far for sig in signatures):
                        break

        if proc.poll() is not None:
            output, _ = proc.communicate(timeout=2)
            output_parts.append(output)
            output = decode_output(b"".join(output_parts))
            print("not ok 1 - qemu exited early during boot smoke")
            for line in output.splitlines():
                print(f"# {line}")
            return 1

        proc.terminate()
        try:
            output, _ = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            output, _ = proc.communicate(timeout=2)
        output_parts.append(output)
        output = decode_output(b"".join(output_parts))

        if signatures:
            missing = [sig for sig in signatures if sig not in output]
            if missing:
                print("not ok 1 - boot signatures")
                for sig in missing:
                    print(f"# missing signature: {sig}")
                for line in output.splitlines():
                    print(f"# {line}")
                return 1
            print("ok 1 - staged OS boot smoke signatures")
            return 0

        if disk:
            print("ok 1 - staged OS boot smoke (disk provided, no signatures configured)")
        else:
            print("ok 1 - staged OS boot smoke harness (firmware-only health check)")
        return 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2)


if __name__ == "__main__":
    sys.exit(main())
