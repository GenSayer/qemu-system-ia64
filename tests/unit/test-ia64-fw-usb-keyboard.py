#!/usr/bin/env python3
#
# IA-64 firmware USB keyboard acceptance test.
# Boots a tiny EFI application with PS/2 disabled, injects a key through QMP,
# and verifies that SimpleTextInput reads it from the default USB keyboard.

import json
import os
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time


SECTOR_SIZE = 512
DISK_SECTORS = 8192
FAT_SECTORS = 32
ROOT_ENTRIES = 512
ROOT_SECTORS = ROOT_ENTRIES * 32 // SECTOR_SIZE
DATA_START = 1 + FAT_SECTORS + ROOT_SECTORS

WAITING_SIGNATURE = "IA64 USB KBD: waiting"
SUCCESS_SIGNATURE = "IA64 USB KBD: read x"
FAILURE_SIGNATURES = [
    "IA64 USB KBD: failed",
    "IA64 USB KBD: unexpected key",
]


def decode_output(output):
    return output.decode("utf-8", errors="replace")


def run_command(args):
    result = subprocess.run(
        args,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "command failed: " + " ".join(args) + "\n" + result.stdout
        )


def build_efi_application(source_root, output_dir):
    source = os.path.join(source_root, "tests/unit/ia64-conin-usb-app.c")
    linker_script = os.path.join(
        source_root, "tests/unit/ia64-storage-io-app.lds"
    )
    obj = os.path.join(output_dir, "ia64-conin-usb-app.o")
    elf = os.path.join(output_dir, "ia64-conin-usb-app.elf")
    efi = os.path.join(output_dir, "BOOTIA64.EFI")

    run_command([
        "ia64-linux-gnu-gcc",
        "-O2",
        "-fno-builtin",
        "-ffreestanding",
        "-nostdinc",
        "-nostdlib",
        "-mno-sdata",
        "-fno-stack-protector",
        "-fno-common",
        "-Wall",
        "-Wextra",
        "-c",
        "-o", obj,
        source,
    ])
    run_command([
        "ia64-linux-gnu-ld",
        "-nostdlib",
        "-static",
        "-T", linker_script,
        "-o", elf,
        obj,
    ])
    run_command([
        "ia64-linux-gnu-objcopy",
        "-R", ".comment",
        "-O", "pei-ia64",
        "--image-base=0x4000000",
        "--subsystem=10",
        elf,
        efi,
    ])
    return efi


def set_fat_entry(fat, cluster, value):
    struct.pack_into("<H", fat, cluster * 2, value)


def directory_entry(name, attributes, cluster, size=0):
    if len(name) != 11:
        raise ValueError("FAT short name must contain exactly 11 bytes")
    entry = bytearray(32)
    entry[0:11] = name
    entry[11] = attributes
    struct.pack_into("<H", entry, 26, cluster)
    struct.pack_into("<I", entry, 28, size)
    return entry


def make_boot_disk(path, efi_path):
    with open(efi_path, "rb") as f:
        efi_image = f.read()

    image = bytearray(DISK_SECTORS * SECTOR_SIZE)
    image[0:3] = b"\xeb\x3c\x90"
    image[3:11] = b"QEMUIA64"
    struct.pack_into("<H", image, 11, SECTOR_SIZE)
    image[13] = 1
    struct.pack_into("<H", image, 14, 1)
    image[16] = 1
    struct.pack_into("<H", image, 17, ROOT_ENTRIES)
    struct.pack_into("<H", image, 19, DISK_SECTORS)
    image[21] = 0xF8
    struct.pack_into("<H", image, 22, FAT_SECTORS)
    struct.pack_into("<H", image, 24, 32)
    struct.pack_into("<H", image, 26, 64)
    image[38] = 0x29
    image[43:54] = b"IA64 USBKBD"
    image[54:62] = b"FAT16   "
    image[510:512] = b"\x55\xaa"

    fat_start = SECTOR_SIZE
    fat = memoryview(image)[
        fat_start:fat_start + FAT_SECTORS * SECTOR_SIZE
    ]
    set_fat_entry(fat, 0, 0xFFF8)
    set_fat_entry(fat, 1, 0xFFFF)
    set_fat_entry(fat, 2, 0xFFFF)
    set_fat_entry(fat, 3, 0xFFFF)

    file_clusters = (len(efi_image) + SECTOR_SIZE - 1) // SECTOR_SIZE
    first_file_cluster = 4
    last_file_cluster = first_file_cluster + file_clusters - 1
    if DATA_START + last_file_cluster - 2 >= DISK_SECTORS:
        raise RuntimeError("EFI test application does not fit in disk image")
    for cluster in range(first_file_cluster, last_file_cluster + 1):
        next_cluster = 0xFFFF if cluster == last_file_cluster else cluster + 1
        set_fat_entry(fat, cluster, next_cluster)

    root_start = (1 + FAT_SECTORS) * SECTOR_SIZE
    image[root_start:root_start + 32] = directory_entry(
        b"EFI        ", 0x10, 2
    )

    efi_dir_start = DATA_START * SECTOR_SIZE
    image[efi_dir_start:efi_dir_start + 32] = directory_entry(
        b"BOOT       ", 0x10, 3
    )
    boot_dir_start = (DATA_START + 1) * SECTOR_SIZE
    image[boot_dir_start:boot_dir_start + 32] = directory_entry(
        b"BOOTIA64EFI", 0x20, first_file_cluster, len(efi_image)
    )

    file_start = (DATA_START + first_file_cluster - 2) * SECTOR_SIZE
    image[file_start:file_start + len(efi_image)] = efi_image

    with open(path, "wb") as f:
        f.write(image)


def qmp_read(sock):
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("QMP socket closed")
        data += chunk
        while b"\n" in data:
            line, data = data.split(b"\n", 1)
            line = line.strip()
            if line:
                return json.loads(line.decode("utf-8"))


def qmp_command(sock, command):
    sock.sendall(json.dumps(command).encode("utf-8") + b"\r\n")
    while True:
        response = qmp_read(sock)
        if "return" in response:
            return response["return"]
        if "error" in response:
            raise RuntimeError(str(response["error"]))


def qmp_send_key(socket_path):
    deadline = time.monotonic() + 5.0
    last_error = None
    while time.monotonic() < deadline:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect(socket_path)
            break
        except OSError as exc:
            last_error = exc
            time.sleep(0.05)
    else:
        raise RuntimeError(f"failed to connect QMP socket: {last_error}")

    with sock:
        qmp_read(sock)
        qmp_command(sock, {"execute": "qmp_capabilities"})
        qmp_command(sock, {
            "execute": "human-monitor-command",
            "arguments": {"command-line": "sendkey x 500"},
        })


def run_qemu(qemu, firmware, disk, qmp_socket):
    args = [
        qemu,
        "-machine", "ia64-vpc,i8042=off",
        "-smp", "1",
        "-m", "512M",
        "-bios", firmware,
        "-display", "none",
        "-serial", "stdio",
        "-monitor", "none",
        "-qmp", f"unix:{qmp_socket},server=on,wait=off",
        "-drive", f"file={disk},format=raw,if=ide",
    ]
    proc = subprocess.Popen(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    output_parts = []
    key_sent = False
    qmp_error = None
    deadline = time.monotonic() + 25.0
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
                output = decode_output(b"".join(output_parts))
                if WAITING_SIGNATURE in output and not key_sent:
                    try:
                        qmp_send_key(qmp_socket)
                        key_sent = True
                    except Exception as exc:
                        qmp_error = str(exc)
                        break
                if (SUCCESS_SIGNATURE in output or
                        any(sig in output for sig in FAILURE_SIGNATURES)):
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
        return (
            returncode,
            decode_output(b"".join(output_parts)),
            key_sent,
            qmp_error,
        )
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2)


def main():
    if len(sys.argv) != 4:
        print(
            "Bail out! usage: test-ia64-fw-usb-keyboard.py "
            "SOURCE_ROOT QEMU_SYSTEM_IA64 IA64_FIRMWARE_BIN"
        )
        return 1

    source_root, qemu, firmware = sys.argv[1:]
    print("TAP version 13")
    print("1..1")

    for path in [qemu, firmware]:
        if not os.path.exists(path):
            print(f"Bail out! missing input: {path}")
            return 1

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            efi_app = build_efi_application(source_root, tmpdir)
        except Exception as exc:
            print("Bail out! failed to build IA-64 EFI USB keyboard application")
            for line in str(exc).splitlines():
                print(f"# {line}")
            return 1

        disk = os.path.join(tmpdir, "usb-keyboard.img")
        qmp_socket = os.path.join(tmpdir, "qmp.sock")
        make_boot_disk(disk, efi_app)
        returncode, output, key_sent, qmp_error = run_qemu(
            qemu, firmware, disk, qmp_socket
        )

    required = [
        "Console In:           Serial/PS2/USB WaitForKey ready",
        "USB Keyboard Test:    HID boot report decode verified",
        "Boot Manager:        trying Boot0000000000000000",
        WAITING_SIGNATURE,
        SUCCESS_SIGNATURE,
    ]
    missing = [signature for signature in required if signature not in output]
    failures = [signature for signature in FAILURE_SIGNATURES
                if signature in output]
    if returncode is not None or missing or failures or not key_sent or qmp_error:
        print("not ok 1 - firmware ConIn reads default USB keyboard")
        if returncode is not None:
            print(f"# qemu exited with status {returncode}")
        if not key_sent:
            print("# QMP sendkey was not issued")
        if qmp_error:
            print(f"# QMP error: {qmp_error}")
        for signature in missing:
            print(f"# missing signature: {signature}")
        for signature in failures:
            print(f"# failure signature: {signature}")
        for line in output.splitlines():
            print(f"# {line}")
        return 1

    print("ok 1 - firmware ConIn reads default USB keyboard")
    return 0


if __name__ == "__main__":
    sys.exit(main())
