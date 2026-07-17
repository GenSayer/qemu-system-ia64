#!/usr/bin/env python3
"""IA-64 firmware boot manager and interactive EFI shell tests."""

# SPDX-License-Identifier: GPL-2.0-or-later

from pathlib import Path

from qemu_test import QemuSystemTest, wait_for_console_pattern

from ia64.console import Ia64FirmwareTest
from ia64.efi_build import app_path
from ia64.media import make_fat_disk


class Ia64BootShell(Ia64FirmwareTest):
    @staticmethod
    def _send_key(vm, qcode):
        vm.cmd("send-key", keys=[{"type": "qcode", "data": qcode}],
               hold_time=50)

    def _open_shell(self, vm, key):
        wait_for_console_pattern(self, "Press F2, F12, or Delete", vm=vm)
        self._send_key(vm, key)
        wait_for_console_pattern(self, "IA-64 EFI shell", vm=vm)

    def _command(self, vm, command, expected):
        vm.console_socket.sendall((command + "\r").encode("ascii"))
        return wait_for_console_pattern(self, expected, vm=vm)

    def test_shell_commands_and_persistence(self):
        disk = Path(self.scratch_file("shell.img"))
        nvram = self.make_nvram("shell.nvram")
        make_fat_disk(disk, app_path("smoke"))

        vm = self.launch_ia64(
            name="shell-first", media=disk,
            machine_options=f"firmware-console=serial,nvram={nvram}")
        self._open_shell(vm, "f2")
        self._command(vm, "info", "NVRAM backing:  persistent")
        self._command(vm, "map", "fs0:")
        self._command(vm, r"ls fs0:\EFI\BOOT", "BOOTIA64.EFI")
        self._command(vm, "date 2024-02-29", "2024-02-29")
        self._command(vm, "time 12:34:56", "12:34:56")
        self._command(vm, "bootorder Boot0000",
                      "BootOrder saved to persistent NVRAM")
        self._command(vm, "bootnext Boot0000",
                      "BootNext saved to persistent NVRAM")
        self._command(vm, r"cd fs0:\EFI\BOOT", r"fs0:\EFI\BOOT>")
        self._command(vm, "pwd", r"fs0:\EFI\BOOT")
        self._command(vm, "run BOOTIA64.EFI",
                      "IA64TEST suite=smoke status=DONE")
        wait_for_console_pattern(self, r"fs0:\EFI\BOOT>", vm=vm)
        vm.shutdown()

        contents = nvram.read_bytes()
        self.assertIn("BootOrder".encode("utf-16le") + b"\0\0", contents)
        self.assertIn(b"IRT64OFT", contents)

        vm = self.launch_ia64(
            name="shell-second", media=disk,
            machine_options=f"firmware-console=serial,nvram={nvram}")
        self._open_shell(vm, "f12")
        self._command(vm, "date", "2024-02-29")
        self._command(vm, "time", "12:34:")
        self._command(vm, "bootorder", "BootOrder: Boot0000")
        self._command(vm, "bootnext", "BootNext: Boot0000")
        vm.console_socket.sendall(b"exit\r")
        wait_for_console_pattern(
            self, "IA64TEST suite=smoke status=DONE", vm=vm)
        vm.shutdown()

        vm = self.launch_ia64(
            name="shell-third", media=disk,
            machine_options=f"firmware-console=serial,nvram={nvram}")
        self._open_shell(vm, "f2")
        self._command(vm, "bootnext", "BootNext is not set")
        vm.shutdown()

    def test_delete_hotkey_and_device_boot(self):
        disk = Path(self.scratch_file("device-boot.img"))
        make_fat_disk(disk, app_path("smoke"))
        vm = self.launch_ia64(
            name="delete-hotkey", media=disk,
            machine_options=(
                "i8042=off,firmware-console=serial,nvram=none"))
        self._open_shell(vm, "delete")
        self._command(vm, "boot fs0:",
                      "IA64TEST suite=smoke status=DONE")


if __name__ == "__main__":
    QemuSystemTest.main()
