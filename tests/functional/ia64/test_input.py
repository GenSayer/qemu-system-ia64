#!/usr/bin/env python3
"""IA-64 firmware keyboard input tests driven through QMP."""

# SPDX-License-Identifier: GPL-2.0-or-later

from pathlib import Path

from qemu_test import QemuSystemTest

from ia64.console import Ia64FirmwareTest
from ia64.efi_build import app_path
from ia64.media import make_fat_disk


INPUT_CASES = {
    "text-input-ex", "ready-basic", "read-key-stroke",
    "ready-modifier", "modifier-key", "modifier-state", "ready-extended",
    "extended-scan-code",
}


class Ia64Input(Ia64FirmwareTest):
    @staticmethod
    def _send_keys(vm, qcodes):
        vm.cmd("send-key", keys=[
            {"type": "qcode", "data": qcode} for qcode in qcodes
        ], hold_time=50)

    def run_input_scenario(self, name, *, usb=False):
        disk = Path(self.scratch_file(f"input-{name}.img"))
        make_fat_disk(disk, app_path("input"))
        options = "firmware-console=serial,nvram=none"
        if usb:
            options += ",i8042=off"
        vm = self.launch_ia64(
            name=name, media=disk, machine_options=options)
        sent = set()

        def respond(case):
            if not case.passed or case.case_id in sent:
                return
            if case.case_id == "ready-basic":
                self._send_keys(vm, ("x",))
            elif case.case_id == "ready-modifier":
                self._send_keys(vm, ("shift", "a"))
            elif case.case_id == "ready-extended":
                self._send_keys(vm, ("up",))
            else:
                return
            sent.add(case.case_id)

        self.wait_ia64_suite(
            vm, "input", INPUT_CASES, timeout=45.0, on_case=respond)
        self.assertEqual(
            sent, {"ready-basic", "ready-modifier", "ready-extended"})

    def test_ps2_keyboard(self):
        self.run_input_scenario("ps2")

    def test_usb_keyboard_without_i8042(self):
        self.run_input_scenario("usb", usb=True)


if __name__ == "__main__":
    QemuSystemTest.main()
