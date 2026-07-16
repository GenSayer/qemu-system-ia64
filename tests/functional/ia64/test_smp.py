#!/usr/bin/env python3
"""Four-processor firmware rendezvous under multi-threaded TCG."""

# SPDX-License-Identifier: GPL-2.0-or-later

from pathlib import Path

from qemu_test import QemuSystemTest

from ia64.console import Ia64FirmwareTest
from ia64.efi_build import app_path
from ia64.media import make_fat_disk


SMP_CASES = {
    "sal-ap-wake", "four-processor-rendezvous", "repeat-rendezvous",
    "atomic-16-byte-semaphore", "big-endian-16-byte-semaphore",
}


class Ia64Smp(Ia64FirmwareTest):
    def test_four_processors_mttcg(self):
        disk = Path(self.scratch_file("smp.img"))
        nvram = self.make_nvram()
        make_fat_disk(disk, app_path("smp"))
        vm = self.launch_ia64(
            media=disk, smp=4,
            machine_options=f"firmware-console=serial,nvram={nvram}",
            extra_args=("-accel", "tcg,thread=multi"))
        result = self.wait_ia64_suite(vm, "smp", SMP_CASES, timeout=60.0)
        self.assertSetEqual(set(result.cases), SMP_CASES)


if __name__ == "__main__":
    QemuSystemTest.main()
