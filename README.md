# qemu-system-ia64

Experimental QEMU system-emulation target for IA-64/Itanium guests.
This codebase is written using LLMs. Therefore, do not send any pull requests related to this project to the QEMU upstream.

## Emulated Platform

The default machine is `ia64-vpc`.  It models a small Itanium 2-class virtual
PC profile intended for firmware, boot loader, and operating-system bring-up:

- IA-64 CPU state, TCG translation, PAL/SAL helpers, register stack engine, TLB
  and VHPT paths
- project-owned IA-64 EFI firmware built from source under `roms/ia64-firmware/`
- 1 vCPU, 2 GiB default RAM
- Local SAPIC and I/O SAPIC interrupt model
- ACPI 2.0-style platform tables
- PCI root bus, CMD646 IDE/ATAPI (disabled by default), LSI53C895A SCSI boot storage, ICH9 AHCI, OHCI/UHCI USB,
  standard VGA, PS/2 input, and MMIO serial console

## Build

Configure and build the IA-64 target with GTK:

```sh
./configure --enable-gtk
ninja -C build qemu-system-ia64 roms/ia64-firmware/ia64-firmware.bin
```

For guest-performance measurements, use an IA-64-only build without the
compiler hardening passes that add substantial overhead to TCG helper calls:

```sh
./configure --target-list=ia64-softmmu \
  --disable-qom-cast-debug \
  --disable-stack-protector \
  --extra-cflags='-O2 -fno-stack-protector -fzero-call-used-regs=skip -ftrivial-auto-var-init=uninitialized'\
  --enable-gtk
ninja -C build qemu-system-ia64 roms/ia64-firmware/ia64-firmware.bin
```

This configuration is intended for performance testing.

The firmware build requires an IA-64 ELF cross toolchain named
`ia64-linux-gnu-*` in `PATH`.

## Run

```sh
./build/qemu-system-ia64 \
  -machine ia64-vpc \
  -bios ./build/roms/ia64-firmware/ia64-firmware.bin \
  -drive file=<guest-media.iso>,media=cdrom,format=raw,readonly=on \
  -vga std \
  -display gtk
```

Use `-serial stdio` to see the serial output. `-debug-port ...` can publish a debug port that Microsoft Windows kernels may use, as standardized in ACPI standard as `DBGP`.
To disable i8042, append `i8042=off` to the `-machine ia64-vpc` option, like `-machine ia64-vpc,i8042=off`. You can use `firmware-console=serial`, which might route the kernel's standard output to the serial.

EFI variables are persistent. By default, `ia64-vpc` loads and saves a 64 KiB
file named `nvram` in the directory containing the firmware selected by
`-bios`. Use a separate file for each virtual machine by specifying
`-machine ia64-vpc,nvram=<path>`. Specify `nvram=none` to use volatile EFI
variables without a backing file. Relative paths are resolved from QEMU's
current working directory.

<img width="639" height="461" alt="Gentoo linux is booting on qemu-system-ia64" src="https://github.com/user-attachments/assets/d16ad66d-ffdb-4e27-8e3d-a056498e4ed7" />


## Tests

Useful smoke checks after building:

```sh
ninja -C build test-ia64-decoder
python3 tests/unit/test-ia64-device-inventory.py ./build/qemu-system-ia64
python3 tests/unit/test-ia64-fw-smoke.py ./build/roms/ia64-firmware/ia64-firmware.bin
```

## Status

The target is still incomplete.  It is suitable for IA-64 firmware and OS boot experiments, but instruction coverage, privileged architecture behavior,
floating-point corner cases, and device compatibility still need validation against the IA-64, EFI, SAL, and ACPI specifications.

## Legal disclaimer

This repository does not include third-party operating system images, disk images, firmware images, machine ROM dumps, proprietary firmware blobs, or operating system binaries.

Guest operating system images, firmware, installation media, and other third-party materials must be supplied by users under their own applicable licenses.

This project is an independent experimental QEMU IA-64 system emulation project. It is not affiliated with, endorsed by, sponsored by, or supported by Intel, HPE, the QEMU Project, the Gentoo Foundation, the Gentoo Project, or Microsoft Corporation.

QEMU is used as the upstream base for this fork. QEMU as a whole is licensed under the GNU General Public License, version 2. See the license files in this repository for details.

Gentoo is a trademark of the Gentoo Foundation, Inc. and of Förderverein Gentoo e.V.

Microsoft and Windows are trademarks of the Microsoft group of companies.

All other product names, project names, company names, and trademarks are the property of their respective owners.
