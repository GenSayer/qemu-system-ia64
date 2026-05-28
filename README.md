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
- PCI root bus, CMD646 IDE/ATAPI boot storage, ICH9 AHCI, OHCI/UHCI USB,
  standard VGA, PS/2 input, and MMIO serial console

## Build

Configure and build the IA-64 target:

```sh
./configure --target-list=ia64-softmmu
ninja -C build qemu-system-ia64 roms/ia64-firmware/ia64-firmware.bin
```

The firmware build requires an IA-64 ELF cross toolchain named
`ia64-linux-gnu-*` in `PATH`.

## Run

```sh
./build/qemu-system-ia64 \
  -machine ia64-vpc \
  -smp 1 \
  -m 2048 \
  -bios ./build/roms/ia64-firmware/ia64-firmware.bin \
  -drive file=<guest-media.iso>,if=ide,media=cdrom,format=raw,readonly=on \
  -vga std \
  -display gtk
```

Use `-serial stdio` to see the serial output.

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

## Legal discrimer

This repository does not contain any kind of unauthorised,unlicensed, or proprietary images or copies, such as disk images and firmware, machine ROM dumps, or operating system binaries.

This project is not affiliated with or endorsed by Intel, HPE or the QEMU project.

Guest operating system images must be supplied by the user under their own applicable licences.
