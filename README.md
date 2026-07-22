# qemu-system-ia64

Experimental QEMU full-system emulation target for IA-64/Itanium guests.
This codebase is written using LLMs. Therefore, do not send any pull requests
related to this project to the QEMU upstream.

## Emulated Platform

The default machine is `ia64-vpc`.
It models an IA-64 virtual PC profile intended for firmware, boot loader, and operating-system bring-up:

- Montecito CPU model by default, with Madison selection available.
  Both models use TCG translation and provide PAL/SAL helpers, the register stack engine, TLB/VHPT paths, and architectural floating-point state.
- 1 vCPU by default, configurable from 1 to 4 vCPUs; MTTCG is supported with `-accel tcg,thread=multi`
- 2 GiB default RAM
- project-owned IA-64 EFI firmware built from source under `roms/ia64-firmware/`
- EFI boot/runtime services, an interactive pre-boot shell, PE/COFF and EBC image loading, decompression, filesystems, graphics, storage, USB/input, and debug-support protocols
- local SAPIC, I/O SAPIC, ACPI platform tables, RTC, watchdog, persistent NVRAM, and serial/debug ports
- PCI root bus with LSI53C895A SCSI boot storage, ICH9 AHCI, e1000 Ethernet, OHCI/UHCI USB, and optional CMD646 IDE/ATAPI
- ATI-compatible PCI graphics by default, with standard VGA available as an alternative
- PS/2 input by default, or an automatically attached USB keyboard and absolute USB tablet when `i8042=off` is selected

## Build

Configure and build the IA-64 target with GTK:

```sh
./configure --enable-gtk
ninja -C build qemu-system-ia64 roms/ia64-firmware/ia64-firmware.bin
```

For guest-performance measurements, use an IA-64-only build without the compiler hardening passes that add substantial overhead to TCG helper calls:

```sh
./configure --target-list=ia64-softmmu \
  --enable-lto \
  --disable-qom-cast-debug \
  --disable-stack-protector \
  --extra-cflags='-O2 -fno-stack-protector -fzero-call-used-regs=skip -ftrivial-auto-var-init=uninitialized' \
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
  -drive file=/path/to/guest-media.iso,media=cdrom,format=raw,readonly=on \
  -display gtk
```

### CPU model selection

The `ia64-vpc` machine uses the `montecito` CPU model by default.
Select a different model with `-cpu`.
For example, use `-cpu madison` when the guest requires the processor's hardware IA-32 execution environment:

```sh
./build/qemu-system-ia64 \
  -machine ia64-vpc \
  -cpu madison \
  -bios ./build/roms/ia64-firmware/ia64-firmware.bin \
  ...
```

CPU selection changes guest-visible CPUID and PAL information as well as the available instruction set.

#### `montecito` (default)

Montecito implements the later 16-byte operations `ld16`, `ld16.acq`, `st16`, `st16.rel`, `cmp8xchg16.acq`, and `cmp8xchg16.rel`.
It has no hardware IA-32 execution engine, so an eligible `br.ia` or `rfi` request to enter IA-32 mode raises a Disabled ISA Transition fault.
The `vmsw.0` and `vmsw.1` encodings are recognized as virtualization instructions.
Because this emulator does not provide an IA-64 virtual-machine environment, these instructions produce the architecturally appropriate Privileged Operation or Virtualization fault instead of executing a mode switch.

#### `madison`

Madison provides the hardware IA-32 execution environment.
Eligible `br.ia` and `rfi` transitions execute IA-32 code, and IA-32 `JMPE` returns to IA-64.
The later 16-byte operations and virtualization instructions are not available and raise an Illegal Operation fault.

`-cpu help` lists the available names.
The generic `ia64-cpu` entry is retained for compatibility and currently has Madison-like capabilities.
Use an explicit generation name for predictable guest-visible behavior.

For four vCPUs, MTTCG, 8 GiB of RAM, and USB input without the PS/2 controller:

```sh
./build/qemu-system-ia64 \
  -machine ia64-vpc,i8042=off,nvram=/path/to/guest.nvram \
  -bios ./build/roms/ia64-firmware/ia64-firmware.bin \
  -drive file=/path/to/guest-media.iso,media=cdrom,format=raw,readonly=on \
  -accel tcg,thread=multi \
  -smp 4 \
  -m 8G \
  -display gtk
```

The machine automatically attaches a USB keyboard and absolute USB tablet when `i8042=off` is used, so `-usb` is not required.
Omitting `-vga` selects the default ATI-compatible display. This is recommended for graphical guests; use `-vga std` only when standard VGA compatibility is specifically needed.

An e1000 (82540EM-compatible) PCI network controller is attached by default.
When QEMU is built with libslirp, connect it to user-mode networking with:

```sh
-nic user,model=e1000
```

For a host TAP interface, use:

```sh
-nic tap,model=e1000,ifname=tap0,script=no,downscript=no
```

Use `-nic none` to omit the controller. EFI network boot is not currently
provided; the controller is available to the guest operating system.

Use `-serial stdio` to view serial output. 
The `-debug-port` option publishes the guest debug transport described by the ACPI DBGP table; for example, `-debug-port tcp::4444,server=on,wait=on,nodelay=on`.

EFI variables are persistent. By default, `ia64-vpc` loads and saves a 64 KiB file named `nvram` in the directory containing the firmware selected by `-bios`. Use a separate file for each virtual machine with
`-machine ia64-vpc,nvram=<path>`, or specify `nvram=none` for volatile EFI variables. Relative paths are resolved from QEMU's current working directory.

At each startup, the firmware waits three seconds for F2, F12, or Delete before continuing normal boot. Any of these keys opens the embedded EFI shell on the graphical and serial consoles. The shell can inspect the machine and its filesystems, launch an EFI application, select a boot target, update the boot order, and set the real-time clock. For example:

```text
info
map
ls fs0:\EFI\BOOT
run fs0:\EFI\BOOT\TOOL.EFI argument
boot
boot Boot0001
boot fs0:
bootorder Boot0001 Boot0000
bootnext Boot0001
date 2026-07-17
time 12:34:56
exit
```

`boot fsN:` launches `\EFI\BOOT\BOOTIA64.EFI` from that filesystem. `bootnext` is consumed by the next automatic boot attempt. Boot order, next-boot selection, and clock changes survive a reset when the machine has NVRAM backing; with `nvram=none`, they remain valid only for the current process.

An installed EFI system can be attached with an ordinary disk drive:

```sh
-drive file=/path/to/guest-disk.qcow2,format=qcow2
```

The firmware supports persistent EFI boot entries, including short-form hard
drive device paths, and can boot supported loaders from FAT partitions.

<img width="692" height="598" alt="Microsoft Windows Server 2008 for Itanium-Based Systems is running on qemu-system-ia64, showing winver and task manager." src="https://github.com/user-attachments/assets/cbf318e6-1202-4a11-95ed-a62f105a8f64" />
<img width="692" height="598" alt="Microsoft Windows Server 2008 for Itanium-Based Systems is running on qemu-system-ia64, executing systeminfo" src="https://github.com/user-attachments/assets/ce893757-a4b0-4003-8ba8-87fad23d739c" />

## Tests

Run the behavior-oriented IA-64 unit, TCG, and machine tests after building:

```sh
build/pyvenv/bin/meson test -C build --suite ia64 --print-errorlogs
build/pyvenv/bin/meson test -C build --suite qtest-ia64 --print-errorlogs
build/pyvenv/bin/meson test -C build --suite func-ia64 --print-errorlogs
build/pyvenv/bin/meson test -C build --suite func-ia64-thorough --print-errorlogs
```

Use the build-local Meson shown above. 

It is the same version selected by QEMU's configure process; a host `meson` of another version may be unable to read `build/meson-private/build.dat`.
 
Plain `meson test` from the source directory is not valid because the Meson build data lives under `build`.

The TCG registry currently contains 1058 architectural microprograms divided between core, memory/NaT, floating-point,
RSE, MMU, interruption, and PAL groups. Machine tests cover platform wiring and display behavior.

The functional suite builds project-owned EFI applications and boots them from deterministic FAT, GPT, MBR, El Torito, and UDF media. It also exercises the firmware shell through PS/2, USB, and serial input, including direct application execution and NVRAM persistence across restarts.

See [`docs/devel/testing/ia64.rst`](docs/devel/testing/ia64.rst) for focused runs and test-authoring rules.

## Status

The current implementation boots several IA-64 operating-system installers and supports up to four guest processors.
Instruction coverage, privileged behavior, floating-point corner cases, and device compatibility still 
require validation against the IA-64, EFI, SAL, and ACPI specifications.

## Legal disclaimer

This repository does not include third-party operating system images, disk images, firmware images, machine ROM dumps, proprietary firmware blobs, or operating system binaries.

Guest operating system images, firmware, installation media, and other third-party materials must be supplied by users under their own applicable licenses.

This project is an independent experimental QEMU IA-64 system emulation project. It is not affiliated with, endorsed by, sponsored by, or supported by Intel, HPE, the QEMU Project, the Gentoo Foundation, the Gentoo Project, or Microsoft Corporation.

QEMU is used as the upstream base for this fork. QEMU as a whole is licensed under the GNU General Public License, version 2. See the license files in this repository for details.

Gentoo is a trademark of the Gentoo Foundation, Inc. and of Förderverein Gentoo e.V.

Microsoft and Windows are trademarks of the Microsoft group of companies.

The screenshot of Windows Operating System is used with permission from Microsoft.

All other product names, project names, company names, and trademarks are the property of their respective owners.
