# SPDX-License-Identifier: GPL-2.0-or-later
# IA-64 firmware build rules
#
# Builds ia64-firmware.bin from entry.S + firmware.c with the IA-64
# cross toolchain in the build directory.

sh_prog = find_program('sh')
build_fw_script = files('build_firmware.sh')

ia64_firmware_bin = custom_target(
  'ia64-firmware.bin',
  output: 'ia64-firmware.bin',
  input: files('entry.S', 'firmware.c', 'decompress.c', 'ebc.c',
               'legacy_io.c', 'debug_protocols.c', 'usb_protocols.c',
               'debug_support.c', 'pointer_protocol.c', 'uga_io.c',
               'firmware.lds', 'linker-symbols.h'),
  command: [
    sh_prog,
    build_fw_script,
    '@OUTPUT@',
    meson.current_source_dir(),
  ],
  build_by_default: true,
  install: false,
)
