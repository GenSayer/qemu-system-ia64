#!/usr/bin/env sh
# SPDX-License-Identifier: GPL-2.0-or-later
set -eu

OUT_BIN="$1"
SRC_DIR="$2"
OUT_DIR="$(dirname "$OUT_BIN")"

AS="${AS:-ia64-linux-gnu-as}"
CC="${CC:-ia64-linux-gnu-gcc}"
LD="${LD:-ia64-linux-gnu-ld}"
OBJCOPY="${OBJCOPY:-ia64-linux-gnu-objcopy}"
LIBGCC="$("$CC" -print-libgcc-file-name)"

ENTRY_O="${OUT_DIR}/ia64-fw-entry.o"
FW_O="${OUT_DIR}/ia64-fw-firmware.o"
FW_ELF="${OUT_DIR}/ia64-firmware.elf"

"$AS" -o "$ENTRY_O" "${SRC_DIR}/entry.S"
"$CC" -O2 -fno-builtin -ffreestanding -nostdinc -nostdlib \
  -G 0 -mno-sdata -fno-stack-protector -fno-common -fno-optimize-sibling-calls \
  -fno-pic \
  -Wall -Wextra -Wno-unused-parameter \
  -c -o "$FW_O" "${SRC_DIR}/firmware.c"
"$LD" -nostdlib -static -T "${SRC_DIR}/firmware.lds" -o "$FW_ELF" "$ENTRY_O" "$FW_O" "$LIBGCC"
"$OBJCOPY" -O binary "$FW_ELF" "$OUT_BIN"
