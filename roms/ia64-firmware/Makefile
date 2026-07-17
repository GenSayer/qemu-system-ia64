# SPDX-License-Identifier: GPL-2.0-or-later
# IA-64 EFI Firmware Makefile
# Build with ia64-linux-gnu-gcc toolchain

CROSS   = ia64-linux-gnu-
CC      = $(CROSS)gcc
AS      = $(CROSS)as
LD      = $(CROSS)ld
OBJCOPY = $(CROSS)objcopy
PYTHON  ?= python3
LIBGCC  := $(shell $(CC) -print-libgcc-file-name)

CFLAGS  = -O2 -fno-builtin -ffreestanding -nostdinc -nostdlib \
          -G 0 -mno-sdata -fno-stack-protector -fno-common \
          -fno-optimize-sibling-calls -fno-pic \
          -Wall -Wextra -Wno-unused-parameter

ASFLAGS =

LDFLAGS = -nostdlib -static -T firmware.lds

OBJS = entry.o firmware.o

all: ia64-firmware.bin

entry.o: entry.S
	$(AS) $(ASFLAGS) -o $@ $<

firmware.o: firmware.c boot_shell.c linker-symbols.h
	$(CC) $(CFLAGS) -c -o $@ $<

ia64-firmware.elf: $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $(LIBGCC)

ia64-firmware.bin: ia64-firmware.elf
	$(OBJCOPY) -O binary $< $@

clean:
	rm -f $(OBJS) ia64-firmware.elf ia64-firmware.bin

.PHONY: all clean
