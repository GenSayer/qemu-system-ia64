#!/usr/bin/env sh
# SPDX-License-Identifier: GPL-2.0-or-later
set -eu

output="$1"
source="$2"
linker_script="$3"
image_base="${4:-0x4000000}"
output_dir=$(dirname "$output")
name=$(basename "$output" .efi)

# Do not inherit the host project's generic CC/LD/OBJCOPY variables: QEMU's
# build environment normally sets those to native tools.  Dedicated overrides
# are still useful for non-standard IA-64 cross-toolchain prefixes.
cc=${IA64_CC:-ia64-linux-gnu-gcc}
ld=${IA64_LD:-ia64-linux-gnu-ld}
objcopy=${IA64_OBJCOPY:-ia64-linux-gnu-objcopy}
object="$output_dir/$name.o"
elf="$output_dir/$name.elf"
libgcc=$($cc -print-libgcc-file-name)

$cc -O2 -ffreestanding -fno-builtin -nostdlib -nostdinc -mno-sdata \
    -fno-stack-protector -fno-common -fno-optimize-sibling-calls -fno-pic \
    -Wall -Wextra -Werror -c -o "$object" "$source"
$ld -nostdlib -static -T "$linker_script" -o "$elf" "$object" "$libgcc"
$objcopy --strip-debug -R .comment -O pei-ia64 \
    --image-base="$image_base" --subsystem=10 \
    "$elf" "$output"
