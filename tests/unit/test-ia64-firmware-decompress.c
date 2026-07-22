/*
 * Host-side test for the freestanding IA-64 EFI decompression module.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "fw-decompress.h"

void fw_set_mem(VOID *buffer, UINTN size, UINT8 value)
{
    UINT8 *bytes = buffer;

    while (size-- != 0) {
        *bytes++ = value;
    }
}

int main(void)
{
    return fw_decompress_selftest() ? 0 : 1;
}
