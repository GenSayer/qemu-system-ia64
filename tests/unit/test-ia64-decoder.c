/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * IA-64 decoder unit tests.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "target/ia64/decoder.h"

typedef const char *(*TestFn)(void);

typedef struct TestCase {
    const char *name;
    TestFn fn;
} TestCase;

static char failure[128];

static const char *failf(const char *message)
{
    snprintf(failure, sizeof(failure), "%s", message);
    return failure;
}

static const char *fail_uint(const char *label, unsigned long long actual,
                             unsigned long long expected)
{
    snprintf(failure, sizeof(failure), "%s: expected %llu got %llu",
             label, expected, actual);
    return failure;
}

static void set_bits(uint8_t bytes[16], unsigned low, unsigned width,
                     uint64_t value)
{
    unsigned i;

    for (i = 0; i < width; ++i) {
        const unsigned bit = low + i;
        const uint8_t mask = 1u << (bit & 7);

        if ((value >> i) & 1ULL) {
            bytes[bit >> 3] |= mask;
        } else {
            bytes[bit >> 3] &= ~mask;
        }
    }
}

static void build_bundle(uint8_t bytes[16], uint8_t template_code,
                         uint64_t slot0, uint64_t slot1, uint64_t slot2)
{
    memset(bytes, 0, 16);
    set_bits(bytes, 0, 5, template_code);
    set_bits(bytes, 5, 41, slot0);
    set_bits(bytes, 46, 41, slot1);
    set_bits(bytes, 87, 41, slot2);
}

static uint64_t load_le64(const uint8_t *bytes)
{
    unsigned i;
    uint64_t value = 0;

    for (i = 0; i < 8; ++i) {
        value |= (uint64_t)bytes[i] << (i * 8);
    }
    return value;
}

static const char *test_template_inventory(void)
{
    unsigned i;
    unsigned defined = 0;
    unsigned reserved = 0;

    for (i = 0; i < 32; ++i) {
        const IA64TemplateInfo *info = ia64_template_info(i);

        if (info->defined) {
            ++defined;
        } else {
            ++reserved;
        }
    }

    if (defined != 24) {
        return fail_uint("defined templates", defined, 24);
    }
    if (reserved != 8) {
        return fail_uint("reserved templates", reserved, 8);
    }
    if (strcmp(ia64_template_info(0x04)->name, "MLX") != 0) {
        return failf("template 0x04 name");
    }
    if (strcmp(ia64_template_info(0x16)->name, "BBB") != 0) {
        return failf("template 0x16 name");
    }
    return NULL;
}

static const char *test_template_stops(void)
{
    const IA64TemplateInfo *t00 = ia64_template_info(0x00);
    const IA64TemplateInfo *t01 = ia64_template_info(0x01);
    const IA64TemplateInfo *t03 = ia64_template_info(0x03);
    const IA64TemplateInfo *t0a = ia64_template_info(0x0a);
    const IA64TemplateInfo *t0b = ia64_template_info(0x0b);

    if (t00->stop_after[0] || t00->stop_after[1] || t00->stop_after[2]) {
        return failf("template 0x00 stop map");
    }
    if (!t01->stop_after[2]) {
        return failf("template 0x01 end stop");
    }
    if (!t03->stop_after[0] || !t03->stop_after[2]) {
        return failf("template 0x03 stop map");
    }
    if (!t0a->stop_after[0] || t0a->stop_after[1] || t0a->stop_after[2]) {
        return failf("template 0x0a stop map");
    }
    if (!t0b->stop_after[0] || !t0b->stop_after[2]) {
        return failf("template 0x0b stop map");
    }
    if (ia64_template_info(0x06)->defined) {
        return failf("template 0x06 must be reserved");
    }
    return NULL;
}

static const char *test_bundle_unpack(void)
{
    uint8_t bytes[16];
    const uint64_t slot0 = 0x0012345678ULL & IA64_SLOT_MASK;
    const uint64_t slot1 = 0x000abcdef0ULL & IA64_SLOT_MASK;
    const uint64_t slot2 = 0x00013579bdULL & IA64_SLOT_MASK;
    uint64_t low;
    uint64_t high;

    build_bundle(bytes, 0x10, slot0, slot1, slot2);
    low = load_le64(bytes);
    high = load_le64(bytes + 8);

    if (ia64_bundle_template_code(low) != 0x10) {
        return fail_uint("bundle template",
                         ia64_bundle_template_code(low), 0x10);
    }
    if (ia64_bundle_slot(low, high, 0) != slot0) {
        return failf("slot 0 unpack");
    }
    if (ia64_bundle_slot(low, high, 1) != slot1) {
        return failf("slot 1 unpack");
    }
    if (ia64_bundle_slot(low, high, 2) != slot2) {
        return failf("slot 2 unpack");
    }
    return NULL;
}

int main(void)
{
    static const TestCase tests[] = {
        { "template inventory", test_template_inventory },
        { "template stops", test_template_stops },
        { "bundle unpack", test_bundle_unpack },
    };
    unsigned i;
    int status = 0;

    printf("TAP version 13\n");
    printf("1..%zu\n", sizeof(tests) / sizeof(tests[0]));

    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
        const char *error = tests[i].fn();

        if (error == NULL) {
            printf("ok %u - %s\n", i + 1, tests[i].name);
        } else {
            status = 1;
            printf("not ok %u - %s\n", i + 1, tests[i].name);
            printf("# %s\n", error);
        }
    }

    return status;
}
