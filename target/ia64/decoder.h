/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * IA-64 bundle/template decode helpers shared by the runtime target and tests.
 */

#ifndef TARGET_IA64_DECODER_H
#define TARGET_IA64_DECODER_H

#include <stdbool.h>
#include <stdint.h>

#define IA64_BUNDLE_SLOTS 3
#define IA64_SLOT_MASK ((1ULL << 41) - 1)

typedef enum IA64TemplateUnit {
    IA64_TEMPLATE_UNIT_RESERVED,
    IA64_TEMPLATE_UNIT_M,
    IA64_TEMPLATE_UNIT_I,
    IA64_TEMPLATE_UNIT_B,
    IA64_TEMPLATE_UNIT_F,
    IA64_TEMPLATE_UNIT_L,
    IA64_TEMPLATE_UNIT_X,
} IA64TemplateUnit;

typedef struct IA64TemplateInfo {
    bool defined;
    const char *name;
    IA64TemplateUnit units[IA64_BUNDLE_SLOTS];
    bool stop_after[IA64_BUNDLE_SLOTS];
} IA64TemplateInfo;

const IA64TemplateInfo *ia64_template_info(uint8_t code);
uint8_t ia64_bundle_template_code(uint64_t low_word);
uint64_t ia64_bundle_slot(uint64_t low_word, uint64_t high_word, unsigned slot);

#endif
