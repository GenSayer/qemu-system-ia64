/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Pure unit tests for the IA-64 floating-point register representation.
 */

#include "qemu/osdep.h"
#include "target/ia64/cpu.h"
#include "target/ia64/fpreg.h"

typedef const char *(*TestFn)(void);

typedef struct TestCase {
    const char *name;
    TestFn fn;
} TestCase;

typedef struct Binary32Case {
    uint32_t value;
    uint64_t low;
    uint64_t high;
} Binary32Case;

typedef struct Binary64Case {
    uint64_t value;
    uint64_t low;
    uint64_t high;
} Binary64Case;

static char failure[192];

static void reset_env(CPUIA64State *env)
{
    memset(env, 0, sizeof(*env));
    env->fr[1] = IA64_FR_ONE;
    set_float_2nan_prop_rule(float_2nan_prop_ab, &env->fp_status);
    set_float_3nan_prop_rule(float_3nan_prop_abc, &env->fp_status);
    set_float_infzeronan_rule(float_infzeronan_dnan_never, &env->fp_status);
    set_float_default_nan_pattern(0b01000000, &env->fp_status);
}

static const char *fail_u64(const char *label, uint64_t actual,
                            uint64_t expected)
{
    snprintf(failure, sizeof(failure),
             "%s: expected %016" PRIx64 " got %016" PRIx64,
             label, expected, actual);
    return failure;
}

static const char *expect_spill(const CPUIA64State *env, unsigned reg,
                                uint64_t expected_low,
                                uint64_t expected_high)
{
    uint64_t low;
    uint64_t high;

    ia64_fpreg_to_spill(env, reg, &low, &high);
    if (low != expected_low) {
        return fail_u64("spill low", low, expected_low);
    }
    if (high != expected_high) {
        return fail_u64("spill high", high, expected_high);
    }
    return NULL;
}

static const char *test_constants(void)
{
    CPUIA64State env;
    const char *error;

    reset_env(&env);
    env.fr[0] = UINT64_MAX;
    env.fr[1] = 0;
    ia64_fpreg_from_spill(&env, 0, UINT64_MAX, 0x3ffff);
    ia64_fpreg_from_spill(&env, 1, UINT64_MAX, 0x3ffff);
    if (env.fr[0] != UINT64_MAX || env.fr[1] != 0) {
        return "write to architectural f0/f1 was not ignored";
    }

    error = expect_spill(&env, 0, 0, 0);
    if (error != NULL) {
        return error;
    }
    error = expect_spill(&env, 1, 0x8000000000000000ULL, 0xffff);
    if (error != NULL) {
        return error;
    }
    if (ia64_fpreg_is_nat(&env, 0) || ia64_fpreg_is_nat(&env, 1)) {
        return "architectural constants reported as NaTVal";
    }
    return NULL;
}

static const char *test_binary32(void)
{
    static const Binary32Case cases[] = {
        { 0x00000000, 0x0000000000000000ULL, 0x0000000000000000ULL },
        { 0x80000000, 0x0000000000000000ULL, 0x0000000000020000ULL },
        { 0x3f800000, 0x8000000000000000ULL, 0x000000000000ffffULL },
        { 0x00000001, 0x0000010000000000ULL, 0x000000000000ff81ULL },
        { 0x7f800000, 0x8000000000000000ULL, 0x000000000001ffffULL },
        { 0x7fc12345, 0xc123450000000000ULL, 0x000000000001ffffULL },
    };
    CPUIA64State env;
    unsigned i;

    reset_env(&env);
    for (i = 0; i < G_N_ELEMENTS(cases); i++) {
        const char *error;

        ia64_fpreg_from_binary32(&env, 2, cases[i].value);
        error = expect_spill(&env, 2, cases[i].low, cases[i].high);
        if (error != NULL) {
            return error;
        }
        if (ia64_fpreg_to_binary32(&env, 2) != cases[i].value) {
            return fail_u64("binary32 round-trip",
                            ia64_fpreg_to_binary32(&env, 2), cases[i].value);
        }
    }
    return NULL;
}

static const char *test_binary64(void)
{
    static const Binary64Case cases[] = {
        { 0x0000000000000000ULL, 0x0000000000000000ULL,
          0x0000000000000000ULL },
        { 0x8000000000000000ULL, 0x0000000000000000ULL,
          0x0000000000020000ULL },
        { 0x3ff0000000000000ULL, 0x8000000000000000ULL,
          0x000000000000ffffULL },
        { 0x0000000000000001ULL, 0x0000000000000800ULL,
          0x000000000000fc01ULL },
        { 0x7ff0000000000000ULL, 0x8000000000000000ULL,
          0x000000000001ffffULL },
        { 0x7ff8123456789abcULL, 0xc091a2b3c4d5e000ULL,
          0x000000000001ffffULL },
    };
    CPUIA64State env;
    unsigned i;

    reset_env(&env);
    for (i = 0; i < G_N_ELEMENTS(cases); i++) {
        const char *error;

        ia64_fpreg_from_binary64(&env, 2, cases[i].value);
        error = expect_spill(&env, 2, cases[i].low, cases[i].high);
        if (error != NULL) {
            return error;
        }
        if (ia64_fpreg_to_binary64(&env, 2) != cases[i].value) {
            return fail_u64("binary64 round-trip",
                            ia64_fpreg_to_binary64(&env, 2), cases[i].value);
        }
    }
    return NULL;
}

static const char *test_integer_significand(void)
{
    CPUIA64State env;
    uint64_t value = 0x0123456789abcdefULL;
    const char *error;

    reset_env(&env);
    ia64_fpreg_from_spill(&env, 5, value, IA64_FP_REG_INTEGER_EXP);
    error = expect_spill(&env, 5, value, IA64_FP_REG_INTEGER_EXP);
    if (error != NULL) {
        return error;
    }
    if (!ia64_fpreg_is_integer(&env, 5) ||
        !(env.fr_int_origin[0] & (1ULL << 5)) ||
        env.fr_int_value[5] != value) {
        return "integer-significand tags were not restored";
    }
    return NULL;
}

static const char *test_extended(void)
{
    CPUIA64State env;
    const uint64_t low = 0x8123456789abcdefULL;
    const uint32_t exp = 0x12345;
    const uint64_t high = exp | (1ULL << 17);
    uint64_t mant;
    uint32_t observed_exp;
    bool sign;
    const char *error;

    reset_env(&env);
    ia64_fpreg_from_spill(&env, 70, low, high);
    error = expect_spill(&env, 70, low, high);
    if (error != NULL) {
        return error;
    }
    if (!ia64_fpreg_get_extended(&env, 70, &sign, &observed_exp, &mant) ||
        !sign || observed_exp != exp || mant != low) {
        return "extended register format was not retained exactly";
    }
    return NULL;
}

static const char *test_natval(void)
{
    CPUIA64State env;
    const char *error;

    reset_env(&env);
    ia64_fpreg_from_spill(&env, 12, 0, IA64_FP_REG_NATVAL_EXP);
    error = expect_spill(&env, 12, 0, IA64_FP_REG_NATVAL_EXP);
    if (error != NULL) {
        return error;
    }
    if (!ia64_fpreg_is_nat(&env, 12) || ia64_fpreg_is_integer(&env, 12)) {
        return "NaTVal tags are inconsistent";
    }
    return NULL;
}

static const char *test_spill_fill_round_trip(void)
{
    static const struct {
        uint64_t low;
        uint64_t high;
    } cases[] = {
        { 0x0000000000000000ULL, 0x0000000000020000ULL },
        { 0xfedcba9876543210ULL, IA64_FP_REG_INTEGER_EXP },
        { 0x0000000000000000ULL, IA64_FP_REG_NATVAL_EXP },
        { 0xc123456789abcdefULL, 0x000000000003ffffULL },
        { 0x8123456789abcdefULL, 0x0000000000023456ULL },
    };
    CPUIA64State env;
    unsigned i;

    reset_env(&env);
    for (i = 0; i < G_N_ELEMENTS(cases); i++) {
        const char *error;

        ia64_fpreg_from_spill(&env, 20 + i, cases[i].low, cases[i].high);
        error = expect_spill(&env, 20 + i, cases[i].low, cases[i].high);
        if (error != NULL) {
            return error;
        }
    }
    return NULL;
}

static const char *test_stale_tags(void)
{
    CPUIA64State env;
    const unsigned reg = 9;
    const uint64_t bit = 1ULL << reg;

    reset_env(&env);
    env.fr_nat[0] |= bit;
    env.fr_sig[0] |= bit;
    env.fr_ext_valid[0] |= bit;
    env.fr_int_origin[0] |= bit;
    env.fr_int_value[reg] = UINT64_MAX;

    ia64_fpreg_from_binary64(&env, reg, 0x4000000000000000ULL);
    if ((env.fr_nat[0] | env.fr_sig[0] | env.fr_ext_valid[0] |
         env.fr_int_origin[0]) & bit) {
        return "binary64 write left a stale representation tag";
    }
    if (env.fr_int_value[reg] != 0) {
        return "binary64 write left a stale integer value";
    }

    ia64_fpreg_from_spill(&env, reg, 0x8000000000000000ULL, 0xffff);
    if ((env.fr_nat[0] | env.fr_sig[0] | env.fr_int_origin[0]) & bit) {
        return "extended fill left an incompatible representation tag";
    }
    if (!(env.fr_ext_valid[0] & bit)) {
        return "extended fill did not set its valid tag";
    }
    return NULL;
}

int main(void)
{
    static const TestCase tests[] = {
        { "architectural f0/f1", test_constants },
        { "binary32 formats", test_binary32 },
        { "binary64 formats", test_binary64 },
        { "integer significand", test_integer_significand },
        { "extended format", test_extended },
        { "NaTVal", test_natval },
        { "spill fill round-trip", test_spill_fill_round_trip },
        { "stale tag clearing", test_stale_tags },
    };
    unsigned i;
    int status = 0;

    printf("TAP version 13\n");
    printf("1..%zu\n", G_N_ELEMENTS(tests));

    for (i = 0; i < G_N_ELEMENTS(tests); i++) {
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
