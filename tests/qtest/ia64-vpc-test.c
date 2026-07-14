/*
 * IA-64 virtual platform machine tests
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "libqtest.h"

#define IA64_LEGACY_IO_BASE         0x000000800010000000ULL
#define IA64_ACPI_PM_IO_BASE        0x00002000ULL
#define IA64_ACPI_PM_RESET_OFFSET   0x0cULL
#define IA64_ACPI_PM_RESET_VALUE    0x01U
#define IA64_FW_HANDOFF_ADDR        0x00000000000ff000ULL
#define IA64_FW_HANDOFF_VERSION_OFF 0x08ULL
#define IA64_FW_HANDOFF_I8042_OFF   0x38ULL
#define IA64_FW_HANDOFF_VERSION     7ULL

static void test_acpi_reset_register(void)
{
    QTestState *qts = qtest_init("-machine ia64-vpc -S");

    qtest_writeb(qts,
                 IA64_LEGACY_IO_BASE + IA64_ACPI_PM_IO_BASE +
                 IA64_ACPI_PM_RESET_OFFSET,
                 IA64_ACPI_PM_RESET_VALUE);
    qtest_qmp_eventwait(qts, "RESET");
    qtest_quit(qts);
}

static void test_i8042_firmware_handoff(void)
{
    QTestState *qts;

    qts = qtest_init("-machine ia64-vpc -S");
    g_assert_cmphex(qtest_readq(qts, IA64_FW_HANDOFF_ADDR +
                               IA64_FW_HANDOFF_VERSION_OFF), ==,
                    IA64_FW_HANDOFF_VERSION);
    g_assert_cmphex(qtest_readq(qts, IA64_FW_HANDOFF_ADDR +
                               IA64_FW_HANDOFF_I8042_OFF), ==, 1);
    qtest_quit(qts);

    qts = qtest_init("-machine ia64-vpc,i8042=off -S");
    g_assert_cmphex(qtest_readq(qts, IA64_FW_HANDOFF_ADDR +
                               IA64_FW_HANDOFF_VERSION_OFF), ==,
                    IA64_FW_HANDOFF_VERSION);
    g_assert_cmphex(qtest_readq(qts, IA64_FW_HANDOFF_ADDR +
                               IA64_FW_HANDOFF_I8042_OFF), ==, 0);
    qtest_quit(qts);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/ia64-vpc/acpi-reset-register",
                   test_acpi_reset_register);
    qtest_add_func("/ia64-vpc/i8042-firmware-handoff",
                   test_i8042_firmware_handoff);

    return g_test_run();
}
