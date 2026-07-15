/*
 * IA-64 virtual platform machine tests
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/bitops.h"
#include "qemu/bswap.h"
#include "qemu/units.h"
#include "qobject/qdict.h"
#include "qobject/qlist.h"
#include "libqtest.h"
#include "libqos/generic-pcihost.h"
#include "libqos/pci.h"
#include "hw/pci/pci_ids.h"
#include "hw/pci/pci_regs.h"

#define IA64_LEGACY_IO_BASE          0x000000800010000000ULL
#define IA64_PCI_CONFIG_BASE         0x0000007ff0000000ULL
#define IA64_ACPI_PM_IO_BASE         0x00002000ULL
#define IA64_ACPI_PM1_CNT_OFFSET     0x04ULL
#define IA64_ACPI_PM_RESET_OFFSET    0x0cULL
#define IA64_ACPI_PM_RESET_VALUE     0x01U
#define IA64_RTC_BASE                0x00000000ffef0000ULL
#define IA64_NVRAM_BASE              0x00000000fff00000ULL
#define IA64_NVRAM_SIZE              (64 * KiB)
#define IA64_NVRAM_COMMIT_OFFSET     (IA64_NVRAM_SIZE - 8)
#define IA64_NVRAM_COMMIT_MAGIC      0x54494d4d4f43564eULL
#define IA64_IOSAPIC_BASE            0x0000000080110000ULL
#define IA64_IOSAPIC_IOREGSEL        0x00ULL
#define IA64_IOSAPIC_IOWIN           0x10ULL
#define IA64_IOSAPIC_EOI             0x40ULL
#define IA64_IOSAPIC_RTE_BASE        0x10U
#define IA64_IOSAPIC_RTE_DELIVERY    BIT(12)
#define IA64_IOSAPIC_RTE_REMOTE_IRR  BIT(14)
#define IA64_IOSAPIC_RTE_LEVEL       BIT(15)
#define IA64_FW_HANDOFF_ADDR         0x00000000000ff000ULL
#define IA64_FW_HANDOFF_MAGIC        0x4d41523436414951ULL
#define IA64_FW_HANDOFF_VERSION      7ULL
#define IA64_FW_HANDOFF_RAM_SIZE     0x10ULL
#define IA64_FW_HANDOFF_CONSOLE      0x18ULL
#define IA64_FW_HANDOFF_IDE_DMA      0x20ULL
#define IA64_FW_HANDOFF_DEBUG        0x28ULL
#define IA64_FW_HANDOFF_DEBUG_BASE   0x30ULL
#define IA64_FW_HANDOFF_I8042        0x38ULL
#define IA64_TEST_RAM_SIZE           (256 * MiB)

typedef struct ExpectedPCIDevice {
    unsigned slot;
    uint16_t vendor;
    uint16_t device;
    uint16_t command;
    uint8_t irq_line;
    uint8_t irq_pin;
    uint32_t bars[6];
} ExpectedPCIDevice;

static QTestState *ia64_vpc_start(const char *extra_args)
{
    return qtest_initf("-machine ia64-vpc -m 256M -S %s",
                       extra_args ?: "");
}

static uint64_t ia64_sparse_io_offset(uint32_t port)
{
    return ((uint64_t)(port >> 2) << 12) | (port & 0xfff);
}

static void test_acpi_reset_register(void)
{
    QTestState *qts = ia64_vpc_start(NULL);

    qtest_writeb(qts,
                 IA64_LEGACY_IO_BASE + IA64_ACPI_PM_IO_BASE +
                 IA64_ACPI_PM_RESET_OFFSET,
                 IA64_ACPI_PM_RESET_VALUE);
    qtest_qmp_eventwait(qts, "RESET");
    qtest_quit(qts);
}

static void assert_firmware_handoff(QTestState *qts, uint64_t i8042)
{
    g_assert_cmphex(qtest_readq(qts, IA64_FW_HANDOFF_ADDR), ==,
                    IA64_FW_HANDOFF_MAGIC);
    g_assert_cmphex(qtest_readq(qts, IA64_FW_HANDOFF_ADDR + 8), ==,
                    IA64_FW_HANDOFF_VERSION);
    g_assert_cmphex(qtest_readq(qts, IA64_FW_HANDOFF_ADDR +
                               IA64_FW_HANDOFF_RAM_SIZE), ==,
                    IA64_TEST_RAM_SIZE);
    g_assert_cmphex(qtest_readq(qts, IA64_FW_HANDOFF_ADDR +
                               IA64_FW_HANDOFF_CONSOLE), ==, 1);
    g_assert_cmphex(qtest_readq(qts, IA64_FW_HANDOFF_ADDR +
                               IA64_FW_HANDOFF_IDE_DMA), ==, 1);
    g_assert_cmphex(qtest_readq(qts, IA64_FW_HANDOFF_ADDR +
                               IA64_FW_HANDOFF_DEBUG), ==, 0);
    g_assert_cmphex(qtest_readq(qts, IA64_FW_HANDOFF_ADDR +
                               IA64_FW_HANDOFF_DEBUG_BASE), ==, 0);
    g_assert_cmphex(qtest_readq(qts, IA64_FW_HANDOFF_ADDR +
                               IA64_FW_HANDOFF_I8042), ==, i8042);
}

static void test_firmware_handoff_defaults(void)
{
    QTestState *qts = ia64_vpc_start(NULL);

    assert_firmware_handoff(qts, 1);
    qtest_quit(qts);
}

static void test_firmware_handoff_i8042_off(void)
{
    QTestState *qts = qtest_init("-machine ia64-vpc,i8042=off "
                                 "-m 256M -S");

    assert_firmware_handoff(qts, 0);
    qtest_quit(qts);
}

static bool rtc_value_is_current(uint64_t value)
{
    int64_t now = time(NULL);

    return value >= now - 5 && value <= now + 5;
}

static void test_rtc_aligned_read(void)
{
    QTestState *qts = ia64_vpc_start(NULL);
    uint64_t before_write;
    uint64_t after_write;
    uint64_t after_reset;

    before_write = qtest_readq(qts, IA64_RTC_BASE);
    g_assert_true(rtc_value_is_current(before_write));

    /* The RTC window is deliberately read-only. */
    qtest_writeq(qts, IA64_RTC_BASE, UINT64_MAX);
    after_write = qtest_readq(qts, IA64_RTC_BASE);
    g_assert_true(rtc_value_is_current(after_write));

    qtest_system_reset(qts);
    after_reset = qtest_readq(qts, IA64_RTC_BASE);
    g_assert_true(rtc_value_is_current(after_reset));
    qtest_quit(qts);
}

static void test_nvram_commit_and_restart(void)
{
    const uint64_t test_value = 0x1122334455667788ULL;
    g_autofree char *tmpdir = NULL;
    g_autofree char *path = NULL;
    g_autofree char *quoted_path = NULL;
    g_autofree char *contents = NULL;
    g_autoptr(GError) error = NULL;
    gsize length = 0;
    QTestState *qts;

    tmpdir = g_dir_make_tmp("ia64-vpc-nvram-XXXXXX", &error);
    g_assert_no_error(error);
    g_assert_nonnull(tmpdir);
    path = g_build_filename(tmpdir, "nvram.bin", NULL);
    quoted_path = g_shell_quote(path);

    qts = qtest_initf("-machine ia64-vpc,nvram=%s -m 256M -S",
                      quoted_path);
    qtest_writeq(qts, IA64_NVRAM_BASE, test_value);
    qtest_writeq(qts, IA64_NVRAM_BASE + IA64_NVRAM_COMMIT_OFFSET,
                 IA64_NVRAM_COMMIT_MAGIC);
    qtest_quit(qts);

    g_assert_true(g_file_get_contents(path, &contents, &length, &error));
    g_assert_no_error(error);
    g_assert_cmpuint(length, ==, IA64_NVRAM_SIZE);
    g_assert_cmphex(ldq_le_p(contents), ==, test_value);

    qts = qtest_initf("-machine ia64-vpc,nvram=%s -m 256M -S",
                      quoted_path);
    g_assert_cmphex(qtest_readq(qts, IA64_NVRAM_BASE), ==, test_value);
    qtest_quit(qts);

    g_assert_cmpint(g_unlink(path), ==, 0);
    g_assert_cmpint(g_rmdir(tmpdir), ==, 0);
}

static void ia64_qpci_init(QGenericPCIBus *gbus, QTestState *qts)
{
    qpci_init_generic(gbus, qts, NULL, false);
    gbus->ecam_alloc_ptr = IA64_PCI_CONFIG_BASE;
    gbus->gpex_pio_base = IA64_LEGACY_IO_BASE;
}

static void assert_pci_device(QPCIBus *bus, const ExpectedPCIDevice *expected)
{
    QPCIDevice *dev = qpci_device_find(bus,
                                       QPCI_DEVFN(expected->slot, 0));
    unsigned bar;

    g_assert_nonnull(dev);
    g_assert_cmphex(qpci_config_readw(dev, PCI_VENDOR_ID), ==,
                    expected->vendor);
    g_assert_cmphex(qpci_config_readw(dev, PCI_DEVICE_ID), ==,
                    expected->device);
    g_assert_cmphex(qpci_config_readw(dev, PCI_COMMAND), ==,
                    expected->command);
    g_assert_cmphex(qpci_config_readb(dev, PCI_INTERRUPT_LINE), ==,
                    expected->irq_line);
    g_assert_cmphex(qpci_config_readb(dev, PCI_INTERRUPT_PIN), ==,
                    expected->irq_pin);
    for (bar = 0; bar < ARRAY_SIZE(expected->bars); bar++) {
        g_assert_cmphex(qpci_config_readl(dev,
                                         PCI_BASE_ADDRESS_0 + bar * 4),
                        ==, expected->bars[bar]);
    }
    g_free(dev);
}

static void test_pci_default_layout(void)
{
    static const ExpectedPCIDevice devices[] = {
        {
            .slot = 1, .vendor = 0x8086, .device = 0x2922,
            .command = PCI_COMMAND_IO | PCI_COMMAND_MEMORY |
                       PCI_COMMAND_MASTER,
            .irq_line = 17, .irq_pin = 1,
            .bars = { [4] = 0x0000c101, [5] = 0xc1020000 },
        }, {
            .slot = 2, .vendor = 0x106b, .device = 0x003f,
            .command = PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER,
            .irq_line = 18, .irq_pin = 1,
            .bars = { [0] = 0xc1010000 },
        }, {
            .slot = 3, .vendor = 0x8086, .device = 0x7020,
            .command = PCI_COMMAND_IO | PCI_COMMAND_MASTER,
            .irq_line = 18, .irq_pin = 4,
            .bars = { [4] = 0x0000c121 },
        }, {
            .slot = 4, .vendor = 0x1000, .device = 0x0012,
            .command = PCI_COMMAND_IO | PCI_COMMAND_MEMORY |
                       PCI_COMMAND_MASTER,
            .irq_line = 16, .irq_pin = 1,
            .bars = {
                [0] = 0x0000c201,
                [1] = 0xc1030000,
                [2] = 0xc1032000,
            },
        }, {
            .slot = 5, .vendor = 0x1002, .device = 0x5046,
            .command = PCI_COMMAND_IO | PCI_COMMAND_MEMORY,
            .irq_line = 17, .irq_pin = 1,
            .bars = {
                [0] = 0xc4000008,
                [1] = 0x0000c301,
                [2] = 0xc8000000,
            },
        },
    };
    QTestState *qts = ia64_vpc_start(NULL);
    QGenericPCIBus gbus;
    unsigned i;

    ia64_qpci_init(&gbus, qts);
    for (i = 0; i < 8; i++) {
        QPCIDevice *empty = qpci_device_find(&gbus.bus, QPCI_DEVFN(0, i));

        g_assert_null(empty);
    }
    for (i = 0; i < ARRAY_SIZE(devices); i++) {
        assert_pci_device(&gbus.bus, &devices[i]);
    }
    qtest_quit(qts);
}

static void test_pci_explicit_cmd646_slot0(void)
{
    QTestState *qts = ia64_vpc_start(
        "-device cmd646-ide,secondary=1,addr=0");
    QGenericPCIBus gbus;
    QPCIDevice *dev;

    ia64_qpci_init(&gbus, qts);
    dev = qpci_device_find(&gbus.bus, QPCI_DEVFN(0, 0));
    g_assert_nonnull(dev);
    g_assert_cmphex(qpci_config_readw(dev, PCI_VENDOR_ID), ==, 0x1095);
    g_assert_cmphex(qpci_config_readw(dev, PCI_DEVICE_ID), ==, 0x0646);
    g_assert_cmphex(qpci_config_readw(dev, PCI_CLASS_DEVICE), ==,
                    PCI_CLASS_STORAGE_IDE);
    g_free(dev);
    qtest_quit(qts);
}

static void iosapic_select(QTestState *qts, uint32_t reg)
{
    qtest_writel(qts, IA64_IOSAPIC_BASE + IA64_IOSAPIC_IOREGSEL, reg);
}

static uint32_t iosapic_read(QTestState *qts, uint32_t reg)
{
    iosapic_select(qts, reg);
    return qtest_readl(qts, IA64_IOSAPIC_BASE + IA64_IOSAPIC_IOWIN);
}

static void iosapic_write(QTestState *qts, uint32_t reg, uint32_t value)
{
    iosapic_select(qts, reg);
    qtest_writel(qts, IA64_IOSAPIC_BASE + IA64_IOSAPIC_IOWIN, value);
}

static char *find_unattached_child(QTestState *qts, const char *qom_type)
{
    g_autoptr(QDict) response = NULL;
    g_autofree char *child_type = g_strdup_printf("child<%s>", qom_type);
    QList *children;
    QListEntry *entry;

    response = qtest_qmp(qts,
                         "{'execute':'qom-list','arguments':"
                         " {'path':'/machine/unattached'}}");
    g_assert(qdict_haskey(response, "return"));
    children = qdict_get_qlist(response, "return");
    QLIST_FOREACH_ENTRY(children, entry) {
        QDict *child = qobject_to(QDict, qlist_entry_obj(entry));

        if (g_str_equal(qdict_get_str(child, "type"), child_type)) {
            return g_strdup_printf("/machine/unattached/%s",
                                   qdict_get_str(child, "name"));
        }
    }

    g_error("QOM child of type %s was not found", qom_type);
    return NULL;
}

static unsigned count_unattached_children(QTestState *qts,
                                          const char *qom_type)
{
    g_autoptr(QDict) response = NULL;
    g_autofree char *child_type = g_strdup_printf("child<%s>", qom_type);
    QList *children;
    QListEntry *entry;
    unsigned count = 0;

    response = qtest_qmp(qts,
                         "{'execute':'qom-list','arguments':"
                         " {'path':'/machine/unattached'}}");
    g_assert(qdict_haskey(response, "return"));
    children = qdict_get_qlist(response, "return");
    QLIST_FOREACH_ENTRY(children, entry) {
        QDict *child = qobject_to(QDict, qlist_entry_obj(entry));

        if (g_str_equal(qdict_get_str(child, "type"), child_type)) {
            count++;
        }
    }
    return count;
}

static void test_default_usb_input(void)
{
    QTestState *qts = qtest_init("-machine ia64-vpc,i8042=off "
                                 "-m 256M -S");

    g_assert_cmpuint(count_unattached_children(qts, "usb-kbd"), ==, 1);
    g_assert_cmpuint(count_unattached_children(qts, "usb-tablet"), ==, 1);
    g_assert_cmpuint(count_unattached_children(qts, "usb-mouse"), ==, 0);
    qtest_quit(qts);
}

static void test_iosapic_level_remote_irr(void)
{
    const unsigned pin = 23;
    const uint8_t vector = 0x51;
    const uint32_t rte_low = IA64_IOSAPIC_RTE_BASE + pin * 2;
    QTestState *qts = ia64_vpc_start(NULL);
    g_autofree char *iosapic_path =
        find_unattached_child(qts, "ia64-iosapic");
    uint32_t rte;

    /* Delivery status and Remote IRR are read-only guest-visible bits. */
    iosapic_write(qts, rte_low,
                  vector | IA64_IOSAPIC_RTE_LEVEL |
                  IA64_IOSAPIC_RTE_DELIVERY |
                  IA64_IOSAPIC_RTE_REMOTE_IRR);
    rte = iosapic_read(qts, rte_low);
    g_assert_cmphex(rte & (IA64_IOSAPIC_RTE_DELIVERY |
                          IA64_IOSAPIC_RTE_REMOTE_IRR), ==, 0);

    qtest_set_irq_in(qts, iosapic_path, NULL, pin, 1);
    rte = iosapic_read(qts, rte_low);
    g_assert_cmphex(rte & IA64_IOSAPIC_RTE_REMOTE_IRR, !=, 0);
    g_assert_cmphex(rte & IA64_IOSAPIC_RTE_DELIVERY, ==, 0);

    /* EOI while the level remains asserted immediately redelivers it. */
    qtest_writel(qts, IA64_IOSAPIC_BASE + IA64_IOSAPIC_EOI, vector);
    g_assert_cmphex(iosapic_read(qts, rte_low) &
                    IA64_IOSAPIC_RTE_REMOTE_IRR, !=, 0);

    qtest_set_irq_in(qts, iosapic_path, NULL, pin, 0);
    g_assert_cmphex(iosapic_read(qts, rte_low) &
                    IA64_IOSAPIC_RTE_REMOTE_IRR, !=, 0);
    qtest_writel(qts, IA64_IOSAPIC_BASE + IA64_IOSAPIC_EOI, vector);
    g_assert_cmphex(iosapic_read(qts, rte_low) &
                    IA64_IOSAPIC_RTE_REMOTE_IRR, ==, 0);
    qtest_quit(qts);
}

static void test_sparse_io_pm_register(void)
{
    const uint32_t port = IA64_ACPI_PM_IO_BASE + IA64_ACPI_PM1_CNT_OFFSET;
    const uint64_t dense = IA64_LEGACY_IO_BASE + port;
    const uint64_t sparse = IA64_LEGACY_IO_BASE +
                            ia64_sparse_io_offset(port);
    QTestState *qts = ia64_vpc_start(NULL);

    g_assert_cmphex(sparse, ==, 0x000000800010801004ULL);

    qtest_writew(qts, dense, 0);
    g_assert_cmphex(qtest_readw(qts, sparse) & 1, ==, 0);

    qtest_writew(qts, sparse, 1);
    g_assert_cmphex(qtest_readw(qts, sparse) & 1, ==, 1);
    g_assert_cmphex(qtest_readw(qts, dense) & 1, ==, 1);

    qtest_writew(qts, sparse, 0);
    g_assert_cmphex(qtest_readw(qts, dense) & 1, ==, 0);
    qtest_quit(qts);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/ia64-vpc/acpi-reset-register",
                   test_acpi_reset_register);
    qtest_add_func("/ia64-vpc/firmware-handoff/defaults",
                   test_firmware_handoff_defaults);
    qtest_add_func("/ia64-vpc/firmware-handoff/i8042-off",
                   test_firmware_handoff_i8042_off);
    qtest_add_func("/ia64-vpc/input/default-usb",
                   test_default_usb_input);
    qtest_add_func("/ia64-vpc/rtc/aligned-read", test_rtc_aligned_read);
    qtest_add_func("/ia64-vpc/nvram/commit-and-restart",
                   test_nvram_commit_and_restart);
    qtest_add_func("/ia64-vpc/pci/default-layout", test_pci_default_layout);
    qtest_add_func("/ia64-vpc/pci/explicit-cmd646-slot0",
                   test_pci_explicit_cmd646_slot0);
    qtest_add_func("/ia64-vpc/iosapic/level-remote-irr",
                   test_iosapic_level_remote_irr);
    qtest_add_func("/ia64-vpc/sparse-io/pm-register",
                   test_sparse_io_pm_register);

    return g_test_run();
}
