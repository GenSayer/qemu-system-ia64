/*
 * QTest testcase for vga cards
 *
 * Copyright (c) 2014 Red Hat, Inc
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "libqtest.h"

#define VBE_DISPI_IOPORT_INDEX 0x1ce
#define VBE_DISPI_IOPORT_DATA  0x1cf
#define VBE_DISPI_INDEX_ID     0
#define VBE_DISPI_INDEX_ENABLE 4
#define VBE_DISPI_ID5          0xb0c5
#define VBE_DISPI_ENABLED      0x01
#define VBE_DISPI_LFB_ENABLED  0x40
#define IA64_LEGACY_IO_BASE    0x000000800010000000ULL
#define VGA_SEQ_INDEX          0x3c4
#define VGA_SEQ_DATA           0x3c5
#define VGA_SEQ_RESET          0

static const char *machine_args(void)
{
    return g_str_equal(qtest_get_arch(), "ia64") ?
           "-machine ia64-vpc " : "";
}

static void pci_multihead(void)
{
    QTestState *qts;

    qts = qtest_initf("%s-vga none -device VGA -device secondary-vga",
                      machine_args());
    qtest_quit(qts);
}

static void test_vga(gconstpointer data)
{
    QTestState *qts;

    qts = qtest_initf("%s-vga none -device %s", machine_args(),
                      (const char *)data);
    qtest_quit(qts);
}

static void vbe_legacy_data_port(void)
{
    QTestState *qts;
    uint16_t id;

    if (g_str_equal(qtest_get_arch(), "ia64")) {
        qts = qtest_init("-machine ia64-vpc -vga std");
        qtest_writew(qts, IA64_LEGACY_IO_BASE + VBE_DISPI_IOPORT_INDEX,
                     VBE_DISPI_INDEX_ID);
        id = qtest_readw(qts,
                         IA64_LEGACY_IO_BASE + VBE_DISPI_IOPORT_INDEX + 2);
        g_assert_cmphex(id, ==, VBE_DISPI_ID5);
        g_assert_cmphex(qtest_readw(qts,
                                    IA64_LEGACY_IO_BASE +
                                    VBE_DISPI_IOPORT_DATA), ==, id);
    } else {
        qts = qtest_init("-vga none -device VGA");
        qtest_outw(qts, VBE_DISPI_IOPORT_INDEX, VBE_DISPI_INDEX_ID);
        id = qtest_inw(qts, VBE_DISPI_IOPORT_INDEX + 2);
        g_assert_cmphex(id, ==, VBE_DISPI_ID5);
        g_assert_cmphex(qtest_inw(qts, VBE_DISPI_IOPORT_DATA), ==, id);
    }
    qtest_quit(qts);
}

static void ati_legacy_mode_switch(void)
{
    QTestState *qts;
    uint64_t index = IA64_LEGACY_IO_BASE + VBE_DISPI_IOPORT_INDEX;
    uint64_t data = index + 2;

    qts = qtest_init("-machine ia64-vpc");
    qtest_writew(qts, index, VBE_DISPI_INDEX_ENABLE);
    qtest_writew(qts, data, VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED);
    g_assert_cmphex(qtest_readw(qts, data), ==,
                    VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED);

    qtest_writeb(qts, IA64_LEGACY_IO_BASE + VGA_SEQ_INDEX, VGA_SEQ_RESET);
    qtest_writeb(qts, IA64_LEGACY_IO_BASE + VGA_SEQ_DATA, 1);

    qtest_writew(qts, index, VBE_DISPI_INDEX_ENABLE);
    g_assert_cmphex(qtest_readw(qts, data), ==, 0);
    qtest_quit(qts);
}

int main(int argc, char **argv)
{
    static const char *devices[] = {
        "cirrus-vga",
        "VGA",
        "secondary-vga",
        "virtio-gpu-pci",
        "virtio-vga"
    };

    g_test_init(&argc, &argv, NULL);

    for (int i = 0; i < ARRAY_SIZE(devices); i++) {
        if (qtest_has_device(devices[i])) {
            char *testpath = g_strdup_printf("/display/pci/%s", devices[i]);
            qtest_add_data_func(testpath, devices[i], test_vga);
            g_free(testpath);
        }
    }

    if (qtest_has_device("secondary-vga")) {
        qtest_add_func("/display/pci/multihead", pci_multihead);
    }
    if (qtest_has_device("VGA")) {
        qtest_add_func("/display/pci/vbe-legacy-data-port",
                       vbe_legacy_data_port);
    }
    if (g_str_equal(qtest_get_arch(), "ia64") &&
        qtest_has_device("ati-vga")) {
        qtest_add_func("/display/pci/ati-legacy-mode-switch",
                       ati_legacy_mode_switch);
    }

    return g_test_run();
}
