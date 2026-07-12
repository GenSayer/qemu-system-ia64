/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QTest fuzzer-generated testcase for LSI53C895A device
 *
 * Copyright (c) Red Hat
 */

#include "qemu/osdep.h"
#include "libqtest.h"

#define LSI_MMIO_BASE           0xff100000
#define LSI_SCRIPT_ADDR         0x00100000
#define LSI_MSGOUT_ADDR         0x00110000
#define LSI_CDB_ADDR            0x00110010
#define LSI_DISCONNECT_ADDR     0x00110020
#define LSI_RESELECT_ADDR       0x00110030
#define LSI_STATUS_ADDR         0x00110040
#define LSI_COMPLETE_ADDR       0x00110050
#define LSI_DATA_ADDR           0x00120000

#define LSI_REG_DSTAT           0x0c
#define LSI_REG_ISTAT0          0x14
#define LSI_REG_DSP             0x2c
#define LSI_REG_SIST0           0x42
#define LSI_REG_SIST1           0x43

#define LSI_ISTAT0_DIP          0x01
#define LSI_ISTAT0_INTF         0x04
#define LSI_DSTAT_SIR           0x04

#define LSI_PHASE_DI            1
#define LSI_PHASE_CMD           2
#define LSI_PHASE_ST            3
#define LSI_PHASE_MO            6
#define LSI_PHASE_MI            7

#define LSI_SCRIPT_SELECT       0x40000008
#define LSI_SCRIPT_WAIT_RESELECT 0x50000000
#define LSI_SCRIPT_DISCONNECT   0x48000000
#define LSI_SCRIPT_MOVE(phase, count) \
    (((phase) << 24) | (count))
#define LSI_SCRIPT_JUMP_PHASE(phase) \
    (0x80000000 | ((phase) << 24) | (1 << 19) | (1 << 17))
#define LSI_SCRIPT_INTERRUPT    0x98080000

typedef struct LsiTagMessage {
    const char *name;
    uint8_t message;
} LsiTagMessage;

static void lsi_write_script_insn(QTestState *s, uint32_t *addr,
                                  uint32_t insn, uint32_t arg)
{
    qtest_writel(s, *addr, insn);
    qtest_writel(s, *addr + 4, arg);
    *addr += 8;
}

static void lsi_setup_tag_script(QTestState *s)
{
    const uint32_t message_in = LSI_SCRIPT_ADDR + 7 * 8;
    const uint32_t data_in = LSI_SCRIPT_ADDR + 14 * 8;
    const uint32_t status = LSI_SCRIPT_ADDR + 17 * 8;
    uint32_t addr = LSI_SCRIPT_ADDR;

    lsi_write_script_insn(s, &addr, LSI_SCRIPT_SELECT, 0);
    lsi_write_script_insn(s, &addr, LSI_SCRIPT_MOVE(LSI_PHASE_MO, 5),
                          LSI_MSGOUT_ADDR);
    lsi_write_script_insn(s, &addr, LSI_SCRIPT_MOVE(LSI_PHASE_CMD, 10),
                          LSI_CDB_ADDR);
    lsi_write_script_insn(s, &addr, LSI_SCRIPT_JUMP_PHASE(LSI_PHASE_MI),
                          message_in);
    lsi_write_script_insn(s, &addr, LSI_SCRIPT_JUMP_PHASE(LSI_PHASE_DI),
                          data_in);
    lsi_write_script_insn(s, &addr, LSI_SCRIPT_JUMP_PHASE(LSI_PHASE_ST),
                          status);
    lsi_write_script_insn(s, &addr, LSI_SCRIPT_INTERRUPT, 1);

    lsi_write_script_insn(s, &addr, LSI_SCRIPT_MOVE(LSI_PHASE_MI, 2),
                          LSI_DISCONNECT_ADDR);
    lsi_write_script_insn(s, &addr, LSI_SCRIPT_DISCONNECT, 0);
    lsi_write_script_insn(s, &addr, LSI_SCRIPT_WAIT_RESELECT, 0);
    lsi_write_script_insn(s, &addr, LSI_SCRIPT_MOVE(LSI_PHASE_MI, 3),
                          LSI_RESELECT_ADDR);
    lsi_write_script_insn(s, &addr, LSI_SCRIPT_JUMP_PHASE(LSI_PHASE_DI),
                          data_in);
    lsi_write_script_insn(s, &addr, LSI_SCRIPT_JUMP_PHASE(LSI_PHASE_ST),
                          status);
    lsi_write_script_insn(s, &addr, LSI_SCRIPT_INTERRUPT, 2);

    lsi_write_script_insn(s, &addr, LSI_SCRIPT_MOVE(LSI_PHASE_DI, 512),
                          LSI_DATA_ADDR);
    lsi_write_script_insn(s, &addr, LSI_SCRIPT_JUMP_PHASE(LSI_PHASE_ST),
                          status);
    lsi_write_script_insn(s, &addr, LSI_SCRIPT_INTERRUPT, 3);

    lsi_write_script_insn(s, &addr, LSI_SCRIPT_MOVE(LSI_PHASE_ST, 1),
                          LSI_STATUS_ADDR);
    lsi_write_script_insn(s, &addr, LSI_SCRIPT_MOVE(LSI_PHASE_MI, 1),
                          LSI_COMPLETE_ADDR);
    lsi_write_script_insn(s, &addr, LSI_SCRIPT_DISCONNECT, 0);
    lsi_write_script_insn(s, &addr, LSI_SCRIPT_INTERRUPT, 0);
}

static uint8_t lsi_run_tag_command(QTestState *s, uint8_t message,
                                   uint8_t reselect[3])
{
    const uint8_t msgout[] = { 0x80, message, 1, message, 2 };
    const uint8_t read_10[] = { 0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0 };
    uint8_t dstat = 0;
    unsigned int i;

    qtest_memwrite(s, LSI_MSGOUT_ADDR, msgout, sizeof(msgout));
    qtest_memwrite(s, LSI_CDB_ADDR, read_10, sizeof(read_10));
    qtest_memset(s, LSI_RESELECT_ADDR, 0xcc, 3);
    qtest_writeb(s, LSI_STATUS_ADDR, 0xff);
    qtest_writeb(s, LSI_COMPLETE_ADDR, 0xff);

    qtest_readb(s, LSI_MMIO_BASE + LSI_REG_DSTAT);
    qtest_readb(s, LSI_MMIO_BASE + LSI_REG_SIST0);
    qtest_readb(s, LSI_MMIO_BASE + LSI_REG_SIST1);
    qtest_writeb(s, LSI_MMIO_BASE + LSI_REG_ISTAT0, LSI_ISTAT0_INTF);
    qtest_writel(s, LSI_MMIO_BASE + LSI_REG_DSP, LSI_SCRIPT_ADDR);

    for (i = 0; i < 1000; i++) {
        if (qtest_readb(s, LSI_MMIO_BASE + LSI_REG_ISTAT0) & LSI_ISTAT0_DIP) {
            dstat = qtest_readb(s, LSI_MMIO_BASE + LSI_REG_DSTAT);
            if (dstat & LSI_DSTAT_SIR) {
                break;
            }
        }
        g_usleep(1000);
    }
    g_assert_cmpuint(dstat & LSI_DSTAT_SIR, !=, 0);
    qtest_memread(s, LSI_RESELECT_ADDR, reselect, 3);
    return qtest_readb(s, LSI_STATUS_ADDR);
}

static void test_lsi_tag_byte_replaced(gconstpointer opaque)
{
    const LsiTagMessage *tag_message = opaque;
    QTestState *s;
    uint8_t reselect[3];
    uint8_t status = 0xff;
    unsigned int attempt;

    s = qtest_init("-M q35 -m 512M -nodefaults "
                   "-blockdev driver=null-co,read-zeroes=on,"
                             "node-name=disk0,size=1048576 "
                   "-device lsi53c895a,id=scsi,addr=1 "
                   "-device scsi-hd,drive=disk0,bus=scsi.0,scsi-id=0");

    qtest_outl(s, 0xcf8, 0x80000804);
    qtest_outw(s, 0xcfc, 0x7);
    qtest_outl(s, 0xcf8, 0x80000814);
    qtest_outl(s, 0xcfc, LSI_MMIO_BASE);
    qtest_outl(s, 0xcf8, 0x80000818);
    qtest_outl(s, 0xcfc, 0xff000000);
    lsi_setup_tag_script(s);

    /* The first command can consume the initial Unit Attention. */
    for (attempt = 0; attempt < 3 && status != 0; attempt++) {
        status = lsi_run_tag_command(s, tag_message->message, reselect);
    }

    g_assert_cmpuint(status, ==, 0);
    g_assert_cmphex(reselect[0], ==, 0x80);
    g_assert_cmphex(reselect[1], ==, 0x20);
    g_assert_cmphex(reselect[2], ==, 2);
    qtest_quit(s);
}

/*
 * This used to trigger a DMA reentrancy issue
 * leading to memory corruption bugs like stack
 * overflow or use-after-free
 * https://gitlab.com/qemu-project/qemu/-/issues/1563
 */
static void test_lsi_dma_reentrancy(void)
{
    QTestState *s;

    s = qtest_init("-M q35 -m 512M -nodefaults "
                   "-blockdev driver=null-co,node-name=null0 "
                   "-device lsi53c810 -device scsi-cd,drive=null0");

    qtest_outl(s, 0xcf8, 0x80000804); /* PCI Command Register */
    qtest_outw(s, 0xcfc, 0x7);        /* Enables accesses */
    qtest_outl(s, 0xcf8, 0x80000814); /* Memory Bar 1 */
    qtest_outl(s, 0xcfc, 0xff100000); /* Set MMIO Address*/
    qtest_outl(s, 0xcf8, 0x80000818); /* Memory Bar 2 */
    qtest_outl(s, 0xcfc, 0xff000000); /* Set RAM Address*/
    qtest_writel(s, 0xff000000, 0xc0000024);
    qtest_writel(s, 0xff000114, 0x00000080);
    qtest_writel(s, 0xff00012c, 0xff000000);
    qtest_writel(s, 0xff000004, 0xff000114);
    qtest_writel(s, 0xff000008, 0xff100014);
    qtest_writel(s, 0xff10002f, 0x000000ff);

    qtest_quit(s);
}

/*
 * This used to trigger a UAF in lsi_do_msgout()
 * https://gitlab.com/qemu-project/qemu/-/issues/972
 */
static void test_lsi_do_msgout_cancel_req(void)
{
    QTestState *s;

    if (sizeof(void *) == 4) {
        g_test_skip("memory size too big for 32-bit build");
        return;
    }

    s = qtest_init("-M q35 -m 2G -nodefaults "
                   "-device lsi53c895a,id=scsi "
                   "-device scsi-hd,drive=disk0 "
                   "-drive file=null-co://,id=disk0,if=none,format=raw");

    qtest_outl(s, 0xcf8, 0x80000810);
    qtest_outl(s, 0xcf8, 0xc000);
    qtest_outl(s, 0xcf8, 0x80000810);
    qtest_outw(s, 0xcfc, 0x7);
    qtest_outl(s, 0xcf8, 0x80000810);
    qtest_outl(s, 0xcfc, 0xc000);
    qtest_outl(s, 0xcf8, 0x80000804);
    qtest_outw(s, 0xcfc, 0x05);
    qtest_writeb(s, 0x69736c10, 0x08);
    qtest_writeb(s, 0x69736c13, 0x58);
    qtest_writeb(s, 0x69736c1a, 0x01);
    qtest_writeb(s, 0x69736c1b, 0x06);
    qtest_writeb(s, 0x69736c22, 0x01);
    qtest_writeb(s, 0x69736c23, 0x07);
    qtest_writeb(s, 0x69736c2b, 0x02);
    qtest_writeb(s, 0x69736c48, 0x08);
    qtest_writeb(s, 0x69736c4b, 0x58);
    qtest_writeb(s, 0x69736c52, 0x04);
    qtest_writeb(s, 0x69736c53, 0x06);
    qtest_writeb(s, 0x69736c5b, 0x02);
    qtest_outl(s, 0xc02d, 0x697300);
    qtest_writeb(s, 0x5a554662, 0x01);
    qtest_writeb(s, 0x5a554663, 0x07);
    qtest_writeb(s, 0x5a55466a, 0x10);
    qtest_writeb(s, 0x5a55466b, 0x22);
    qtest_writeb(s, 0x5a55466c, 0x5a);
    qtest_writeb(s, 0x5a55466d, 0x5a);
    qtest_writeb(s, 0x5a55466e, 0x34);
    qtest_writeb(s, 0x5a55466f, 0x5a);
    qtest_writeb(s, 0x5a345a5a, 0x77);
    qtest_writeb(s, 0x5a345a5b, 0x55);
    qtest_writeb(s, 0x5a345a5c, 0x51);
    qtest_writeb(s, 0x5a345a5d, 0x27);
    qtest_writeb(s, 0x27515577, 0x41);
    qtest_outl(s, 0xc02d, 0x5a5500);
    qtest_writeb(s, 0x364001d0, 0x08);
    qtest_writeb(s, 0x364001d3, 0x58);
    qtest_writeb(s, 0x364001da, 0x01);
    qtest_writeb(s, 0x364001db, 0x26);
    qtest_writeb(s, 0x364001dc, 0x0d);
    qtest_writeb(s, 0x364001dd, 0xae);
    qtest_writeb(s, 0x364001de, 0x41);
    qtest_writeb(s, 0x364001df, 0x5a);
    qtest_writeb(s, 0x5a41ae0d, 0xf8);
    qtest_writeb(s, 0x5a41ae0e, 0x36);
    qtest_writeb(s, 0x5a41ae0f, 0xd7);
    qtest_writeb(s, 0x5a41ae10, 0x36);
    qtest_writeb(s, 0x36d736f8, 0x0c);
    qtest_writeb(s, 0x36d736f9, 0x80);
    qtest_writeb(s, 0x36d736fa, 0x0d);
    qtest_outl(s, 0xc02d, 0x364000);

    qtest_quit(s);
}

/*
 * This used to trigger the assert in lsi_do_dma()
 * https://bugs.launchpad.net/qemu/+bug/697510
 * https://bugs.launchpad.net/qemu/+bug/1905521
 * https://bugs.launchpad.net/qemu/+bug/1908515
 */
static void test_lsi_do_dma_empty_queue(void)
{
    QTestState *s;

    s = qtest_init("-M q35 -nographic -monitor none -serial none "
                   "-drive if=none,id=drive0,"
                            "file=null-co://,file.read-zeroes=on,format=raw "
                   "-device lsi53c895a,id=scsi0 "
                   "-device scsi-hd,drive=drive0,"
                            "bus=scsi0.0,channel=0,scsi-id=0,lun=0");
    qtest_outl(s, 0xcf8, 0x80001814);
    qtest_outl(s, 0xcfc, 0xe1068000);
    qtest_outl(s, 0xcf8, 0x80001818);
    qtest_outl(s, 0xcf8, 0x80001804);
    qtest_outw(s, 0xcfc, 0x7);
    qtest_outl(s, 0xcf8, 0x80002010);

    qtest_writeb(s, 0xe106802e, 0xff); /* Fill DSP bits 16-23 */
    qtest_writeb(s, 0xe106802f, 0xff); /* Fill DSP bits 24-31: trigger SCRIPT */

    qtest_quit(s);
}

int main(int argc, char **argv)
{
    static const LsiTagMessage tag_messages[] = {
        { "simple",  0x20 },
        { "head",    0x21 },
        { "ordered", 0x22 },
    };
    size_t i;

    g_test_init(&argc, &argv, NULL);

    if (!qtest_has_device("lsi53c895a")) {
        return 0;
    }

    qtest_add_func("fuzz/lsi53c895a/lsi_do_dma_empty_queue",
                   test_lsi_do_dma_empty_queue);

    qtest_add_func("fuzz/lsi53c895a/lsi_do_msgout_cancel_req",
                   test_lsi_do_msgout_cancel_req);

    qtest_add_func("fuzz/lsi53c895a/lsi_dma_reentrancy",
                   test_lsi_dma_reentrancy);

    for (i = 0; i < ARRAY_SIZE(tag_messages); i++) {
        g_autofree char *path = g_strdup_printf(
            "fuzz/lsi53c895a/tag-byte/%s", tag_messages[i].name);

        qtest_add_data_func(path, &tag_messages[i],
                            test_lsi_tag_byte_replaced);
    }

    return g_test_run();
}
