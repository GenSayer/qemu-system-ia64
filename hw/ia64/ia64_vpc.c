/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * IA-64 virtual PC platform.
 *
 * Provides RAM, a bootstrap CPU, a memory-mapped serial console,
 * firmware ROM loading via -bios, a PCI host bridge, SCSI and AHCI storage
 * controllers, OHCI/UHCI USB, local SAPIC/I/O SAPIC wiring,
 * and ACPI fixed power-management registers.
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/cutils.h"
#include "qemu/datadir.h"
#include "qemu/error-report.h"
#include "hw/core/boards.h"
#include "hw/core/cpu.h"
#include "hw/core/qdev-properties.h"
#include "hw/char/serial-mm.h"
#include "hw/core/loader.h"
#include "hw/core/sysbus.h"
#include "hw/ide/ahci-pci.h"
#include "hw/input/i8042.h"
#include "hw/acpi/acpi.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_bus.h"
#include "hw/isa/isa.h"
#include "hw/usb/hcd-uhci.h"
#include "hw/usb/usb.h"
#include "hw/ia64/ia64_pci.h"
#include "hw/ia64/ia64_iosapic.h"
#include "system/address-spaces.h"
#include "system/rtc.h"
#include "system/runstate.h"
#include "system/system.h"
#include "system/reset.h"
#include "target/ia64/cpu-qom.h"
#include "target/ia64/cpu.h"

#define IA64_UART_BASE  0x00000047f0000000ULL
#define IA64_DEBUG_UART_BASE 0x00000047f0001000ULL
#define IA64_FW_BASE    0x0000000000100000ULL
#define IA64_LOW_RAM_LIMIT 0x0000000080000000ULL
#define IA64_HIGH_RAM_BASE 0x0000000080200000ULL
#define IA64_FIRMWARE_ADDRESS_SPACE_BASE 0x00000000ff000000ULL
#define IA64_FIRMWARE_ADDRESS_SPACE_SIZE (16 * MiB)
#define IA64_NVRAM_BASE 0x00000000fff00000ULL
#define IA64_NVRAM_SIZE (64 * KiB)
#define IA64_NVRAM_COMMIT_OFFSET (IA64_NVRAM_SIZE - 8)
#define IA64_NVRAM_COMMIT_MAGIC 0x54494d4d4f43564eULL /* "NVCOMMIT" */
#define IA64_HIGH_RAM_AFTER_FIRMWARE_BASE \
    (IA64_FIRMWARE_ADDRESS_SPACE_BASE + IA64_FIRMWARE_ADDRESS_SPACE_SIZE)
#define IA64_FW_BOOTSTRAP_STACK_TOP (128 * MiB)
#define IA64_FW_LOW_RAM_MIN IA64_FW_BOOTSTRAP_STACK_TOP
#define IA64_IVT_BASE   0x10000ULL
#define IA64_IVT_SIZE   0x8000ULL
#define IA64_AHCI_IDP_IO_BASE   0x0000c100U
#define IA64_UHCI_IO_BASE       0x0000c120U
/* LSI BAR0 is 0x100 bytes and therefore requires 0x100-byte alignment. */
#define IA64_LSI_IO_BASE        0x0000c200U
#define IA64_OHCI_MMIO_PCI_BASE (IA64_PCI_MMIO_BASE + 0x00010000ULL)
#define IA64_AHCI_MMIO_PCI_BASE (IA64_PCI_MMIO_BASE + 0x00020000ULL)
#define IA64_LSI_MMIO_PCI_BASE  (IA64_PCI_MMIO_BASE + 0x00030000ULL)
#define IA64_LSI_RAM_PCI_BASE   (IA64_PCI_MMIO_BASE + 0x00032000ULL)
#define IA64_VGA_FB_PCI_BASE    (IA64_PCI_MMIO_BASE + 0x01000000ULL)
#define IA64_VGA_MMIO_PCI_BASE  (IA64_PCI_MMIO_BASE + 0x02000000ULL)
#define IA64_VGA_LEGACY_BASE   0x000a0000U
#define IA64_VGA_LEGACY_SIZE   0x00020000U
#define IA64_IOSAPIC_BASE       0x0000000080110000ULL
#define IA64_IOSAPIC_SIZE       0x0000000000002000ULL
#define IA64_ACPI_PM_IO_BASE    0x00002000U
#define IA64_ACPI_PM_IO_SIZE    0x00000010U
#define IA64_ACPI_SCI_IRQ       9
#define IA64_FW_HANDOFF_ADDR         0x00000000000ff000ULL
#define IA64_FW_HANDOFF_MAGIC        0x4d41523436414951ULL /* "QIA64RAM" */
#define IA64_FW_HANDOFF_VERSION      5ULL
#define IA64_FW_CONSOLE_SERIAL       0ULL
#define IA64_FW_CONSOLE_VGA          1ULL
#define IA64_FW_DEBUG_PORT_PRESENT   1ULL
#define IA64_PIB_IPI_LIMIT          0x00100000ULL
#define IA64_PIB_INTA_OFFSET        0x001e0000ULL
#define IA64_PIB_XTP_OFFSET         0x001e0008ULL

static PCIDevice *ia64_vpc_ahci_dev;
static PCIDevice *ia64_vpc_ohci_dev;
static PCIDevice *ia64_vpc_uhci_dev;
static PCIDevice *ia64_vpc_lsi_dev;
static PCIDevice *ia64_vpc_vga_dev;
static MemoryRegion *ia64_vpc_vga_fb_alias;
static MemoryRegion *ia64_vpc_vga_mmio_alias;
static MemoryRegion *ia64_vpc_vga_legacy_alias;
static Object *ia64_vpc_pci_fixup_reset;
static MemoryRegion *ia64_vpc_lsapic_mmio;
static MemoryRegion ia64_vpc_firmware_space;
static MemoryRegion ia64_vpc_nvram_mmio;
static uint8_t ia64_vpc_nvram_data[IA64_NVRAM_SIZE];
static char *ia64_vpc_nvram_path;
static char *ia64_vpc_nvram_resolved_path;
static bool ia64_vpc_nvram_write_warning;
static MemoryRegion ia64_vpc_acpi_pm;
static ACPIREGS ia64_vpc_acpi_regs;
static qemu_irq ia64_vpc_acpi_sci_irq;
static Notifier ia64_vpc_powerdown_notifier;
static qemu_irq ia64_vpc_isa_irqs[ISA_NUM_IRQS];
static bool ia64_vpc_i8042_enabled = true;
static bool ia64_vpc_firmware_ide_dma = true;
static uint64_t ia64_vpc_firmware_console = IA64_FW_CONSOLE_VGA;

static char *ia64_vpc_get_nvram(Object *obj, Error **errp)
{
    (void)obj;
    (void)errp;

    return g_strdup(ia64_vpc_nvram_path ?: "auto");
}

static void ia64_vpc_set_nvram(Object *obj, const char *value, Error **errp)
{
    (void)obj;
    (void)errp;

    g_free(ia64_vpc_nvram_path);
    ia64_vpc_nvram_path = g_strcmp0(value, "auto") == 0 ?
                           NULL : g_strdup(value);
}

static uint64_t ia64_vpc_nvram_read(void *opaque, hwaddr addr,
                                    unsigned size)
{
    uint64_t value = 0;
    unsigned i;

    (void)opaque;
    for (i = 0; i < size; i++) {
        value |= (uint64_t)ia64_vpc_nvram_data[addr + i] << (i * 8);
    }
    return value;
}

static void ia64_vpc_nvram_commit(void)
{
    g_autoptr(GError) err = NULL;

    if (!ia64_vpc_nvram_resolved_path) {
        return;
    }
    if (!g_file_set_contents(ia64_vpc_nvram_resolved_path,
                             (const char *)ia64_vpc_nvram_data,
                             sizeof(ia64_vpc_nvram_data), &err) &&
        !ia64_vpc_nvram_write_warning) {
        warn_report("failed to save IA-64 NVRAM '%s': %s",
                    ia64_vpc_nvram_resolved_path,
                    err ? err->message : "unknown error");
        ia64_vpc_nvram_write_warning = true;
    }
}

static void ia64_vpc_nvram_write(void *opaque, hwaddr addr,
                                 uint64_t value, unsigned size)
{
    unsigned i;

    (void)opaque;
    if (addr == IA64_NVRAM_COMMIT_OFFSET && size == 8 &&
        value == IA64_NVRAM_COMMIT_MAGIC) {
        ia64_vpc_nvram_commit();
        return;
    }
    for (i = 0; i < size; i++) {
        ia64_vpc_nvram_data[addr + i] = value >> (i * 8);
    }
}

static const MemoryRegionOps ia64_vpc_nvram_ops = {
    .read = ia64_vpc_nvram_read,
    .write = ia64_vpc_nvram_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 8,
        .unaligned = true,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
        .unaligned = true,
    },
};

static void ia64_vpc_init_nvram(MachineState *machine)
{
    g_autofree char *firmware_path = NULL;
    g_autofree char *directory = NULL;
    g_autofree char *contents = NULL;
    g_autoptr(GError) err = NULL;
    gsize length = 0;

    memset(ia64_vpc_nvram_data, 0, sizeof(ia64_vpc_nvram_data));
    g_clear_pointer(&ia64_vpc_nvram_resolved_path, g_free);
    ia64_vpc_nvram_write_warning = false;

    if (g_strcmp0(ia64_vpc_nvram_path, "none") != 0) {
        if (ia64_vpc_nvram_path) {
            ia64_vpc_nvram_resolved_path =
                g_strdup(ia64_vpc_nvram_path);
        } else if (machine->firmware) {
            firmware_path = qemu_find_file(QEMU_FILE_TYPE_BIOS,
                                           machine->firmware);
            if (!firmware_path) {
                firmware_path = g_strdup(machine->firmware);
            }
            directory = g_path_get_dirname(firmware_path);
            ia64_vpc_nvram_resolved_path =
                g_build_filename(directory, "nvram", NULL);
        }
    }

    if (ia64_vpc_nvram_resolved_path &&
        g_file_get_contents(ia64_vpc_nvram_resolved_path, &contents,
                            &length, &err)) {
        if (length == sizeof(ia64_vpc_nvram_data)) {
            memcpy(ia64_vpc_nvram_data, contents, length);
        } else {
            warn_report("ignoring IA-64 NVRAM '%s': expected %zu bytes, "
                        "found %zu",
                        ia64_vpc_nvram_resolved_path,
                        sizeof(ia64_vpc_nvram_data), (size_t)length);
        }
    } else if (err && !g_error_matches(err, G_FILE_ERROR,
                                       G_FILE_ERROR_NOENT)) {
        warn_report("failed to load IA-64 NVRAM '%s': %s",
                    ia64_vpc_nvram_resolved_path, err->message);
    }

    memory_region_init_io(&ia64_vpc_nvram_mmio, OBJECT(machine),
                          &ia64_vpc_nvram_ops, NULL, "ia64-vpc.nvram",
                          IA64_NVRAM_SIZE);
    memory_region_add_subregion_overlap(get_system_memory(), IA64_NVRAM_BASE,
                                        &ia64_vpc_nvram_mmio, 2);
}

static GlobalProperty ia64_vpc_compat_defaults[] = {
    /*
     * Windows Server 2003's IA-64 USB hub driver performs an
     * alignment-requiring 32-bit load from offset 10 of Microsoft OS
     * extended-property descriptors.  The offset is packed by definition,
     * so do not expose the optional selective-suspend property on HID input
     * devices.
     */
    { "usb-kbd", "msos-desc", "off" },
    { "usb-mouse", "msos-desc", "off" },
    { "usb-tablet", "msos-desc", "off" },
};

static uint16_t ia64_lduw(const uint8_t *p)
{
    return p[0] | (p[1] << 8);
}

static uint32_t ia64_ldl(const uint8_t *p)
{
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

static bool ia64_vpc_get_i8042(Object *obj, Error **errp)
{
    (void)obj;
    (void)errp;

    return ia64_vpc_i8042_enabled;
}

static void ia64_vpc_set_i8042(Object *obj, bool value, Error **errp)
{
    (void)obj;
    (void)errp;

    ia64_vpc_i8042_enabled = value;
}

static bool ia64_vpc_get_firmware_ide_dma(Object *obj, Error **errp)
{
    (void)obj;
    (void)errp;

    return ia64_vpc_firmware_ide_dma;
}

static void ia64_vpc_set_firmware_ide_dma(Object *obj, bool value,
                                          Error **errp)
{
    (void)obj;
    (void)errp;

    ia64_vpc_firmware_ide_dma = value;
}

static char *ia64_vpc_get_firmware_console(Object *obj, Error **errp)
{
    (void)obj;
    (void)errp;

    return g_strdup(ia64_vpc_firmware_console == IA64_FW_CONSOLE_VGA ?
                    "vga" : "serial");
}

static void ia64_vpc_set_firmware_console(Object *obj, const char *value,
                                          Error **errp)
{
    (void)obj;

    if (g_strcmp0(value, "serial") == 0) {
        ia64_vpc_firmware_console = IA64_FW_CONSOLE_SERIAL;
        return;
    }
    if (g_strcmp0(value, "vga") == 0) {
        ia64_vpc_firmware_console = IA64_FW_CONSOLE_VGA;
        return;
    }

    error_setg(errp, "firmware-console must be 'serial' or 'vga'");
}

static void ia64_vpc_acpi_update_sci(ACPIREGS *ar)
{
    acpi_update_sci(ar, ia64_vpc_acpi_sci_irq);
}

static void ia64_vpc_init_acpi_pm(MachineState *machine, DeviceState *iosapic,
                                  MemoryRegion *pci_io)
{
    ia64_vpc_acpi_sci_irq = qdev_get_gpio_in(iosapic, IA64_ACPI_SCI_IRQ);

    memory_region_init(&ia64_vpc_acpi_pm, OBJECT(machine), "ia64-acpi-pm",
                       IA64_ACPI_PM_IO_SIZE);
    memory_region_add_subregion(pci_io, IA64_ACPI_PM_IO_BASE,
                                &ia64_vpc_acpi_pm);

    acpi_pm1_evt_init(&ia64_vpc_acpi_regs, ia64_vpc_acpi_update_sci,
                      &ia64_vpc_acpi_pm);
    acpi_pm1_cnt_init(&ia64_vpc_acpi_regs, &ia64_vpc_acpi_pm,
                      false, false, 0, true);
    acpi_pm_tmr_init(&ia64_vpc_acpi_regs, ia64_vpc_acpi_update_sci,
                     &ia64_vpc_acpi_pm);

    /*
     * acpi_update_sci() always folds in GPE status.  The current platform
     * exposes no GPE block to the guest, but the shared ACPI core still needs
     * backing storage for that internal zero-valued contribution.
     */
    acpi_gpe_init(&ia64_vpc_acpi_regs, 2);
}

static void ia64_vpc_powerdown_req(Notifier *n, void *opaque)
{
    (void)n;
    (void)opaque;

    if (ia64_vpc_acpi_regs.pm1.evt.en & ACPI_BITMASK_POWER_BUTTON_ENABLE) {
        acpi_pm1_evt_power_down(&ia64_vpc_acpi_regs);
    } else {
        /* Avoid making QEMU's powerdown action a no-op before ACPI is armed. */
        qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
    }
}

static uint64_t ia64_vpc_lsapic_read(void *opaque, hwaddr addr,
                                       unsigned size)
{
    (void)opaque;

    if (addr == IA64_PIB_INTA_OFFSET && size == 1) {
        return 0;
    }
    return 0;
}

static void ia64_vpc_lsapic_write(void *opaque, hwaddr addr,
                                    uint64_t value, unsigned size)
{
    CPUState *cs;
    uint32_t cpu_index;
    uint8_t vector;

    (void)opaque;
    /*
     * The upper half of the Processor Interrupt Block contains the XTP byte.
     * XTP is a platform hint; systems without XTP support must still accept
     * and discard the one-byte store.
     */
    if (addr == IA64_PIB_XTP_OFFSET && size == 1) {
        return;
    }

    if (addr >= IA64_PIB_IPI_LIMIT || size != 8 || (addr & 7)) {
        return;
    }

    /*
     * The lower half of the Processor Interrupt Block is the IPI delivery
     * region.  The address selects the target processor and the low data byte
     * carries the interrupt vector for INT delivery messages.
     */
    cpu_index = addr >> 4;
    vector = value & 0xff;
    cs = qemu_get_cpu(cpu_index);
    if (cs == NULL || vector < 16) {
        return;
    }

    ia64_sapic_set_irq(cs, vector);
}

static const MemoryRegionOps ia64_vpc_lsapic_ops = {
    .read = ia64_vpc_lsapic_read,
    .write = ia64_vpc_lsapic_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 8,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
    },
};

static void ia64_vpc_map_lsapic(void)
{
    if (ia64_vpc_lsapic_mmio != NULL) {
        return;
    }

    ia64_vpc_lsapic_mmio = g_new(MemoryRegion, 1);
    memory_region_init_io(ia64_vpc_lsapic_mmio, NULL,
                          &ia64_vpc_lsapic_ops, NULL,
                          "ia64-vpc.local-sapic",
                          IA64_LOCAL_SAPIC_SIZE);
    memory_region_add_subregion(get_system_memory(), IA64_LOCAL_SAPIC_PA,
                                ia64_vpc_lsapic_mmio);
}

static void ia64_vpc_map_firmware_address_space(void)
{
    /*
     * IA-64 reserves the top 16 MiB below 4 GiB for PAL/SAL firmware
     * resources.  Decode it so firmware identity mappings can use the
     * platform address space directly.
     */
    memory_region_init_ram(&ia64_vpc_firmware_space, NULL,
                           "ia64-firmware-address-space",
                           IA64_FIRMWARE_ADDRESS_SPACE_SIZE, &error_fatal);
    memory_region_add_subregion_overlap(get_system_memory(),
                                        IA64_FIRMWARE_ADDRESS_SPACE_BASE,
                                        &ia64_vpc_firmware_space, 1);
}

static uint64_t ia64_vpc_map_ram_alias(MachineState *machine,
                                       hwaddr guest_base,
                                       uint64_t backing_offset,
                                       uint64_t remaining,
                                       uint64_t capacity,
                                       const char *name)
{
    MemoryRegion *alias;
    uint64_t size = MIN(remaining, capacity);

    if (size == 0) {
        return 0;
    }

    alias = g_new(MemoryRegion, 1);
    memory_region_init_alias(alias, OBJECT(machine), name, machine->ram,
                             backing_offset, size);
    memory_region_add_subregion(get_system_memory(), guest_base, alias);
    return size;
}

static void ia64_vpc_map_ram(MachineState *machine)
{
    uint64_t remaining = machine->ram_size;
    uint64_t offset = 0;
    uint64_t size;

    if (machine->ram == NULL) {
        return;
    }

    /*
     * Keep the RAM backing densely packed while leaving the platform's
     * firmware and PCI apertures free in the guest physical address space.
     * RAM displaced by those apertures is mapped above 4 GiB instead of
     * being hidden by higher-priority device regions.
     */
    size = ia64_vpc_map_ram_alias(machine, 0, offset, remaining,
                                  IA64_LOW_RAM_LIMIT,
                                  "ia64-vpc.low-ram");
    offset += size;
    remaining -= size;

    size = ia64_vpc_map_ram_alias(machine, IA64_HIGH_RAM_BASE, offset,
                                  remaining,
                                  IA64_PCI_MMIO_BASE - IA64_HIGH_RAM_BASE,
                                  "ia64-vpc.high-ram-below-pci");
    offset += size;
    remaining -= size;

    size = ia64_vpc_map_ram_alias(
        machine, IA64_PCI_MMIO_BASE + IA64_PCI_MMIO_SIZE, offset, remaining,
        IA64_LOCAL_SAPIC_PA -
            (IA64_PCI_MMIO_BASE + IA64_PCI_MMIO_SIZE),
        "ia64-vpc.high-ram-above-pci");
    offset += size;
    remaining -= size;

    ia64_vpc_map_ram_alias(machine, IA64_HIGH_RAM_AFTER_FIRMWARE_BASE,
                           offset, remaining, remaining,
                           "ia64-vpc.high-ram-above-4g");
}

static void ia64_vpc_write_firmware_handoff(MachineState *machine)
{
    uint8_t handoff[112] = { 0 };
    struct tm tm;
    bool debug_port_present = debug_port_get_chardev() != NULL;

    stq_le_p(handoff, IA64_FW_HANDOFF_MAGIC);
    stq_le_p(handoff + 8, IA64_FW_HANDOFF_VERSION);
    stq_le_p(handoff + 16, machine->ram_size);
    qemu_get_timedate(&tm, 0);
    stq_le_p(handoff + 24, 1);
    stq_le_p(handoff + 32, tm.tm_year + 1900);
    stq_le_p(handoff + 40, tm.tm_mon + 1);
    stq_le_p(handoff + 48, tm.tm_mday);
    stq_le_p(handoff + 56, tm.tm_hour);
    stq_le_p(handoff + 64, tm.tm_min);
    stq_le_p(handoff + 72, tm.tm_sec);
    stq_le_p(handoff + 80, ia64_vpc_firmware_console);
    stq_le_p(handoff + 88, ia64_vpc_firmware_ide_dma);
    stq_le_p(handoff + 96,
             debug_port_present ? IA64_FW_DEBUG_PORT_PRESENT : 0);
    stq_le_p(handoff + 104, debug_port_present ? IA64_DEBUG_UART_BASE : 0);
    cpu_physical_memory_write(IA64_FW_HANDOFF_ADDR, handoff, sizeof(handoff));
}

static void ia64_vpc_configure_pci_irq(PCIDevice *pci_dev)
{
    uint8_t pin;

    if (pci_dev == NULL) {
        return;
    }

    pin = pci_dev->config[PCI_INTERRUPT_PIN];
    if (pin >= 1 && pin <= PCI_NUM_PINS) {
        pci_default_write_config(pci_dev, PCI_INTERRUPT_LINE,
                                 ia64_pci_route_intx_gsi(pci_dev->devfn,
                                                         pin - 1), 1);
    }
}

static void ia64_vpc_configure_ahci(PCIDevice *pci_dev)
{
    if (pci_dev == NULL) {
        return;
    }

    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_4,
                             IA64_AHCI_IDP_IO_BASE, 4);
    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_5,
                             IA64_AHCI_MMIO_PCI_BASE, 4);
    pci_default_write_config(pci_dev, PCI_COMMAND,
                             PCI_COMMAND_IO | PCI_COMMAND_MEMORY |
                             PCI_COMMAND_MASTER, 2);
}

static void ia64_vpc_configure_ohci(PCIDevice *pci_dev)
{
    if (pci_dev == NULL) {
        return;
    }

    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_0,
                             IA64_OHCI_MMIO_PCI_BASE, 4);
    pci_default_write_config(pci_dev, PCI_COMMAND,
                             PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER, 2);
}

static void ia64_vpc_configure_uhci(PCIDevice *pci_dev)
{
    if (pci_dev == NULL) {
        return;
    }

    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_4,
                             IA64_UHCI_IO_BASE, 4);
    pci_default_write_config(pci_dev, PCI_COMMAND,
                             PCI_COMMAND_IO | PCI_COMMAND_MASTER, 2);
}

static void ia64_vpc_configure_lsi(PCIDevice *pci_dev)
{
    if (pci_dev == NULL) {
        return;
    }

    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_0,
                             IA64_LSI_IO_BASE, 4);
    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_1,
                             IA64_LSI_MMIO_PCI_BASE, 4);
    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_2,
                             IA64_LSI_RAM_PCI_BASE, 4);
    pci_default_write_config(pci_dev, PCI_COMMAND,
                             PCI_COMMAND_IO | PCI_COMMAND_MEMORY |
                             PCI_COMMAND_MASTER, 2);
}

static void ia64_vpc_configure_vga(PCIDevice *pci_dev)
{
    if (pci_dev == NULL) {
        return;
    }

    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_0,
                             IA64_VGA_FB_PCI_BASE, 4);
    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_0 + 8,
                             IA64_VGA_MMIO_PCI_BASE, 4);
    pci_default_write_config(pci_dev, PCI_COMMAND,
                             PCI_COMMAND_IO | PCI_COMMAND_MEMORY, 2);

}

static void ia64_vpc_configure_platform_pci(void)
{
    ia64_vpc_configure_ahci(ia64_vpc_ahci_dev);
    ia64_vpc_configure_ohci(ia64_vpc_ohci_dev);
    ia64_vpc_configure_uhci(ia64_vpc_uhci_dev);
    ia64_vpc_configure_lsi(ia64_vpc_lsi_dev);
    ia64_vpc_configure_vga(ia64_vpc_vga_dev);
    ia64_vpc_configure_pci_irq(ia64_vpc_ahci_dev);
    ia64_vpc_configure_pci_irq(ia64_vpc_ohci_dev);
    ia64_vpc_configure_pci_irq(ia64_vpc_uhci_dev);
    ia64_vpc_configure_pci_irq(ia64_vpc_lsi_dev);
    ia64_vpc_configure_pci_irq(ia64_vpc_vga_dev);
}

#define TYPE_IA64_PCI_FIXUP_RESET "ia64-pci-fixup-reset"
OBJECT_DECLARE_SIMPLE_TYPE(IA64PciFixupReset, IA64_PCI_FIXUP_RESET)

struct IA64PciFixupReset {
    Object parent;
    ResettableState reset_state;
};

OBJECT_DEFINE_SIMPLE_TYPE_WITH_INTERFACES(
    IA64PciFixupReset, ia64_pci_fixup_reset, IA64_PCI_FIXUP_RESET, OBJECT,
    { TYPE_RESETTABLE_INTERFACE }, { })

static ResettableState *ia64_pci_fixup_reset_get_state(Object *obj)
{
    IA64PciFixupReset *s = IA64_PCI_FIXUP_RESET(obj);

    return &s->reset_state;
}

static void ia64_pci_fixup_reset_exit(Object *obj, ResetType type)
{
    (void)obj;
    (void)type;

    ia64_vpc_configure_platform_pci();
}

static void ia64_pci_fixup_reset_class_init(ObjectClass *klass,
                                            const void *data)
{
    ResettableClass *rc = RESETTABLE_CLASS(klass);

    (void)data;
    rc->get_state = ia64_pci_fixup_reset_get_state;
    rc->phases.exit = ia64_pci_fixup_reset_exit;
}

static void ia64_pci_fixup_reset_init(Object *obj)
{
    (void)obj;
}

static void ia64_pci_fixup_reset_finalize(Object *obj)
{
    (void)obj;
}

static void ia64_vpc_map_vga_fixed_windows(PCIDevice *pci_dev)
{
    PCIIORegion *fb;
    PCIIORegion *mmio;

    if (pci_dev == NULL) {
        return;
    }

    fb = &pci_dev->io_regions[0];
    mmio = &pci_dev->io_regions[2];
    if (fb->memory == NULL || mmio->memory == NULL ||
        fb->address_space == NULL || mmio->address_space == NULL) {
        return;
    }

    if (fb->address_space != mmio->address_space) {
        return;
    }

    if (ia64_vpc_vga_fb_alias == NULL) {
        ia64_vpc_vga_fb_alias = g_new(MemoryRegion, 1);
        memory_region_init_alias(ia64_vpc_vga_fb_alias, OBJECT(pci_dev),
                                 "ia64-vga-fb-fixed", fb->memory, 0, fb->size);
        memory_region_add_subregion_overlap(fb->address_space,
                                            IA64_VGA_FB_PCI_BASE,
                                            ia64_vpc_vga_fb_alias, 1);
    }

    if (ia64_vpc_vga_mmio_alias == NULL) {
        ia64_vpc_vga_mmio_alias = g_new(MemoryRegion, 1);
        memory_region_init_alias(ia64_vpc_vga_mmio_alias, OBJECT(pci_dev),
                                 "ia64-vga-mmio-fixed", mmio->memory, 0,
                                 mmio->size);
        memory_region_add_subregion_overlap(fb->address_space,
                                            IA64_VGA_MMIO_PCI_BASE,
                                            ia64_vpc_vga_mmio_alias, 1);
    }

    if (ia64_vpc_vga_legacy_alias == NULL) {
        ia64_vpc_vga_legacy_alias = g_new(MemoryRegion, 1);
        memory_region_init_alias(ia64_vpc_vga_legacy_alias,
                                 OBJECT(pci_dev),
                                 "ia64-vga-legacy-fixed",
                                 fb->address_space,
                                 IA64_VGA_LEGACY_BASE,
                                 IA64_VGA_LEGACY_SIZE);
        memory_region_add_subregion_overlap(get_system_memory(),
                                            IA64_VGA_LEGACY_BASE,
                                            ia64_vpc_vga_legacy_alias, 1);
    }
}

static void ia64_vpc_init_usb(MachineState *machine, PCIBus *pci_bus)
{
    USBBus *usb_bus;
    bool add_default_input;

    machine->usb |= defaults_enabled() && !machine->usb_disabled;
    if (!machine->usb) {
        return;
    }

    ia64_vpc_ohci_dev = pci_create_simple(pci_bus, -1, "pci-ohci");
    ia64_vpc_configure_ohci(ia64_vpc_ohci_dev);

    add_default_input = defaults_enabled() && !ia64_vpc_i8042_enabled;
    if (add_default_input) {
        /*
         * Attach default USB input only when PS/2 is disabled. HID keyboards
         * become QEMU's active input handler, which would otherwise hide
         * firmware-visible PS/2 input before a guest USB stack exists.
         */
        usb_bus = USB_BUS(object_resolve_type_unambiguous(TYPE_USB_BUS,
                                                          &error_abort));
        usb_create_simple(usb_bus, "usb-kbd");
        usb_create_simple(usb_bus, "usb-mouse");
    }

    ia64_vpc_uhci_dev = pci_create_simple(pci_bus, -1, TYPE_PIIX3_USB_UHCI);
    ia64_vpc_configure_uhci(ia64_vpc_uhci_dev);
}

/*
 * CPU state initialization — called on every reset.
 *
 * Sets up the CPU in physical mode with firmware entry point.
 * Note: ROM content is loaded by rom_reset() which may run before or
 * after this handler, so we must NOT read ROM content here.  PE32+
 * plabel parsing is deferred to the machine_done notifier.
 */
static void ia64_vpc_reset(void *opaque)
{
    CPUState *cs = first_cpu;
    CPUIA64State *env = cpu_env(cs);

    (void)opaque;

    /* Set initial PSR: physical mode, interrupts disabled, cpl=0 */
    env->psr = 0;

    /* Set initial IP to start of firmware */
    env->ip = IA64_FW_BASE;

    /* Set up b0 (return branch register) to firmware entry */
    env->br[0] = IA64_FW_BASE;

    /* IVA (Interrupt Vector Address) */
    env->cr_iva = IA64_IVT_BASE;

    /* Initialize PTA with VHPT disabled for physical mode */
    env->cr_pta = 0;

    /* Region registers */
    env->cr[8] = 0x0000000000000030ULL;  /* rr0: 256MB page, RID=0 */

    /* Initialize DCR */
    env->cr_dcr = IA64_DCR_DM | IA64_DCR_DP;

    /* Kernel registers */
    env->ar_kr0 = IA64_FW_BASE;
    env->ar_kr7 = 0;

    /* RSE state */
    env->ar_rsc = IA64_RSC_MODE;
    env->ar_bsp = 0x80000;
    env->ar_bspstore = 0x80000;
    env->ar_rnat = 0;
    env->cfm_sof = 0;
    env->cfm_sol = 0;
    env->cfm_sor = 0;
    env->cfm_rrb_gr = 0;

    /* Stack pointer */
    env->gr[12] = 0x200000;

    /* Loader base.  The flat firmware entry code derives its link-time GP. */
    env->gr[1] = IA64_FW_BASE;

    /* ITC timer */
    ia64_itc_write(env, 0);

    /* FPSR */
    env->ar_fpsr = IA64_FPSR_DEFAULT;

    /* FP status */
    set_float_rounding_mode(float_round_nearest_even, &env->fp_status);
    set_flush_to_zero(false, &env->fp_status);
    set_flush_inputs_to_zero(false, &env->fp_status);
    set_default_nan_mode(false, &env->fp_status);

    acpi_pm1_evt_reset(&ia64_vpc_acpi_regs);
    acpi_pm1_cnt_reset(&ia64_vpc_acpi_regs);
    acpi_pm_tmr_reset(&ia64_vpc_acpi_regs);
    acpi_gpe_reset(&ia64_vpc_acpi_regs);
}

/*
 * Machine-done notifier — runs after the first reset cycle completes,
 * so ROM content is guaranteed to be in guest memory.  Parse a firmware
 * plabel only when the firmware image is a valid IA-64 PE32+ binary.
 */
typedef struct {
    Notifier notifier;
    MachineState *machine;
} IA64VpcDoneNotifier;

static void ia64_vpc_machine_done(Notifier *notifier, void *data)
{
    IA64VpcDoneNotifier *n = container_of(notifier,
                                            IA64VpcDoneNotifier, notifier);
    MachineState *machine = n->machine;
    CPUState *cs = first_cpu;
    CPUIA64State *env = cpu_env(cs);

    ia64_vpc_configure_platform_pci();

    if (!machine->firmware) {
        return;
    }

    uint8_t mz_hdr[0x40];
    uint8_t pe_hdr[24];
    uint8_t opt_hdr[20];
    uint32_t e_lfanew, entry_rva;
    uint16_t machine_type, opt_magic;
    uint64_t plabel[2];

    /*
     * The project firmware is a flat raw binary (no DOS+PE header).
     * Without a strict PE signature gate, random bytes can be mistaken
     * for PE metadata and clobber startup registers (including gp).
     */
    cpu_physical_memory_read(IA64_FW_BASE, mz_hdr, sizeof(mz_hdr));
    if (ia64_lduw(mz_hdr) != 0x5a4d) {
        return;
    }

    /* Read PE header offset (e_lfanew at offset 0x3C in MZ header) */
    e_lfanew = ia64_ldl(mz_hdr + 0x3c);
    if (e_lfanew < sizeof(mz_hdr) || e_lfanew > 0x100000) {
        return;
    }

    cpu_physical_memory_read(IA64_FW_BASE + e_lfanew, pe_hdr, sizeof(pe_hdr));
    if (memcmp(pe_hdr, "PE\0\0", 4) != 0) {
        return;
    }

    machine_type = ia64_lduw(pe_hdr + 4);
    if (machine_type != 0x0200) {
        return;
    }

    cpu_physical_memory_read(IA64_FW_BASE + e_lfanew + 24, opt_hdr,
                             sizeof(opt_hdr));
    opt_magic = ia64_lduw(opt_hdr);
    if (opt_magic != 0x020b) {
        return;
    }

    /* PE32+ optional header: AddressOfEntryPoint at offset 16 */
    entry_rva = ia64_ldl(opt_hdr + 16);
    if (entry_rva == 0) {
        return;
    }

    /* Read plabel (function descriptor) at entry point RVA */
    cpu_physical_memory_read(IA64_FW_BASE + entry_rva, plabel, 16);

    {
        uint64_t entry_addr = le64_to_cpu(plabel[0]);
        uint64_t gp_val = le64_to_cpu(plabel[1]);

        /* Sanity: entry must be in a reasonable address range */
        if (entry_addr != 0 && entry_addr < 0x100000000ULL) {
            env->ip = entry_addr;
            env->br[0] = entry_addr;
            env->gr[1] = gp_val;
        }
    }
}

static IA64VpcDoneNotifier vpc_done_notifier;

static void ia64_vpc_init(MachineState *machine)
{
    DeviceState *pci_host;
    DeviceState *iosapic;
    PCIBus *pci_bus;
    ISABus *isa_bus;
    MemoryRegion *pci_io;
    int i;

    if (machine->ram_size < IA64_FW_LOW_RAM_MIN) {
        char *sz = size_to_str(IA64_FW_LOW_RAM_MIN);

        error_report("Invalid RAM size, should be at least %s", sz);
        g_free(sz);
        exit(1);
    }

    ia64_vpc_map_ram(machine);
    ia64_vpc_map_firmware_address_space();
    ia64_vpc_init_nvram(machine);
    ia64_vpc_write_firmware_handoff(machine);

    cpu_create(machine->cpu_type);
    ia64_vpc_map_lsapic();

    iosapic = qdev_new(TYPE_IA64_IOSAPIC);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(iosapic), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(iosapic), 0, IA64_IOSAPIC_BASE);

    serial_mm_init(get_system_memory(), IA64_UART_BASE, 0,
                   qdev_get_gpio_in(iosapic, 4),
                   115200, serial_hd(0), DEVICE_LITTLE_ENDIAN);
    if (debug_port_get_chardev()) {
        serial_mm_init(get_system_memory(), IA64_DEBUG_UART_BASE, 0,
                       qdev_get_gpio_in(iosapic, 3),
                       115200, debug_port_get_chardev(),
                       DEVICE_LITTLE_ENDIAN);
    }

    if (machine->firmware) {
        if (rom_add_file_fixed(machine->firmware, IA64_FW_BASE, -1)) {
            error_report("failed to load firmware '%s'", machine->firmware);
            exit(1);
        }
    }

    /* Fill IVT with break bundles (one-time, before any reset) */
    {
        uint64_t break_bundle[2] = {0, 0};
        hwaddr offset;

        for (offset = 0; offset < IA64_IVT_SIZE; offset += 16) {
            cpu_physical_memory_write(IA64_IVT_BASE + offset,
                                      break_bundle, 16);
        }
    }

    /* Defer PE32+ plabel parsing until after ROM content is loaded */
    vpc_done_notifier.machine = machine;
    vpc_done_notifier.notifier.notify = ia64_vpc_machine_done;
    qemu_add_machine_init_done_notifier(&vpc_done_notifier.notifier);

    pci_host = qdev_new(TYPE_IA64_PCI_HOST_BRIDGE);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(pci_host), &error_fatal);
    pci_bus = PCI_BUS(qdev_get_child_bus(pci_host, "pci"));

    /*
     * Slot 0 is intentionally empty in the default machine.  Reserve it while
     * creating the built-in devices so their historical slot numbers remain
     * stable, then release it for an explicitly requested PCI controller.
     */
    pci_bus_set_slot_reserved_mask(pci_bus, 1U << 0);
    pci_io = pci_bus->address_space_io;
    ia64_vpc_init_acpi_pm(machine, iosapic, pci_io);

    /* Leave ISA/SCI lines in the legacy range and route PCI INTx above 15. */
    for (i = 0; i < IA64_PCI_INTX_LINES; i++) {
        qdev_connect_gpio_out(pci_host, i,
                              qdev_get_gpio_in(iosapic,
                                               IA64_PCI_INTX_GSI_BASE + i));
    }

    /*
     * AHCI remains available for guests that support SATA.  Firmware boot
     * storage is provided by the LSI SCSI HBA below.
     */
    ia64_vpc_ahci_dev = pci_create_simple(pci_bus, -1, TYPE_ICH9_AHCI);
    ia64_vpc_configure_ahci(ia64_vpc_ahci_dev);

    isa_bus = isa_bus_new(NULL, get_system_memory(), pci_io, &error_fatal);
    for (i = 0; i < ISA_NUM_IRQS; i++) {
        ia64_vpc_isa_irqs[i] = qdev_get_gpio_in(iosapic, i);
    }
    isa_bus_register_input_irqs(isa_bus, ia64_vpc_isa_irqs);
    if (ia64_vpc_i8042_enabled) {
        isa_create_simple(isa_bus, TYPE_I8042);
    }

    ia64_vpc_init_usb(machine, pci_bus);

    /*
     * Put the SCSI HBA on device 4.  The firmware DSDT _PRT covers root-bus
     * devices 0..4, and VGA does not require an interrupt line.
     */
    ia64_vpc_lsi_dev = pci_new(PCI_DEVFN(4, 0), "lsi53c895a");
    qdev_prop_set_bit(DEVICE(ia64_vpc_lsi_dev),
                      "disconnect-on-data-wait", false);
    pci_realize_and_unref(ia64_vpc_lsi_dev, pci_bus, &error_fatal);
    ia64_vpc_configure_lsi(ia64_vpc_lsi_dev);
    lsi53c8xx_handle_legacy_cmdline(DEVICE(ia64_vpc_lsi_dev));

    ia64_vpc_vga_dev = pci_vga_init(pci_bus);
    ia64_vpc_configure_vga(ia64_vpc_vga_dev);
    ia64_vpc_map_vga_fixed_windows(ia64_vpc_vga_dev);
    pci_bus_clear_slot_reserved_mask(pci_bus, 1U << 0);

    ia64_vpc_powerdown_notifier.notify = ia64_vpc_powerdown_req;
    qemu_register_powerdown_notifier(&ia64_vpc_powerdown_notifier);

    qemu_register_reset(ia64_vpc_reset, NULL);
    ia64_vpc_pci_fixup_reset = object_new(TYPE_IA64_PCI_FIXUP_RESET);
    qemu_register_resettable(ia64_vpc_pci_fixup_reset);
}

static void ia64_vpc_machine_init(MachineClass *mc)
{
    ObjectClass *oc = OBJECT_CLASS(mc);

    mc->desc = "IA-64 virtual PC platform";
    mc->init = ia64_vpc_init;
    mc->max_cpus = 1;
    mc->default_cpus = 1;
    mc->default_cpu_type = IA64_CPU_TYPE_NAME("itanium2");
    mc->default_ram_size = 2 * GiB;
    mc->default_ram_id = "ia64-vpc.ram";
    mc->default_display = "std";
    mc->block_default_type = IF_SCSI;
    mc->no_serial = 0;
    mc->no_parallel = 1;
    mc->no_floppy = 1;
    mc->no_cdrom = 0;

    compat_props_add(mc->compat_props, ia64_vpc_compat_defaults,
                     G_N_ELEMENTS(ia64_vpc_compat_defaults));

    object_class_property_add_bool(oc, "i8042",
                                   ia64_vpc_get_i8042,
                                   ia64_vpc_set_i8042);
    object_class_property_set_description(oc, "i8042",
        "Set on/off to enable/disable the i8042 PS/2 controller");
    object_class_property_add_bool(oc, "firmware-ide-dma",
                                   ia64_vpc_get_firmware_ide_dma,
                                   ia64_vpc_set_firmware_ide_dma);
    object_class_property_set_description(oc, "firmware-ide-dma",
        "Set on/off to enable/disable firmware IDE bus-master DMA");
    object_class_property_add_str(oc, "firmware-console",
                                  ia64_vpc_get_firmware_console,
                                  ia64_vpc_set_firmware_console);
    object_class_property_set_description(oc, "firmware-console",
        "Set firmware HCDP primary console to 'serial' or 'vga'");
    object_class_property_add_str(oc, "nvram",
                                  ia64_vpc_get_nvram,
                                  ia64_vpc_set_nvram);
    object_class_property_set_description(oc, "nvram",
        "Set the IA-64 EFI NVRAM file path, 'auto', or 'none'");
}

DEFINE_MACHINE("ia64-vpc", ia64_vpc_machine_init)
