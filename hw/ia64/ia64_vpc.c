/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * IA-64 virtual PC platform.
 *
 * Provides RAM, a bootstrap CPU, a memory-mapped serial console,
 * firmware ROM loading via -bios, a PCI host bridge, SCSI and AHCI storage
 * controllers, an Ethernet controller, OHCI/UHCI USB,
 * local SAPIC/I/O SAPIC wiring,
 * and ACPI fixed power-management registers.
 */

#include "qemu/osdep.h"

#include CONFIG_DEVICES

#include "qemu/units.h"
#include "qemu/cutils.h"
#include "qemu/datadir.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "hw/core/boards.h"
#include "hw/core/cpu.h"
#include "hw/core/qdev-properties.h"
#include "hw/char/serial-mm.h"
#include "hw/core/loader.h"
#include "hw/core/sysbus.h"
#include "hw/ide/ahci-pci.h"
#include "hw/ide/ide-dev.h"
#include "hw/input/i8042.h"
#include "hw/acpi/acpi.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_bus.h"
#include "net/net.h"
#include "hw/isa/isa.h"
#include "hw/usb/hcd-uhci.h"
#include "hw/usb/usb.h"
#include "hw/ia64/ia64_loader.h"
#include "hw/ia64/ia64_pci.h"
#include "hw/ia64/ia64_iosapic.h"
#include "system/address-spaces.h"
#include "system/rtc.h"
#include "system/runstate.h"
#include "system/system.h"
#include "system/reset.h"
#include "system/watchdog.h"
#include "target/ia64/cpu-qom.h"
#include "target/ia64/cpu.h"

#define IA64_FW_BASE    0x0000000000100000ULL
#define IA64_LOW_RAM_LIMIT 0x0000000080000000ULL
#define IA64_HIGH_RAM_BASE 0x0000000080200000ULL
#define IA64_FIRMWARE_ADDRESS_SPACE_BASE 0x00000000ff000000ULL
#define IA64_FIRMWARE_ADDRESS_SPACE_SIZE (16 * MiB)
#define IA64_RTC_BASE 0x00000000ffef0000ULL
#define IA64_RTC_SIZE (8 * KiB)
#define IA64_WATCHDOG_BASE 0x00000000ffee0000ULL
#define IA64_WATCHDOG_SIZE (4 * KiB)
#define IA64_WATCHDOG_TIMEOUT 0x00
#define IA64_WATCHDOG_CODE    0x08
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
#define IA64_VGA_IO_BASE        0x0000c300U
#define IA64_E1000_IO_BASE      0x0000c400U
#define IA64_OHCI_MMIO_PCI_BASE (IA64_PCI_MMIO_BASE + 0x00010000ULL)
#define IA64_AHCI_MMIO_PCI_BASE (IA64_PCI_MMIO_BASE + 0x00020000ULL)
#define IA64_LSI_MMIO_PCI_BASE  (IA64_PCI_MMIO_BASE + 0x00030000ULL)
#define IA64_LSI_RAM_PCI_BASE   (IA64_PCI_MMIO_BASE + 0x00032000ULL)
#define IA64_E1000_MMIO_PCI_BASE (IA64_PCI_MMIO_BASE + 0x00040000ULL)
#define IA64_E1000_MMIO_SIZE    0x00020000ULL
#define IA64_E1000_IO_SIZE      0x00000040U
#define IA64_VGA_FB_PCI_BASE    0x00000000c4000000ULL
#define IA64_VGA_MMIO_PCI_BASE  0x00000000c8000000ULL
#define IA64_VGA_LEGACY_BASE   0x000a0000U
#define IA64_VGA_LEGACY_SIZE   0x00020000U
#define IA64_IOSAPIC_BASE       0x0000000080110000ULL
#define IA64_IOSAPIC_SIZE       0x0000000000002000ULL
#define IA64_ACPI_PM_IO_BASE    0x00002000U
#define IA64_ACPI_PM_IO_SIZE    0x00000010U
#define IA64_ACPI_PM_RESET_OFFSET 0x0000000cU
#define IA64_ACPI_PM_RESET_VALUE  0x01U
#define IA64_ACPI_SCI_IRQ       9
#define IA64_PIB_IPI_LIMIT          0x00100000ULL
#define IA64_PIB_INTA_OFFSET        0x001e0000ULL
#define IA64_PIB_XTP_OFFSET         0x001e0008ULL
#define IA64_VPC_MAX_CPUS           4
#define IA64_VPC_NIC_SLOT           6
#define IA64_VPC_RSE_STACK_SIZE     0x8000ULL
#define IA64_VPC_EARLY_STACK_TOP    0x08000000ULL
#define IA64_VPC_AP_EARLY_STACK_TOP 0x00100000ULL
#define IA64_VPC_EARLY_STACK_STRIDE 0x10000ULL

#define IA64_SAPIC_DELIVERY_INT     0
#define IA64_SAPIC_DELIVERY_NMI     4
#define IA64_SAPIC_DELIVERY_EXTINT  7

#define TYPE_IA64_VPC_MACHINE MACHINE_TYPE_NAME("ia64-vpc")
OBJECT_DECLARE_SIMPLE_TYPE(IA64VpcMachineState, IA64_VPC_MACHINE)

struct IA64VpcMachineState {
    MachineState parent_obj;

    bool i8042_enabled;
    bool firmware_ide_dma;
    uint64_t firmware_console;
    char *nvram_path;
    bool alat_full;

    PCIDevice *ahci_dev;
    PCIDevice *ohci_dev;
    PCIDevice *uhci_dev;
    PCIDevice *lsi_dev;
    PCIDevice *vga_dev;
    PCIDevice *nic_devs[MAX_NICS];
    unsigned int nic_count;

    MemoryRegion *ram_aliases[4];
    unsigned int ram_alias_count;
    MemoryRegion *vga_fb_alias;
    MemoryRegion *vga_mmio_alias;
    MemoryRegion *vga_legacy_alias;
    MemoryRegion *lsapic_mmio;
    MemoryRegion firmware_space;
    MemoryRegion rtc_mmio;
    MemoryRegion watchdog_mmio;
    MemoryRegion nvram_mmio;
    MemoryRegion acpi_pm;
    MemoryRegion acpi_reset;

    Object *pci_fixup_reset;
    QEMUTimer *watchdog_timer;
    uint64_t watchdog_timeout;
    uint64_t watchdog_code;
    uint8_t nvram_data[IA64_NVRAM_SIZE];
    size_t firmware_size;
    char *nvram_resolved_path;
    bool nvram_write_warning;
    ACPIREGS acpi_regs;
    qemu_irq acpi_sci_irq;
    qemu_irq isa_irqs[ISA_NUM_IRQS];
    Notifier powerdown_notifier;
    Notifier done_notifier;
};

static uint64_t ia64_vpc_rtc_read(void *opaque, hwaddr addr, unsigned size)
{
    struct tm tm;

    (void)opaque;
    if (addr != 0 || size != sizeof(uint64_t)) {
        return 0;
    }

    /*
     * Expose the QEMU-configured RTC as seconds since the Unix epoch.  A
     * single aligned 64-bit read is intrinsically coherent, unlike a bank of
     * calendar registers whose fields could straddle a second boundary.
     */
    qemu_get_timedate(&tm, 0);
    return mktimegm(&tm);
}

static void ia64_vpc_rtc_write(void *opaque, hwaddr addr, uint64_t value,
                               unsigned size)
{
    /* The platform RTC is a read-only seconds-since-epoch register. */
    (void)opaque;
    (void)addr;
    (void)value;
    (void)size;
}

static const MemoryRegionOps ia64_vpc_rtc_ops = {
    .read = ia64_vpc_rtc_read,
    .write = ia64_vpc_rtc_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 8,
        .max_access_size = 8,
        .unaligned = false,
    },
    .impl = {
        .min_access_size = 8,
        .max_access_size = 8,
        .unaligned = false,
    },
};

static void ia64_vpc_init_rtc(IA64VpcMachineState *s)
{
    memory_region_init_io(&s->rtc_mmio, OBJECT(s),
                          &ia64_vpc_rtc_ops, s, "ia64-vpc.rtc",
                          IA64_RTC_SIZE);
    memory_region_add_subregion_overlap(get_system_memory(), IA64_RTC_BASE,
                                        &s->rtc_mmio, 2);
}

static void ia64_vpc_watchdog_expired(void *opaque)
{
    IA64VpcMachineState *s = opaque;

    warn_report("IA-64 firmware watchdog expired (code 0x%" PRIx64 ")",
                s->watchdog_code);
    s->watchdog_timeout = 0;
    watchdog_perform_action();
}

static uint64_t ia64_vpc_watchdog_read(void *opaque, hwaddr addr,
                                       unsigned size)
{
    IA64VpcMachineState *s = opaque;

    (void)size;

    switch (addr) {
    case IA64_WATCHDOG_TIMEOUT:
        return s->watchdog_timeout;
    case IA64_WATCHDOG_CODE:
        return s->watchdog_code;
    default:
        return 0;
    }
}

static void ia64_vpc_watchdog_write(void *opaque, hwaddr addr,
                                    uint64_t value, unsigned size)
{
    IA64VpcMachineState *s = opaque;
    int64_t now;
    int64_t delta;

    if (size != sizeof(uint64_t)) {
        return;
    }

    switch (addr) {
    case IA64_WATCHDOG_CODE:
        s->watchdog_code = value;
        break;
    case IA64_WATCHDOG_TIMEOUT:
        s->watchdog_timeout = value;
        timer_del(s->watchdog_timer);
        if (value == 0) {
            break;
        }
        now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        if (value > (uint64_t)(INT64_MAX - now) / NANOSECONDS_PER_SECOND) {
            delta = INT64_MAX - now;
        } else {
            delta = value * NANOSECONDS_PER_SECOND;
        }
        timer_mod(s->watchdog_timer, now + delta);
        break;
    default:
        break;
    }
}

static const MemoryRegionOps ia64_vpc_watchdog_ops = {
    .read = ia64_vpc_watchdog_read,
    .write = ia64_vpc_watchdog_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 8,
        .max_access_size = 8,
        .unaligned = false,
    },
    .impl = {
        .min_access_size = 8,
        .max_access_size = 8,
        .unaligned = false,
    },
};

static void ia64_vpc_watchdog_reset(void *opaque)
{
    IA64VpcMachineState *s = opaque;

    timer_del(s->watchdog_timer);
    s->watchdog_timeout = 0;
    s->watchdog_code = 0;
}

static void ia64_vpc_init_watchdog(IA64VpcMachineState *s)
{
    s->watchdog_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                     ia64_vpc_watchdog_expired, s);
    memory_region_init_io(&s->watchdog_mmio, OBJECT(s),
                          &ia64_vpc_watchdog_ops, s,
                          "ia64-vpc.firmware-watchdog",
                          IA64_WATCHDOG_SIZE);
    memory_region_add_subregion_overlap(get_system_memory(),
                                        IA64_WATCHDOG_BASE,
                                        &s->watchdog_mmio, 2);
    qemu_register_reset(ia64_vpc_watchdog_reset, s);
}

static char *ia64_vpc_get_nvram(Object *obj, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    (void)errp;

    return g_strdup(s->nvram_path ?: "auto");
}

static void ia64_vpc_set_nvram(Object *obj, const char *value, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    (void)errp;

    g_free(s->nvram_path);
    s->nvram_path = g_strcmp0(value, "auto") == 0 ?
                    NULL : g_strdup(value);
}

static uint64_t ia64_vpc_nvram_read(void *opaque, hwaddr addr,
                                    unsigned size)
{
    IA64VpcMachineState *s = opaque;
    uint64_t value = 0;
    unsigned i;

    for (i = 0; i < size; i++) {
        value |= (uint64_t)s->nvram_data[addr + i] << (i * 8);
    }
    return value;
}

static void ia64_vpc_nvram_commit(IA64VpcMachineState *s)
{
    g_autoptr(GError) err = NULL;

    if (!s->nvram_resolved_path) {
        return;
    }
    if (!g_file_set_contents(s->nvram_resolved_path,
                             (const char *)s->nvram_data,
                             sizeof(s->nvram_data), &err) &&
        !s->nvram_write_warning) {
        warn_report("failed to save IA-64 NVRAM '%s': %s",
                    s->nvram_resolved_path,
                    err ? err->message : "unknown error");
        s->nvram_write_warning = true;
    }
}

static void ia64_vpc_nvram_write(void *opaque, hwaddr addr,
                                 uint64_t value, unsigned size)
{
    IA64VpcMachineState *s = opaque;
    unsigned i;

    if (addr == IA64_NVRAM_COMMIT_OFFSET && size == 8 &&
        value == IA64_NVRAM_COMMIT_MAGIC) {
        ia64_vpc_nvram_commit(s);
        return;
    }
    for (i = 0; i < size; i++) {
        s->nvram_data[addr + i] = value >> (i * 8);
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

static void ia64_vpc_init_nvram(IA64VpcMachineState *s)
{
    MachineState *machine = MACHINE(s);
    g_autofree char *firmware_path = NULL;
    g_autofree char *directory = NULL;
    g_autofree char *contents = NULL;
    g_autoptr(GError) err = NULL;
    gsize length = 0;

    memset(s->nvram_data, 0, sizeof(s->nvram_data));
    g_clear_pointer(&s->nvram_resolved_path, g_free);
    s->nvram_write_warning = false;

    if (g_strcmp0(s->nvram_path, "none") != 0) {
        if (s->nvram_path) {
            s->nvram_resolved_path = g_strdup(s->nvram_path);
        } else if (machine->firmware) {
            firmware_path = qemu_find_file(QEMU_FILE_TYPE_BIOS,
                                           machine->firmware);
            if (!firmware_path) {
                firmware_path = g_strdup(machine->firmware);
            }
            directory = g_path_get_dirname(firmware_path);
            s->nvram_resolved_path =
                g_build_filename(directory, "nvram", NULL);
        }
    }

    if (s->nvram_resolved_path &&
        g_file_get_contents(s->nvram_resolved_path, &contents,
                            &length, &err)) {
        if (length == sizeof(s->nvram_data)) {
            memcpy(s->nvram_data, contents, length);
        } else {
            warn_report("ignoring IA-64 NVRAM '%s': expected %zu bytes, "
                        "found %zu",
                        s->nvram_resolved_path,
                        sizeof(s->nvram_data), (size_t)length);
        }
    } else if (err && !g_error_matches(err, G_FILE_ERROR,
                                       G_FILE_ERROR_NOENT)) {
        warn_report("failed to load IA-64 NVRAM '%s': %s",
                    s->nvram_resolved_path, err->message);
    }

    memory_region_init_io(&s->nvram_mmio, OBJECT(s),
                          &ia64_vpc_nvram_ops, s, "ia64-vpc.nvram",
                          IA64_NVRAM_SIZE);
    memory_region_add_subregion_overlap(get_system_memory(), IA64_NVRAM_BASE,
                                        &s->nvram_mmio, 2);
}

typedef struct IA64VpcCompatDefault {
    const char *driver;
    const char *property;
    const char *value;
} IA64VpcCompatDefault;

static const IA64VpcCompatDefault ia64_vpc_compat_defaults[] = {
    /*
     * Some IA-64 USB hub drivers use an alignment-requiring 32-bit load for
     * packed extended-property descriptors.  Do not expose the optional
     * selective-suspend property on HID input devices.
     */
    { "usb-kbd", "msos-desc", "off" },
    { "usb-mouse", "msos-desc", "off" },
    { "usb-tablet", "msos-desc", "off" },
};

static void ia64_vpc_add_compat_defaults(MachineClass *mc)
{
    size_t i;

    for (i = 0; i < G_N_ELEMENTS(ia64_vpc_compat_defaults); i++) {
        const IA64VpcCompatDefault *value = &ia64_vpc_compat_defaults[i];
        GlobalProperty *property = g_new0(GlobalProperty, 1);

        property->driver = value->driver;
        property->property = value->property;
        property->value = value->value;
        g_ptr_array_add(mc->compat_props, property);
    }
}

static bool ia64_vpc_get_i8042(Object *obj, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    (void)errp;

    return s->i8042_enabled;
}

static void ia64_vpc_set_i8042(Object *obj, bool value, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

#ifndef CONFIG_IA64_VPC_PS2
    if (value) {
        error_setg(errp, "i8042 support is not present in this build");
        return;
    }
#else
    (void)errp;
#endif

    s->i8042_enabled = value;
}

static bool ia64_vpc_get_firmware_ide_dma(Object *obj, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    (void)errp;

    return s->firmware_ide_dma;
}

static void ia64_vpc_set_firmware_ide_dma(Object *obj, bool value,
                                          Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

#ifndef CONFIG_IA64_VPC_STORAGE
    if (value) {
        error_setg(errp,
                   "firmware IDE DMA support is not present in this build");
        return;
    }
#else
    (void)errp;
#endif

    s->firmware_ide_dma = value;
}

static char *ia64_vpc_get_firmware_console(Object *obj, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    (void)errp;

    return g_strdup(s->firmware_console == IA64_FW_CONSOLE_VGA ?
                    "vga" : "serial");
}

static void ia64_vpc_set_firmware_console(Object *obj, const char *value,
                                          Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    if (g_strcmp0(value, "serial") == 0) {
        s->firmware_console = IA64_FW_CONSOLE_SERIAL;
        return;
    }
    if (g_strcmp0(value, "vga") == 0) {
#ifndef CONFIG_IA64_VPC_GRAPHICS
        error_setg(errp, "VGA support is not present in this build");
#else
        s->firmware_console = IA64_FW_CONSOLE_VGA;
#endif
        return;
    }

    error_setg(errp, "firmware-console must be 'serial' or 'vga'");
}

static char *ia64_vpc_get_alat(Object *obj, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    (void)errp;

    return g_strdup(s->alat_full ? "full" : "zero");
}

static void ia64_vpc_set_alat(Object *obj, const char *value, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    if (g_strcmp0(value, "zero") == 0) {
        s->alat_full = false;
        return;
    }
    if (g_strcmp0(value, "full") == 0) {
        s->alat_full = true;
        return;
    }

    error_setg(errp, "alat must be 'zero' or 'full'");
}

static void ia64_vpc_acpi_update_sci(ACPIREGS *ar)
{
    IA64VpcMachineState *s = container_of(ar, IA64VpcMachineState,
                                          acpi_regs);

    acpi_update_sci(ar, s->acpi_sci_irq);
}

static uint64_t ia64_vpc_acpi_reset_read(void *opaque, hwaddr addr,
                                         unsigned size)
{
    (void)opaque;
    (void)addr;
    (void)size;
    return 0;
}

static void ia64_vpc_acpi_reset_write(void *opaque, hwaddr addr,
                                      uint64_t value, unsigned size)
{
    (void)opaque;
    if (addr == 0 && size == 1 &&
        (value & 0xff) == IA64_ACPI_PM_RESET_VALUE) {
        qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
    }
}

static const MemoryRegionOps ia64_vpc_acpi_reset_ops = {
    .read = ia64_vpc_acpi_reset_read,
    .write = ia64_vpc_acpi_reset_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 1,
    },
};

static void ia64_vpc_init_acpi_pm(IA64VpcMachineState *s,
                                  DeviceState *iosapic,
                                  MemoryRegion *pci_io)
{
    s->acpi_sci_irq = qdev_get_gpio_in(iosapic, IA64_ACPI_SCI_IRQ);

    memory_region_init(&s->acpi_pm, OBJECT(s), "ia64-acpi-pm",
                       IA64_ACPI_PM_IO_SIZE);
    memory_region_add_subregion(pci_io, IA64_ACPI_PM_IO_BASE,
                                &s->acpi_pm);

    acpi_pm1_evt_init(&s->acpi_regs, ia64_vpc_acpi_update_sci,
                      &s->acpi_pm);
    acpi_pm1_cnt_init(&s->acpi_regs, &s->acpi_pm,
                      false, false, 0, true);
    acpi_pm_tmr_init(&s->acpi_regs, ia64_vpc_acpi_update_sci,
                     &s->acpi_pm);
    memory_region_init_io(&s->acpi_reset, OBJECT(s),
                          &ia64_vpc_acpi_reset_ops, s,
                          "ia64-acpi-reset", 1);
    memory_region_add_subregion(&s->acpi_pm,
                                IA64_ACPI_PM_RESET_OFFSET,
                                &s->acpi_reset);

    /*
     * acpi_update_sci() always folds in GPE status.  The current platform
     * exposes no GPE block to the guest, but the shared ACPI core still needs
     * backing storage for that internal zero-valued contribution.
     */
    acpi_gpe_init(&s->acpi_regs, 2);
}

static void ia64_vpc_powerdown_req(Notifier *n, void *opaque)
{
    IA64VpcMachineState *s = container_of(n, IA64VpcMachineState,
                                          powerdown_notifier);

    (void)opaque;

    if (s->acpi_regs.pm1.evt.en & ACPI_BITMASK_POWER_BUTTON_ENABLE) {
        acpi_pm1_evt_power_down(&s->acpi_regs);
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
    unsigned delivery;
    uint8_t id;
    uint8_t eid;
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
    id = (addr >> 12) & 0xff;
    eid = (addr >> 4) & 0xff;
    delivery = (value >> 8) & 7;
    switch (delivery) {
    case IA64_SAPIC_DELIVERY_INT:
        vector = value & 0xff;
        if (!ia64_external_interrupt_vector_valid(vector)) {
            return;
        }
        break;
    case IA64_SAPIC_DELIVERY_NMI:
        vector = 2;
        break;
    case IA64_SAPIC_DELIVERY_EXTINT:
        vector = 0;
        break;
    default:
        return;
    }

    cs = ia64_cpu_by_sapic_id(id, eid);
    if (cs == NULL) {
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

static void ia64_vpc_map_lsapic(IA64VpcMachineState *s)
{
    if (s->lsapic_mmio != NULL) {
        return;
    }

    s->lsapic_mmio = g_new(MemoryRegion, 1);
    memory_region_init_io(s->lsapic_mmio, OBJECT(s),
                          &ia64_vpc_lsapic_ops, s,
                          "ia64-vpc.local-sapic",
                          IA64_LOCAL_SAPIC_SIZE);
    memory_region_add_subregion(get_system_memory(), IA64_LOCAL_SAPIC_PA,
                                s->lsapic_mmio);
}

static bool ia64_vpc_map_firmware_address_space(IA64VpcMachineState *s,
                                                Error **errp)
{
    Error *local_err = NULL;

    /*
     * IA-64 reserves the top 16 MiB below 4 GiB for PAL/SAL firmware
     * resources.  Decode it so firmware identity mappings can use the
     * platform address space directly.
     */
    memory_region_init_ram(&s->firmware_space, NULL,
                           "ia64-firmware-address-space",
                           IA64_FIRMWARE_ADDRESS_SPACE_SIZE, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return false;
    }
    memory_region_add_subregion_overlap(get_system_memory(),
                                        IA64_FIRMWARE_ADDRESS_SPACE_BASE,
                                        &s->firmware_space, 1);
    return true;
}

static uint64_t ia64_vpc_map_ram_alias(IA64VpcMachineState *s,
                                       hwaddr guest_base,
                                       uint64_t backing_offset,
                                       uint64_t remaining,
                                       uint64_t capacity,
                                       const char *name)
{
    MachineState *machine = MACHINE(s);
    MemoryRegion *alias;
    uint64_t size = MIN(remaining, capacity);

    if (size == 0) {
        return 0;
    }

    g_assert(s->ram_alias_count < ARRAY_SIZE(s->ram_aliases));
    alias = g_new(MemoryRegion, 1);
    s->ram_aliases[s->ram_alias_count++] = alias;
    memory_region_init_alias(alias, OBJECT(s), name, machine->ram,
                             backing_offset, size);
    memory_region_add_subregion(get_system_memory(), guest_base, alias);
    return size;
}

static void ia64_vpc_map_ram(IA64VpcMachineState *s)
{
    MachineState *machine = MACHINE(s);
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
    size = ia64_vpc_map_ram_alias(s, 0, offset, remaining,
                                  IA64_LOW_RAM_LIMIT,
                                  "ia64-vpc.low-ram");
    offset += size;
    remaining -= size;

    size = ia64_vpc_map_ram_alias(s, IA64_HIGH_RAM_BASE, offset,
                                  remaining,
                                  IA64_PCI_MMIO_BASE - IA64_HIGH_RAM_BASE,
                                  "ia64-vpc.high-ram-below-pci");
    offset += size;
    remaining -= size;

    size = ia64_vpc_map_ram_alias(
        s, IA64_PCI_MMIO_BASE + IA64_PCI_MMIO_SIZE, offset, remaining,
        IA64_LOCAL_SAPIC_PA -
            (IA64_PCI_MMIO_BASE + IA64_PCI_MMIO_SIZE),
        "ia64-vpc.high-ram-above-pci");
    offset += size;
    remaining -= size;

    ia64_vpc_map_ram_alias(s, IA64_HIGH_RAM_AFTER_FIRMWARE_BASE,
                           offset, remaining, remaining,
                           "ia64-vpc.high-ram-above-4g");
}

static void ia64_vpc_write_firmware_handoff(IA64VpcMachineState *s)
{
    MachineState *machine = MACHINE(s);
    IA64VpcHandoff handoff = { 0 };
    bool debug_port_present = debug_port_get_chardev() != NULL;

    _Static_assert(sizeof(IA64VpcHandoff) == 80,
                   "IA-64 firmware handoff ABI size changed");
    _Static_assert(offsetof(IA64VpcHandoff, ProcessorCount) == 64,
                   "IA-64 firmware handoff CPU count offset changed");
    _Static_assert(offsetof(IA64VpcHandoff, NvramPersistent) == 72,
                   "IA-64 firmware handoff NVRAM offset changed");

    handoff.Magic = cpu_to_le64(IA64_FW_HANDOFF_MAGIC);
    handoff.Version = cpu_to_le64(IA64_FW_HANDOFF_VERSION);
    handoff.RamSize = cpu_to_le64(machine->ram_size);
    handoff.ConsolePolicy = cpu_to_le64(s->firmware_console);
    handoff.IdeDmaEnabled = cpu_to_le64(s->firmware_ide_dma);
    handoff.DebugPortFlags = cpu_to_le64(
        debug_port_present ? IA64_FW_DEBUG_PORT_PRESENT : 0);
    handoff.DebugPortBase = cpu_to_le64(
        debug_port_present ? IA64_DEBUG_UART_BASE : 0);
    handoff.I8042Enabled = cpu_to_le64(s->i8042_enabled);
    handoff.ProcessorCount = cpu_to_le64(machine->smp.cpus);
    handoff.NvramPersistent = cpu_to_le64(
        s->nvram_resolved_path != NULL);
    cpu_physical_memory_write(IA64_FW_HANDOFF_ADDR, &handoff,
                              sizeof(handoff));
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
    if (pci_dev->io_regions[1].memory != NULL) {
        pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_0 + 4,
                                 IA64_VGA_IO_BASE, 4);
    }
    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_0 + 8,
                             IA64_VGA_MMIO_PCI_BASE, 4);
    pci_default_write_config(pci_dev, PCI_COMMAND,
                             PCI_COMMAND_IO | PCI_COMMAND_MEMORY, 2);

}

static bool ia64_vpc_enable_vga_legacy_switch(PCIDevice *pci_dev,
                                               Error **errp)
{
    if (pci_dev == NULL ||
        !object_property_find(OBJECT(pci_dev),
                              "x-vbe-legacy-mode-switch")) {
        return true;
    }

    return object_property_set_bool(OBJECT(pci_dev),
                                    "x-vbe-legacy-mode-switch", true,
                                    errp);
}

static void ia64_vpc_configure_nic(PCIDevice *pci_dev, unsigned int index)
{
    uint64_t mmio_base;
    uint32_t io_base;

    if (pci_dev == NULL || index >= MAX_NICS) {
        return;
    }

    mmio_base = IA64_E1000_MMIO_PCI_BASE +
                index * IA64_E1000_MMIO_SIZE;
    io_base = IA64_E1000_IO_BASE + index * IA64_E1000_IO_SIZE;
    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_0, mmio_base, 4);
    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_1, io_base, 4);
    pci_default_write_config(pci_dev, PCI_COMMAND,
                             PCI_COMMAND_IO | PCI_COMMAND_MEMORY |
                             PCI_COMMAND_MASTER, 2);
}

static void ia64_vpc_configure_platform_pci(IA64VpcMachineState *s)
{
    ia64_vpc_configure_ahci(s->ahci_dev);
    ia64_vpc_configure_ohci(s->ohci_dev);
    ia64_vpc_configure_uhci(s->uhci_dev);
    ia64_vpc_configure_lsi(s->lsi_dev);
    ia64_vpc_configure_vga(s->vga_dev);
    for (unsigned int i = 0; i < s->nic_count; i++) {
        ia64_vpc_configure_nic(s->nic_devs[i], i);
    }
    ia64_vpc_configure_pci_irq(s->ahci_dev);
    ia64_vpc_configure_pci_irq(s->ohci_dev);
    ia64_vpc_configure_pci_irq(s->uhci_dev);
    ia64_vpc_configure_pci_irq(s->lsi_dev);
    ia64_vpc_configure_pci_irq(s->vga_dev);
    for (unsigned int i = 0; i < s->nic_count; i++) {
        ia64_vpc_configure_pci_irq(s->nic_devs[i]);
    }
}

#ifdef CONFIG_IA64_VPC_NETWORK
static void ia64_vpc_record_nic(IA64VpcMachineState *s, PCIBus *bus,
                                PCIDevice *pci_dev)
{
    uint16_t class;

    if (pci_dev == NULL || s->nic_count >= MAX_NICS) {
        return;
    }

    class = pci_get_word(pci_dev->config + PCI_CLASS_DEVICE);
    if (class != PCI_CLASS_NETWORK_ETHERNET ||
        pci_dev->io_regions[0].size != IA64_E1000_MMIO_SIZE ||
        pci_dev->io_regions[1].size != IA64_E1000_IO_SIZE ||
        pci_get_bus(pci_dev) != bus) {
        return;
    }

    s->nic_devs[s->nic_count] = pci_dev;
    ia64_vpc_configure_nic(pci_dev, s->nic_count);
    ia64_vpc_configure_pci_irq(pci_dev);
    s->nic_count++;
}

static void ia64_vpc_init_network(IA64VpcMachineState *s, PCIBus *pci_bus)
{
    MachineState *machine = MACHINE(s);
    MachineClass *mc = MACHINE_GET_CLASS(machine);
    unsigned int slot;

    s->nic_count = 0;
    memset(s->nic_devs, 0, sizeof(s->nic_devs));

    /* Keep the default adapter at a stable BDF after the built-in devices. */
    pci_init_nic_in_slot(pci_bus, mc->default_nic, NULL,
                         stringify(IA64_VPC_NIC_SLOT));
    pci_init_nic_devices(pci_bus, mc->default_nic);

    for (slot = IA64_VPC_NIC_SLOT; slot < PCI_SLOT_MAX; slot++) {
        ia64_vpc_record_nic(s, pci_bus,
                            pci_find_device(pci_bus, 0, PCI_DEVFN(slot, 0)));
    }
}
#endif

#define TYPE_IA64_PCI_FIXUP_RESET "ia64-pci-fixup-reset"
OBJECT_DECLARE_SIMPLE_TYPE(IA64PciFixupReset, IA64_PCI_FIXUP_RESET)

struct IA64PciFixupReset {
    Object parent;
    ResettableState reset_state;
    IA64VpcMachineState *machine;
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
    IA64PciFixupReset *r = IA64_PCI_FIXUP_RESET(obj);

    (void)type;

    ia64_vpc_configure_platform_pci(r->machine);
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

static void ia64_vpc_map_vga_fixed_windows(IA64VpcMachineState *s,
                                           PCIDevice *pci_dev)
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

    if (s->vga_fb_alias == NULL) {
        s->vga_fb_alias = g_new(MemoryRegion, 1);
        memory_region_init_alias(s->vga_fb_alias, OBJECT(s),
                                 "ia64-vga-fb-fixed", fb->memory, 0, fb->size);
        memory_region_add_subregion_overlap(fb->address_space,
                                            IA64_VGA_FB_PCI_BASE,
                                            s->vga_fb_alias, 1);
    }

    if (s->vga_mmio_alias == NULL) {
        s->vga_mmio_alias = g_new(MemoryRegion, 1);
        memory_region_init_alias(s->vga_mmio_alias, OBJECT(s),
                                 "ia64-vga-mmio-fixed", mmio->memory, 0,
                                 mmio->size);
        memory_region_add_subregion_overlap(fb->address_space,
                                            IA64_VGA_MMIO_PCI_BASE,
                                            s->vga_mmio_alias, 1);
    }

    if (s->vga_legacy_alias == NULL) {
        s->vga_legacy_alias = g_new(MemoryRegion, 1);
        memory_region_init_alias(s->vga_legacy_alias,
                                 OBJECT(s),
                                 "ia64-vga-legacy-fixed",
                                 fb->address_space,
                                 IA64_VGA_LEGACY_BASE,
                                 IA64_VGA_LEGACY_SIZE);
        memory_region_add_subregion_overlap(get_system_memory(),
                                            IA64_VGA_LEGACY_BASE,
                                            s->vga_legacy_alias, 1);
    }
}

#ifdef CONFIG_IA64_VPC_USB
static bool ia64_vpc_init_usb(IA64VpcMachineState *s, PCIBus *pci_bus,
                              Error **errp)
{
    MachineState *machine = MACHINE(s);
    USBBus *usb_bus;
    bool add_default_input;

    machine->usb |= defaults_enabled() && !machine->usb_disabled;
    if (!machine->usb) {
        return true;
    }

    s->ohci_dev = pci_create_simple(pci_bus, -1, "pci-ohci");
    ia64_vpc_configure_ohci(s->ohci_dev);

    add_default_input = defaults_enabled() && !s->i8042_enabled;
    if (add_default_input) {
        /*
         * Attach default USB input only when PS/2 is disabled. HID keyboards
         * become QEMU's active input handler, which would otherwise hide
         * firmware-visible PS/2 input before a guest USB stack exists.  Use
         * an absolute pointer so graphical front ends do not require a
         * relative-pointer grab.
         */
        usb_bus = USB_BUS(object_resolve_type_unambiguous(TYPE_USB_BUS,
                                                          errp));
        if (usb_bus == NULL) {
            return false;
        }
        usb_create_simple(usb_bus, "usb-kbd");
        usb_create_simple(usb_bus, "usb-tablet");
    }

    s->uhci_dev = pci_create_simple(pci_bus, -1, TYPE_PIIX3_USB_UHCI);
    ia64_vpc_configure_uhci(s->uhci_dev);
    return true;
}
#endif

static IA64BootInfo ia64_vpc_boot_info(unsigned int cpu_index,
                                       uint64_t entry,
                                       uint64_t global_pointer)
{
    IA64BootInfo info = {
        .firmware_base = IA64_FW_BASE,
        .firmware_entry = entry,
        .global_pointer = global_pointer,
        .iva = IA64_IVT_BASE,
        .bsp = 0x80000 + cpu_index * IA64_VPC_RSE_STACK_SIZE,
        .stack_pointer = cpu_index == 0 ?
            IA64_VPC_EARLY_STACK_TOP - 16 :
            IA64_VPC_AP_EARLY_STACK_TOP - 16 -
                cpu_index * IA64_VPC_EARLY_STACK_STRIDE,
        .rsc = IA64_RSC_MODE,
        .powered_off = cpu_index != 0,
    };

    return info;
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
    IA64VpcMachineState *s = opaque;
    CPUState *cs;

    CPU_FOREACH(cs) {
        /* The CPUs are not children of the platform system bus. */
        ia64_cpu_reset_to_boot_info(IA64_CPU(cs));
    }

    acpi_pm1_evt_reset(&s->acpi_regs);
    acpi_pm1_cnt_reset(&s->acpi_regs);
    acpi_pm_tmr_reset(&s->acpi_regs);
    acpi_gpe_reset(&s->acpi_regs);
}

/*
 * Machine-done notifier — runs after the first reset cycle completes,
 * so ROM content is guaranteed to be in guest memory.  Parse a firmware
 * plabel only when the firmware image is a valid IA-64 PE32+ binary.
 */
static void ia64_vpc_machine_done(Notifier *notifier, void *data)
{
    IA64VpcMachineState *s = container_of(notifier, IA64VpcMachineState,
                                          done_notifier);
    MachineState *machine = MACHINE(s);
    g_autofree uint8_t *image = NULL;
    IA64FirmwareEntrypoint entrypoint;
    CPUState *cs;

    (void)data;
    ia64_vpc_configure_platform_pci(s);

    if (!machine->firmware || s->firmware_size == 0) {
        return;
    }

    /*
     * The project firmware is a flat raw binary (no DOS+PE header).
     * Without a strict PE signature gate, random bytes can be mistaken
     * for PE metadata and clobber startup registers (including gp).
     */
    image = g_malloc(s->firmware_size);
    cpu_physical_memory_read(IA64_FW_BASE, image, s->firmware_size);
    if (!ia64_loader_parse_pe_plabel(image, s->firmware_size,
                                     &entrypoint)) {
        return;
    }

    CPU_FOREACH(cs) {
        IA64BootInfo info = ia64_vpc_boot_info(cs->cpu_index,
                                               entrypoint.entry,
                                               entrypoint.global_pointer);

        ia64_cpu_set_boot_info(IA64_CPU(cs), &info);
        ia64_cpu_reset_to_boot_info(IA64_CPU(cs));
    }
}

static bool ia64_vpc_validate_configuration(MachineState *machine,
                                            IA64VpcMachineState *s,
                                            Error **errp)
{
    if (machine->ram_size < IA64_FW_LOW_RAM_MIN) {
        g_autofree char *size = size_to_str(IA64_FW_LOW_RAM_MIN);

        error_setg(errp, "Invalid RAM size, should be at least %s", size);
        return false;
    }
    if (s->alat_full && machine->smp.cpus > 1) {
        error_setg(errp, "full ALAT emulation is not SMP-safe");
        return false;
    }
    return true;
}

static bool ia64_vpc_load_firmware(IA64VpcMachineState *s,
                                   MachineState *machine, Error **errp)
{
    g_autofree char *firmware_path = NULL;
    Error *local_err = NULL;
    int64_t firmware_size;

    if (machine->firmware == NULL) {
        return true;
    }

    firmware_path = qemu_find_file(QEMU_FILE_TYPE_BIOS, machine->firmware);
    if (firmware_path == NULL) {
        firmware_path = g_strdup(machine->firmware);
    }
    firmware_size = get_image_size(firmware_path, &local_err);
    if (local_err != NULL) {
        error_prepend(&local_err, "failed to inspect firmware '%s': ",
                      machine->firmware);
        error_propagate(errp, local_err);
        return false;
    }
    if (firmware_size <= 0 ||
        (uint64_t)firmware_size > machine->ram_size - IA64_FW_BASE) {
        error_setg(errp, "invalid firmware image size for '%s'",
                   machine->firmware);
        return false;
    }
    if (rom_add_file_fixed(machine->firmware, IA64_FW_BASE, -1)) {
        error_setg(errp, "failed to load firmware '%s'", machine->firmware);
        return false;
    }
    s->firmware_size = firmware_size;
    return true;
}

static bool ia64_vpc_build(MachineState *machine, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(machine);
    IA64CPU *cpu;
    DeviceState *pci_host;
    DeviceState *iosapic;
    PCIBus *pci_bus;
    ISABus *isa_bus;
    MemoryRegion *pci_io;
#ifdef CONFIG_IA64_VPC_STORAGE
    DriveInfo *sata_drives[6] = { NULL };
    AHCIPCIState *ahci;
#endif
    int i;

    if (!ia64_vpc_validate_configuration(machine, s, errp)) {
        return false;
    }

    ia64_vpc_map_ram(s);
    if (!ia64_vpc_map_firmware_address_space(s, errp)) {
        return false;
    }
    ia64_vpc_init_rtc(s);
    ia64_vpc_init_watchdog(s);
    ia64_vpc_init_nvram(s);
    ia64_vpc_write_firmware_handoff(s);

    for (i = 0; i < machine->smp.cpus; i++) {
        uint32_t threads = MAX(machine->smp.threads, 1U);
        uint32_t cores = MAX(machine->smp.cores, 1U);
        uint32_t per_socket = threads * cores;
        uint32_t package_base = (i / per_socket) * per_socket;
        IA64BootInfo boot_info = ia64_vpc_boot_info(i, IA64_FW_BASE,
                                                    IA64_FW_BASE);

        cpu = IA64_CPU(object_new(machine->cpu_type));
        cpu->alat_full = s->alat_full;
        cpu->socket_id = i / per_socket;
        cpu->core_id = (i / threads) % cores;
        cpu->thread_id = i % threads;
        cpu->cores_per_socket = cores;
        cpu->threads_per_core = threads;
        cpu->package_base = package_base;
        cpu->package_cpus = MIN(per_socket,
                                machine->smp.cpus - package_base);
        ia64_cpu_set_boot_info(cpu, &boot_info);
        if (!qdev_realize_and_unref(DEVICE(cpu), NULL, errp)) {
            return false;
        }
    }
    ia64_vpc_map_lsapic(s);

    iosapic = qdev_new(TYPE_IA64_IOSAPIC);
    if (!sysbus_realize_and_unref(SYS_BUS_DEVICE(iosapic), errp)) {
        return false;
    }
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

    if (!ia64_vpc_load_firmware(s, machine, errp)) {
        return false;
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
    s->done_notifier.notify = ia64_vpc_machine_done;
    qemu_add_machine_init_done_notifier(&s->done_notifier);

    pci_host = qdev_new(TYPE_IA64_PCI_HOST_BRIDGE);
    if (!sysbus_realize_and_unref(SYS_BUS_DEVICE(pci_host), errp)) {
        return false;
    }
    pci_bus = PCI_BUS(qdev_get_child_bus(pci_host, "pci"));

    /*
     * Slot 0 is intentionally empty in the default machine.  Reserve it while
     * creating the built-in devices so their historical slot numbers remain
     * stable, then release it for an explicitly requested PCI controller.
     */
    pci_bus_set_slot_reserved_mask(pci_bus, 1U << 0);
    pci_io = pci_bus->address_space_io;
    ia64_vpc_init_acpi_pm(s, iosapic, pci_io);

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
#ifdef CONFIG_IA64_VPC_STORAGE
    s->ahci_dev = pci_create_simple(pci_bus, -1, TYPE_ICH9_AHCI);
    ia64_vpc_configure_ahci(s->ahci_dev);
    ahci = ICH9_AHCI(s->ahci_dev);
    g_assert(ahci->ahci.ports <= ARRAY_SIZE(sata_drives));
    ide_drive_get(sata_drives, ahci->ahci.ports);
    ahci_ide_create_devs(&ahci->ahci, sata_drives);
#endif

    isa_bus = isa_bus_new(NULL, get_system_memory(), pci_io, errp);
    if (isa_bus == NULL) {
        return false;
    }
    for (i = 0; i < ISA_NUM_IRQS; i++) {
        s->isa_irqs[i] = qdev_get_gpio_in(iosapic, i);
    }
    isa_bus_register_input_irqs(isa_bus, s->isa_irqs);
#ifdef CONFIG_IA64_VPC_PS2
    if (s->i8042_enabled) {
        isa_create_simple(isa_bus, TYPE_I8042);
    }
#endif

#ifdef CONFIG_IA64_VPC_USB
    if (!ia64_vpc_init_usb(s, pci_bus, errp)) {
        return false;
    }
#endif

    /* Put the SCSI HBA on device 4. */
#ifdef CONFIG_IA64_VPC_STORAGE
    s->lsi_dev = pci_new(PCI_DEVFN(4, 0), "lsi53c895a");
    qdev_prop_set_bit(DEVICE(s->lsi_dev),
                      "disconnect-on-data-wait", false);
    if (!pci_realize_and_unref(s->lsi_dev, pci_bus, errp)) {
        return false;
    }
    ia64_vpc_configure_lsi(s->lsi_dev);
    lsi53c8xx_handle_legacy_cmdline(DEVICE(s->lsi_dev));
#endif

#ifdef CONFIG_IA64_VPC_GRAPHICS
    s->vga_dev = pci_vga_init(pci_bus);
#endif
    if (!ia64_vpc_enable_vga_legacy_switch(s->vga_dev, errp)) {
        return false;
    }
    ia64_vpc_configure_vga(s->vga_dev);
    ia64_vpc_map_vga_fixed_windows(s, s->vga_dev);
#ifdef CONFIG_IA64_VPC_NETWORK
    ia64_vpc_init_network(s, pci_bus);
#endif
    pci_bus_clear_slot_reserved_mask(pci_bus, 1U << 0);

    s->powerdown_notifier.notify = ia64_vpc_powerdown_req;
    qemu_register_powerdown_notifier(&s->powerdown_notifier);

    qemu_register_reset(ia64_vpc_reset, s);
    s->pci_fixup_reset = object_new(TYPE_IA64_PCI_FIXUP_RESET);
    IA64_PCI_FIXUP_RESET(s->pci_fixup_reset)->machine = s;
    qemu_register_resettable(s->pci_fixup_reset);
    return true;
}

static void ia64_vpc_init(MachineState *machine)
{
    Error *err = NULL;

    if (!ia64_vpc_build(machine, &err)) {
        error_propagate(&error_fatal, err);
    }
}

static void ia64_vpc_machine_instance_init(Object *obj)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

#ifdef CONFIG_IA64_VPC_PS2
    s->i8042_enabled = true;
#endif
#ifdef CONFIG_IA64_VPC_STORAGE
    s->firmware_ide_dma = true;
#endif
#ifdef CONFIG_IA64_VPC_GRAPHICS
    s->firmware_console = IA64_FW_CONSOLE_VGA;
#else
    s->firmware_console = IA64_FW_CONSOLE_SERIAL;
#endif
}

static void ia64_vpc_machine_instance_finalize(Object *obj)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    g_free(s->nvram_path);
    g_free(s->nvram_resolved_path);
}

static void ia64_vpc_machine_class_init(ObjectClass *oc, const void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    (void)data;

    mc->desc = "IA-64 virtual PC platform";
    mc->init = ia64_vpc_init;
    mc->max_cpus = IA64_VPC_MAX_CPUS;
    mc->default_cpus = 1;
    mc->default_cpu_type = IA64_CPU_TYPE_NAME("montecito");
    mc->smp_props.prefer_sockets = true;
    mc->default_ram_size = 2 * GiB;
    mc->default_ram_id = "ia64-vpc.ram";
#ifdef CONFIG_IA64_VPC_GRAPHICS
    mc->default_display = "ati";
#endif
#ifdef CONFIG_IA64_VPC_NETWORK
    mc->default_nic = "e1000";
#endif
#ifdef CONFIG_IA64_VPC_STORAGE
    mc->block_default_type = IF_SCSI;
#else
    mc->block_default_type = IF_NONE;
#endif
    mc->no_serial = 0;
    mc->no_parallel = 1;
    mc->no_floppy = 1;
    mc->no_cdrom = 1;

    ia64_vpc_add_compat_defaults(mc);

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
    object_class_property_add_str(oc, "alat",
                                  ia64_vpc_get_alat,
                                  ia64_vpc_set_alat);
    object_class_property_set_description(oc, "alat",
        "Set the IA-64 ALAT model to 'zero' (default) or 'full'");
}

static const TypeInfo ia64_vpc_machine_typeinfo = {
    .name = TYPE_IA64_VPC_MACHINE,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(IA64VpcMachineState),
    .instance_init = ia64_vpc_machine_instance_init,
    .instance_finalize = ia64_vpc_machine_instance_finalize,
    .class_init = ia64_vpc_machine_class_init,
};

static void ia64_vpc_machine_register_types(void)
{
    type_register_static(&ia64_vpc_machine_typeinfo);
}

type_init(ia64_vpc_machine_register_types)
