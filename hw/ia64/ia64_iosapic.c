/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Minimal IA-64 I/O SAPIC device model.
 * Routes 24 external interrupt pins to the CPU Local SAPIC.
 */

#include "qemu/osdep.h"
#include "hw/ia64/ia64_iosapic.h"
#include "cpu.h"
#include "system/address-spaces.h"

#define IOSAPIC_IOREGSEL   0x00
#define IOSAPIC_IOWIN      0x10
#define IOSAPIC_EOI        0x40

#define IOSAPIC_REG_ID     0x00
#define IOSAPIC_REG_VER    0x01
#define IOSAPIC_RTE_BASE   0x10

#define RTE_VECTOR_MASK    0x00000000000000FFULL
#define RTE_MASKED         0x0000000000010000ULL
#define RTE_TRIGGER_LEVEL  0x0000000000008000ULL

struct IA64IOSapicState {
    SysBusDevice parent_obj;
    MemoryRegion mmio;
    uint64_t rte[IA64_IOSAPIC_NUM_PINS];
    uint8_t  irq_level[IA64_IOSAPIC_NUM_PINS];
    uint32_t reg_select;
};

static void iosapic_update(IA64IOSapicState *s, int pin)
{
    uint64_t rte = s->rte[pin];
    uint8_t vector = rte & RTE_VECTOR_MASK;
    bool masked = (rte & RTE_MASKED) != 0;
    CPUState *cs;

    if (masked || vector == 0) {
        return;
    }

    cs = first_cpu;
    if (cs) {
        ia64_sapic_set_irq(cs, vector);
    }
}

static void iosapic_irq_handler(void *opaque, int pin, int level)
{
    IA64IOSapicState *s = opaque;

    if (pin < 0 || pin >= IA64_IOSAPIC_NUM_PINS) {
        return;
    }

    s->irq_level[pin] = (uint8_t)level;
    if (level) {
        iosapic_update(s, pin);
    }
}

static uint64_t iosapic_read(void *opaque, hwaddr addr, unsigned size)
{
    IA64IOSapicState *s = opaque;
    uint32_t result = 0;
    uint32_t index;

    switch (addr) {
    case IOSAPIC_IOREGSEL:
        result = s->reg_select;
        break;
    case IOSAPIC_IOWIN:
        index = s->reg_select;
        if (index == IOSAPIC_REG_ID) {
            result = 0;
        } else if (index == IOSAPIC_REG_VER) {
            result = ((IA64_IOSAPIC_NUM_PINS - 1) << 16) | 0x11;
        } else if (index >= IOSAPIC_RTE_BASE &&
                   index < IOSAPIC_RTE_BASE + IA64_IOSAPIC_NUM_PINS * 2) {
            int pin = (index - IOSAPIC_RTE_BASE) / 2;
            if ((index - IOSAPIC_RTE_BASE) & 1) {
                result = (uint32_t)(s->rte[pin] >> 32);
            } else {
                result = (uint32_t)s->rte[pin];
            }
        }
        break;
    case IOSAPIC_EOI:
        break;
    default:
        break;
    }
    return result;
}

static void iosapic_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    IA64IOSapicState *s = opaque;
    uint32_t index;

    switch (addr) {
    case IOSAPIC_IOREGSEL:
        s->reg_select = (uint32_t)val;
        break;
    case IOSAPIC_IOWIN:
        index = s->reg_select;
        if (index == IOSAPIC_REG_ID) {
            break;
        } else if (index >= IOSAPIC_RTE_BASE &&
                   index < IOSAPIC_RTE_BASE + IA64_IOSAPIC_NUM_PINS * 2) {
            int pin = (index - IOSAPIC_RTE_BASE) / 2;
            if ((index - IOSAPIC_RTE_BASE) & 1) {
                s->rte[pin] = (s->rte[pin] & 0xFFFFFFFFULL) |
                              ((uint64_t)val << 32);
            } else {
                s->rte[pin] = (s->rte[pin] & 0xFFFFFFFF00000000ULL) | val;
            }
        }
        break;
    case IOSAPIC_EOI:
        {
            unsigned pin;
            for (pin = 0; pin < IA64_IOSAPIC_NUM_PINS; pin++) {
                if ((s->rte[pin] & RTE_VECTOR_MASK) == ((uint32_t)val & 0xFF)) {
                    break;
                }
            }
            if (pin < IA64_IOSAPIC_NUM_PINS &&
                (s->rte[pin] & RTE_TRIGGER_LEVEL) && s->irq_level[pin]) {
                iosapic_update(s, pin);
            }
        }
        break;
    default:
        break;
    }
}

static const MemoryRegionOps iosapic_ops = {
    .read = iosapic_read,
    .write = iosapic_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static void iosapic_realize(DeviceState *dev, Error **errp)
{
    IA64IOSapicState *s = IA64_IOSAPIC(dev);

    qdev_init_gpio_in(dev, iosapic_irq_handler, IA64_IOSAPIC_NUM_PINS);
    memory_region_init_io(&s->mmio, OBJECT(dev), &iosapic_ops, s,
                          "iosapic", 0x2000);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->mmio);
}

static void iosapic_reset(DeviceState *dev)
{
    IA64IOSapicState *s = IA64_IOSAPIC(dev);
    int i;

    memset(s->rte, 0, sizeof(s->rte));
    memset(s->irq_level, 0, sizeof(s->irq_level));
    for (i = 0; i < IA64_IOSAPIC_NUM_PINS; i++) {
        s->rte[i] = RTE_MASKED;
    }
    s->reg_select = 0;
}

static void iosapic_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = iosapic_realize;
    device_class_set_legacy_reset(dc, iosapic_reset);
}

static const TypeInfo iosapic_info = {
    .name          = TYPE_IA64_IOSAPIC,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(IA64IOSapicState),
    .class_init    = iosapic_class_init,
};

static void iosapic_register_types(void)
{
    type_register_static(&iosapic_info);
}
type_init(iosapic_register_types);
