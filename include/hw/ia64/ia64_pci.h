/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_IA64_PCI_H
#define HW_IA64_PCI_H

#define TYPE_IA64_PCI_HOST_BRIDGE "ia64-pcihost"

int ia64_pci_route_intx(uint8_t devfn, int irq_num);

#endif
