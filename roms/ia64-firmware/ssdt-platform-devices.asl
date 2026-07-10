// SPDX-License-Identifier: GPL-2.0-or-later

DefinitionBlock ("", "SSDT", 2, "QEMU  ", "IA64SSDT", 0x00000001)
{
    External (\_SB.PCI0, DeviceObj)

    Scope (\_SB)
    {
        Processor (CPU0, 0, 0, 0)
        {
        }
    }

    Scope (\_SB.PCI0)
    {
        Device (UAR0)
        {
            Name (_HID, "PNP0501")
            Name (_UID, 0)
            Name (_CRS, ResourceTemplate ()
            {
                QWordMemory (ResourceConsumer, PosDecode, MinFixed,
                    MaxFixed, NonCacheable, ReadWrite,
                    0, 0x00000047F0000000, 0x00000047F0000007,
                    0, 8)
                IRQNoFlags () {4}
            })
        }

        Device (PS2K)
        {
            Name (_HID, EisaId ("PNP0303"))
            Name (_CRS, ResourceTemplate ()
            {
                IO (Decode16, 0x0060, 0x0060, 1, 1)
                IO (Decode16, 0x0064, 0x0064, 1, 1)
                IRQNoFlags () {1}
            })
        }

        Device (PS2M)
        {
            Name (_HID, EisaId ("PNP0F13"))
            Name (_CRS, ResourceTemplate ()
            {
                IRQNoFlags () {12}
            })
        }
    }
}
