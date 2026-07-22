// SPDX-License-Identifier: GPL-2.0-or-later

DefinitionBlock ("", "DSDT", 2, "QEMU  ", "IA64DSDT", 0x00000001)
{
    Name (_S5, Package (0x04)
    {
        Zero,
        Zero,
        Zero,
        Zero
    })

    Scope (\_SB)
    {
        Device (PCI0)
        {
            Name (_HID, "PNP0A03")
            Name (_CID, "PNP0A03")
            Name (_SEG, Zero)
            Name (_BBN, Zero)
            Name (_UID, Zero)
            Name (_CCA, One)
            Name (_CRS, ResourceTemplate ()
            {
                WordBusNumber (ResourceProducer, MinFixed, MaxFixed,
                    PosDecode, 0, 0, 0x00FF, 0, 0x0100)
                QWordIO (ResourceProducer, MinFixed, MaxFixed, PosDecode,
                    EntireRange, 0, 0, 0x00FFFFFF, 0, 0x01000000,
                    , , , TypeStatic, DenseTranslation)
                DWordMemory (ResourceProducer, PosDecode, MinFixed,
                    MaxFixed, Cacheable, ReadWrite,
                    0, 0x000A0000, 0x000BFFFF, 0, 0x00020000)
                QWordMemory (ResourceProducer, PosDecode, MinFixed,
                    MaxFixed, NonCacheable, ReadWrite,
                    0, 0xC1000000, 0xD0FFFFFF, 0, 0x10000000)
            })
            Name (_PRT, Package ()
            {
                Package () { 0x0000FFFF, 0, Zero, 16 },
                Package () { 0x0000FFFF, 1, Zero, 17 },
                Package () { 0x0000FFFF, 2, Zero, 18 },
                Package () { 0x0000FFFF, 3, Zero, 19 },
                Package () { 0x0001FFFF, 0, Zero, 17 },
                Package () { 0x0001FFFF, 1, Zero, 18 },
                Package () { 0x0001FFFF, 2, Zero, 19 },
                Package () { 0x0001FFFF, 3, Zero, 16 },
                Package () { 0x0002FFFF, 0, Zero, 18 },
                Package () { 0x0002FFFF, 1, Zero, 19 },
                Package () { 0x0002FFFF, 2, Zero, 16 },
                Package () { 0x0002FFFF, 3, Zero, 17 },
                Package () { 0x0003FFFF, 0, Zero, 19 },
                Package () { 0x0003FFFF, 1, Zero, 16 },
                Package () { 0x0003FFFF, 2, Zero, 17 },
                Package () { 0x0003FFFF, 3, Zero, 18 },
                Package () { 0x0004FFFF, 0, Zero, 16 },
                Package () { 0x0004FFFF, 1, Zero, 17 },
                Package () { 0x0004FFFF, 2, Zero, 18 },
                Package () { 0x0004FFFF, 3, Zero, 19 },
                Package () { 0x0005FFFF, 0, Zero, 17 },
                Package () { 0x0005FFFF, 1, Zero, 18 },
                Package () { 0x0005FFFF, 2, Zero, 19 },
                Package () { 0x0005FFFF, 3, Zero, 16 },
                Package () { 0x0006FFFF, 0, Zero, 18 },
                Package () { 0x0006FFFF, 1, Zero, 19 },
                Package () { 0x0006FFFF, 2, Zero, 16 },
                Package () { 0x0006FFFF, 3, Zero, 17 }
            })
        }
    }
}
