/* SPDX-License-Identifier: GPL-2.0-or-later */
ENTRY(__efi_entry_descriptor)

SECTIONS
{
    . = 0x05000000;

    .text : { *(.text*) }
    . = ALIGN(16);
    .rodata : { *(.rodata*) }
    . = ALIGN(16);
    .opd : {
        __efi_entry_descriptor = .;
        *(.opd)
    }
    . = ALIGN(16);
    .data : { *(.data*) }
    . = ALIGN(16);
    .rsrc : {
        __hii_resource_start = .;

        /* Root directory: one custom type named "HII". */
        LONG(0); LONG(0); SHORT(0); SHORT(0); SHORT(1); SHORT(0);
        LONG(0x80000000 | (__hii_type_name - __hii_resource_start));
        LONG(0x80000000 | (__hii_name_directory - __hii_resource_start));

        __hii_type_name = .;
        SHORT(3); SHORT(0x48); SHORT(0x49); SHORT(0x49);

        __hii_name_directory = .;
        LONG(0); LONG(0); SHORT(0); SHORT(0); SHORT(0); SHORT(1);
        LONG(1);
        LONG(0x80000000 | (__hii_language_directory -
                           __hii_resource_start));

        __hii_language_directory = .;
        LONG(0); LONG(0); SHORT(0); SHORT(0); SHORT(0); SHORT(1);
        LONG(0x409);
        LONG(__hii_data_entry - __hii_resource_start);

        __hii_data_entry = .;
        LONG(__hii_packages - 0x05000000);
        LONG(__hii_packages_end - __hii_packages);
        LONG(0); LONG(0);

        __hii_packages = .;
        LONG(0); LONG(0); LONG(0); LONG(0);
        LONG(__hii_packages_end - __hii_packages);
        LONG(0xdf000004);
        __hii_packages_end = .;
    }
    . = ALIGN(16);
    .got : { *(.got*) }
    .IA_64.unwind_info : { *(.IA_64.unwind_info*) }
    .IA_64.unwind : { *(.IA_64.unwind*) }
    .bss : {
        *(.bss*)
        *(COMMON)
    }
}
