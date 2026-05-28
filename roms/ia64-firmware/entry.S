/* SPDX-License-Identifier: GPL-2.0-or-later */
/* IA-64 EFI firmware entry point (GCC assembler syntax).
 *
 * The linker script links at VMA=0x100000, so all symbols (`__gp`,
 * firmware_main, etc.) are already at correct runtime addresses.
 * No GP manual offset computation is needed.
 */

    .section .text._start, "ax"
    .global _start
    .type _start, @function
    .proc _start
    .explicit
_start:
    /* r0=0 hardwired, r1=IA64_FW_BASE from machine model, r12=sp */
    movl r12 = 0x08000000
    ;;

    /* GP = linker-defined __gp (already at runtime VMA=0x100000 address) */
    movl r1 = __gp
    ;;

    /* Alloc: 0 ins, 13 locals, 3 outs → output regs r45-r47
     * After br.call these become callee's input r32-r34. */
    alloc r2 = ar.pfs, 0, 13, 3, 0
    ;;

    /* Save return pointer */
    mov r3 = b0
    ;;

    /* Pass args: gp, sp, boot_b0 */
    mov r45 = r1               /* arg0 → callee r32 = gp      */
    mov r46 = r12              /* arg1 → callee r33 = sp      */
    mov r47 = r3               /* arg2 → callee r34 = boot_b0 */
    ;;

    br.call.sptk.many b0 = firmware_main
    ;;

    /* firmware_main should not return */
    break 0
    ;;
    .endp _start
    .size _start, . - _start

    .section .text.pal_proc_entry, "ax"
    .global pal_proc_entry
    .type pal_proc_entry, @function
    .proc pal_proc_entry
    .explicit
pal_proc_entry:
    break.m 0x100000
    ;;
    br.many b0
    ;;
    .endp pal_proc_entry
    .size pal_proc_entry, . - pal_proc_entry
