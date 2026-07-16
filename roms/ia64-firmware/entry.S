/* SPDX-License-Identifier: GPL-2.0-or-later */
/* IA-64 EFI firmware entry point (GCC assembler syntax).
 *
 * The linker script links at VMA=0x100000, so all symbols (`__gp`,
 * firmware_main, etc.) are already at correct runtime addresses.
 * No GP manual offset computation is needed.
 */

    .section .text._start, "ax"
    .equ FW_BOOTSTRAP_STACK_TOP, 0x08000000
    .equ FW_AP_BOOTSTRAP_STACK_TOP, 0x00100000
    .global _start
    .type _start, @function
    .proc _start
    .explicit
_start:
    /* Secondary processors resume here when the platform wake IPI arrives. */
    mov r14 = cr.lid
    ;;
    cmp.ne p6, p7 = r14, r0
    ;;
(p6) br.cond.sptk.few start_secondary
    ;;

    /*
     * Use the minimum-memory stack until the machine handoff has been
     * validated.  start_after_pal moves to the selected RAM-top stack before
     * entering the C firmware.
     */
    movl r12 = (FW_BOOTSTRAP_STACK_TOP - 16)
    ;;

    br.cond.sptk.few start_after_pal
    ;;
    .org 0x60
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

    .section .text.start_after_pal, "ax"
    .type start_after_pal, @function
    .proc start_after_pal
    .explicit
start_after_pal:

    /*
     * QEMU reloads the firmware image on reset, but the raw binary does not
     * contain the trailing NOBITS .bss.  Clear it here so guest-requested and
     * monitor-requested resets start with the same firmware state as a fresh
     * process.
     */
    movl r14 = _bss_start
    ;;
    movl r15 = _bss_end
    ;;
1:
    cmp.ltu p6, p7 = r14, r15
    ;;
(p7) br.cond.dpnt.few 2f
    ;;
    st8 [r14] = r0, 8
    ;;
    br.cond.sptk.few 1b
    ;;
2:
    ;;

    /* GP = linker-defined __gp (already at runtime VMA=0x100000 address) */
    movl r1 = __gp
    ;;

    /*
     * Preserve the reset return pointer across the ABI call, then move the
     * firmware stack to the top of installed low RAM.
     */
    mov r4 = b0
    ;;
    br.call.sptk.many b0 = fw_boot_stack_top
    ;;
    /*
     * The region top may be the exact end of installed RAM, and the psABI
     * lets callees use the 16-byte scratch area [sp, sp+16).  Start sp 16
     * bytes below the region top so that scratch area stays inside RAM.
     */
    adds r12 = -16, r8
    mov r3 = r4
    ;;

    /* Alloc: 0 ins, 13 locals, 3 outs → output regs r45-r47
     * After br.call these become callee's input r32-r34. */
    alloc r2 = ar.pfs, 0, 13, 3, 0
    ;;

    /* Pass args: gp, stack region top, boot_b0 */
    mov r45 = r1               /* arg0 → callee r32 = gp      */
    mov r46 = r8               /* arg1 → callee r33 = stack region top */
    mov r47 = r3               /* arg2 → callee r34 = boot_b0 */
    ;;

    br.call.sptk.many b0 = firmware_main
    ;;

    /* firmware_main should not return */
    break 0
    ;;
    .endp start_after_pal
    .size start_after_pal, . - start_after_pal

    .section .text.start_secondary, "ax"
    .type start_secondary, @function
    .proc start_secondary
    .explicit
start_secondary:
    movl r1 = __gp
    ;;
    mov r14 = cr.lid
    ;;
    extr.u r14 = r14, 24, 8
    ;;
    shl r15 = r14, 16
    movl r12 = (FW_AP_BOOTSTRAP_STACK_TOP - 16)
    ;;
    sub r12 = r12, r15
    ;;
    alloc r2 = ar.pfs, 0, 3, 1, 0
    ;;
    mov r32 = r14
    mov r35 = r14
    ;;
    br.call.sptk.many b0 = fw_ap_stack_top
    ;;
    adds r12 = -16, r8
    mov r35 = r32
    ;;
    br.call.sptk.many b0 = firmware_ap_main
    ;;
    break 0
    ;;
    .endp start_secondary
    .size start_secondary, . - start_secondary

    .section .text.fw_pal_halt_light, "ax"
    .global fw_pal_halt_light
    .type fw_pal_halt_light, @function
    .proc fw_pal_halt_light
    .explicit
fw_pal_halt_light:
    alloc r33 = ar.pfs, 0, 2, 0, 0
    ;;
    mov r32 = b0
    movl r28 = 0x1d
    ;;
    movl r14 = pal_proc_entry
    ;;
    mov b6 = r14
    movl r14 = 1f
    ;;
    mov b0 = r14
    ;;
    br.sptk.many b6
    ;;
1:
    mov b0 = r32
    mov ar.pfs = r33
    ;;
    br.ret.sptk.many b0
    ;;
    .endp fw_pal_halt_light
    .size fw_pal_halt_light, . - fw_pal_halt_light
