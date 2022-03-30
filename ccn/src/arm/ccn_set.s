# Copyright (c) (2010,2011,2012,2015,2016,2019) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to 
# people who accept that license. IMPORTANT:  Any license rights granted to you by 
# Apple Inc. (if any) are limited to internal use within your organization only on 
# devices and computers you own or control, for the sole purpose of verifying the 
# security characteristics and correct functioning of the Apple Software.  You may 
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.
#include <corecrypto/cc_config.h>


#if defined(_ARM_ARCH_7) && CCN_SET_ASM

.text
.align 2
    .syntax unified
    .code   16
    .thumb_func _ccn_set


	.globl _ccn_set

#if 1
_ccn_set: /* void ccn_set(unsigned int count, void *r, const void *s); */
    stmfd   sp!, { r8-r10, lr }
    b       Lfirst
Ldo4words:
    ldmia	r2!, { r8, r9, r12, lr }
    stmia   r1!, { r8, r9, r12, lr }
Lfirst:
    subs    r0, r0, #4
    bcs     Ldo4words
Llessthan4left:
    tst     r0, #2
    beq     Llessthan2left
    ldmia   r2!, { r12, lr }
    stmia   r1!, { r12, lr }
Llessthan2left:
    tst     r0, #1
    beq     Ldone
    ldr     r12, [r2], #4
    str     r12, [r1], #4
Ldone:
    ldmfd	sp!, { r8-r10, pc }
#else
_ccn_set: /* void ccn_set(unsigned int count, void *r, const void *s); */
    stmfd   sp!, { r8-r10, lr }
    movs    r0, r0, lsr #1
    bcc     Lskipcount1
    ldr     r12, [r2], #4
    str     r12, [r1], #4
Lskipcount1:
    tst     r0, #1
    beq     Lskipcount2
    ldmia   r2!, { r12, lr }
    stmia   r1!, { r12, lr }
Lskipcount2:
    bics    r0, r0, #1
    beq     Ldone
Ldo_count4loop:
    ldmia	r2!, { r8, r9, r12, lr }
    stmia   r1!, { r8, r9, r12, lr }
    subs    r0, r0, #2
    bne     Ldo_count4loop
Ldone:
    ldmfd	sp!, { r8-r10, pc }
#endif

#endif /* CCN_SET_ASM */

