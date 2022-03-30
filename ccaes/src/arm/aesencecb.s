# Copyright (c) (2011-2016,2018-2020) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>


#if defined(__arm64__)
#include "ccarm_intrinsic_compatability.h"
#include "ccarm_pac_bti_macros.h"
	// per block implementation

	#define in      x0
    #define out     x1
    #define key     x2
    #define keylen  x3
    #define t       x5

    .macro round blk, key
    AESE    \blk, \key
    AESMC   \blk, \blk
    .endm

    .macro final_round blk, key, finalkey
    AESE    \blk, \key
    eor.16b v\blk, v\blk, v\finalkey
    .endm

	.text
	.align	4
    .globl  _ccaes_arm_encrypt
_ccaes_arm_encrypt:
    BRANCH_TARGET_CALL
#if CC_KERNEL
    // save used vector registers
    sub         sp, sp, #3*16
    st1.4s      {v0,v1,v2}, [sp]
#endif

    ldr     w3, [key, #240]         // keylength = 32-bit, 160/192/224
    ldr     q0, [in]                // plain data
    ldr     q1, [key]	            // expanded key
    ldr     q2, [key, keylen]       // final expanded key
    mov     t, #16
0:
    round   0, 1
    ldr     q1, [key, t]	        // expanded key
	add		t, t, #16
    cmp     t, keylen
    b.lt    0b

    final_round 0, 1, 2
    str     q0, [out]

#if CC_KERNEL
    // restore used vector registers
    ld1.4s      {v0,v1,v2}, [sp], #48
#endif

    mov     x0, #0
    ret     lr

	#undef in
    #undef out
    #undef key
    #undef keylen

    #define key     x0
	#define	nblocks	w1
	#define in      x2
    #define out     x3
    #define keylen  x4

	.align	4
    .globl  _ccaes_arm_encrypt_ecb
_ccaes_arm_encrypt_ecb:
    BRANCH_TARGET_CALL
#if CC_KERNEL
    // save used vector registers
    sub     x4, sp, #18*16
    sub     sp, sp, #18*16
    st1.4s      {v0,v1,v2,v3}, [x4], #4*16
    st1.4s      {v4,v5}, [x4], #2*16
    st1.4s      {v16,v17,v18,v19}, [x4], #4*16
    st1.4s      {v20,v21,v22,v23}, [x4], #4*16
    st1.4s      {v24,v25,v26,v27}, [x4], #4*16
#endif

    ldr     w4, [key, #240]         // keylength = 32-bit, 160/192/224
    ldr     q5, [key, keylen]       // expanded key

#if (CC_IBOOT==0)

	subs	nblocks, nblocks, #16	// pre-decrement nblocks by 8
	b.lt	1f						// if nblocks < 16, go to unroll 8 blocks

L_16blocks:

    // handle 16 blocks per iteration
    ldr     q4, [key]               // expanded key
    mov     t, #16+16
    ldr     q0, [in, #0*16]
    ldr     q1, [in, #1*16]
    ldr     q2, [in, #2*16]
    round    0, 4
    ldr     q3, [in, #3*16]
    round    1, 4
    ldr     q16, [in, #4*16]
    round    2, 4
    ldr     q17, [in, #5*16]
    round    3, 4
    ldr     q18, [in, #6*16]
    round    16, 4
    ldr     q19, [in, #7*16]
    round    17, 4
    ldr     q20, [in, #8*16]
    round    18, 4
    ldr     q21, [in, #9*16]
    round    19, 4
    ldr     q22, [in, #10*16]
    round    20, 4
    ldr     q23, [in, #11*16]
    round    21, 4
    ldr     q24, [in, #12*16]
    round    22, 4
    ldr     q25, [in, #13*16]
    round    23, 4
    ldr     q26, [in, #14*16]
    round    24, 4
    ldr     q27, [in, #15*16]
    round    25, 4
    round    26, 4
    add     in, in, #16*16
    round    27, 4
    ldr     q4, [key, #16]                 // expanded key
0:
    round    0, 4
    round    1, 4
    round    2, 4
    round    3, 4
    round    16, 4
    round    17, 4
    round    18, 4
    round    19, 4
    round    20, 4
    round    21, 4
    round    22, 4
    round    23, 4
    round    24, 4
    round    25, 4
    round    26, 4
    round    27, 4

    ldr     q4, [key, t]                 // expanded key
    add     t, t, #16
    cmp     t, keylen
    b.lt    0b

    final_round    0, 4, 5
    final_round    1, 4, 5
    final_round    2, 4, 5
    str     q0, [out]
    add     out, out, #16*16
    final_round    3, 4, 5
    str     q1, [out, #-15*16]
    final_round    16, 4, 5
    str     q2, [out, #-14*16]
    final_round    17, 4, 5
    str     q3, [out, #-13*16]
    final_round    18, 4, 5
    str     q16, [out, #-12*16]
    final_round    19, 4, 5
    str     q17, [out, #-11*16]
    final_round    20, 4, 5
    str     q18, [out, #-10*16]
    final_round    21, 4, 5
    str     q19, [out, #-9*16]
    final_round    22, 4, 5
    str     q20, [out, #-8*16]
    final_round    23, 4, 5
    str     q21, [out, #-7*16]
    final_round    24, 4, 5
    str     q22, [out, #-6*16]
    final_round    25, 4, 5
    str     q23, [out, #-5*16]
    final_round    26, 4, 5
    str     q24, [out, #-4*16]
    final_round    27, 4, 5
    str     q25, [out, #-3*16]
    str     q26, [out, #-2*16]
    str     q27, [out, #-1*16]

    subs    nblocks, nblocks, #16
    b.ge    L_16blocks

1:  // less than 16 blocks
	adds	nblocks, nblocks, #8	// post-increment 16 + pre-decrement 8
	b.lt	1f						// if nblocks < 8, go to unroll 4 blocks

L_8blocks:

    // handle 8 blocks per iteration
    ldr     q4, [key]               // expanded key
    mov     t, #16+16
    ldr     q0, [in, #0*16]
    ldr     q1, [in, #1*16]
    round    0, 4
    ldr     q2, [in, #2*16]
    round    1, 4
    ldr     q3, [in, #3*16]
    round    2, 4
    ldr     q16, [in, #4*16]
    round    3, 4
    ldr     q17, [in, #5*16]
    round    16, 4
    ldr     q18, [in, #6*16]
    round    17, 4
    ldr     q19, [in, #7*16]
    round    18, 4
    add     in, in, #8*16
    round    19, 4
    ldr     q4, [key, #16]                 // expanded key

0:
    round    0, 4
    round    1, 4
    round    2, 4
    round    3, 4
    round    16, 4
    round    17, 4
    round    18, 4
    round    19, 4
    ldr     q4, [key, t]                 // expanded key
    add     t, t, #16
    cmp     t, keylen
    b.lt    0b

    final_round    0, 4, 5
    final_round    1, 4, 5
    final_round    2, 4, 5
    str     q0, [out], #8*16
    final_round    3, 4, 5
    str     q1, [out, #-7*16]
    final_round    16, 4, 5
    str     q2, [out, #-6*16]
    final_round    17, 4, 5
    str     q3, [out, #-5*16]
    final_round    18, 4, 5
    str     q16, [out, #-4*16]
    final_round    19, 4, 5
    str     q17, [out, #-3*16]
    str     q18, [out, #-2*16]
    str     q19, [out, #-1*16]

    subs    nblocks, nblocks, #8
    b.ge    L_8blocks

1:  // less than 8 blocks
	adds	nblocks, nblocks, #4	// post-increment 8 + pre-decrement 4
	b.lt	1f						// if nblocks < 4, go to scalar loop

#else   // CC_IBOOT has limited space, no unroll to 16 or 8 blocks

	subs	nblocks, nblocks, #4	// pre-decrement nblocks by 8
	b.lt	1f						// if nblocks < 16, go to unroll 8 blocks

#endif  // CC_IBOOT has limited space, no unroll to 16 or 8 blocks

L_4blocks:

	// handle 4 blocks per iteration
    ldr     q4, [key]	            // expanded key
    ldr     q0, [in], #4*16
    ldr     q1, [in, #-3*16]
    round   0, 4
    ldr     q2, [in, #-2*16]
    round   1, 4
    ldr     q3, [in, #-1*16]
    round   2, 4
    mov     t, #32
    round   3, 4
    ldr     q4, [key, #16]		         // expanded key

0:
    round   0, 4
    round   1, 4
    round   2, 4
    round   3, 4
    ldr     q4, [key, t]		         // expanded key
	add		t, t, #16
    cmp     t, keylen
    b.lt    0b

    final_round    0, 4, 5
    final_round    1, 4, 5
    final_round    2, 4, 5
    str     q0, [out], #4*16
    final_round    3, 4, 5
    str     q1, [out, #-3*16]
    str     q2, [out, #-2*16]
    str     q3, [out, #-1*16]

	subs	nblocks, nblocks, #4
	b.ge	L_4blocks



1:	// handle 1 block per iteration
	ands	nblocks, nblocks, #3
	b.eq	9f	

L_1block:
    ldr     q4, [key]	            // expanded key
    mov     t, #16
    ldr     q0, [in], #16		// plain data
0:
    round   0, 4
    ldr     q4, [key, t]		         // expanded key
    add     t, t, #16
    cmp     t, keylen
    b.lt    0b

    final_round 0, 4, 5

    str     q0, [out], #16

	subs	nblocks, nblocks, #1	
	b.gt	L_1block

9:
#if CC_KERNEL
    // restore used vector registers
    ld1.4s      {v0,v1,v2,v3}, [sp], #4*16
    ld1.4s      {v4,v5}, [sp], #2*16
    ld1.4s      {v16,v17,v18,v19}, [sp], #4*16
    ld1.4s      {v20,v21,v22,v23}, [sp], #4*16
    ld1.4s      {v24,v25,v26,v27}, [sp], #4*16
#endif

    mov     x0, #0
    ret     lr

	#undef in
    #undef out
    #undef key
    #undef nblocks
    #undef keylen


#else

	#define	Select	0		// Select=0 to define aes_encrypt from EncryptDecrypt.s
	#include "EncryptDecrypt.s"
	#undef	Select

#endif

