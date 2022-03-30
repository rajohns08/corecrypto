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

	// per block
	#define in      x0
    #define out     x1
    #define key     x2
    #define keylen  x3
    #define t       x5


	.text	
	.align	4	
	    .globl _ccaes_arm_decrypt
_ccaes_arm_decrypt:
	BRANCH_TARGET_CALL
#if CC_KERNEL
	// save used vector registers
	sub		sp, sp, #3*16
	st1.4s		{v0,v1,v2}, [sp]
#endif

    ldr     w3, [key, #240]         // keylength = 32-bit
    ldr     q0, [in]                // plain data
    mov     t, keylen
    ldr     q1, [key, t]		        // expanded key
	sub		t, t, #16
    ldr     q2, [key]               // expanded key
0:
    AESD    0, 1
    AESIMC   0, 0
    ldr     q1, [key, t]				// expanded key
    subs    t, t, #16
    b.gt    0b
    AESD    0, 1
    eor.16b v0, v0, v2
    str     q0, [out]

#if CC_KERNEL
	// restore used vector registers
	ld1.4s		{v0,v1,v2}, [sp], #48
#endif

    mov     x0, #0
    ret     lr

	#undef in
    #undef out
    #undef key
    #undef keylen


	// ecb mode

    #define key     x0
	#define	nblocks	w1
	#define in      x2
    #define out     x3
    #define keylen  x4


    .macro  decrypt blk, key
    AESD     \blk, \key
    AESIMC   \blk, \blk
    .endm

    .macro  final_decrypt blk, key, finalkey
    AESD    \blk, \key
    eor.16b v\blk, v\blk, v\finalkey
    .endm

	    .globl _ccaes_arm_decrypt_ecb
	.align	4
_ccaes_arm_decrypt_ecb:
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

    ldr     w4, [key, #240]         // keylength = 32-bit
    ldr     q5, [key]               // expanded key

#if (CC_IBOOT==0)

	subs	nblocks, nblocks, #16
	b.lt	L_lessthan16

L_16blocks:

	ldr     q0, [in]
    add     in, in, #16*16
    ldr     q4, [key, keylen]	        // expanded key
	ldr     q1, [in, #-15*16]
    sub     t, keylen, #16
	ldr     q2, [in, #-14*16]
    decrypt  0, 4
	ldr     q3, [in, #-13*16]
    decrypt  1, 4
	ldr     q16, [in, #-12*16]
    decrypt  2, 4
	ldr     q17, [in, #-11*16]
    decrypt  3, 4
	ldr     q18, [in, #-10*16]
    decrypt  16, 4
	ldr     q19, [in, #-9*16]
    decrypt  17, 4
	ldr     q20, [in, #-8*16]
    decrypt  18, 4
	ldr     q21, [in, #-7*16]
    decrypt  19, 4
	ldr     q22, [in, #-6*16]
    decrypt  20, 4
	ldr     q23, [in, #-5*16]
    decrypt  21, 4
	ldr     q24, [in, #-4*16]
    decrypt  22, 4
	ldr     q25, [in, #-3*16]
    decrypt  23, 4
	ldr     q26, [in, #-2*16]
    decrypt  24, 4
	ldr     q27, [in, #-1*16]
    decrypt  25, 4
    decrypt  26, 4
    decrypt  27, 4
    ldr         q4, [key, t]				// expanded key
    subs        t, t, #16
0:
    decrypt  0, 4
    decrypt  1, 4
    decrypt  2, 4
    decrypt  3, 4
    decrypt  16, 4
    decrypt  17, 4
    decrypt  18, 4
    decrypt  19, 4
    decrypt  20, 4
    decrypt  21, 4
    decrypt  22, 4
    decrypt  23, 4
    decrypt  24, 4
    decrypt  25, 4
    decrypt  26, 4
    decrypt  27, 4
    ldr         q4, [key, t]				// expanded key
    subs        t, t, #16
    b.gt        0b

    final_decrypt   0, 4, 5
    final_decrypt   1, 4, 5
    final_decrypt   2, 4, 5
    str     q0, [out]
    add     out, out, #16*16
    final_decrypt   3, 4, 5
    str     q1, [out, #-15*16]
    final_decrypt   16, 4, 5
    str     q2, [out, #-14*16]
    final_decrypt   17, 4, 5
    str     q3, [out, #-13*16]
    final_decrypt   18, 4, 5
    str     q16, [out, #-12*16]
    final_decrypt   19, 4, 5
    str     q17, [out, #-11*16]
    final_decrypt   20, 4, 5
    str     q18, [out, #-10*16]
    final_decrypt   21, 4, 5
    str     q19, [out, #-9*16]
    final_decrypt   22, 4, 5
    str     q20, [out, #-8*16]
    final_decrypt   23, 4, 5
    str     q21, [out, #-7*16]
    final_decrypt   24, 4, 5
    str     q22, [out, #-6*16]
    final_decrypt   25, 4, 5
    str     q23, [out, #-5*16]
    final_decrypt   26, 4, 5
    str     q24, [out, #-4*16]
    final_decrypt   27, 4, 5
    str     q25, [out, #-3*16]
    str     q26, [out, #-2*16]
    str     q27, [out, #-1*16]
	subs	nblocks, nblocks, #16
	b.ge	L_16blocks

L_lessthan16:

	adds	nblocks, nblocks, #8
	b.lt	L_lessthan8

L_8blocks:

	ldr     q0, [in], #8*16
    ldr     q4, [key, keylen]	        // expanded key
	ldr     q1, [in, #-7*16]
    sub     t, keylen, #16
	ldr     q2, [in, #-6*16]
    decrypt  0, 4
	ldr     q3, [in, #-5*16]
    decrypt  1, 4
	ldr     q16, [in, #-4*16]
    decrypt  2, 4
	ldr     q17, [in, #-3*16]
    decrypt  3, 4
	ldr     q18, [in, #-2*16]
    decrypt  16, 4
	ldr     q19, [in, #-1*16]
    decrypt  17, 4
    decrypt  18, 4
    decrypt  19, 4
    ldr         q4, [key, t]				// expanded key
    subs        t, t, #16
0:
    decrypt  0, 4
    decrypt  1, 4
    decrypt  2, 4
    decrypt  3, 4
    decrypt  16, 4
    decrypt  17, 4
    decrypt  18, 4
    decrypt  19, 4
    ldr         q4, [key, t]				// expanded key
    subs        t, t, #16
    b.gt        0b

    final_decrypt   0, 4, 5
    final_decrypt   1, 4, 5
    final_decrypt   2, 4, 5
    str     q0, [out], #8*16
    final_decrypt   3, 4, 5
    str     q1, [out, #-7*16]
    final_decrypt   16, 4, 5
    str     q2, [out, #-6*16]
    final_decrypt   17, 4, 5
    str     q3, [out, #-5*16]
    final_decrypt   18, 4, 5
    str     q16, [out, #-4*16]
    final_decrypt   19, 4, 5
    str     q17, [out, #-3*16]
    str     q18, [out, #-2*16]
    str     q19, [out, #-1*16]

	subs	nblocks, nblocks, #8
	b.ge	L_8blocks

L_lessthan8:
	adds	nblocks, nblocks, #4
	b.lt	L_lessthan4

#else   // CC_IBOOT == 0, not enough space to unroll to 8 or 16 blocks

	subs	nblocks, nblocks, #4
	b.lt	L_lessthan4

#endif  // CC_IBOOT

L_4blocks:
	ldr     q0, [in], #4*16
    ldr     q4, [key, keylen]	        // expanded key
	ldr     q1, [in, #-3*16]
    sub     t, keylen, #16
	ldr     q2, [in, #-2*16]
    decrypt  0, 4
	ldr     q3, [in, #-1*16]
    decrypt  1, 4
    decrypt  2, 4
    decrypt  3, 4
    ldr         q4, [key, t]				// expanded key
    subs        t, t, #16
0:
    decrypt  0, 4
    decrypt  1, 4
    decrypt  2, 4
    decrypt  3, 4
    ldr         q4, [key, t]				// expanded key
    subs        t, t, #16
    b.gt        0b
    final_decrypt   0, 4, 5
    final_decrypt   1, 4, 5
    final_decrypt   2, 4, 5
    str     q0, [out], #4*16
    final_decrypt   3, 4, 5
    str     q1, [out, #-3*16]
    str     q2, [out, #-2*16]
    str     q3, [out, #-1*16]

	subs	nblocks, nblocks, #4
	b.ge	L_4blocks

L_lessthan4:
	ands	nblocks, nblocks, #3
	b.eq	9f

L_1block:
    mov     t, keylen
    ldr     q0, [in], #16          // plain data
    ldr     q4, [key, t]	        // expanded key
    sub     t, t, #16
0:
    AESD    0, 4
    AESIMC   0, 0
    ldr     q4, [key, t]			// expanded key
    subs        t, t, #16
    b.gt        0b

    AESD    0, 4
    eor.16b v0, v0, v5

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

	#define	Select	1		// Select=1 to define aes_decryptc from EncryptDecrypt.s
	#include "EncryptDecrypt.s"
	#undef	Select

#endif

