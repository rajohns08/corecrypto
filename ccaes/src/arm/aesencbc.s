# Copyright (c) (2011-2016,2019,2020) Apple Inc. All rights reserved.
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

	// encrypt C code
/*
	aes_rqal aes_encrypt_cbc(const aes_encrypt_ctx *ctx, __m128 *iv, int num_blk, const __m128 *ibuf, __m128 *obuf)
    {

		while (num_blk--) {
              *iv ^= *ibuf++;
              aes_encrypt(iv, iv, ctx);
              *obuf++ = *iv;
	}

        return 0;
    }
*/

	#define	ctx		x0
	#define	iv		x1
	#define	num_blk	x2
	#define	ibuf	x3
	#define	obuf	x4
	#define	keylen	x5
	#define	keylenw	w5
	#define	t		x6

	.text


	.align	4
	.globl	_ccaes_arm_encrypt_cbc

_ccaes_arm_encrypt_cbc:
	BRANCH_TARGET_CALL
	// early exit if input number of blocks is zero
	cbnz		num_blk, 1f
	ret			lr
1:

	ldr			keylenw, [ctx, #240]

	cmp     	keylenw, #160
    b.eq   		2f
    cmp     	keylenw, #192
    b.eq   		2f
    cmp     	keylenw, #224
    b.eq     	2f

	mov     	x0, #-1     // Return error.
	ret			lr

2:

#if CC_KERNEL
    // save used vector registers
    sub     sp, sp, #4*16
    st1.4s      {v0,v1,v2,v3}, [sp]
#endif

	ldr			q0, [iv]				// initial *iv

L_scalar:

	sub			t, keylen, #16
	ld1.4s		{v1}, [ibuf], #16	// state = in
	ld1.4s      {v2}, [ctx], #16    // expanded key[10]

	eor.16b		v0, v0, v1				// *iv ^= *ibuf++;

	// aes_encrypt(iv, iv, ctx);
0:
	AESE		0, 2					// 	xor/SubByte/ShiftRows
	AESMC		0, 0					// MixColumns
	ld1.4s      {v2}, [ctx], #16		// expanded key[t]
	subs		t, t, #16
	b.gt		0b

	ldr			q3, [ctx]				// expanded key[0]
	AESE		0, 2					// 	xor/SubByte/ShiftRows
	eor.16b		v0, v0, v3				// v1 now is the final *iv
	sub			ctx, ctx, keylen

	st1.4s      {v0}, [obuf], #16
	subs		num_blk, num_blk, #1
	b.gt		L_scalar

L_done:
	mov			x0, #0
	str			q0, [iv]
#if CC_KERNEL
    // restore used vector registers
    st1.4s      {v0,v1,v2,v3}, [sp], #4*16
#endif
	ret			lr

#else

	#define	Select	0		// Select=0 to define aes_encrypt_cbc from aes_cbc.s
	#include "aes_cbc.s"
	#undef	Select

#endif

