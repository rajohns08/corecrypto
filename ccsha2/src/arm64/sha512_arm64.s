# Copyright (c) (2016,2018-2020) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

/*
	This file provides arm64 hand implementation of the following function

    void ccsha512_compress(uint64_t *state, size_t nblocks, const void *in);

	sha512 algorithm per block description:

		1. W(0:15) = big-endian (per 8 bytes) loading of input data (128 bytes)
		2. load 8 digests (each 64bit) a-h from state
		3. for r = 0:15
				T1 = h + Sigma1(e) + Ch(e,f,g) + K[r] + W[r];
				d += T1;
				h = T1 + Sigma0(a) + Maj(a,b,c)
				permute a,b,c,d,e,f,g,h into h,a,b,c,d,e,f,g
		4. for r = 16:79
				W[r] = W[r-16] + Gamma1(W[r-2]) + W[r-7] + Gamma0(W[r-15]);
				T1 = h + Sigma1(e) + Ch(e,f,g) + K[r] + W[r];
				d += T1;
				h = T1 + Sigma0(a) + Maj(a,b,c)
				permute a,b,c,d,e,f,g,h into h,a,b,c,d,e,f,g

	In the assembly implementation:
		- a circular window of message schedule W(r:r+15) is updated and stored in v0-v7
		- its corresponding W+K(r:r+15) is updated and stored in a stack space circular buffer
		- the 8 digests (a-h) will be stored in GPR (%r8-%r15) 

	----------------------------------------------------------------------------

	our implementation (allows multiple blocks per call) pipelines the loading of W/WK of a future block
	into the last 16 rounds of its previous block:

	----------------------------------------------------------------------------

	load W(0:15) (big-endian per 8 bytes) into v0:v7
	pre_calculate and store W+K(0:15) in stack

L_loop:

	load digests a-h from ctx->state;

	for (r=0;r<64;r+=2) {
		digests a-h update and permute round r:r+1
		update W([r:r+1]%16) and WK([r:r+1]%16) for the next 8th iteration
	}

	num_block--;
	if (num_block==0)	jmp L_last_block;

	for (r=64;r<80;r+=2) {
		digests a-h update and permute round r:r+1
		load W([r:r+1]%16) (big-endian per 8 bytes) into v0:v7
		pre_calculate and store W+K([r:r+1]%16) in stack
	}

	ctx->states += digests a-h;

	jmp	L_loop;

L_last_block:

	for (r=64;r<80;r+=2) {
		digests a-h update and permute round r:r+2
	}

	ctx->states += digests a-h;

	------------------------------------------------------------------------

	Apple CoreOS vector & numerics
*/

#include <corecrypto/cc_config.h>

#if CCSHA2_VNG_ARM

#if defined __arm64__

#include "ccarm_pac_bti_macros.h"

	// associate variables with registers or memory

    #define stack_size     (16*8) 

	#define	ctx			x0
	#define num_blocks	x1
	#define	data        x2

	#define	a			x4
	#define	bb			x5
	#define	c			x6
	#define	d			x7
	#define	e			x8
	#define	f			x9
	#define	g			x10
	#define	h			x11

	#define	K			x3

	// 3 local variables
	#define	s	x12
	#define	t	x13
	#define	u	x14

	// a window (16 quad-words) of message scheule
	#define	W0	v0
	#define	W1	v1
	#define	W2	v2
	#define	W3	v3
	#define	W4	v4
	#define	W5	v5
	#define	W6	v6
	#define	W7	v7

	// circular buffer for WK[(r:r+15)%16]
	#define WK(x)   [sp,#((x)&15)*8]

// #define Ch(x,y,z)   (((x) & (y)) ^ ((~(x)) & (z)))

    /* t = Ch($0, $1, $2) */
	.macro Ch
    eor     t, $1, $2  
    and     t, t, $0
    eor     t, t, $2
	.endm

// #define Maj(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

    
    /* t = Maj($0, $1, $2) */
	.macro	Maj
	eor     t, $1, $2  // y^z
	and		s, $1,$2   // y&z
	and		t, t, $0   // x&(y^z)
	eor		t, t, s    // Maj(x,y,z)
	.endm

// #define Gamma0(x)   (S64(1,  (x)) ^ S64(8, (x)) ^ R(7 ,   (x)))

	// performs Gamma0_512 on 2 words on an vector registers
	// use v16/v17 as intermediate registers
	.macro	Gamma0
    ushr.2d v16, $0, #1         // part of S64(1, x)
    shl.2d  v17, $0, #56        // part of S64(8, x)
    ushr.2d $0, $0, #7          // R(7, x)
    eor.16b $0, $0, v16
    ushr.2d v16, v16, #7        // part of S64(8, x)
    eor.16b $0, $0, v17
    shl.2d  v17,v17, #7         // part of S64(1, x)
    eor.16b $0, $0, v16
    eor.16b $0, $0, v17
	.endm

// #define Gamma1(x)   (S64(19, (x)) ^ S64(61, (x)) ^ R(6,   (x)))

	// performs Gamma1_512 on 2 words on an vector registers
	// use v16/v17 as intermediate registers
	.macro	Gamma1
    ushr.2d v16, $0, #19        // part of S64(19, x)
    shl.2d  v17, $0, #3         // part of S64(61, x)
    ushr.2d $0, $0, #6          // R(6, x)
    eor.16b $0, $0, v16
    ushr.2d v16, v16, #42       // part of S64(61, x)
    eor.16b $0, $0, v17
    shl.2d  v17,v17, #42        // part of S64(19, x)
    eor.16b $0, $0, v16
    eor.16b $0, $0, v17
	.endm

    // W[r] = W[r-16] + Gamma1(W[r-2]) + W[r-7] + Gamma0(W[r-15]);
    /*
        W0 W1 W2 W3 W4 W5 W6 W7
        
        update 2 quad words in W0 = W0 + Gamma1(W7) + vext(W4,W5) + Gamma0(vext(W0,W1)). 
        use v16-v19 for temp
    */
    .macro  message_update2
    ext.16b v18, $4, $5, #8         // vext(W4,W5)
    ext.16b v19, $0, $1, #8         // vext(W0,W1)
    add.2d  $0, $0, v18             // W0 + vext(W4,W5)
    ushr.2d  v16, $7, #19            // part of S64(19, x)
    shl.2d  v17, $7, #3             // part of S64(61, x)
    ushr.2d  v18, $7, #6             // R(6,x)
    eor.16b v18, v18, v16
    ushr.2d  v16, v16, #42           // part of S64(61, x)
    eor.16b v18, v18, v17
    shl.2d  v17, v17, #42           // part of S64(19, x)
    eor.16b v18, v18, v16
    eor.16b v18, v18, v17
    Gamma0  v19                     // Gamma0(vext(W0,W1))
    add.2d  $0, $0, v18             // W0 + Gamma1(W7) + vext(W4,W5)
    add.2d  $0, $0, v19             // W0 + Gamma1(W7) + vext(W4,W5) + Gamma0(vext(W0,W1))
    .endm 

// #define Sigma0(x)   (S64(28,  (x)) ^ S64(34, (x)) ^ S64(39, (x)))

	.macro	Sigma0
    ror     t, $0, #28
    eor     t, t, $0, ror #34
    eor     t, t, $0, ror #39
	.endm

// #define Sigma1(x)   (S(14,  (x)) ^ S(18, (x)) ^ S(41, (x)))

	.macro	Sigma1
    ror     t, $0, #14
    eor     t, t, $0, ror #18
    eor     t, t, $0, ror #41
	.endm

	// per round digests update
	.macro	round_ref
	Sigma1	$4				// t = Sigma1(e);
	add		$7, $7, t		// h = h+Sigma1(e)
	Ch		$4, $5, $6		// t = Ch (e, f, g);
    ldr     s, WK($8)       // s = WK
	add		$7, $7, t		// h = h+Sigma1(e)+Ch(e,f,g);
	add		$7, $7, s		// h = h+Sigma1(e)+Ch(e,f,g)+WK
	add		$3, $3, $7		// d += h;
	Sigma0	$0				// t = Sigma0(a);
	add		$7, $7, t		// h += Sigma0(a);
	Maj		$0, $1, $2		// t = Maj(a,b,c)
	add		$7, $7, t		// h = T1 + Sigma0(a) + Maj(a,b,c);
	.endm

	.macro	round
    ror     t, $4, #14
    eor     s, $5, $6  
    eor     t, t, $4, ror #18
    ldr     u, WK($8)       // t = WK
    and     s, s, $4
    eor     t, t, $4, ror #41
	add		$7, $7, u		// h = h+WK
    eor     s, s, $6
	add		$7, $7, t		// h = h+WK+Sigma1(e)
	eor     t, $1, $2  // y^z
	add		$7, $7, s		// h = h+WK+Sigma1(e)+Ch(e,f,g);
    ror     s, $0, #28
	add		$3, $3, $7		// d += h;
	and		u, $1,$2   // y&z
    eor     s, s, $0, ror #34
	and		t, t, $0   // x&(y^z)
    eor     s, s, $0, ror #39
	eor		t, t, u    // Maj(x,y,z)
	add		$7, $7, s		// h += Sigma0(a);
	add		$7, $7, t		// h = T1 + Sigma0(a) + Maj(a,b,c);
	.endm

    /*
        16 rounds of hash update, update input schedule W (in vector register v0-v7) and WK = W + K (in stack)
    */
	.macro	rounds_schedule
    message_update2 W0, W1, W2, W3, W4, W5, W6, W7
    ld1.2d  {v16}, [K], #16     
	round	$0, $1, $2, $3, $4, $5, $6, $7, 0+$8
    add.2d  v16, v16, W0
	round	$7, $0, $1, $2, $3, $4, $5, $6, 1+$8
    str     q16, WK(0)  

    message_update2 W1, W2, W3, W4, W5, W6, W7, W0
    ld1.2d  {v16}, [K], #16     
	round	$6, $7, $0, $1, $2, $3, $4, $5, 2+$8
    add.2d  v16, v16, W1
	round	$5, $6, $7, $0, $1, $2, $3, $4, 3+$8
    str     q16, WK(2)  

    message_update2 W2, W3, W4, W5, W6, W7, W0, W1
    ld1.2d  {v16}, [K], #16     
	round	$4, $5, $6, $7, $0, $1, $2, $3, 4+$8
    add.2d  v16, v16, W2
	round	$3, $4, $5, $6, $7, $0, $1, $2, 5+$8
    str     q16, WK(4)  

    message_update2 W3, W4, W5, W6, W7, W0, W1, W2
    ld1.2d  {v16}, [K], #16     
	round	$2, $3, $4, $5, $6, $7, $0, $1, 6+$8
    add.2d  v16, v16, W3
	round	$1, $2, $3, $4, $5, $6, $7, $0, 7+$8
    str     q16, WK(6)  

    message_update2 W4, W5, W6, W7, W0, W1, W2, W3
    ld1.2d  {v16}, [K], #16     
	round	$0, $1, $2, $3, $4, $5, $6, $7, 8+$8
    add.2d  v16, v16, W4
	round	$7, $0, $1, $2, $3, $4, $5, $6, 9+$8
    str     q16, WK(8)  

    message_update2 W5, W6, W7, W0, W1, W2, W3, W4
    ld1.2d  {v16}, [K], #16     
	round	$6, $7, $0, $1, $2, $3, $4, $5, 10+$8
    add.2d  v16, v16, W5
	round	$5, $6, $7, $0, $1, $2, $3, $4, 11+$8
    str     q16, WK(10)  

    message_update2 W6, W7, W0, W1, W2, W3, W4, W5
    ld1.2d  {v16}, [K], #16     
	round	$4, $5, $6, $7, $0, $1, $2, $3, 12+$8
    add.2d  v16, v16, W6
	round	$3, $4, $5, $6, $7, $0, $1, $2, 13+$8
    str     q16, WK(12)  

    message_update2 W7, W0, W1, W2, W3, W4, W5, W6
    ld1.2d  {v16}, [K], #16     
	round	$2, $3, $4, $5, $6, $7, $0, $1, 14+$8
    add.2d  v16, v16, W7
	round	$1, $2, $3, $4, $5, $6, $7, $0, 15+$8
    str     q16, WK(14)  

	.endm

    /*
        16 rounds of hash update, load new input schedule W (in vector register v0-v7) and update WK = W + K (in stack)
    */
	.macro	rounds_schedule_initial
    ld1.16b {W0}, [data], #16
    ld1.2d  {v16}, [K], #16
    rev64.16b   W0, W0
	round	$0, $1, $2, $3, $4, $5, $6, $7, 0+$8
    add.2d  v16, v16, W0
	round	$7, $0, $1, $2, $3, $4, $5, $6, 1+$8
    str     q16, WK(0)  
    
    ld1.16b {W1}, [data], #16
    ld1.2d  {v16}, [K], #16
    rev64.16b   W1, W1
	round	$6, $7, $0, $1, $2, $3, $4, $5, 2+$8
    add.2d  v16, v16, W1
	round	$5, $6, $7, $0, $1, $2, $3, $4, 3+$8
    str     q16, WK(2)  

    ld1.16b {W2}, [data], #16
    ld1.2d  {v16}, [K], #16
    rev64.16b   W2, W2
	round	$4, $5, $6, $7, $0, $1, $2, $3, 4+$8
    add.2d  v16, v16, W2
	round	$3, $4, $5, $6, $7, $0, $1, $2, 5+$8
    str     q16, WK(4)  

    ld1.16b {W3}, [data], #16
    ld1.2d  {v16}, [K], #16
    rev64.16b   W3, W3
	round	$2, $3, $4, $5, $6, $7, $0, $1, 6+$8
    add.2d  v16, v16, W3
	round	$1, $2, $3, $4, $5, $6, $7, $0, 7+$8
    str     q16, WK(6)  

    ld1.16b {W4}, [data], #16
    ld1.2d  {v16}, [K], #16
    rev64.16b   W4, W4
	round	$0, $1, $2, $3, $4, $5, $6, $7, 8+$8
    add.2d  v16, v16, W4
	round	$7, $0, $1, $2, $3, $4, $5, $6, 9+$8
    str     q16, WK(8)  

    ld1.16b {W5}, [data], #16
    ld1.2d  {v16}, [K], #16
    rev64.16b   W5, W5
	round	$6, $7, $0, $1, $2, $3, $4, $5, 10+$8
    add.2d  v16, v16, W5
	round	$5, $6, $7, $0, $1, $2, $3, $4, 11+$8
    str     q16, WK(10)  

    ld1.16b {W6}, [data], #16
    ld1.2d  {v16}, [K], #16
    rev64.16b   W6, W6
	round	$4, $5, $6, $7, $0, $1, $2, $3, 12+$8
    add.2d  v16, v16, W6
	round	$3, $4, $5, $6, $7, $0, $1, $2, 13+$8
    str     q16, WK(12)  

    ld1.16b {W7}, [data], #16
    ld1.2d  {v16}, [K], #16
    rev64.16b   W7, W7
	round	$2, $3, $4, $5, $6, $7, $0, $1, 14+$8
    add.2d  v16, v16, W7
	round	$1, $2, $3, $4, $5, $6, $7, $0, 15+$8
    str     q16, WK(14)  

	.endm

    /*
        16 rounds of hash update
    */
	.macro	rounds_schedule_final
	round	$0, $1, $2, $3, $4, $5, $6, $7, 0+$8
	round	$7, $0, $1, $2, $3, $4, $5, $6, 1+$8

	round	$6, $7, $0, $1, $2, $3, $4, $5, 2+$8
	round	$5, $6, $7, $0, $1, $2, $3, $4, 3+$8

	round	$4, $5, $6, $7, $0, $1, $2, $3, 4+$8
	round	$3, $4, $5, $6, $7, $0, $1, $2, 5+$8

	round	$2, $3, $4, $5, $6, $7, $0, $1, 6+$8
	round	$1, $2, $3, $4, $5, $6, $7, $0, 7+$8

	round	$0, $1, $2, $3, $4, $5, $6, $7, 8+$8
	round	$7, $0, $1, $2, $3, $4, $5, $6, 9+$8

	round	$6, $7, $0, $1, $2, $3, $4, $5, 10+$8
	round	$5, $6, $7, $0, $1, $2, $3, $4, 11+$8

	round	$4, $5, $6, $7, $0, $1, $2, $3, 12+$8
	round	$3, $4, $5, $6, $7, $0, $1, $2, 13+$8

	round	$2, $3, $4, $5, $6, $7, $0, $1, 14+$8
	round	$1, $2, $3, $4, $5, $6, $7, $0, 15+$8
	.endm

    .align  4
	.text
    .globl	_ccsha512_vng_arm64_compress
_ccsha512_vng_arm64_compress:
	BRANCH_TARGET_CALL

    adrp    K, _ccsha512_K@page
    cbnz    num_blocks, 1f                       // if number of blocks is nonzero, go on for sha256 transform operation
    ret     lr                          // otherwise, return
1:
    add     K, K, _ccsha512_K@pageoff 

#if CC_KERNEL
    // v0-v7, v16-v19
    sub     x4, sp, #12*16
    sub     sp, sp, #12*16
    st1.4s  {v0, v1, v2, v3}, [x4], #64
    st1.4s  {v4, v5, v6, v7}, [x4], #64
    st1.4s  {v16, v17, v18, v19}, [x4], #64
#endif


	// allocate stack space for WK[0:15]
	sub		sp, sp, #stack_size

    ld1.16b  {v0,v1,v2,v3}, [data], #64
    ld1.16b  {v4,v5,v6,v7}, [data], #64

    rev64.16b   v0, v0
    rev64.16b   v1, v1
    rev64.16b   v2, v2
    rev64.16b   v3, v3
    rev64.16b   v4, v4
    rev64.16b   v5, v5
    rev64.16b   v6, v6
    rev64.16b   v7, v7



    mov     x4, sp
	// compute WK[0:15] and save in stack
    ld1.2d  {v16,v17,v18,v19}, [K], #64
    add.2d  v16, v16, v0
    add.2d  v17, v17, v1
    add.2d  v18, v18, v2
    add.2d  v19, v19, v3
    st1.2d  {v16,v17,v18,v19}, [x4], #64
    ld1.2d  {v16,v17,v18,v19}, [K], #64
    add.2d  v16, v16, v4
    add.2d  v17, v17, v5
    add.2d  v18, v18, v6
    add.2d  v19, v19, v7
    st1.2d  {v16,v17,v18,v19}, [x4], #64

L_loop:

	// digests a-h = ctx->states;
    ldp     a, bb, [ctx]
    ldp     c, d, [ctx, #16]
    ldp     e, f, [ctx, #32]
    ldp     g, h, [ctx, #48]

	// rounds 0:47 interleaved with W/WK update for rounds 16:63
    mov     w15, #4
L_i_loop:
    rounds_schedule a, bb, c, d, e, f, g, h, 16
    subs    w15, w15, #1
    b.gt    L_i_loop

	// revert K to the beginning of K256[]
	sub		K, K, #640
	subs    num_blocks, num_blocks, #1				// num_blocks--

	b.eq	L_final_block				// if final block, wrap up final rounds

    rounds_schedule_initial a, bb, c, d, e, f, g, h, 0

	// ctx->states += digests a-h
    ldp     s, t, [ctx]
    add     s, s, a
    add     t, t, bb
    stp     s, t, [ctx]
    ldp     s, t, [ctx, #16]
    add     s, s, c
    add     t, t, d
    stp     s, t, [ctx, #16]
    ldp     s, t, [ctx, #32]
    add     s, s, e
    add     t, t, f
    stp     s, t, [ctx, #32]
    ldp     s, t, [ctx, #48]
    add     s, s, g
    add     t, t, h
    stp     s, t, [ctx, #48]

	b		L_loop				// branch for next block

	// wrap up digest update round 48:63 for final block
L_final_block:
    rounds_schedule_final a, bb, c, d, e, f, g, h, 0

	// ctx->states += digests a-h
    ldp     s, t, [ctx]
    add     s, s, a
    add     t, t, bb
    stp     s, t, [ctx]
    ldp     s, t, [ctx, #16]
    add     s, s, c
    add     t, t, d
    stp     s, t, [ctx, #16]
    ldp     s, t, [ctx, #32]
    add     s, s, e
    add     t, t, f
    stp     s, t, [ctx, #32]
    ldp     s, t, [ctx, #48]
    add     s, s, g
    add     t, t, h
    stp     s, t, [ctx, #48]

	// if kernel, restore used vector registers
#if CC_KERNEL
    ld1.4s  {v0, v1, v2, v3}, [sp], #64
    ld1.4s  {v4, v5, v6, v7}, [sp], #64
    ld1.4s  {v16, v17, v18, v19}, [sp], #64
#endif

	// free allocated stack memory
    add     sp, sp, #stack_size

	// return
	ret     lr

#endif      // __arm64__

#endif
