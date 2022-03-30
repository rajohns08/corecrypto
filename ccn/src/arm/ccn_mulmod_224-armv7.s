# Copyright (c) (2019) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to 
# people who accept that license. IMPORTANT:  Any license rights granted to you by 
# Apple Inc. (if any) are limited to internal use within your organization only on 
# devices and computers you own or control, for the sole purpose of verifying the 
# security characteristics and correct functioning of the Apple Software.  You may 
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>

#if defined(_ARM_ARCH_7) && CCN_MULMOD_224_ASM

.subsections_via_symbols

.text
.syntax unified
.code 16

/**
 * A32 implementation of Montgomery modular multiplication, squaring, and
 * reduction.
 */

#define Z0 r2
#define Z1 r3
#define Z2 r4
#define Z3 r5
#define Z4 r6
#define Z5 r7
#define Z6 r8
#define Z7 r9

#define u r10
#define q r11
#define t r12

/**
 * This is the heart of Montgomery's REDC algorithm and computes:
 *
 *   Q = z[0] * m[0]' mod R
 *   Z = (P + q * M) / R
 *
 * Where M is the P-224 prime:
 *
 *   0xffffffff 0xffffffff 0xffffffff 0xffffffff 0x00000000 0x00000000 0x00000001
 *
 * It's a word-wise algorithm that needs to be run once per every output word
 * in Z. For a 224-bit Z it needs to be run seven times to (almost) reduce P.
 *
 * The resulting Z will be a 257-bit number with the least-signifcant 32 bits
 * cleared. We shift by 32 bits by reducing directly into registers Z0-Z7.
 */
.macro partial_redc
    // m[0]' = -m[0]^(-1) (mod 2^32)
    //
    // The modular inverse of m[0] (mod 2^32) is just m[0] itself, because:
    //   m[0] * m[0] = 1 (mod 2^32)
    //
    // And thus:
    //   -m[0]^(-1) = -1 (mod 2^32)

    // q = z[0] * m[0]' = z[0] * -1 = -z[0]
    neg q, Z0

    // (u,v) = z[0] + m[0] * q
    adds Z0, Z0, q

    // (u,v) = z[1..2] + m[1..2] * q
    adcs Z0, Z1, #0
    adcs Z1, Z2, #0

    // (u,v) = z[3..6] + m[3..6] * q
    adcs Z2, Z3, #0
    adcs Z3, Z4, #0
    adcs Z4, Z5, #0
    adcs Z5, Z6, #0
    adcs Z6, Z7, q

    mov u, #0
    adc u, u, #0

    // Carry from previous round.
    adds Z6, Z6, t

    mov t, #0
    adc t, u, #0

    subs Z2, Z2, q
    sbcs Z3, Z3, #0
    sbcs Z4, Z4, #0
    sbcs Z5, Z5, #0
    sbcs Z6, Z6, #0
    sbc t, t, #0
.endm


/**
 * The last step of Montgomery's REDC algorithm is:
 *
 *   if Z >= M then Z = Z - M
 *
 * Where M is the P-224 prime:
 *
 *   0xffffffff 0xffffffff 0xffffffff 0xffffffff 0x00000000 0x00000000 0x00000001
 *
 * This is a constant-time implementation of the above, first subtracting M
 * from Z and optionally adding it back if Z was smaller than M.
 */
.macro final_sub
    // Subtract M.
    subs r2, r2, #1
    sbcs r3, r3, #0
    sbcs r4, r4, #0
    sbcs r5, r5, 0xffffffff
    sbcs r6, r6, 0xffffffff
    sbcs r7, r7, 0xffffffff
    sbcs r8, r8, 0xffffffff

    // r10 = (Z < M) ? 0xffffffff : 0
    sbc r10, t, #0

    // Add p back, if needed.
    adds r2, r2, r10, lsr #31
    adcs r3, r3, #0
    adcs r4, r4, #0
    adcs r5, r5, r10
    adcs r6, r6, r10
    adcs r7, r7, r10
    adc  r8, r8, r10
.endm


/**
 * Montgomery modular multiplication
 *
 * Given:
 *   + A modulus M (the P-224 prime)
 *   + Operands A,B where both A,B < M
 *   + Constant M' = -M^(-1) mod R
 *   + Montgomery residual factor R = 2^n where R > M and gcd(M, R) = 1
 *
 * Result:
 *   Z = (A * B) / R mod M
 *
 * Steps:
 *   1) P = A * B
 *   2) Q = P * M' mod R
 *   3) Z = (P + Q * M) / R
 *   4) if Z >= M then Z = Z - M
 *
 * This implementation follows a Full Operand-Caching approach. The 448-bit
 * product P is stored on the stack and iteratively reduced modulo M.
 */
.align 2
.globl _ccn_mul_224_montgomery
.thumb_func _ccn_mul_224_montgomery
_ccn_mul_224_montgomery: /* void ccn_mul_224_montgomery(cc_unit *r, const cc_unit *a, const cc_unit *b); */
    push { r4-r12, r14 }

    // Store the 448-bit product on the stack.
    sub sp, #(14*4)

    ldr r3, [r1, #(0*4)]
    ldr r4, [r1, #(1*4)]
    ldr r5, [r1, #(6*4)]
    ldr r6, [r2, #(0*4)]
    ldr r7, [r2, #(1*4)]
    ldr r8, [r2, #(2*4)]

    /***** C6 *****/

    // A6 * B0
    umull r9, r10, r5, r6

    str  r9, [sp, #(6*4)]
    str r10, [sp, #(7*4)]

    /***** C0 *****/

    // A0 * B0
    umull r9, r10, r3, r6

    mov r11, #0
    mov r12, #0

    str r9, [sp, #(0*4)]

    /***** C1 *****/

    // A1 * B0
    umlal r10, r11, r4, r6

    // A0 * B1
    umlal r10, r12, r3, r7

    str r10, [sp, #(1*4)]

    /***** C2 *****/

    ldr r5, [r1, #(2*4)]

    mov r9, #0
    mov r10, #0

    // A2 * B0
    umaal r11, r12, r5, r6

    // A1 * B1
    umlal r11, r9, r4, r7

    // A0 * B2
    umlal r11, r10, r3, r8

    str r11, [sp, #(2*4)]

    /***** C3 *****/

    ldr r6, [r2, #(3*4)]

    mov r11, #0

    // A2 * B1
    umaal r10, r12, r5, r7

    // A1 * B2
    umaal r10, r9, r4, r8

    // A0 * B3
    umlal r10, r11, r3, r6

    str r10, [sp, #(3*4)]

    /***** C4 *****/

    ldr r7, [r2, #(4*4)]

    mov r10, #0

    // A2 * B2
    umaal r9, r11, r5, r8

    // A1 * B3
    umaal r9, r12, r4, r6

    // A0 * B4
    umlal r9, r10, r3, r7

    str r9, [sp, #(4*4)]

    /***** C5 *****/

    ldr r8, [r2, #(5*4)]

    mov r9, #0

    // A2 * B3
    umaal r10, r11, r5, r6

    // A1 * B4
    umaal r10, r12, r4, r7

    // A0 * B5
    umlal r10, r9, r3, r8

    str r10, [sp, #(5*4)]

    /***** C6 *****/

    ldr  r6, [r2, #(6*4)]
    ldr r10, [sp, #(6*4)]

    // A2 * B4
    umaal r11, r12, r5, r7

    // A1 * B5
    umaal r11, r9, r4, r8

    // A0 * B6
    umaal r11, r10, r3, r6

    str r11, [sp, #(6*4)]

    /***** C7 *****/

    ldr  r3, [r1, #(3*4)]
    ldr r11, [sp, #(7*4)]

    // A3 * B4
    umaal r9, r10, r3, r7

    // A2 * B5
    umaal r9, r12, r5, r8

    // A1 * B6
    umaal r9, r11, r4, r6

    str r9, [sp, #(7*4)]

    /***** C8 *****/

    // A3 * B5
    umaal r10, r11, r3, r8

    // A2 * B6
    umaal r10, r12, r5, r6

    str r10, [sp, #(8*4)]

    /***** C9 *****/

    // A3 * B6
    umaal r11, r12, r3, r6

    str r11, [sp,  #(9*4)]
    str r12, [sp, #(10*4)]

    /***** C3 *****/

    ldr r6, [r2, #(0*4)]
    ldr r9, [sp, #(3*4)]

    mov r10, #0

    // A3 * B0
    umlal r9, r10, r3, r6

    str r9, [sp, #(3*4)]

    /***** C4 *****/

    ldr  r4, [r1, #(4*4)]
    ldr  r7, [r2, #(1*4)]
    ldr r11, [sp, #(4*4)]

    mov r9, #0

    // A4 * B0
    umaal r10, r11, r4, r6

    // A3 * B1
    umlal r10, r9, r3, r7

    str r10, [sp, #(4*4)]

    /***** C5 *****/

    ldr  r5, [r1, #(5*4)]
    ldr  r8, [r2, #(2*4)]
    ldr r10, [sp, #(5*4)]

    mov r12, #0

    // A5 * B0
    umaal r10, r11, r5, r6

    // A4 * B1
    umaal r10, r9, r4, r7

    // A3 * B2
    umlal r10, r12, r3, r8

    str r10, [sp, #(5*4)]

    /***** C6 *****/

    ldr  r6, [r2, #(3*4)]
    ldr r10, [sp, #(6*4)]

    // A5 * B1
    umaal r9, r11, r5, r7

    // A4 * B2
    umaal r9, r12, r4, r8

    // A3 * B3
    umaal r9, r10, r3, r6

    str r9, [sp, #(6*4)]

    /***** C7 *****/

    ldr r3, [r1, #(6*4)]
    ldr r9, [sp, #(7*4)]

    // A6 * B1
    umaal r10, r11, r3, r7

    // A5 * B2
    umaal r10, r12, r5, r8

    // A4 * B3
    umaal r10, r9, r4, r6

    str r10, [sp, #(7*4)]

    /***** C8 *****/

    ldr r7, [r2, #(4*4)]
    ldr r10, [sp, #(8*4)]

    // A6 * B2
    umaal r11, r12, r3, r8

    // A5 * B3
    umaal r11, r9, r5, r6

    // A4 * B4
    umaal r11, r10, r4, r7

    str r11, [sp, #(8*4)]

    /***** C9 *****/

    ldr r8, [r2, #(5*4)]
    ldr r11, [sp, #(9*4)]

    // A6 * B3
    umaal r9, r10, r3, r6

    // A5 * B4
    umaal r9, r12, r5, r7

    // A4 * B5
    umaal r9, r11, r4, r8

    str r9, [sp, #(9*4)]

    /***** C10 *****/

    ldr r6, [r2, #(6*4)]
    ldr r9, [sp, #(10*4)]

    // A6 * B4
    umaal r10, r11, r3, r7

    // A5 * B5
    umaal r10, r12, r5, r8

    // A4 * B6
    umaal r10, r9, r4, r6

    str r10, [sp, #(10*4)]

    /***** C11 *****/

    // A6 * B5
    umaal r11, r12, r3, r8

    // A5 * B6
    umaal r11, r9, r5, r6

    str r11, [sp, #(11*4)]

    /***** C12+13 *****/

    // A6 * B6
    umaal r9, r12, r3, r6

    str  r9, [sp, #(12*4)]
    str r12, [sp, #(13*4)]

    // Load Z.
    ldmia sp, { Z0-Z7 }

    mov t, #0

    // Partially reduce seven times.
    partial_redc

    ldr Z7, [sp, #(4*8)]
    partial_redc

    ldr Z7, [sp, #(4*9)]
    partial_redc

    ldr Z7, [sp, #(4*10)]
    partial_redc

    ldr Z7, [sp, #(4*11)]
    partial_redc

    ldr Z7, [sp, #(4*12)]
    partial_redc

    ldr Z7, [sp, #(4*13)]
    partial_redc

    // if Z >= M then Z := Z − M
    final_sub

    // Write Z.
    stmia r0, { Z0-Z6 }

    add sp, #(4*14)
    pop { r4-r12, r14 }
    bx lr


/**
 * Montgomery modular squaring
 *
 * Product scanning is used to compute the partial product for the upper part
 * of the triangle, doubling immediately before writing to the stack, thereby
 * cutting the number of multiplications in almost half.
 *
 * The bottom line representing squared limbs is computed last and simply
 * added to the partial upper product.
 */
.align 2
.globl _ccn_sqr_224_montgomery
.thumb_func _ccn_sqr_224_montgomery
_ccn_sqr_224_montgomery: /* void ccn_sqr_224_montgomery(cc_unit *r, const cc_unit *a); */
    push { r4-r12, r14 }

    // Store the 448-bit product on the stack.
    sub sp, #(14*4)

    // Load A.
    ldmia r1, { r2-r8 } // A0-A6

    /***** C1 *****/

    // A1 * A0
    umull r9, r10, r3, r2

    // << 1
    adds r9, r9, r9

    str r9, [sp, #(1*4)]

    /***** C2 *****/

    mov r11, #0

    // A2 * A0
    umlal r10, r11, r4, r2

    // << 1
    adcs r10, r10, r10

    str r10, [sp, #(2*4)]

    /***** C3 *****/

    mov r9, #0
    mov r12, #0

    // A3 * A0
    umlal r11, r9, r5, r2

    // A2 * A1
    umlal r11, r12, r4, r3

    // << 1
    adcs r11, r11, r11

    str r11, [sp, #(3*4)]

    /***** C4 *****/

    mov r10, #0

    // A4 * A0
    umaal r9, r12, r6, r2

    // A3 * A1
    umlal r9, r10, r5, r3

    // << 1
    adcs r9, r9, r9

    str r9, [sp, #(4*4)]

    /***** C5 *****/

    mov r9, #0
    mov r11, #0

    // A5 * A0
    umaal r10, r12, r7, r2

    // A4 * A1
    umlal r10, r11, r6, r3

    // A3 * A2
    umlal r10, r9, r5, r4

    // << 1
    adcs r10, r10, r10

    str r10, [sp, #(5*4)]

    /***** C6 *****/

    mov r10, #0

    // A6 * A0
    umaal r11, r12, r8, r2

    // A5 * A1
    umaal r11, r9, r7, r3

    // A4 * A2
    umlal r11, r10, r6, r4

    // << 1
    adcs r11, r11, r11

    str r11, [sp, #(6*4)]

    /***** C7 *****/

    mov r11, #0

    // A6 * A1
    umaal r9, r12, r8, r3

    // A5 * A2
    umaal r9, r10, r7, r4

    // A4 * A3
    umlal r9, r11, r6, r5

    // << 1
    adcs r9, r9, r9

    str r9, [sp, #(7*4)]

    /***** C8 *****/

    // A6 * A2
    umaal r10, r12, r8, r4

    // A5 * A3
    umaal r10, r11, r7, r5

    // << 1
    adcs r10, r10, r10

    str r10, [sp, #(8*4)]

    /***** C9 *****/

    mov r10, #0

    // A6 * A3
    umaal r11, r12, r8, r5

    // A5 * A4
    umlal r11, r10, r7, r6

    // << 1
    adcs r11, r11, r11

    str r11, [sp, #(9*4)]

    /***** C10 *****/

    // A6 * A4
    umaal r10, r12, r8, r6

    // << 1
    adcs r10, r10, r10

    str r10, [sp, #(10*4)]

    /***** C11+12+13 *****/

    mov r11, #0

    // A6 * A5
    umlal r12, r11, r8, r7

    // << 1
    adcs r12, r12, r12
    adcs r11, r11, r11

    mov r10, #0
    adc r10, r10, #0

    str r12, [sp, #(11*4)]
    str r11, [sp, #(12*4)]
    str r10, [sp, #(13*4)]

    /***** C0+1 *****/

    ldr r11, [sp, #(1*4)]

    // A0 * A0
    umull r10, r12, r2, r2
    adds r11, r11, r12

    str r10, [sp, #(0*4)]
    str r11, [sp, #(1*4)]

    /***** C2+3 *****/

    ldr r12, [sp, #(2*4)]
    ldr r9, [sp, #(3*4)]

    // A1 * A1
    umull r10, r11, r3, r3
    adcs r12, r12, r10
    adcs r9, r9, r11

    str r12, [sp, #(2*4)]
    str r9, [sp, #(3*4)]

    /***** C4+5 *****/

    ldr r10, [sp, #(4*4)]
    ldr r11, [sp, #(5*4)]

    // A2 * A2
    umull r12, r9, r4, r4
    adcs r10, r10, r12
    adcs r11, r11, r9

    str r10, [sp, #(4*4)]
    str r11, [sp, #(5*4)]

    /***** C6+7 *****/

    ldr r12, [sp, #(6*4)]
    ldr r9, [sp, #(7*4)]

    // A3 * A3
    umull r10, r11, r5, r5
    adcs r12, r12, r10
    adcs r9, r9, r11

    str r12, [sp, #(6*4)]
    str r9, [sp, #(7*4)]

    /***** C8+9 *****/

    ldr r10, [sp, #(8*4)]
    ldr r11, [sp, #(9*4)]

    // A4 * A4
    umull r12, r9, r6, r6
    adcs r10, r10, r12
    adcs r11, r11, r9

    str r10, [sp, #(8*4)]
    str r11, [sp, #(9*4)]

    /***** C10+11 *****/

    ldr r12, [sp, #(10*4)]
    ldr r9, [sp, #(11*4)]

    // A5 * A5
    umull r10, r11, r7, r7
    adcs r12, r12, r10
    adcs r9, r9, r11

    str r12, [sp, #(10*4)]
    str r9, [sp, #(11*4)]

    /***** C12+13 *****/

    ldr r10, [sp, #(12*4)]
    ldr r11, [sp, #(13*4)]

    // A6 * A6
    umull r12, r9, r8, r8
    adcs r10, r10, r12
    adcs r11, r11, r9

    str r10, [sp, #(12*4)]
    str r11, [sp, #(13*4)]

    // Load Z.
    ldmia sp, { Z0-Z7 }

    mov t, #0

    // Partially reduce seven times.
    partial_redc

    ldr Z7, [sp, #(4*8)]
    partial_redc

    ldr Z7, [sp, #(4*9)]
    partial_redc

    ldr Z7, [sp, #(4*10)]
    partial_redc

    ldr Z7, [sp, #(4*11)]
    partial_redc

    ldr Z7, [sp, #(4*12)]
    partial_redc

    ldr Z7, [sp, #(4*13)]
    partial_redc

    // if Z >= M then Z := Z − M
    final_sub

    // Write Z.
    stmia r0, { Z0-Z6 }

    add sp, #(4*14)
    pop { r4-r12, r14 }
    bx lr


/**
 * Montgomery modular reduction
 *
 * Converts a given number A < M from the Montgomery representation by
 * computing Z = A / R mod M.
 */
.align 2
.globl _ccn_mod_224_montgomery
.thumb_func _ccn_mod_224_montgomery
_ccn_mod_224_montgomery: /* void ccn_mod_224_montgomery(cc_unit *r, const cc_unit *a); */
    push { r4-r12, r14 }

    ldmia r1, { Z0-Z6 }

    mov Z7, #0
    mov t, #0

    // Reduce once per limb (seven times).
    partial_redc
    partial_redc
    partial_redc
    partial_redc
    partial_redc
    partial_redc
    partial_redc

    // if Z >= M then Z := Z − M
    final_sub

    // Write Z.
    stmia r0, { Z0-Z6 }

    pop { r4-r12, r14 }
    bx lr

#endif

