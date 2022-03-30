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

#if defined(_ARM_ARCH_7) && CCN_MULMOD_256_ASM

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
#define Z8 r10

#define u r11
#define q r12
#define t r14

/**
 * This is the heart of Montgomery's REDC algorithm and computes:
 *
 *   Q = z[0] * m[0]' mod R
 *   Z = (P + q * M) / R
 *
 * Where M is the P-256 prime:
 *
 *   0xffffffff 0x00000001 0x00000000 0x00000000 0x00000000 0xffffffff 0xffffffff 0xffffffff
 *
 * It's a word-wise algorithm that needs to be run once per every output word
 * in Z. For a 256-bit Z it needs to be run eight times to (almost) reduce P.
 *
 * The resulting Z will be a 289-bit number with the least-signifcant 32 bits
 * cleared. We shift by 32 bits by reducing directly into registers Z0-Z7.
 */
.macro partial_redc
    // m[0]' = -m[0]^(-1) (mod 2^32)
    //
    // The modular inverse of m[0] (mod 2^32) is just m[0] itself, because:
    //   m[0] * m[0] = 1 (mod 2^32)
    //
    // And thus:
    //   -m[0]^(-1) = 1 (mod 2^32)

    // q = z[0] * m[0]' = z[0] * 1 = z[0]
    mov q, Z0

    // (u,v) = z[0] + m[0] * q = z[0] + m[0] * z[0]
    //
    // We don't need to multiply to compute the above equation, as:
    //   X * 0xffffffff = (X << 32) - X
    //
    // Simplified:
    //   (u,v) = z[0] + (q << 32) - q
    //
    // And because q = z[0]:
    //   (u,v) = z[0] + (z[0] << 32) - z[0] = z[0] << 32
    //
    // z[0] doesn't change, q will be carried over.
    mov Z0, Z1

    // (u,v) = m[1] * q + z[1] + u
    //
    // We can avoid multiplication here too, because:
    //   X * 0xffffffff = (X << 32) - X
    //
    // z[1] doesn't change, q will be carried over.
    mov Z1, Z2

    // (u,v) = m[2] * q + z[2] + u
    //
    // We can avoid multiplication here too, because:
    //   X * 0xffffffff = (X << 32) - X
    //
    // z[2] doesn't change, q will be carried over.
    adds Z2, Z3, q

    adcs Z3, Z4, #0
    adcs Z4, Z5, #0
    adcs Z5, Z6, q
    adcs Z6, Z7, #0
    adc   u,  q, #0

    // Need to subtract q for m[7], because again:
    //   X * 0xffffffff = (X << 32) - X
    subs Z6, Z6, q
    sbc  q, u, #0

    mov u, #0
    adds Z7, Z8, t
    adc  t,  u, #0

    adds Z7, Z7, q
    adc  t, t, #0
.endm


/**
 * The last step of Montgomery's REDC algorithm is:
 *
 *   if Z >= M then Z = Z - M
 *
 * Where M is the P-256 prime:
 *
 *   0xffffffff 0x00000001 0x00000000 0x00000000 0x00000000 0xffffffff 0xffffffff 0xffffffff
 *
 * This is a constant-time implementation of the above, first subtracting M
 * from Z and optionally adding it back if Z was smaller than M.
 */
.macro final_sub
    // Subtract M.
    subs r2, r2, 0xffffffff
    sbcs r3, r3, 0xffffffff
    sbcs r4, r4, 0xffffffff
    sbcs r5, r5, #0
    sbcs r6, r6, #0
    sbcs r7, r7, #0
    sbcs r8, r8, #1
    sbcs r9, r9, 0xffffffff

    // r10 = (Z < M) ? 0xffffffff : 0
    sbc r10, t, #0

    // Add p back, if needed.
    adds r2, r2, r10
    adcs r3, r3, r10
    adcs r4, r4, r10
    adcs r5, r5, #0
    adcs r6, r6, #0
    adcs r7, r7, #0
    adcs r8, r8, r10, lsr #31
    adc  r9, r9, r10
.endm


/**
 * Montgomery modular multiplication
 *
 * Given:
 *   + A modulus M (the P-256 prime)
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
 * This implementation follows a Full Operand-Caching approach. The 512-bit
 * product P is stored on the stack and iteratively reduced modulo M.
 */
.align 2
.globl _ccn_mul_256_montgomery
.thumb_func _ccn_mul_256_montgomery
_ccn_mul_256_montgomery: /* void ccn_mul_256_montgomery(cc_unit *r, const cc_unit *a, const cc_unit *b); */
    push { r4-r12, r14 }

    // Store the 512-bit product on the stack.
    sub sp, #(16*4)

    ldr r3, [r1, #(6*4)]
    ldr r4, [r1, #(7*4)]
    ldr r6, [r2, #(0*4)]
    ldr r7, [r2, #(1*4)]
    ldr r8, [r2, #(2*4)]

    /***** C6 *****/

    // A6 * B0
    umull r9, r10, r3, r6

    str r9, [sp, #(6*4)]

    /***** C7 *****/

    mov r11, #0
    mov r12, #0

    // A7 * B0
    umlal r10, r11, r4, r6

    // A6 * B1
    umlal r10, r12, r3, r7

    str r10, [sp, #(7*4)]

    /***** C8 *****/

    // A7 * B1
    umaal r12, r11, r4, r7

    ldr r3, [r1, #(0*4)]
    ldr r4, [r1, #(1*4)]
    ldr r5, [r1, #(2*4)]

    str r12, [sp, #(8*4)]
    str r11, [sp, #(9*4)]

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

    ldr  r7, [r2, #(7*4)]
    ldr r11, [sp, #(7*4)]

    // A2 * B5
    umaal r9, r10, r5, r8

    // A1 * B6
    umaal r9, r12, r4, r6

    // A0 * B7
    umaal r9, r11, r3, r7

    str r9, [sp, #(7*4)]

    /***** C8 *****/

    ldr r3, [r1, #(3*4)]
    ldr r9, [sp, #(8*4)]

    // A3 * B5
    umaal r10, r11, r3, r8

    // A2 * B6
    umaal r10, r12, r5, r6

    // A1 * B7
    umaal r10, r9, r4, r7

    str r10, [sp, #(8*4)]

    /***** C9 *****/

    ldr  r4, [r1, #(4*4)]
    ldr r10, [sp, #(9*4)]

    // A4 * B5
    umaal r11, r12, r4, r8

    // A3 * B6
    umaal r11, r9, r3, r6

    // A2 * B7
    umaal r11, r10, r5, r7

    str r11, [sp, #(9*4)]

    /***** C10 *****/

    // A4 * B6
    umaal r9, r10, r4, r6

    // A3 * B7
    umaal r9, r12, r3, r7

    str r9, [sp, #(10*4)]

    /***** C11 *****/

    // A4 * B7
    umaal r10, r12, r4, r7

    str r10, [sp, #(11*4)]
    str r12, [sp, #(12*4)]

    /***** C3 *****/

    ldr r6, [r2, #(0*4)]
    ldr r9, [sp, #(3*4)]

    mov r10, #0

    // A3 * B0
    umlal r9, r10, r3, r6

    str r9, [sp, #(3*4)]

    /***** C4 *****/

    ldr  r7, [r2, #(1*4)]
    ldr r11, [sp, #(4*4)]

    mov r12, #0

    // A4 * B0
    umaal r10, r11, r4, r6

    // A3 * B1
    umlal r10, r12, r3, r7

    str r10, [sp, #(4*4)]

    /***** C5 *****/

    ldr  r5, [r1, #(5*4)]
    ldr  r8, [r2, #(2*4)]
    ldr r10, [sp, #(5*4)]

    mov r9, #0

    // A5 * B0
    umaal r11, r12, r5, r6

    // A4 * B1
    umaal r11, r10, r4, r7

    // A3 * B2
    umlal r11, r9, r3, r8

    str r11, [sp, #(5*4)]

    /***** C6 *****/

    ldr  r6, [r2, #(3*4)]
    ldr r11, [sp, #(6*4)]

    // A5 * B1
    umaal r9, r10, r5, r7

    // A4 * B2
    umaal r9, r12, r4, r8

    // A3 * B3
    umaal r9, r11, r3, r6

    str r9, [sp, #(6*4)]

    /***** C7 *****/

    ldr r7, [r2, #(4*4)]
    ldr r9, [sp, #(7*4)]

    // A5 * B2
    umaal r10, r11, r5, r8

    // A4 * B3
    umaal r10, r12, r4, r6

    // A3 * B4
    umaal r10, r9, r3, r7

    str r10, [sp, #(7*4)]

    /***** C8 *****/

    ldr  r3, [r1, #(6*4)]
    ldr r10, [sp, #(8*4)]

    // A6 * B2
    umaal r11, r12, r3, r8

    // A5 * B3
    umaal r11, r9, r5, r6

    // A4 * B4
    umaal r11, r10, r4, r7

    str r11, [sp, #(8*4)]

    /***** C9 *****/

    ldr  r4, [r1, #(7*4)]
    ldr r11, [sp, #(9*4)]

    // A7 * B2
    umaal r9, r10, r4, r8

    // A6 * B3
    umaal r9, r12, r3, r6

    // A5 * B4
    umaal r9, r11, r5, r7

    str r9, [sp, #(9*4)]

    /***** C10 *****/

    ldr r8, [r2,  #(5*4)]
    ldr r9, [sp, #(10*4)]

    // A7 * B3
    umaal r11, r12, r4, r6

    // A6 * B4
    umaal r11, r10, r3, r7

    // A5 * B5
    umaal r11, r9, r5, r8

    str r11, [sp, #(10*4)]

    /***** C11 *****/

    ldr  r6, [r2,  #(6*4)]
    ldr r11, [sp, #(11*4)]

    // A7 * B4
    umaal r9, r10, r4, r7

    // A6 * B5
    umaal r9, r12, r3, r8

    // A5 * B6
    umaal r9, r11, r5, r6

    str r9, [sp, #(11*4)]

    /***** C12 *****/

    ldr r7, [r2,  #(7*4)]
    ldr r9, [sp, #(12*4)]

    // A7 * B5
    umaal r10, r11, r4, r8

    // A6 * B6
    umaal r10, r12, r3, r6

    // A5 * B7
    umaal r10, r9, r5, r7

    str r10, [sp, #(12*4)]

    /***** C13 *****/

    // A7 * B6
    umaal r11, r12, r4, r6

    // A6 * B7
    umaal r11, r9, r3, r7

    str r11, [sp, #(13*4)]

    /***** C14+15 *****/

    // A7 * B7
    umaal r9, r12, r4, r7

    str  r9, [sp, #(14*4)]
    str r12, [sp, #(15*4)]

    // Load Z.
    ldmia sp, { Z0-Z8 }

    mov t, #0

    // Partially reduce eight times.
    partial_redc

    ldr Z8, [sp, #(4*9)]
    partial_redc

    ldr Z8, [sp, #(4*10)]
    partial_redc

    ldr Z8, [sp, #(4*11)]
    partial_redc

    ldr Z8, [sp, #(4*12)]
    partial_redc

    ldr Z8, [sp, #(4*13)]
    partial_redc

    ldr Z8, [sp, #(4*14)]
    partial_redc

    ldr Z8, [sp, #(4*15)]
    partial_redc

    // if Z >= M then Z := Z − M
    final_sub

    // Write Z.
    stmia r0, { Z0-Z7 }

    add sp, #(4*16)
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
.globl _ccn_sqr_256_montgomery
.thumb_func _ccn_sqr_256_montgomery
_ccn_sqr_256_montgomery: /* void ccn_sqr_256_montgomery(cc_unit *r, const cc_unit *a); */
    push { r4-r12, r14 }

    // Store the 512-bit product on the stack.
    sub sp, #(16*4)

    // Load A.
    ldmia r1, { r2-r9 } // A0-A7

    /***** C1 *****/

    // A1 * A0
    umull r14, r10, r3, r2

    // << 1
    adds r14, r14, r14

    str r14, [sp, #(1*4)]

    /***** C2 *****/

    mov r11, #0

    // A2 * A0
    umlal r10, r11, r4, r2

    // << 1
    adcs r10, r10, r10

    str r10, [sp, #(2*4)]

    /***** C3 *****/

    mov r14, #0
    mov r12, #0

    // A3 * A0
    umlal r11, r14, r5, r2

    // A2 * A1
    umlal r11, r12, r4, r3

    // << 1
    adcs r11, r11, r11

    str r11, [sp, #(3*4)]

    /***** C4 *****/

    mov r10, #0

    // A4 * A0
    umaal r14, r12, r6, r2

    // A3 * A1
    umlal r14, r10, r5, r3

    // << 1
    adcs r14, r14, r14

    str r14, [sp, #(4*4)]

    /***** C5 *****/

    mov  r14, #0
    mov r11, #0

    // A5 * A0
    umaal r10, r12, r7, r2

    // A4 * A1
    umlal r10, r11, r6, r3

    // A3 * A2
    umlal r10, r14, r5, r4

    // << 1
    adcs r10, r10, r10

    str r10, [sp, #(5*4)]

    /***** C6 *****/

    mov r10, #0

    // A6 * A0
    umaal r11, r12, r8, r2

    // A5 * A1
    umaal r11, r14, r7, r3

    // A4 * A2
    umlal r11, r10, r6, r4

    // << 1
    adcs r11, r11, r11

    str r11, [sp, #(6*4)]

    /***** C7 *****/

    mov r11, #0

    // A7 * A0
    umaal r14, r10, r9, r2

    str r10, [sp, #(8*4)]

    // A6 * A1
    umaal r14, r12, r8, r3

    // A5 * A2
    umlal r14, r11, r7, r4

    mov r10, #0

    // A4 * A3
    umlal r14, r10, r6, r5

    // << 1
    adcs r14, r14, r14

    str r14, [sp, #(7*4)]

    /***** C8 *****/

    ldr r14, [sp, #(8*4)]

    // A7 * A1
    umaal r10, r11, r9, r3

    // A6 * A2
    umaal r10, r12, r8, r4

    // A5 * A3
    umaal r10, r14, r7, r5

    // << 1
    adcs r10, r10, r10

    str r10, [sp, #(8*4)]

    /***** C9 *****/

    mov r10, #0

    // A7 * A2
    umaal r11, r12, r9, r4

    // A6 * A3
    umaal r11, r14, r8, r5

    // A5 * A4
    umlal r11, r10, r7, r6

    // << 1
    adcs r11, r11, r11

    str r11, [sp, #(9*4)]

    /***** C10 *****/

    // A7 * A3
    umaal r10, r12, r9, r5

    // A6 * A4
    umaal r10, r14, r8, r6

    // << 1
    adcs r10, r10, r10

    str r10, [sp, #(10*4)]

    /***** C11 *****/

    mov r11, #0

    // A7 * A4
    umaal r12, r14, r9, r6

    // A6 * A5
    umlal r12, r11, r8, r7

    // << 1
    adcs r12, r12, r12

    str r12, [sp, #(11*4)]

    /***** C12 *****/

    // A7 * A5
    umaal r11, r14, r9, r7

    // << 1
    adcs r11, r11, r11

    str r11, [sp, #(12*4)]

    /***** C13+14+15 *****/

    mov r10, #0

    // A7 * A6
    umlal r14, r10, r9, r8

    // << 1
    adcs r14, r14, r14
    adcs r10, r10, r10

    mov r11, #0
    adc r11, r11, #0

    str r14, [sp, #(13*4)]
    str r10, [sp, #(14*4)]
    str r11, [sp, #(15*4)]

    /***** C0+1 *****/

    ldr r11, [sp, #(1*4)]

    // A0 * A0
    umull r10, r12, r2, r2
    adds r11, r11, r12

    str r10, [sp, #(0*4)]
    str r11, [sp, #(1*4)]

    /***** C2+3 *****/

    ldr r12, [sp, #(2*4)]
    ldr r14, [sp, #(3*4)]

    // A1 * A1
    umull r10, r11, r3, r3
    adcs r12, r12, r10
    adcs r14, r14, r11

    str r12, [sp, #(2*4)]
    str r14, [sp, #(3*4)]

    /***** C4+5 *****/

    ldr r10, [sp, #(4*4)]
    ldr r11, [sp, #(5*4)]

    // A2 * A2
    umull r12, r14, r4, r4
    adcs r10, r10, r12
    adcs r11, r11, r14

    str r10, [sp, #(4*4)]
    str r11, [sp, #(5*4)]

    /***** C6+7 *****/

    ldr r12, [sp, #(6*4)]
    ldr r14, [sp, #(7*4)]

    // A3 * A3
    umull r10, r11, r5, r5
    adcs r12, r12, r10
    adcs r14, r14, r11

    str r12, [sp, #(6*4)]
    str r14, [sp, #(7*4)]

    /***** C8+9 *****/

    ldr r10, [sp, #(8*4)]
    ldr r11, [sp, #(9*4)]

    // A4 * A4
    umull r12, r14, r6, r6
    adcs r10, r10, r12
    adcs r11, r11, r14

    str r10, [sp, #(8*4)]
    str r11, [sp, #(9*4)]

    /***** C10+11 *****/

    ldr r12, [sp, #(10*4)]
    ldr r14, [sp, #(11*4)]

    // A5 * A5
    umull r10, r11, r7, r7
    adcs r12, r12, r10
    adcs r14, r14, r11

    str r12, [sp, #(10*4)]
    str r14, [sp, #(11*4)]

    /***** C12+13 *****/

    ldr r10, [sp, #(12*4)]
    ldr r11, [sp, #(13*4)]

    // A6 * A6
    umull r12, r14, r8, r8
    adcs r10, r10, r12
    adcs r11, r11, r14

    str r10, [sp, #(12*4)]
    str r11, [sp, #(13*4)]

    /***** C14+15 *****/

    ldr r12, [sp, #(14*4)]
    ldr r14, [sp, #(15*4)]

    // A7 * A7
    umull r10, r11, r9, r9
    adcs r12, r12, r10
    adc  r14, r14, r11

    str r12, [sp, #(14*4)]
    str r14, [sp, #(15*4)]

    // Load Z.
    ldmia sp, { Z0-Z8 }

    mov t, #0

    // Partially reduce eight times.
    partial_redc

    ldr Z8, [sp, #(4*9)]
    partial_redc

    ldr Z8, [sp, #(4*10)]
    partial_redc

    ldr Z8, [sp, #(4*11)]
    partial_redc

    ldr Z8, [sp, #(4*12)]
    partial_redc

    ldr Z8, [sp, #(4*13)]
    partial_redc

    ldr Z8, [sp, #(4*14)]
    partial_redc

    ldr Z8, [sp, #(4*15)]
    partial_redc

    // if Z >= M then Z := Z − M
    final_sub

    // Write Z.
    stmia r0, { Z0-Z7 }

    add sp, #(4*16)
    pop { r4-r12, r14 }
    bx lr


/**
 * Montgomery modular reduction
 *
 * Converts a given number A < M from the Montgomery representation by
 * computing Z = A / R mod M.
 */
.align 2
.globl _ccn_mod_256_montgomery
.thumb_func _ccn_mod_256_montgomery
_ccn_mod_256_montgomery: /* void ccn_mod_256_montgomery(cc_unit *r, const cc_unit *a); */
    push { r4-r12, r14 }

    ldmia r1, { Z0-Z7 }

    mov Z8, #0
    mov t, #0

    // Reduce once per limb (eight times).
    partial_redc
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
    stmia r0, { Z0-Z7 }

    pop { r4-r12, r14 }
    bx lr

#endif
