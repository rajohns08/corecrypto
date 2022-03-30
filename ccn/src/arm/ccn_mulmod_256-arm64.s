# Copyright (c) (2019,2020) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>

#if defined(__arm64__) && CCN_MULMOD_256_ASM

#include "ccarm_pac_bti_macros.h"

.subsections_via_symbols

.text

/**
 * A64 implementation of Montgomery modular multiplication, squaring, and
 * reduction.
 */

#define A0 x3
#define A1 x4
#define A2 x5
#define A3 x6

#define B0 x7
#define B1 x8
#define B2 x9
#define B3 x10

#define Z0 x11
#define Z1 x12
#define Z2 x13
#define Z3 x14
#define Z4 x15
#define Z5 x16

#define v x1
#define u x2
#define q x17

/**
 * This is the heart of Montgomery's REDC algorithm and computes:
 *
 *   Q = z[0] * m[0]' mod R
 *   Z = (P + q * M) / R
 *
 * Where M is the P-256 prime:
 *
 *   0xffffffff00000001 0x0000000000000000 0x00000000ffffffff 0xffffffffffffffff
 *
 * It's a word-wise algorithm that needs to be run once per every output word
 * in Z. For a 256-bit Z it needs to be run four times to (almost) reduce P.
 *
 * The resulting Z will be a 289-bit number with the least-signifcant 64 bits
 * cleared. We shift by 64 bits by reducing directly into registers Z0-Z4.
 */
.macro partial_redc
    // m[0]' = -m[0]^(-1) (mod 2^64)
    //
    // The modular inverse of m[0] (mod 2^64) is just m[0] itself, because:
    //   m[0] * m[0] = 1 (mod 2^64)
    //
    // And thus:
    //   -m[0]^(-1) = 1 (mod 2^64)

    // q = z[0] * m[0]' = z[0] * 1 = z[0]
    mov q, Z0

    // (u,v) = z[0] + m[0] * q = z[0] + m[0] * z[0]
    //
    // We don't need to multiply to compute the above equation, as:
    //   X * 0xffffffffffffffff = (X << 64) - X
    //
    // Simplified:
    //   (u,v) = z[0] + (q << 64) - q
    //
    // And because q = z[0]:
    //   (u,v) = z[0] + (z[0] << 64) - z[0] = z[0] << 64
    //
    // z[0] will be carried over into z[1].

    // (u,v) = m[1] * q + z[1] + u
    //
    // We can avoid multiplication here too, because:
    //   X * 0x00000000ffffffff = (X << 32) - X
    //
    // Simplified:
    //   (u,v) = (q << 32) - q + z[1] + u
    //
    // And because u = q:
    //   (u,v) = (q << 32) - q + z[1] + q = (q << 32) + z[1]
    adds Z0, Z1, q, lsl #32
    lsr Z1, q, #32

    // (u,v) = m[2] * q + z[2] + u
    //
    // Because m[2] = 0:
    //   (u,v) = 0 * q + z[2] + u = z[2] + u
    adcs Z1, Z2, Z1

    // (u,v) = m[3] * q + z[3] + u
    //       = z[3] + (q << 64) - (q << 32) + q
    adcs Z2, Z3, q
    adcs Z3, Z4, q
    adc  Z4, Z5, xzr

    // Subtract (v << 32).
    subs Z2, Z2, q, lsl #32
    lsr u, q, #32

    sbcs Z3, Z3, u
    sbc  Z4, Z4, xzr
.endm


/**
 * The last step of Montgomery's REDC algorithm is:
 *
 *   if Z >= M then Z = Z - M
 *
 * Where M is the P-256 prime:
 *
 *   0xffffffff00000001 0x0000000000000000 0x00000000ffffffff 0xffffffffffffffff
 *
 * This is a constant-time implementation of the above, first subtracting M
 * from Z and optionally adding it back if Z was smaller than M.
 */
.macro final_sub
    mov u, 0x00000000ffffffff // m[1]
    mov v, 0xffffffff00000001 // m[3]

    // Subtract M.
    subs Z0, Z0, 0xffffffffffffffff
    sbcs Z1, Z1, u
    sbcs Z2, Z2, xzr
    sbcs Z3, Z3, v
    sbcs Z4, Z4, xzr

    // q = (Z < M) ? 0xffffffffffffffff : 0
    sbc q, xzr, xzr

    // Clear u,v if (Z >= M).
    and u, u, q
    and v, v, q

    // Add M back, if needed.
    adds Z0, Z0, q
    adcs Z1, Z1, u
    adcs Z2, Z2, xzr
    adc  Z3, Z3, v
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
 * This implementation follows a Coarsely Integrated Product Scanning
 * approach. A and B are multiplied using product scanning and four partial
 * Montgomery reductions are performed on intermediate results - alternating
 * between multiplication and reduction.
 */
.align 4
.globl _ccn_mul_256_montgomery
_ccn_mul_256_montgomery: /* void ccn_mul_256_montgomery(cc_unit *r, const cc_unit *a, const cc_unit *b); */

    BRANCH_TARGET_CALL
    // Load A.
    ldp A0, A1, [x1], #16
    ldp A2, A3, [x1]

    // Load B.
    ldp B0, B1, [x2], #16
    ldp B2, B3, [x2]

    // Z0 = A0 * B0
    mul   Z0, A0, B0
    umulh Z1, A0, B0

    // Z1 += A1 * B0
    mul    v, A1, B0
    umulh Z2, A1, B0

    adds Z1, Z1, v
    adc  Z2, Z2, xzr

    // Z1 += A0 * B1
    mul   v, A0, B1
    umulh u, A0, B1

    adds Z1, Z1, v
    adcs Z2, Z2, u
    adc  Z3, xzr, xzr

    // Z2 += A2 * B0
    mul   v, A2, B0
    umulh u, A2, B0

    adds Z2, Z2, v
    adcs Z3, Z3, u
    adc  Z4, xzr, xzr

    // Z2 += A1 * B1
    mul   v, A1, B1
    umulh u, A1, B1

    adds Z2, Z2, v
    adcs Z3, Z3, u
    adc  Z4, Z4, xzr

    // Z2 += A0 * B2
    mul   v, A0, B2
    umulh u, A0, B2

    adds Z2, Z2, v
    adcs Z3, Z3, u
    adc  Z4, Z4, xzr

    // Z3 += A3 * B0
    mul   v, A3, B0
    umulh u, A3, B0

    adds Z3, Z3, v
    adcs Z4, Z4, u
    adc  Z5, xzr, xzr

    // Z3 += A2 * B1
    mul   v, A2, B1
    umulh u, A2, B1

    adds Z3, Z3, v
    adcs Z4, Z4, u
    adc  Z5, Z5, xzr

    // Z3 += A1 * B2
    mul   v, A1, B2
    umulh u, A1, B2

    adds Z3, Z3, v
    adcs Z4, Z4, u
    adc  Z5, Z5, xzr

    // Z3 += A0 * B3
    mul   v, A0, B3
    umulh u, A0, B3

    adds Z3, Z3, v
    adcs Z4, Z4, u
    adc  Z5, Z5, xzr

    // Partial reduction.
    partial_redc

    // Z3 += A3 * B1
    mul   v, A3, B1
    umulh u, A3, B1

    adds Z3, Z3, v
    adcs Z4, Z4, u
    adc  Z5, xzr, xzr

    // Z3 += A2 * B2
    mul   v, A2, B2
    umulh u, A2, B2

    adds Z3, Z3, v
    adcs Z4, Z4, u
    adc  Z5, Z5, xzr

    // Z3 += A1 * B3
    mul   v, A1, B3
    umulh u, A1, B3

    adds Z3, Z3, v
    adcs Z4, Z4, u
    adc  Z5, Z5, xzr

    // Partial reduction.
    partial_redc

    // Z3 += A3 * B2
    mul   v, A3, B2
    umulh u, A3, B2

    adds Z3, Z3, v
    adcs Z4, Z4, u
    adc  Z5, xzr, xzr

    // Z3 += A2 * B3
    mul   v, A2, B3
    umulh u, A2, B3

    adds Z3, Z3, v
    adcs Z4, Z4, u
    adc  Z5, Z5, xzr

    // Partial reduction.
    partial_redc

    // Z3 += A3 * B3
    mul   v, A3, B3
    umulh u, A3, B3

    adds Z3, Z3, v
    adcs Z4, Z4, u
    adc  Z5, xzr, xzr

    // Partial reduction.
    partial_redc

    // if Z >= M then Z := Z − M
    final_sub

    // Write Z.
    stp Z0, Z1, [x0], #16
    stp Z2, Z3, [x0]

    ret


/**
 * Montgomery modular squaring
 *
 * Intermediate products with the same factors are grouped together, and thus
 * the number of multiplications is reduced by almost half.
 *
 * The number of additions is reduced by employing "Lazy Doubling". The LD
 * method defers doubling of intermediate products as far as possible so it
 * can be performed on multiple intermediate results at once.
 */
.align 4
.globl _ccn_sqr_256_montgomery
_ccn_sqr_256_montgomery: /* void ccn_sqr_256_montgomery(cc_unit *r, const cc_unit *a); */

    BRANCH_TARGET_CALL
    // Load A.
    ldp A0, A1, [x1], #16
    ldp A2, A3, [x1]

    // A0 * A1
    mul   Z1, A0, A1
    umulh Z2, A0, A1

    // A0 * A2
    mul    v, A0, A2
    umulh Z3, A0, A2

    // A0 * A3
    mul    u, A0, A3
    umulh Z4, A0, A3

    // Accumulate.
    adds Z2, Z2, v
    adcs Z3, Z3, u
    adcs Z4, Z4, xzr
    adc  Z5, xzr, xzr

    // A1 * A2
    mul   v, A1, A2
    umulh u, A1, A2

    // Accumulate.
    adds Z3, Z3, v
    adcs Z4, Z4, u
    adc  Z5, Z5, xzr

    // Double. (<< 1)
    extr Z5, Z5, Z4, #63
    extr Z4, Z4, Z3, #63
    extr Z3, Z3, Z2, #63
    extr Z2, Z2, Z1, #63
    lsl Z1, Z1, #1

    // A0 * A0
    mul   Z0, A0, A0
    umulh  v, A0, A0

    // A1 * A1
    mul   u, A1, A1
    umulh q, A1, A1

    // Add A0A0 and A1A1.
    adds Z1, Z1, v
    adcs Z2, Z2, u
    adcs Z3, Z3, q
    adcs Z4, Z4, xzr
    adc  Z5, Z5, xzr

    // Partial reduction.
    partial_redc

    // A1 * A3
    mul   v, A1, A3
    umulh u, A1, A3

    // 2 * A1A3 (<< 1)
    lsr Z5, u, #63
    extr u, u, v, #63

    adds Z3, Z3, v, lsl #1
    adcs Z4, Z4, u
    adc  Z5, Z5, xzr

    // A2 * A2
    mul   v, A2, A2
    umulh u, A2, A2

    adds Z3, Z3, v
    adcs Z4, Z4, u
    adc  Z5, Z5, xzr

    // Partial reduction.
    partial_redc

    // A2 * A3
    mul   v, A2, A3
    umulh u, A2, A3

    // 2 * A2A3 (<< 1)
    lsr Z5, u, #63
    extr u, u, v, #63

    adds Z3, Z3, v, lsl #1
    adcs Z4, Z4, u
    adc  Z5, Z5, xzr

    // Partial reduction.
    partial_redc

    // A3 * A3
    mul   v, A3, A3
    umulh u, A3, A3

    adds Z3, Z3, v
    adcs Z4, Z4, u
    adc  Z5, xzr, xzr

    // Partial reduction.
    partial_redc

    // if Z >= M then Z := Z − M
    final_sub

    // Write Z.
    stp Z0, Z1, [x0], #16
    stp Z2, Z3, [x0]

    ret


/**
 * Montgomery modular reduction
 *
 * Converts a given number A < M from the Montgomery representation by
 * computing Z = A / R mod M.
 */
.align 4
.globl _ccn_mod_256_montgomery
_ccn_mod_256_montgomery: /* void ccn_mod_256_montgomery(cc_unit *r, const cc_unit *a); */

    BRANCH_TARGET_CALL
    // Load A.
    ldp Z0, Z1, [x1], #16
    ldp Z2, Z3, [x1]

    // Initialize Z.
    mov Z4, #0
    mov Z5, #0

    // Reduce once per limb (four times).
    partial_redc
    partial_redc
    partial_redc
    partial_redc

    // if Z >= M then Z := Z − M
    final_sub

    // Write Z.
    stp Z0, Z1, [x0], #16
    stp Z2, Z3, [x0]

    ret

#endif
