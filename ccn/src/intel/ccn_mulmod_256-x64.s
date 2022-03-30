# Copyright (c) (2020) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>

#if defined(__x86_64__) && CCN_MULMOD_256_ASM

.text

/**
 * x64 implementation of Montgomery modular multiplication, squaring, and
 * reduction.
 */

#define Z0 %r8
#define Z1 %r9
#define Z2 %r10
#define Z3 %r11
#define Z4 %r12
#define Z5 %r13

#define u %rax
#define v %rbx
#define q %rcx

#define s %r14
#define t %r15

#define r %rdi
#define a %rsi
#define b %r14

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
    movq Z0, q

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

    // Z0 = Z1 + (q << 32)
    movq _IMM(32), u
    shlx u, q, v
    movq v, Z0
    addq Z1, Z0

    // Z1 = q >> 32
    shrx u, q, Z1
    movq Z1, u

    // (u,v) = m[2] * q + z[2] + u
    //
    // Because m[2] = 0:
    //   (u,v) = 0 * q + z[2] + u = z[2] + u
    adcq Z2, Z1

    // (u,v) = m[3] * q + z[3] + u
    //       = z[3] + (q << 64) - (q << 32) + q
    movq q, Z2
    adcq Z3, Z2
    movq q, Z3
    adcq Z4, Z3
    movq Z5, Z4
    adcq _IMM(0), Z4

    // Subtract (v << 32).
    subq v, Z2
    sbbq u, Z3
    sbbq _IMM(0), Z4
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
    movq _IMM(0x00000000ffffffff), u // m[1]
    movq _IMM(0xffffffff00000001), v // m[3]

    // Subtract M.
    subq _IMM(0xffffffffffffffff), Z0
    sbbq u, Z1
    sbbq _IMM(0), Z2
    sbbq v, Z3
    sbbq _IMM(0), Z4

    // q = (Z < M) ? 0xffffffffffffffff : 0
    movq _IMM(0), q
    sbbq _IMM(0), q

    // Clear u,v if (Z >= M).
    andq q, u
    andq q, v

    // Add M back, if needed.
    addq q, Z0
    adcq u, Z1
    adcq _IMM(0), Z2
    adcq v, Z3
.endm


/**
 * Inner operation of operand scanning for ccn_mul_256_montgomery().
 * Computes Z += Ax * B and reduces once.
 */
.macro addmul_redc
    // Clear flags.
    xorq Z5, Z5

    // Ax * B0
    mulxq (b), u, v

    adox u, Z0

    // Ax * B1
    mulxq 8(b), u, q

    adcx v, Z1
    adox u, Z1

    // Ax * B2
    mulxq 16(b), u, v

    adcx q, Z2
    adox u, Z2

    // Ax * B3
    mulxq 24(b), u, q

    adcx v, Z3
    adox u, Z3

    movq _IMM(0), v
    adcx q, Z4
    adox v, Z4

    // Partial reduction.
    partial_redc
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
 * This implementation follows a Coarsely Integrated Operand Scanning
 * approach. A and B are multiplied using operand scanning and four partial
 * Montgomery reductions are performed on intermediate results - alternating
 * between multiplication and reduction.
 */
.align 4
.globl _ccn_mul_256_montgomery
_ccn_mul_256_montgomery: /* void ccn_mul_256_montgomery(cc_unit *r, const cc_unit *a, const cc_unit *b); */
    pushq %rbp
    movq %rsp, %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %rbx

    // Free %rdx.
    movq %rdx, b

    // Clear flags.
    xorq Z5, Z5

    // Load A0.
    movq (a), %rdx

    // A0 * B0
    mulxq (b), Z0, Z1

    // A0 * B1
    mulxq 8(b), v, Z2

    addq v, Z1

    // A0 * B2
    mulxq 16(b), v, Z3

    adcq v, Z2

    // A0 * B3
    mulxq 24(b), v, Z4

    adcq v, Z3
    adcq $0, Z4

    // Partial reduction.
    partial_redc

    // Load A1.
    movq 8(a), %rdx

    // A1 * B and reduce.
    addmul_redc

    // Load A2.
    movq 16(a), %rdx

    // A2 * B and reduce.
    addmul_redc

    // Load A3.
    movq 24(a), %rdx

    // A3 * B and reduce.
    addmul_redc

    // if Z >= M then Z := Z − M
    final_sub

    // Write Z.
    movq Z0, (r)
    movq Z1, 8(r)
    movq Z2, 16(r)
    movq Z3, 24(r)

    popq %rbx
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    ret


/**
 * Montgomery modular squaring
 *
 * Intermediate products with the same factors are grouped together, and thus
 * the number of multiplications is reduced by almost half.
 */
.align 4
.globl _ccn_sqr_256_montgomery
_ccn_sqr_256_montgomery: /* void ccn_sqr_256_montgomery(cc_unit *r, const cc_unit *a); */
    pushq %rbp
    movq %rsp, %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    pushq %rbx

    // Load A1.
    movq 8(a), %rdx

    // A1 * A1
    mulxq %rdx, Z2, Z3

    // Load A0.
    movq (a), %rdx

    // A0 * A0
    mulxq %rdx, Z0, Z1

    movq $0, Z4
    movq $0, Z5

    // Partial reduction.
    partial_redc

    // A0 * A1
    mulxq 8(a), u, v

    // A0 * A2
    mulxq 16(a), q, s

    addq v, q

    // A0 * A3
    mulxq 24(a), v, t

    adcq s, v
    adcq $0, t

    // Double.
    xorq Z5, Z5

    adox u, Z0
    adcx u, Z0

    adox q, Z1
    adcx q, Z1

    adox v, Z2
    adcx v, Z2

    adox t, Z3
    adcx t, Z3

    adox Z5, Z4
    adcx Z5, Z4

    // Partial reduction.
    partial_redc

    // Load A1.
    movq 8(a), %rdx

    // A2 * A1
    mulxq 16(a), u, v

    // A3 * A1
    mulxq 24(a), q, s

    addq v, q

    // Load A2.
    movq 16(a), %rdx

    // A3 * A2
    mulxq 24(a), v, t

    adcq s, v
    adcq $0, t

    // Double.
    xorq Z5, Z5

    adox u, Z1
    adcx u, Z1

    adox q, Z2
    adcx q, Z2

    adox v, Z3
    adcx v, Z3

    adox t, Z4
    adcx t, Z4

    movq $0, s
    adox s, Z5
    adcx s, Z5

    // Partial reduction.
    partial_redc

    xorq Z5, Z5

    // A2 * A2
    mulxq %rdx, u, v

    addq u, Z1
    adcq v, Z2

    // Load A3.
    movq 24(a), %rdx

    // A3 * A3
    mulxq %rdx, u, v

    adcq u, Z3
    adcq v, Z4
    adcq $0, Z5

    // Partial reduction.
    partial_redc

    // if Z >= M then Z := Z − M
    final_sub

    // Write Z.
    movq Z0, (r)
    movq Z1, 8(r)
    movq Z2, 16(r)
    movq Z3, 24(r)

    popq %rbx
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
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
    pushq %rbp
    movq %rsp, %rbp
    pushq %r12
    pushq %r13
    pushq %rbx

    // Load A.
    movq (a), Z0
    movq 8(a), Z1
    movq 16(a), Z2
    movq 24(a), Z3

    // Initialize Z.
    movq $0, Z4
    movq $0, Z5

    // Reduce once per limb (four times).
    partial_redc
    partial_redc
    partial_redc
    partial_redc

    // if Z >= M then Z := Z − M
    final_sub

    // Write Z.
    movq Z0, (r)
    movq Z1, 8(r)
    movq Z2, 16(r)
    movq Z3, 24(r)

    popq %rbx
    popq %r13
    popq %r12
    popq %rbp
    ret

#endif
