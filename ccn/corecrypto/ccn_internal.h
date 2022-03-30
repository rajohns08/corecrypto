/* Copyright (c) (2017,2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef corecrypto_ccn_internal_h
#define corecrypto_ccn_internal_h

#include <corecrypto/ccn.h>
#include "cc_memory.h"

#if CCN_UNIT_SIZE == 8
#define cc_clz_nonzero cc_clz64
#define cc_ctz_nonzero cc_ctz64
#define CC_STORE_UNIT_BE(x, out) CC_STORE64_BE(x, out)
#define CC_LOAD_UNIT_BE(x, out) CC_LOAD64_BE(x, out)
#elif CCN_UNIT_SIZE == 4
#define cc_clz_nonzero cc_clz32
#define cc_ctz_nonzero cc_ctz32
#define CC_STORE_UNIT_BE(x, out) CC_STORE32_BE(x, out)
#define CC_LOAD_UNIT_BE(x, out) CC_LOAD32_BE(x, out)
#else
#error unsupported CCN_UNIT_SIZE
#endif

#define CCN_DIV_EUCLID_WORKSPACE_SIZE(na, nd) \
    (nd + 1 + 4 + CCN_DIV_USE_RECIP_WORKSPACE_SIZE(na, nd))

// Same as ccn_div_euclid(), takes a ws.
int ccn_div_euclid_ws(cc_ws_t ws, cc_size nq, cc_unit *q, cc_size nr, cc_unit *r,
                      cc_size na, const cc_unit *a, cc_size nd, const cc_unit *d);

// perform division the division a/d, whne size n of a are d are the same. Returns remainder r and
// a cc_unit quotient. To be used only in xgcd. Exported here for test purpose only.
CC_NONNULL((1, 3, 4, 5))
cc_unit ccn_div_equal_size_ws(cc_ws_t ws, cc_size n, cc_unit *r, const cc_unit *a, const cc_unit *d);

/* |s - t| -> r return 1 iff t > s, 0 otherwise */
cc_unit ccn_abs_ws(cc_ws_t ws, cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t);

#define CCN_ABS_WORKSPACE_N(n) (n)

/* Returns the number of bits which are zero before the first one bit
   counting from least to most significant bit. */
CC_NONNULL((2))
size_t ccn_trailing_zeros(cc_size n, const cc_unit *s);

/*! @function ccn_shift_right_multi
 @abstract Constant-time, SPA-safe, right shift.

 @param n Length of r and s as number of cc_units.
 @param r Destination, can overlap with s.
 @param s Input that's shifted by k bits.
 @param k Number of bits by which to shift s to the right.
 */
CC_NONNULL_ALL
void ccn_shift_right_multi(cc_size n, cc_unit *r, const cc_unit *s, size_t k);

/* s << k -> r return bits shifted out of most significant word in bits [0, n>
 { N bit, scalar -> N bit } N = n * sizeof(cc_unit) * 8
 the _multi version doesn't return the shifted bits, but does support multiple
 word shifts */
CC_NONNULL_ALL
void ccn_shift_left(cc_size n, cc_unit *r, const cc_unit *s, size_t k) __asm__("_ccn_shift_left");

CC_NONNULL_ALL
void ccn_shift_left_multi(cc_size n, cc_unit *r, const cc_unit *s, size_t k);

// Conditionally swap the content of r0 and r1 buffers in constant time
// r0:r1 <- r1*k1 + s0*(k1-1)
CC_NONNULL_ALL
void ccn_cond_swap(cc_size n, cc_unit ki, cc_unit *r0, cc_unit *r1);

/*! @function ccn_cond_shift_right
 @abstract Constant-time, SPA-safe, conditional right shift.

 @param n Length of a as number of cc_units.
 @param s Selector bit (0 or 1).
 @param r Destination, can overlap with a.
 @param a Input that's shifted by k bits, if s=1.
 @param k Number of bits by which to shift a to the right, if s=1.
          (k must not be larger than CCN_UNIT_BITS.)
 */
CC_NONNULL_ALL
void ccn_cond_shift_right(cc_size n, cc_unit s, cc_unit *r, const cc_unit *a, size_t k);

/*! @function ccn_cond_neg
 @abstract Constant-time, SPA-safe, conditional negation.

 @param n Length of a as number of cc_units.
 @param s Selector bit (0 or 1).
 @param r Destination, can overlap with x.
 @param x Input that's negated, if s=1.
 */
void ccn_cond_neg(cc_size n, cc_unit s, cc_unit *r, const cc_unit *x);

/*! @function ccn_cond_shift_right_carry
 @abstract Constant-time, SPA-safe, conditional right shift.

 @param n Length of a as number of cc_units.
 @param s Selector bit (0 or 1).
 @param r Destination, can overlap with a.
 @param a Input that's shifted by k bits, if s=1.
 @param k Number of bits by which to shift a to the right, if s=1.
          (k must not be larger than CCN_UNIT_BITS.)
 @param c Carry bit(s), the most significant bit(s) after shifting, if s=1.
 */
CC_NONNULL_ALL
void ccn_cond_shift_right_carry(cc_size n, cc_unit s, cc_unit *r, const cc_unit *a, size_t k, cc_unit c);

/*! @function ccn_cond_add
 @abstract Constant-time, SPA-safe, conditional addition.

 @param n Length of a as number of cc_units.
 @param s Selector bit (0 or 1).
 @param r Destination, can overlap with x or y.
 @param x First addend.
 @param y Second addend.

 @return The carry bit, if s=1. 0 otherwise.
 */
CC_NONNULL_ALL
cc_unit ccn_cond_add(cc_size n, cc_unit s, cc_unit *r, const cc_unit *x, const cc_unit *y);

/*! @function ccn_mux
 @abstract Constant-time, SPA-safe multiplexer. Sets r = (s ? a : b).

 @discussion This works like a normal multiplexer (s & a) | (~s & b) but is
             slightly more complicated and expensive. Out of `s` we build
             half-word masks to hide extreme Hamming weights of operands.

 @param n Length of a and b as number of cc_units.
 @param s Selector bit (0 or 1).
 @param r Destination, can overlap with a or b.
 @param a Input selected when s=1.
 @param b Input selected when s=0.
 */
CC_NONNULL_ALL
void ccn_mux(cc_size n, cc_unit s, cc_unit *r, const cc_unit *a, const cc_unit *b);

/*!
 @brief ccn_div_use_recip(nq, q, nr, r, na, a, nd, d) computes q=a/d and r=a%d
 @discussion q and r can be NULL. Reads na from a and nd from d. Writes nq in q and nr in r. nq and
 nr must be large enough to accomodate results, otherwise error is returned. Execution time depends
 on the size of a. Computation is perfomed on of fixedsize and the leading zeros of a of q are are
 also used in the computation.
 @param nq length of array q that hold the quotients. The maximum length of quotient is the actual
 length of dividend a
 @param q  returned quotient. If nq is larger than needed, it is filled with leading zeros. If it is
 smaller, error is returned. q can be set to NULL, if not needed.
 @param nr length of array r that hold the remainder. The maximum length of remainder is the actual
 length of divisor d
 @param r  returned remainder. If nr is larger than needed, it is filled with leading zeros. If nr is
 smaller, an error is returned. r can be set to NULL if not required.
 @param na length of dividend. Dividend may have leading zeros.
 @param a  input Dividend
 @param nd length of input divisor. Divisor may have leading zeros.
 @param d  input Divisor
 @param recip_d The reciprocal of d, of length nd+1.

 @return  returns 0 if successful, negative of error.
 */
CC_NONNULL((7, 9, 10))
#define CCN_DIV_USE_RECIP_WORKSPACE_SIZE(na, nd) (6 * (CC_MAX(2 * nd, na)) + 4 + na)
int ccn_div_use_recip_ws(cc_ws_t ws,
                         cc_size nq,
                         cc_unit *q,
                         cc_size nr,
                         cc_unit *r,
                         cc_size na,
                         const cc_unit *a,
                         cc_size nd,
                         const cc_unit *d,
                         const cc_unit *recip_d);

/*! @function ccn_gcd_ws
 @abstract Computes the greatest common divisor of s and t,
           r = gcd(s,t) / 2^k, and returns k.

 @param ws Workspace.
 @param rn Length of r as a number of cc_units.
 @param r  Resulting GCD.
 @param sn Length of s as a number of cc_units.
 @param s  First number s.
 @param tn Length of t as a number of cc_units.
 @param t  First number t.

 @return The factor of two to shift r by to compute the actual GCD.
 */
CC_NONNULL_ALL
size_t ccn_gcd_ws(cc_ws_t ws, cc_size rn, cc_unit *r, cc_size sn, const cc_unit *s, cc_size tn, const cc_unit *t);

#define CCN_GCD_WORKSPACE_N(n) (5 * (n) + 2)

/*! @function ccn_lcm_ws
 @abstract Computes lcm(s,t), the least common multiple of s and t.

 @param ws  Workspace.
 @param n   Length of s,t as a number of cc_units.
 @param r2n Resulting LCM of length 2*n.
 @param s   First number s.
 @param t   First number t.
 */
void ccn_lcm_ws(cc_ws_t ws, cc_size n, cc_unit *r2n, const cc_unit *s, const cc_unit *t);

#define CCN_LCM_WORKSPACE_N(n) (                    \
    (n) + CC_MAX_EVAL(CCN_DIV_EXACT_WORKSPACE_N(n), \
                      CCN_GCD_WORKSPACE_N(n))       \
)

/* s * t -> r_2n                   r_2n must not overlap with s nor t
 { n bit, n bit -> 2 * n bit } n = count * sizeof(cc_unit) * 8
 { N bit, N bit -> 2N bit } N = ccn_bitsof(n)
 Provide a workspace for potential speedup */
#define CCN_MUL_WS_WORKSPACE_N(n) (4 * ((n) + 1))
CC_NONNULL((1, 3, 4, 5))
void ccn_mul_ws(cc_ws_t ws, cc_size count, cc_unit *r, const cc_unit *s, const cc_unit *t);

/*!
 @brief ccn_make_recip(cc_size nd, cc_unit *recip, const cc_unit *d)
    computes the reciprocal of d: recip = 2^2b/d where b=bitlen(d)
    if d = 0, recip is set to 0.

 @param nd      length of array d
 @param recip   returned reciprocal of size nd+1
 @param d       input number d
*/
CC_NONNULL((2, 3))
int ccn_make_recip(cc_size nd, cc_unit *recip, const cc_unit *d);

// Same ccn_make_recip, takes a ws
#define CCN_MAKE_RECIP_WORKSPACE_SIZE(n) (6 * (n + 1) + CCN_MUL_WS_WORKSPACE_N(n + 1))
void ccn_make_recip_ws(cc_ws_t ws, cc_size nd, cc_unit *recip, const cc_unit *d);

#if CCN_DEDICATED_SQR

#define CCN_SQR_WS_WORKSPACE_N(n) (2 * (n))

/* s^2 -> r
 { n bit -> 2 * n bit } */
CC_NONNULL((2, 3))
void ccn_sqr(cc_size n, cc_unit *r, const cc_unit *s);

/* s^2 -> r
 { n bit -> 2 * n bit } */
CC_NONNULL((1, 3, 4))
void ccn_sqr_ws(cc_ws_t ws, cc_size n, cc_unit *r, const cc_unit *s);

#else

#define CCN_SQR_WS_WORKSPACE_N(n) CCN_MUL_WS_WORKSPACE_N((n))

/* s^2 -> r
 { n bit -> 2 * n bit } */
CC_INLINE CC_NONNULL((2, 3)) void ccn_sqr(cc_size n, cc_unit *r, const cc_unit *s)
{
    ccn_mul(n, r, s, s);
}

/* s^2 -> r
 { n bit -> 2 * n bit } */
CC_INLINE CC_NONNULL((1, 3, 4)) void ccn_sqr_ws(cc_ws_t ws, cc_size n, cc_unit *r, const cc_unit *s)
{
    ccn_mul_ws(ws, n, r, s, s);
}

#endif

/*! @function ccn_div_ws
 @abstract Computes q = a / d.

 @discussion Use CCN_DIV_EUCLID_WORKSPACE_SIZE(na, nd) for the workspace.

 @param ws  Workspace
 @param nq  Length of q as a number of cc_units.
 @param q   The resulting quotient.
 @param na  Length of a as a number of cc_units.
 @param a   The dividend a.
 @param nd  Length of d as a number of cc_units.
 @param d   The divisor d.

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
#define ccn_div_ws(ws, nq, q, na, a, nd, d) ccn_div_euclid_ws(ws, nq, q, 0, NULL, na, a, nd, d)

/*! @function ccn_mod_ws
 @abstract Computes r = a % d.

 @discussion Use CCN_DIV_EUCLID_WORKSPACE_SIZE(na, nd) for the workspace.

 @param ws  Workspace
 @param nr  Length of r as a number of cc_units.
 @param r   The resulting remainder.
 @param na  Length of a as a number of cc_units.
 @param a   The dividend a.
 @param nd  Length of d as a number of cc_units.
 @param d   The divisor d.

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
#define ccn_mod_ws(ws, nr, r, na, a, nd, d) ccn_div_euclid_ws(ws, 0, NULL, nr, r, na, a, nd, d)

/*! @function ccn_neg
 @abstract Computes the two's complement of x.

 @param n  Length of r and x
 @param r  Result of the negation
 @param x  Number to negate
 */
CC_NONNULL_ALL
void ccn_neg(cc_size n, cc_unit *r, const cc_unit *x);

/*! @function ccn_invert
 @abstract Computes x^-1 (mod 2^w).

 @param x  Number to invert

 @return x^-1 (mod 2^w)
 */
CC_CONST CC_NONNULL_ALL
CC_INLINE cc_unit ccn_invert(cc_unit x)
{
    cc_assert(x & 1);

    // Initial precision is 5 bits.
    cc_unit y = (3 * x) ^ 2;

    // Newton-Raphson iterations.
    // Precision doubles with every step.
    y *= 2 - y * x;
    y *= 2 - y * x;
    y *= 2 - y * x;
#if CCN_UNIT_SIZE > 4
    y *= 2 - y * x;
#endif

    cc_assert(y * x == 1);
    return y;
}

/*! @function ccn_div_exact_ws
 @abstract Computes q = a / d where a = 0 (mod d).

 @param ws  Workspace
 @param n   Length of q,a,d as a number of cc_units.
 @param q   The resulting exact quotient.
 @param a   The dividend a.
 @param d   The divisor d.
 */
CC_NONNULL_ALL
void ccn_div_exact_ws(cc_ws_t ws, cc_size n, cc_unit *q, const cc_unit *a, const cc_unit *d);

#define CCN_DIV_EXACT_WORKSPACE_N(n) (3 * (n))

/*! @function ccn_divides1
 @abstract Returns whether q divides x.

 @param n  Length of x as a number of cc_units.
 @param x  The dividend x.
 @param q  The divisor q.

 @return True if q divides x without remainder, false otherwise.
 */
CC_NONNULL_ALL
bool ccn_divides1(cc_size n, const cc_unit *x, cc_unit q);

/*! @function ccn_select
 @abstract Select r[i] in constant-time, not revealing i via cache-timing.

 @param start Start index.
 @param end   End index (length of r).
 @param r     Big int r.
 @param i     Offset into r.

 @return r[i], or zero if start > i or end < i.
 */
CC_INLINE cc_unit ccn_select(cc_size start, cc_size end, const cc_unit *r, cc_size i)
{
    cc_unit ri = 0;

    for (cc_size j = start; j < end; j++) {
        cc_size i_neq_j; // i≠j?
        CC_HEAVISIDE_STEP(i_neq_j, i ^ j);
        ri |= r[j] & ((cc_unit)i_neq_j - 1);
    }

    return ri;
}

/*! @function ccn_invmod
 @abstract Computes the inverse of x modulo m, r = x^-1 (mod m).
           Returns an error if there's no inverse, i.e. gcd(x,m) ≠ 1.

 @discussion This is a very generic version of the binary XGCD algorithm. You
             don't want to use it when you have an odd modulus.

             This function is meant to be used by RSA key generation, for
             computation of d = e^1 (mod lcm(p-1,q-1)), where m can be even.

             x > m is allowed as long as xn == n, i.e. they occupy the same
             number of cc_units.

 @param n  Length of r and p as a number of cc_units.
 @param r  The resulting inverse r.
 @param xn Length of x as a number of cc_units.
 @param x  The number to invert.
 @param m  The modulus.

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
int ccn_invmod(cc_size n, cc_unit *r, cc_size xn, const cc_unit *x, const cc_unit *m);

int ccn_invmod_ws(cc_ws_t ws, cc_size n, cc_unit *r, cc_size xn, const cc_unit *x, const cc_unit *m);

#define CCN_INVMOD_WORKSPACE_N(n) (8 * (n))

#endif
