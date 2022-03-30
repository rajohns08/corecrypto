/* Copyright (c) (2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccn_internal.h"
#include "cczp_internal.h"

/*! @function cczp_mm_redc
 @abstract Computes r := x / R (mod p) via Montgomery's REDC algorithm.

 @param zp  Multiplicative group Z/(p)
 @param r   Result of the reduction
 @param t   Number to reduce
 */
static void cczp_mm_redc(cczp_const_t zp, cc_unit *r, cc_unit *t)
{
    cc_size n = cczp_n(zp);
    cc_unit n0 = cczp_mm_p0inv(zp);

    // t += (t * N' (mod R)) * N
    for (cc_size i = 0; i < n; i++) {
        // Write carries to t[i] directly as each iteration of the partial
        // REDC algorithm zeroes the current word t[i]. When finished, the
        // lower half of t contains the carries that are then added to the
        // intermediate result in t's upper half.
        t[i] = ccn_addmul1(n, &t[i], cczp_prime(zp), t[i] * n0);
    }

    // Optional final reduction.
    cc_unit s = ccn_add(n, &t[n], &t[n], t);
    s ^= ccn_sub(n, t, &t[n], cczp_prime(zp));
    ccn_mux(n, s, r, &t[n], t);

    /* Sanity check. */
    cc_assert(ccn_cmp(n, r, cczp_prime(zp)) < 0);
}

/*! @function cczp_mm_mul_ws
 @abstract Multiplies two numbers x and y.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Multiplier
 @param y   Multiplicand
 */
CC_NONNULL_ALL
static void cczp_mm_mul_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    CC_DECL_BP_WS(ws, bp);
    cc_size n = cczp_n(zp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_mul_ws(ws, n, rbig, x, y);
    cczp_mm_redc(zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

/*! @function cczp_mm_sqr_ws
 @abstract Squares a number x.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Number to square
 */
CC_NONNULL_ALL
static void cczp_mm_sqr_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CC_DECL_BP_WS(ws, bp);
    cc_size n = cczp_n(zp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_sqr_ws(ws, n, rbig, x);
    cczp_mm_redc(zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

/*! @function cczp_mm_mod_ws
 @abstract Reduces a number x modulo p.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Number to reduce
 */
CC_NONNULL_ALL
static void cczp_mm_mod_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CC_DECL_BP_WS(ws, bp);

    cc_size n = cczp_n(zp);
    cc_unit *t = CC_ALLOC_WS(ws, 2 * n);
    ccn_set(2 * n, t, x);

    cczp_mm_redc(zp, r, t);

    CC_FREE_BP_WS(ws, bp);
}

/*! @function cczp_mm_inv_ws
 @abstract Computes r := 1 / x (mod p).

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result of the inverstion
 @param x   Number to invert
 */
static int cczp_mm_inv_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, CC_UNUSED cc_unit *r, CC_UNUSED const cc_unit *x)
{
    // cczp_inv() maps to this function, which is used by EC code only.
    cc_try_abort("not implemented");
    return CCERR_INTERNAL;
}

/*! @function cczp_mm_sqrt_ws
 @abstract Computes r := x^(1/2) (mod p).

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Square root of x
 @param x   Quadratic residue
 */
static int cczp_mm_sqrt_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, CC_UNUSED cc_unit *r, CC_UNUSED const cc_unit *x)
{
    // cczp_sqrt() maps to this function, which is used by EC code only.
    cc_try_abort("not implemented");
    return CCERR_INTERNAL;
}

/*! @function cczp_mm_to_ws
 @abstract Computes r := x * R (mod p) to convert x to Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result in Montgomery space
 @param x   Number to convert
 */
static void cczp_mm_to_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_size n = cczp_n(zp);
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_mul_ws(ws, n, rbig, x, cczp_mm_r2(zp));
    cczp_mm_redc(zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

/*! @function cczp_mm_from_ws
 @abstract Computes r := x / R (mod p) to convert x out of Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result not in Montgomery space
 @param x   Number to convert
 */
static void cczp_mm_from_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_size n = cczp_n(zp);
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_setn(2 * n, rbig, n, x);
    cczp_mm_redc(zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

/*! @function cczp_mm_is_one_ws
 @abstract Returns whether x = R (mod p), i.e. whether x = 1 in Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param x   Number

 @return True, if x = R (mod p). False otherwise.
 */
static bool cczp_mm_is_one_ws(CC_UNUSED cc_ws_t ws, cczp_const_t zp, const cc_unit *x)
{
    return ccn_cmp(cczp_n(zp), x, cczp_mm_r1(zp)) == 0;
}

// Montgomery multiplication functions for cczp.
cczp_funcs_decl(cczp_montgomery_funcs,
    cczp_mm_mul_ws,
    cczp_mm_sqr_ws,
    cczp_mm_mod_ws,
    cczp_mm_inv_ws,
    cczp_mm_sqrt_ws,
    cczp_mm_to_ws,
    cczp_mm_from_ws,
    cczp_mm_is_one_ws);

/*! @function cczp_mm_compute_r1r2
 @abstract Computes R (mod p) and R^2 (mod p).

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 */
CC_NONNULL_ALL
static void cczp_mm_compute_r1r2(cc_ws_t ws, cczp_t zp)
{
    CC_DECL_BP_WS(ws, bp);
    cc_unit *c0 = cczp_mm_r1(zp);

    cc_size n = cczp_n(zp);
    cc_size nbits = ccn_bitsof_n(n);
    cc_size np = ccn_nof(cczp_bitlen(zp));

    // Set c0 = 2^((w-1) * n) < N.
    ccn_clear(n, c0);
    ccn_set_bit(c0, ccn_bitsof_n(np - 1), 1);

    // R = 2^(wn).
    for (unsigned i = 0; i < ccn_bitsof_n(n - np + 1); i++) {
        cczp_add_ws(ws, zp, c0, c0, c0);
    }

    // Set t = 2 * R.
    cc_unit *t = CC_ALLOC_WS(ws, n);
    cczp_add_ws(ws, zp, t, c0, c0);

    // Set c0 = 2^(wn) = R.
    c0 = cczp_mm_r2(zp);
    ccn_set(n, c0, cczp_mm_r1(zp));

    // Compute final R^2 (mod p).
    while (nbits > 0) {
        if (nbits & 1) {
            cczp_mm_mul_ws(ws, zp, c0, c0, t);
        }

        nbits >>= 1;
        cczp_mm_sqr_ws(ws, zp, t, t);
    }

    CC_FREE_BP_WS(ws, bp);
}

void cczp_mm_init_ws(cc_ws_t ws, cczp_t zp, cc_size n, const cc_unit *p)
{
    // Odd moduli >= 3 supported only.
    cc_assert((p[0] & 1) && (ccn_n(n, p) > 1 || p[0] >= 3));

    CCZP_N(zp) = n;
    CCZP_BITLEN(zp) = ccn_bitlen(n, p);
    ccn_set(n, CCZP_PRIME(zp), p);
    CCZP_FUNCS(zp) = &cczp_montgomery_funcs;

    // -m[0]^(-1) (mod 2^w)
    cczp_mm_p0inv(zp) = -ccn_invert(p[0]);

    // R (mod p) and R^2 (mod p)
    cczp_mm_compute_r1r2(ws, zp);
}

void cczp_mm_init_precomp(cczp_t zp, cc_size n, const cc_unit *p, cc_unit p0inv, const cc_unit *r1, const cc_unit *r2)
{
    // Odd moduli >= 3 supported only.
    cc_assert((p[0] & 1) && (ccn_n(n, p) > 1 || p[0] >= 3));

    CCZP_N(zp) = n;
    CCZP_BITLEN(zp) = ccn_bitlen(n, p);
    ccn_set(n, CCZP_PRIME(zp), p);
    CCZP_FUNCS(zp) = &cczp_montgomery_funcs;

    // -m[0]^(-1) (mod 2^w)
    cczp_mm_p0inv(zp) = p0inv;

    // R (mod p) and R^2 (mod p)
    ccn_set(n, cczp_mm_r1(zp), r1);
    ccn_set(n, cczp_mm_r2(zp), r2);
}

// Function pointer for one of the cczp_power* functions (with workspace).
typedef int (*cczp_power_ws_func)(cc_ws_t, cczp_const_t, cc_unit*, const cc_unit*, const cc_unit*);

/*! @function cczp_mm_power_func_ws
 @abstract Run a given cczp_power*() function with Montgomery multiplication.
           Computes r := x^e, where x < p is required.

 @discussion Use CCZP_MM_POWER_WORKSPACE_N() when allocating a workspace.

 @param f   cczp_power* function pointer
 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result of the exponentiation
 @param x   Base
 @param e   Exponent

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL
static int cczp_mm_power_func_ws(cczp_power_ws_func f, cc_ws_t ws, cczp_const_t zp,
                                 cc_unit *r, const cc_unit *x, const cc_unit *e)
{
    cc_assert(r != e);

    cc_size n = cczp_n(zp);

    // cczp_power* functions require x < p.
    if (ccn_cmp(n, x, cczp_prime(zp)) >= 0) {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);
    cczp_t zpmm = (cczp_t)CC_ALLOC_WS(ws, cczp_mm_nof_n(n));
    cczp_mm_init_ws(ws, zpmm, n, cczp_prime(zp));
    cczp_mm_to_ws(ws, zpmm, r, x);

    int rv = f(ws, zpmm, r, r, e);
    if (rv == CCERR_OK) {
        cczp_mm_from_ws(ws, zpmm, r, r);
    }

    cczp_mm_clear_n(n, zpmm);
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int cczp_mm_power_fast(cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *e)
{
    cc_size n = cczp_n(zp);
    cc_size pn = CCZP_POWER_FAST_WORKSPACE_N(n);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZP_MM_POWER_WORKSPACE_N(n, pn));
    int rv = cczp_mm_power_func_ws(cczp_power_fast_ws, ws, zp, r, x, e);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int cczp_mm_power_ssma_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *e)
{
    return cczp_mm_power_func_ws(cczp_power_ssma_ws, ws, zp, r, x, e);
}

int cczp_mm_power_ssma(cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *e)
{
    cc_size n = cczp_n(zp);
    cc_size pn = CCZP_POWER_SSMA_WORKSPACE_N(n);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZP_MM_POWER_WORKSPACE_N(n, pn));
    int rv = cczp_mm_power_ssma_ws(ws, zp, r, x, e);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int cczp_mm_power(cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *e)
{
    cc_size n = cczp_n(zp);
    cc_size pn = CCZP_POWER_WORKSPACE_N(n);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZP_MM_POWER_WORKSPACE_N(n, pn));
    int rv = cczp_mm_power_func_ws(cczp_power_ws, ws, zp, r, x, e);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
