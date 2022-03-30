/* Copyright (c) (2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cczp_internal.h"

/*! @function cczp_div2_fast
 @abstract Computes r = x / 2 (mod p).

 @discussion Fast, non-constant-time version of cczp_div2().

 @param zp Multiplicative group Z/(p).
 @param r  Result.
 @param x  Element to divide.
 */
CC_NONNULL_ALL
static void cczp_div2_fast(cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    const cc_size n = cczp_n(zp);

    cc_unit carry = 0;
    bool x_odd = x[0] & 1;

    // if x is odd, r := (x + p) >> 1
    if (x_odd) {
        carry = ccn_add(n, r, x, cczp_prime(zp));
    }

    ccn_shift_right(n, r, r, 1);

    // if x is odd, set carry, if any
    if (x_odd) {
        r[n - 1] |= carry << (CCN_UNIT_BITS - 1);
    }

    cc_assert(ccn_cmp(n, r, cczp_prime(zp)) < 0);
}

/*! @function cczp_sub_fast
 @abstract Computes r = x - y (mod p).

 @discussion Fast, non-constant-time version of cczp_sub().

 @param zp Multiplicative group Z/(p).
 @param r  Result.
 @param x  Dividend.
 @param y  Divisor.
 */
CC_NONNULL_ALL
static void cczp_sub_fast(cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    const cc_size n = cczp_n(zp);
    cc_unit borrow = ccn_sub(n, r, x, y);

    if (borrow) {
        ccn_add(n, r, cczp_prime(zp), r);
    }

    cc_assert(ccn_cmp(n, r, cczp_prime(zp)) < 0);
}

int cczp_inv_fast_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    int rv = CCZP_INV_NO_INVERSE;
    const cc_size n = cczp_n(zp);

    // Odd moduli only.
    if ((cczp_prime(zp)[0] & 1) == 0) {
        return CCERR_PARAMETER;
    }

    // Ensure 0 < x < p.
    if (ccn_is_zero(n, x) || ccn_is_zero(n, cczp_prime(zp))) {
        return CCERR_PARAMETER;
    }

    if (ccn_cmp(n, x, cczp_prime(zp)) >= 0) {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);

    if (cczp_is_one_ws(ws, zp, x)) {
        ccn_set(n, r, x);
        rv = CCERR_OK;
        goto cleanup;
    }

    cc_unit *a = CC_ALLOC_WS(ws, n);
    cc_unit *b = CC_ALLOC_WS(ws, n);

    cc_unit *u = CC_ALLOC_WS(ws, n);
    cc_unit *v = CC_ALLOC_WS(ws, n);

    cczp_from_ws(ws, zp, a, x);
    ccn_set(n, b, cczp_prime(zp));
    ccn_seti(n, u, 1);
    ccn_zero(n, v);

    while (!ccn_is_zero(n, a)) {
        if (a[0] & 1) {
            if (ccn_cmp(n, a, b) < 0) {
                CC_SWAP(a, b);
                CC_SWAP(u, v);
            }

            ccn_sub(n, a, a, b);
            cczp_sub_fast(zp, u, u, v);
        }

        ccn_shift_right(n, a, a, 1);
        cczp_div2_fast(zp, u, u);
    }

    if (ccn_is_one(n, b)) {
        rv = CCERR_OK;
    }

    cczp_to_ws(ws, zp, r, v);
    cc_assert(ccn_cmp(n, r, cczp_prime(zp)) < 0);

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int cczp_inv_fast(cczp_const_t zp, cc_unit *r, const cc_unit *a)
{
    cc_size n = cczp_n(zp);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZP_INV_FAST_WORKSPACE_N(n));
    int rv = cczp_inv_fast_ws(ws, zp, r, a);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
