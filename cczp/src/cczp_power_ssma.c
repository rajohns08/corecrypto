/* Copyright (c) (2011,2012,2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cczp.h>
#include "cczp_internal.h"
#include "ccn_internal.h"
#include "cc_debug.h"
#include "cc_macros.h"

/* Copy the correct operand into buffer r:
 r <- *(s+kii*n) */
static void copy_mux4(int kii, cc_unit *r, cc_size n, const cc_unit *s)
{
    cc_unit mask0, mask1, mask2, mask3;
    int ki = kii & 1;
    int kj = (kii >> 1) & 1;
    mask0 = ((cc_unit)(ki | kj) - (cc_unit)1);
    mask1 = ((cc_unit)((1 ^ ki) | kj) - (cc_unit)1);
    mask2 = ((cc_unit)(ki | (kj ^ 1)) - (cc_unit)1);
    mask3 = ~((cc_unit)(ki & kj) - (cc_unit)1);

    // Copy involving all 4 possible operands
    for (cc_size i = 0; i < n; i++) {
        /* clang-format off */
        r[i] = ((mask0 & s[i])
              | (mask1 & s[i+n])
              | (mask2 & s[i+2*n])
              | (mask3 & s[i+3*n]));
        /* clang-format on */
    }
}

/* r = s^e (mod zp->prime).
 Implements square square multiply always: 2bit fix windows
 running in constant time. A dummy multiplication is performed when both bit
 are zeros so that the execution has a regular flow
 This approach is sensitive to cache attacks and therefore this implementation
 should be used with randomized (blinded) operands only.

 Caller provides recip of m as recip; s and r can have the same address. */
int cczp_power_ssma_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *s, const cc_unit *e)
{
    cc_size n = cczp_n(zp);

    /* We require s < p. */
    if (ccn_cmp(cczp_n(zp), s, cczp_prime(zp)) >= 0) {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);

    cc_unit *minusone = CC_ALLOC_WS(ws, n);
    cc_unit *m1 = CC_ALLOC_WS(ws, n);
    cc_unit *m2 = CC_ALLOC_WS(ws, n);
    cc_unit *m3 = CC_ALLOC_WS(ws, n);
    cc_unit *t = CC_ALLOC_WS(ws, n);

    /* Precomputations */

    // Use -1 since 1 has very low hamming weight. Minus one is much less leakage prone.
    ccn_sub1(n, minusone, cczp_prime(zp), 1);
    cczp_to_ws(ws, zp, minusone, minusone);
    ccn_set(n, m1, s);
    cczp_sqr_ws(ws, zp, m2, s);
    cczp_mul_ws(ws, zp, m3, s, m2);
    ccn_set(n, r, minusone);

    size_t exp_bitlen = ccn_bitlen(n, e);
    exp_bitlen = (exp_bitlen + 1) & ~(size_t)1; // round up to even number

    // For each cc_unit
    int i = (exp_bitlen - 2) & (CCN_UNIT_BITS - 1); // First loop is shorter, start at the MSbits.
    cc_unit msword = 0;
    for (size_t k = ccn_nof(exp_bitlen); k > 0; --k) {
        msword = e[k - 1];

        /* 2bit fixed window */
        for (; i >= 0; i -= 2) {
            cczp_sqr_ws(ws, zp, r, r);
            cczp_sqr_ws(ws, zp, r, r);
            copy_mux4((int)(msword >> i), t, n, minusone);
            cczp_mul_ws(ws, zp, r, r, t);
        }
        i = CCN_UNIT_BITS - 2;
    }

    /* compensate for extra -1 operation */
    ccn_sub(n, t, cczp_prime(zp), r);
    ccn_mux(n, ((msword >> 1) | msword) & 1, r, r, t);

    CC_FREE_BP_WS(ws, bp);
    return CCERR_OK;
}

int cczp_power_ssma(cczp_const_t zp, cc_unit *r, const cc_unit *s, const cc_unit *e)
{
    int rc;
    cc_size n = cczp_n(zp);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZP_POWER_SSMA_WORKSPACE_N(n));
    rc = cczp_power_ssma_ws(ws, zp, r, s, e);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return rc;
}
