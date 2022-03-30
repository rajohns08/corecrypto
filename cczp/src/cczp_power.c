/* Copyright (c) (2011,2012,2014,2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
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

/* r = s^e (mod zp->prime). Implements Montgomery ladder.
 Caller provides recip of m as recip; s and r can have the same address. */
int cczp_powern_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *s,
                   size_t ebitlen, const cc_unit *e)
{
    cc_size n = cczp_n(zp);

    /* We require s < p. */
    if (ccn_cmp(n, s, cczp_prime(zp)) >= 0) {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);
    cc_unit *r1 = CC_ALLOC_WS(ws, n);
    ccn_set(n, r1, s);

    ccn_seti(n, r, 1);
    cczp_to_ws(ws, zp, r, r);

    cc_unit ebit = 0;
    for (int bit = (int)ebitlen - 1; bit >= 0; --bit) {
        ebit ^= ccn_bit(e, bit);
        ccn_cond_swap(n, ebit, r, r1);
        cczp_mul_ws(ws, zp, r1, r, r1);
        cczp_sqr_ws(ws, zp, r, r);
        ebit = ccn_bit(e, bit);
    }

    // Might have to swap again.
    ccn_cond_swap(n, ebit, r, r1);

    CC_FREE_BP_WS(ws, bp);
    return CCERR_OK;
}

int cczp_powern(cczp_const_t zp, cc_unit *r, const cc_unit *s, size_t ebitlen, const cc_unit *e)
{
    cc_size n = cczp_n(zp);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZP_POWER_WORKSPACE_N(n));
    int rv = cczp_powern_ws(ws, zp, r, s, ebitlen, e);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return rv;
}

int cczp_power_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *s, const cc_unit *e)
{
    cc_size n = cczp_n(zp);
    unsigned long ebitlen = ccn_bitlen(n, e);
    return cczp_powern_ws(ws, zp, r, s, ebitlen, e);
}

int cczp_power(cczp_const_t zp, cc_unit *r, const cc_unit *s, const cc_unit *e)
{
    return cczp_powern(zp, r, s, ccn_bitlen(cczp_n(zp), e), e);
}
