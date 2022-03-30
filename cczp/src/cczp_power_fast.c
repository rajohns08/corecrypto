/* Copyright (c) (2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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
#include "cc_macros.h"

int cczp_power_fast(cczp_const_t zp, cc_unit *r, const cc_unit *s, const cc_unit *e)
{
    int status;
    cc_size n = cczp_n(zp);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZP_POWER_FAST_WORKSPACE_N(n));
    status = cczp_power_fast_ws(ws, zp, r, s, e);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return status;
}

/* r = s^e (mod zp->prime). Implements 2bit window method
 Leaks the exponent, to be used with public values only.
 Caller provides recip of m as recip; s and r can have the same address. */
int cczp_power_fast_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *s, const cc_unit *e)
{
    cc_size n = cczp_n(zp);

    /* We require s < p. */
    if (ccn_cmp(cczp_n(zp), s, cczp_prime(zp)) >= 0) {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);

    cc_unit *s1 = CC_ALLOC_WS(ws, n);
    ccn_set(n, s1, s);

    ccn_seti(n, r, 1);
    cczp_to_ws(ws, zp, r, r);

    size_t ebitlen = ccn_bitlen(n, e);

    // 1-bit window for small exponents.
    if (ebitlen <= 32) {
        for (size_t bit = ebitlen - 1; bit < ebitlen; --bit) {
            cczp_sqr_ws(ws, zp, r, r);
            if (ccn_bit(e, bit)) {
                cczp_mul_ws(ws, zp, r, r, s1);
            }
        }

        CC_FREE_BP_WS(ws, bp);
        return CCERR_OK;
    }

    cc_unit *s2 = CC_ALLOC_WS(ws, n);
    cc_unit *s3 = CC_ALLOC_WS(ws, n);

    // 2bit window for the exponentiation

    // Precomputation
    size_t bit = ((ebitlen + 1) & ~(size_t)1) - 1; // First bit to process
    cczp_sqr_ws(ws, zp, s2, s1);     // s^2
    cczp_mul_ws(ws, zp, s3, s2, s1); // s^3

    // First iteration is different
    switch ((ccn_bit(e, bit) << 1) | ccn_bit(e, bit - 1)) {
    case 1:
        ccn_set(n, r, s1); // set r to s
        break;
    case 2:
        ccn_set(n, r, s2); // set r to s^2
        break;
    case 3:
        ccn_set(n, r, s3); // set r to s^3
        break;
    default:
        // Can't happen:
        // Most significant bit can't be zero if bitlen > 32.
        cc_assert(ccn_bit(e, ebitlen - 1) == 1);
        break;
    }

    // Loop
    for (bit -= 2; bit < ebitlen; bit -= 2) {
        cczp_sqr_ws(ws, zp, r, r);
        cczp_sqr_ws(ws, zp, r, r);

        switch ((ccn_bit(e, bit) << 1) | ccn_bit(e, bit - 1)) {
        case 1:
            cczp_mul_ws(ws, zp, r, r, s1);
            break;
        case 2:
            cczp_mul_ws(ws, zp, r, r, s2);
            break;
        case 3:
            cczp_mul_ws(ws, zp, r, r, s3);
            break;
        }
    }

    CC_FREE_BP_WS(ws, bp);
    return CCERR_OK;
}
