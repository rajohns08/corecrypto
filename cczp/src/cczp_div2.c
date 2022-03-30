/* Copyright (c) (2010,2011,2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
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
#include "ccn_internal.h"

void cczp_div2_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_size n = cczp_n(zp);
    CC_DECL_BP_WS(ws, bp);
    cc_unit *t = CC_ALLOC_WS(ws, n);
    cc_unit odd = x[0] & 1;

    // if x is odd, r := (x + p) >> 1
    cc_unit carry = ccn_add(n, t, x, cczp_prime(zp));
    ccn_mux(n, odd, r, t, x);

    ccn_shift_right(n, r, r, 1);

    // if x is odd, set carry, if any
    r[cczp_n(zp) - 1] |= (carry & odd) << (CCN_UNIT_BITS - 1);

    cc_assert(ccn_cmp(n, r, cczp_prime(zp)) < 0);
    CC_FREE_BP_WS(ws, bp);
}
