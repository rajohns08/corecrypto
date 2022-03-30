/* Copyright (c) (2010,2011,2012,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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

void cczp_add_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    CC_DECL_BP_WS(ws, bp);
    cc_unit *t = CC_ALLOC_WS(ws, cczp_n(zp));

    cc_unit carry = ccn_add(cczp_n(zp), r, x, y);
    cc_unit borrow = ccn_sub(cczp_n(zp), t, r, cczp_prime(zp));
    ccn_mux(cczp_n(zp), carry | (borrow ^ 1), r, t, r);

    cc_assert(ccn_cmp(cczp_n(zp), r, cczp_prime(zp)) < 0);
    CC_FREE_BP_WS(ws, bp);
}

void cczp_add(cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    CC_DECL_WORKSPACE_STACK(ws, CCZP_ADD_WORKSPACE_N(cczp_n(zp)));
    cczp_add_ws(ws, zp, r, x, y);
    CC_FREE_WORKSPACE_STACK(ws);
}
