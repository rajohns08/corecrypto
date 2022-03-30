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

#include "cczp_internal.h"

bool cczp_is_one_default_ws(cc_ws_t ws, cczp_const_t zp, const cc_unit *x)
{
    CC_DECL_BP_WS(ws, bp);

    cc_size n = cczp_n(zp);
    cc_unit *y = CC_ALLOC_WS(ws, n);
    cczp_from_ws(ws, zp, y, x);

    bool rv = ccn_is_one(n, y);
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

bool cczp_is_one_ws(cc_ws_t ws, cczp_const_t zp, const cc_unit *x)
{
    return CCZP_FUNC_IS_ONE(zp)(ws, zp, x);
}
