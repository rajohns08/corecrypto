/* Copyright (c) (2012,2015,2020) Apple Inc. All rights reserved.
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

int cczp_inv_default_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_size n = cczp_n(zp);
    cczp_from_ws(ws, zp, r, x);
    int rv = ccn_invmod_ws(ws, n, r, n, r, cczp_prime(zp));
    cczp_to_ws(ws, zp, r, r);
    return rv;
}

int cczp_inv_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    return CCZP_FUNC_INV(zp)(ws, zp, r, x);
}

int cczp_inv(cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZP_INV_WORKSPACE_N(cczp_n(zp)));
    int rv = cczp_inv_ws(ws, zp, r, x);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
