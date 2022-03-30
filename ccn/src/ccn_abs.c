/* Copyright (c) (2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc_priv.h>
#include "ccn_internal.h"

// r = |s-t|
// Returns 1 when t>s, or 0 when t<=s
cc_unit ccn_abs_ws(cc_ws_t ws, cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t)
{
    CC_DECL_BP_WS(ws, bp);
    cc_unit *q = CC_ALLOC_WS(ws, n);

    cc_unit c = ccn_sub(n, r, s, t);
    (void)ccn_sub(n, q, t, s);
    ccn_mux(n, c, r, q, r);

    CC_FREE_BP_WS(ws,bp);
    return c;
}
