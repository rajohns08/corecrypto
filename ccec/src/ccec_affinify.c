/* Copyright (c) (2010,2011,2012,2013,2014,2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccec_priv.h>
#include "cczp_internal.h"
#include "ccn_internal.h"
#include "ccec_internal.h"

int ccec_affinify(ccec_const_cp_t cp, ccec_affine_point_t r, ccec_const_projective_point_t s)
{
    int status=-1;
    if (ccn_is_zero(ccec_cp_n(cp), ccec_const_point_z(s, cp))) {
        return -1; // Point at infinity
    }

#if CCEC_DEBUG
    ccec_plprint(cp, "ccec_affinify input", s);
#endif

    cc_size n = ccec_cp_n(cp);
    CC_DECL_WORKSPACE_OR_FAIL(ws,2*n+CCZP_INV_WORKSPACE_N(n));
    CC_DECL_BP_WS(ws,bp);
    // Allows "in place" operation => the result can be set in any of the point coordinate.
    cc_unit *lambda=CC_ALLOC_WS(ws,n);
    cc_unit *t=CC_ALLOC_WS(ws,n);

    status=cczp_inv_ws(ws,ccec_cp_zp(cp), lambda, ccec_const_point_z(s, cp));    // lambda = sz^-1
    cczp_sqr_ws(ws,ccec_cp_zp(cp), t, lambda);                                   // t = lambda^2
    cczp_mul_ws(ws,ccec_cp_zp(cp), ccec_point_x(r, cp), t, ccec_const_point_x(s, cp)); // rx = t * sx
    cczp_mul_ws(ws,ccec_cp_zp(cp), t, t, lambda);                                // t = lambda^3
    cczp_mul_ws(ws,ccec_cp_zp(cp), ccec_point_y(r, cp), t, ccec_const_point_y(s, cp)); // ry = t * sy

    // Back from Montgomery
    cczp_from_ws(ws, ccec_cp_zp(cp), ccec_point_x(r, cp), ccec_point_x(r, cp));
    cczp_from_ws(ws, ccec_cp_zp(cp), ccec_point_y(r, cp), ccec_point_y(r, cp));

#if CCEC_DEBUG
    ccec_alprint(cp, "ccec_affinify output", r);
#endif
    CC_FREE_BP_WS(ws,bp);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return status;
}

int ccec_affinify_x_only(ccec_const_cp_t cp, cc_unit *sx, ccec_const_projective_point_t s)
{
    if (ccn_is_zero(ccec_cp_n(cp), ccec_const_point_z(s, cp))) {
        return CCERR_PARAMETER;
    }

    cc_size n = ccec_cp_n(cp);
    CC_DECL_WORKSPACE_OR_FAIL(ws, n + CCZP_INV_WORKSPACE_N(n));
    CC_DECL_BP_WS(ws, bp);

    // Allows "in place" operation.
    cc_unit *lambda = CC_ALLOC_WS(ws, n);
    cczp_sqr_ws(ws, ccec_cp_zp(cp), lambda, ccec_const_point_z(s, cp)); // sz^2

    // lambda = sz^-2
    int status = cczp_inv_ws(ws, ccec_cp_zp(cp), lambda, lambda);
    cczp_mul_ws(ws, ccec_cp_zp(cp), sx, ccec_const_point_x(s, cp), lambda); // rx = sx * lambda^2
    cczp_from_ws(ws, ccec_cp_zp(cp), sx, sx);

    CC_FREE_BP_WS(ws, bp);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return status;
}
