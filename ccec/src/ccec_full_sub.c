/* Copyright (c) (2010,2011,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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
#include "ccec_internal.h"
#include "cczp_internal.h"

void ccec_full_sub_normalized_ws(cc_ws_t ws,ccec_const_cp_t cp,
                              ccec_projective_point_t r,
                              ccec_const_projective_point_t s,
                              ccec_const_projective_point_t t) {

    // The point T is expected to have Z set to the neutral element
    // 1 or the montgomery constant R if using Montgomery form
    if (ccn_is_zero(ccec_cp_n(cp), ccec_const_point_z(s, cp))) {
        ccn_set(ccec_cp_n(cp), ccec_point_x(r, cp), ccec_const_point_x(t, cp));
        cczp_sub_ws(ws,ccec_cp_zp(cp), ccec_point_y(r, cp), ccec_cp_p(cp), ccec_const_point_y(t, cp));
        ccn_set(ccec_cp_n(cp), ccec_point_z(r, cp), ccec_const_point_z(t, cp));
        return;
    }
    ccec_add_ws(ws,cp, r, s, t, T_NEGATIVE | T_NORMALIZED);
}

void ccec_full_sub_ws(cc_ws_t ws,ccec_const_cp_t cp,
                   ccec_projective_point_t r,
                   ccec_const_projective_point_t s,
                   ccec_const_projective_point_t t) {

    if (ccn_is_zero(ccec_cp_n(cp), ccec_const_point_z(s, cp))) {
        ccn_set(ccec_cp_n(cp), ccec_point_x(r, cp), ccec_const_point_x(t, cp));
        cczp_sub_ws(ws,ccec_cp_zp(cp), ccec_point_y(r, cp), ccec_cp_p(cp), ccec_const_point_y(t, cp));
        ccn_set(ccec_cp_n(cp), ccec_point_z(r, cp), ccec_const_point_z(t, cp));
        return;
    }
    if (ccn_is_zero(ccec_cp_n(cp), ccec_const_point_z(t, cp))) {
        ccn_set(ccec_cp_n(cp), ccec_point_x(r, cp), ccec_const_point_x(s, cp));
        ccn_set(ccec_cp_n(cp), ccec_point_y(r, cp), ccec_const_point_y(s, cp));
        ccn_set(ccec_cp_n(cp), ccec_point_z(r, cp), ccec_const_point_z(s, cp));
        return;
    }
    ccec_add_ws(ws,cp, r, s, t, T_NEGATIVE);
}

void ccec_full_sub(ccec_const_cp_t cp,
                   ccec_projective_point_t r,
                   ccec_const_projective_point_t s,
                   ccec_const_projective_point_t t)
{
    CC_DECL_WORKSPACE_STACK(ws, CCEC_ADD_SUB_WORKSPACE_SIZE(ccec_cp_n(cp)));
    ccec_full_sub_ws(ws, cp, r, s, t);
    CC_FREE_WORKSPACE_STACK(ws);
}
