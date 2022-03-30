/* Copyright (c) (2010,2011,2014,2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
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

/* accept two distinct, non–infinite, projective points S, T and set R equal to the projective point S + T . Routine 2.2.7 performs no checks on its inputs.

   /                         / SyTz^3 - TySz^3 == 0 => ccec_double
  / SxTz^2 - TxSz^2 == 0 => {
 /                           \ SyTz^3 - TySz^3 != 0 => Point at Infinity
{
 \                           / (SyTz^3 - TySz^3)^2
  \ SxTz^2 - TxSz^2 != 0 => {  (SyTz^3 - TySz^3(3(SxTz^2 + TxSz^2)(SxTz^2 - TxSz^2)^2 - 2(SyTz^3 - TySz^3)^2) - (SyTz^3 + TySz^3)(SxTz^2 - TxSz^2)^3) / 2
   \                         \ SxSzTz^3 - TxTzSz^3
 */

void ccec_add_ws(cc_ws_t ws,
              ccec_const_cp_t cp,
              ccec_projective_point_t r,
              ccec_const_projective_point_t s,
              ccec_const_projective_point_t t,
              uint32_t t_flags) {
    cczp_const_decl(zp, ccec_cp_zp(cp));
    cc_unit
        *t1=ccec_point_x(r, cp),
        *t2=ccec_point_y(r, cp),
        *t3=ccec_point_z(r, cp);
    CC_DECL_BP_WS(ws, bp);
    cc_size n=ccec_cp_n(cp);
    cc_unit *t4=CC_ALLOC_WS(ws, n);
    cc_unit *t5=CC_ALLOC_WS(ws, n);
    cc_unit *t6=CC_ALLOC_WS(ws, n);

    cc_assert(r!=t); // the points r and t must not overlap.

    // Cost:
    // Normalized:     3S +  8M + 10add/sub + 1div2
    // Not normalized: 4S + 12M + 10add/sub + 1div2

    if (t_flags&T_NORMALIZED) {
        ccn_set(ccec_cp_n(cp), t1, ccec_const_point_x(s, cp));  // t1 = Sx
        ccn_set(ccec_cp_n(cp), t2, ccec_const_point_y(s, cp));  // t2 = Sy
    }
    else {
        // if Tz != 1
        cczp_sqr_ws(ws, zp, t6, ccec_const_point_z(t, cp));                              // t6 = Tz^2
        cczp_mul_ws(ws, zp, t1, ccec_const_point_x(s, cp), t6);                          // t1 = SxTz^2
        cczp_mul_ws(ws, zp, t6, ccec_const_point_z(t, cp), t6);                          // t6 = Tz^3
        cczp_mul_ws(ws, zp, t2, ccec_const_point_y(s, cp), t6);                          // t2 = SyTz^3
    }

    cczp_sqr_ws(ws, zp, t6, ccec_const_point_z(s, cp));                                  // t6 = Sz^2
    cczp_mul_ws(ws, zp, t4, ccec_const_point_x(t, cp), t6);                              // t4 = TxSz^2
    cczp_mul_ws(ws, zp, t6, ccec_const_point_z(s, cp), t6);                              // t6 = Sz^3
    cczp_mul_ws(ws, zp, t5, ccec_const_point_y(t, cp), t6);                              // t5 = TySz^3
    if (t_flags&T_NEGATIVE) {
        cczp_sub_ws(ws, ccec_cp_zp(cp), t5, ccec_cp_p(cp), t5);
    }
    cczp_sub_ws(ws, zp, t4, t1, t4);                              // t4 = SxTz^2 - TxSz^2
    cczp_sub_ws(ws, zp, t5, t2, t5);                              // t5 = SyTz^3 - TySz^3

    // If t4 ==0 => x_s == x_t, s = +/- t, not supported or result is point at infinity.
    if (ccn_is_zero(n,t4) && ccn_is_zero(n,t5)) {
        CC_FREE_BP_WS(ws, bp);
        ccec_double_ws(ws,cp,r,t);
        return;
    }
    // This will naturally propagate to Z, no need for early abort.

    cczp_add_ws(ws, zp, t1, t1, t1);                              // Or cczp__shift_left(t1, t1, 1, cp)
    cczp_sub_ws(ws, zp, t1, t1, t4);                              // t1 = SxTz^2 + TxSz^2

    cczp_add_ws(ws, zp, t2, t2, t2);// Or cczp__shift_left(t2, t2, 1, cp)
    cczp_sub_ws(ws, zp, t2, t2, t5);                              // t2 = SyTz^3 + TySz^3
    if (t_flags&T_NORMALIZED) {                                       // if Tz != 1
        cczp_mul_ws(ws, zp, t3, ccec_const_point_z(s, cp), t4);       // t3 = SxSzTz^3 - TxTzSz^3
    } else {
        cczp_mul_ws(ws, zp, t3, ccec_const_point_z(s, cp), ccec_const_point_z(t, cp));                          // t3 = SzTz
        cczp_mul_ws(ws, zp, t3, t3, t4);                              // t3 = SxSzTz^3 - TxTzSz^3
    }
    cczp_sqr_ws(ws, zp, t6, t4);                                  // t6 = (SxTz^2 - TxSz^2)^2
    cczp_mul_ws(ws, zp, t4, t4, t6);                              // t4 = (SxTz^2 - TxSz^2)^3
    cczp_mul_ws(ws, zp, t6, t1, t6);                              // t6 = (SxTz^2 + TxSz^2)(SxTz^2 - TxSz^2)^2
    cczp_sqr_ws(ws, zp, t1, t5);                                  // t1 = (SyTz^3 - TySz^3)^2
    cczp_sub_ws(ws, zp, t1, t1, t6);                              // t1 = (SyTz^3 - TySz^3)^2 - (SxTz^2 + TxSz^2)(SxTz^2 - TxSz^2)^2
    cczp_sub_ws(ws, zp, t6, t6, t1);
    cczp_sub_ws(ws, zp, t6, t6, t1);                              // t6 = 3(SxTz^2 + TxSz^2)(SxTz^2 - TxSz^2)^2 - 2(SyTz^3 - TySz^3)^2
    cczp_mul_ws(ws, zp, t5, t5, t6);                              // t5 = SyTz^3 - TySz^3(3(SxTz^2 + TxSz^2)(SxTz^2 - TxSz^2)^2 - 2(SyTz^3 - TySz^3)^2)
    cczp_mul_ws(ws, zp, t4, t2, t4);                              // t4 = (SyTz^3 + TySz^3)(SxTz^2 - TxSz^2)^3
    cczp_sub_ws(ws, zp, t2, t5, t4);                              // t2 = SyTz^3 - TySz^3(3(SxTz^2 + TxSz^2)(SxTz^2 - TxSz^2)^2 - 2(SyTz^3 - TySz^3)^2) - (SyTz^3 + TySz^3)(SxTz^2 - TxSz^2)^3
    // Rx = (SyTz^3 - TySz^3)^2
    cczp_div2_ws(ws, zp, t2, t2);            // Ry = (SyTz^3 - TySz^3(3(SxTz^2 + TxSz^2)(SxTz^2 - TxSz^2)^2 - 2(SyTz^3 - TySz^3)^2) - (SyTz^3 + TySz^3)(SxTz^2 - TxSz^2)^3) / 2
    // Rz = SxSzTz^3 - TxTzSz^3

    // Result point is {t1,t2,t3}
    CC_FREE_BP_WS(ws, bp);
}

void ccec_full_add_normalized_ws(cc_ws_t ws,ccec_const_cp_t cp,
                              ccec_projective_point_t r,
                              ccec_const_projective_point_t s,
                              ccec_const_projective_point_t t) {
    // The point T is expected to have Z set to the neutral element
    // 1 or the montgomery constant R if using Montgomery form
    cc_size n = ccec_cp_n(cp);
    if (ccn_is_zero(n, ccec_const_point_z(s, cp))) {
        ccn_set(n, ccec_point_x(r, cp), ccec_const_point_x(t, cp));
        ccn_set(n, ccec_point_y(r, cp), ccec_const_point_y(t, cp));
        ccn_set(n, ccec_point_z(r, cp), ccec_const_point_z(t, cp));
        return;
    }
    ccec_add_ws(ws, cp, r, s, t,T_NORMALIZED);
}

void ccec_full_add_ws(cc_ws_t ws,ccec_const_cp_t cp,
                   ccec_projective_point_t r,
                   ccec_const_projective_point_t s,
                   ccec_const_projective_point_t t) {
    cc_size n = ccec_cp_n(cp);
    if (ccn_is_zero(n, ccec_const_point_z(s, cp))) {
        ccn_set(n, ccec_point_x(r, cp), ccec_const_point_x(t, cp));
        ccn_set(n, ccec_point_y(r, cp), ccec_const_point_y(t, cp));
        ccn_set(n, ccec_point_z(r, cp), ccec_const_point_z(t, cp));
        return;
    }
    if (ccn_is_zero(n, ccec_const_point_z(t, cp))) {
        ccn_set(n, ccec_point_x(r, cp), ccec_const_point_x(s, cp));
        ccn_set(n, ccec_point_y(r, cp), ccec_const_point_y(s, cp));
        ccn_set(n, ccec_point_z(r, cp), ccec_const_point_z(s, cp));
        return;
    }
    ccec_add_ws(ws,cp, r, s, t,0);
}

void ccec_full_add(ccec_const_cp_t cp,
                   ccec_projective_point_t r,
                   ccec_const_projective_point_t s,
                   ccec_const_projective_point_t t)
{
    CC_DECL_WORKSPACE_STACK(ws, CCEC_ADD_SUB_WORKSPACE_SIZE(ccec_cp_n(cp)));
    ccec_full_add_ws(ws, cp, r, s, t);
    CC_FREE_WORKSPACE_STACK(ws);
}
