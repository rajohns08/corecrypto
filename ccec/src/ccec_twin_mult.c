/* Copyright (c) (2010,2011,2014-2020) Apple Inc. All rights reserved.
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
#include "cc_debug.h"
#include "ccec_internal.h"

/* Define to 1 to use a table for f_2_2_11 instead of a function.  Saves
   16 bytes on arm (saves 48 bytes code, then adds 32 bytes const data for
   the table). */
#define USE_F_TABLE    1

#if USE_F_TABLE
static const uint8_t f_2_2_11_t[32] = {
    12, 12, 12, 12,                  // [0, 4>
    14, 14, 14, 14, 14, 14, 14, 14,  // [4, 12>
    12, 12,                          // [12, 14>
    10, 10, 10, 10,                  // [14, 18>
    9, 9, 9, 9,                      // [18, 22>
    11, 11,                          // [22, 24>
    12, 12, 12, 12, 12, 12, 12, 12   // [24, 32>
};
#define f_2_2_11(T) ((__typeof__ (T))f_2_2_11_t[(T)])
#else
/* Routine 2.2.11 F (t): an auxilliary function for ccec_twin_mult */
static cc_unit f_2_2_11(cc_unit t) {
    if (18 <= t && t < 22) {
        return 9;
    } else if (14 <= t && t < 18) {
        return 10;
    } else if (22 <= t && t < 24) {
        return 11;
    } else if (4 <= t && t < 12) {
        return 14;
    } else {
        return 12;
    }
}
#endif

static void twin_mult_normalize(ccec_const_cp_t cp, ccec_projective_point_t r, ccec_const_projective_point_t s, const cc_unit *e, const cc_unit *b, const cc_unit *cd)
{
    cczp_const_decl(zp, ccec_cp_zp(cp));
    cc_size n = ccec_cp_n(cp);

    cc_unit lambda[n], t[n];
    cczp_mul(zp, t, b, cd);                                  // bcd = b * cd
    cczp_mul(zp, lambda, e, t);                              // lambda = a^-1 = (abcd)^-1 * bcd
    cczp_sqr(zp, t, lambda);                                 // t = lambda^2
    cczp_mul(zp, ccec_point_x(r, cp), t, ccec_const_point_x(s, cp));   // rx = t * sx
    cczp_mul(zp, t, t, lambda);                              // t = lambda^3
    cczp_mul(zp, ccec_point_y(r, cp), t, ccec_const_point_y(s, cp));   // ry = t * sy
    // Don't touch z here since it's still used by our caller.
}

// s and t must be different
int ccec_twin_mult(ccec_const_cp_t cp, ccec_projective_point_t r, const cc_unit *d0, ccec_const_projective_point_t s, const cc_unit *d1, ccec_const_projective_point_t t)
{
    cczp_const_decl(zp, ccec_cp_zp(cp));
    cc_size n = ccec_cp_n(cp);

    ccec_point_decl_cp(cp, spt);
    ccec_point_decl_cp(cp, smt);
    cc_unit st[ccec_cp_n(cp)], sptsmt[ccec_cp_n(cp)], stsptsmt_1[ccec_cp_n(cp)];
    {   // In a block for workspace
        CC_DECL_WORKSPACE_OR_FAIL(ws,CCEC_ADD_SUB_WORKSPACE_SIZE(n));
        ccec_full_add_ws(ws,cp, spt, s, t); // spt = S + T
        ccec_full_sub_ws(ws,cp, smt, s, t); // smt = S - T
        cczp_mul_ws(ws, zp, st, ccec_const_point_z(s, cp), ccec_const_point_z(t, cp));
        cczp_mul_ws(ws, zp, sptsmt, ccec_const_point_z(spt, cp), ccec_const_point_z(smt, cp));
        cczp_mul_ws(ws, zp, stsptsmt_1, st, sptsmt);
        CC_CLEAR_AND_FREE_WORKSPACE(ws);
    }

    int rv = cczp_inv(zp, stsptsmt_1, stsptsmt_1); // Inverse: (z(s)*z(t)*z(spt)*z(smt))^-1 mod p
    if (rv) {
        return rv;
    }

    /* Normalize s, t, spt and smt (have them all in affine format) */
    ccec_point_decl_cp(cp, ns);
    ccec_point_decl_cp(cp, nt);

    twin_mult_normalize(cp, ns,  s,   stsptsmt_1, ccec_const_point_z(t, cp), sptsmt);
    twin_mult_normalize(cp, nt,  t,   stsptsmt_1, ccec_const_point_z(s, cp), sptsmt);
    twin_mult_normalize(cp, spt, spt, stsptsmt_1, st,   ccec_const_point_z(smt, cp));
    twin_mult_normalize(cp, smt, smt, stsptsmt_1, st,   ccec_const_point_z(spt, cp));

    ccn_seti(n, stsptsmt_1, 1);
    cczp_to(zp, ccec_point_z(ns, cp), stsptsmt_1);
    ccn_set(n, ccec_point_z(nt, cp),  ccec_point_z(ns, cp));
    ccn_set(n, ccec_point_z(spt, cp), ccec_point_z(ns, cp));
    ccn_set(n, ccec_point_z(smt, cp), ccec_point_z(ns, cp));

    const cc_unit *e[2] = { d0, d1 };
    size_t m0 = ccn_bitlen(n, d0);
    size_t m1 = ccn_bitlen(n, d1);
    size_t m = CC_MAX(m0,m1);

    cc_unit c[2];
    for (size_t i = 0; i < 2 ; ++i) {
        c[i] = ((ccn_bit(e[i], m - 1) << 3) +
                (ccn_bit(e[i], m - 2) << 2) +
                (ccn_bit(e[i], m - 3) << 1) +
                (ccn_bit(e[i], m - 4) << 0));
    }

    ccn_seti(n, ccec_point_x(r, cp), 1);
    ccn_seti(n, ccec_point_y(r, cp), 1);
    ccn_seti(n, ccec_point_z(r, cp), 0);

    CC_DECL_WORKSPACE_OR_FAIL(ws,CCEC_ADD_SUB_WORKSPACE_SIZE(n));
    for (size_t k = m + 1; k--;) {
        cc_unit h[2];
        for (int i = 0; i < 2 ; ++i) {
            h[i] = c[i] & 0x1f;
            if (c[i] & 0x20) {
                h[i] = 31 - h[i];
            }
        }
        int u[2];
        for (int i = 0; i < 2 ; ++i) {
            cc_unit cmask = (k >= 5) ? ccn_bit(e[i], k - 5) : 0;
            if (h[i] < f_2_2_11(h[1-i])) {
                u[i] = 0;
            } else {
                cmask += 0x20;
                u[i] = c[i] & 0x20 ? -1 : 1;
            }
            c[i] = (c[i] << 1) ^ cmask;
        }
        ccec_double_ws(ws, cp, r, r);
        if (u[0] == 0 && u[1] == 0)   {continue;} // probability ~1/2
        if (u[0] == -1 && u[1] == -1) {ccec_full_sub_normalized_ws(ws,cp, r, r, spt);}
        if (u[0] == -1 && u[1] ==  0) {ccec_full_sub_normalized_ws(ws,cp, r, r, ns);}
        if (u[0] == -1 && u[1] ==  1) {ccec_full_sub_normalized_ws(ws,cp, r, r, smt);}
        if (u[0] ==  0 && u[1] == -1) {ccec_full_sub_normalized_ws(ws,cp, r, r, nt);}
        if (u[0] ==  0 && u[1] ==  1) {ccec_full_add_normalized_ws(ws,cp, r, r, nt);}
        if (u[0] ==  1 && u[1] == -1) {ccec_full_add_normalized_ws(ws,cp, r, r, smt);}
        if (u[0] ==  1 && u[1] ==  0) {ccec_full_add_normalized_ws(ws,cp, r, r, ns);}
        if (u[0] ==  1 && u[1] ==  1) {ccec_full_add_normalized_ws(ws,cp, r, r, spt);}

    }
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    cc_assert(ccec_is_point_projective(cp, r));
    return 0;
}
