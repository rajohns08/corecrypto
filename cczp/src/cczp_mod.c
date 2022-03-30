/* Copyright (c) (2011,2012,2014,2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
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

/* compute r = s % d, where d=cczp_prime(zp). ns is the length of s.
   cczp_init(zp) must have been called before calling this function, since ccn_div_use_recip()
   uses the reciprocal of d.
 */

int cczp_modn(cczp_const_t zp, cc_unit *r, cc_size ns, const cc_unit *s)
{
    int status;
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCN_DIV_USE_RECIP_WORKSPACE_SIZE(ns, cczp_n(zp)));
    status = cczp_modn_ws(ws, zp, r, ns, s);
    CC_FREE_WORKSPACE(ws);
    return status;
}

int cczp_modn_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, cc_size ns, const cc_unit *s)
{
    return ccn_div_use_recip_ws(
        ws, 0, NULL, cczp_n(zp), r, ns, s, cczp_n(zp), cczp_prime(zp), cczp_recip(zp));
}

/* Do r = s2n % d,  where d=cczp_prime(zp). where
 - The recip is the precalculated steady-state reciprocal of d
 - r is count cc_units in size, s2n is 2 * count units
 - d is count units in size and recip is count + 1 units in size.
 - IMPORTANT: Use only if s2n < 2^2s   (see the math section below)
 */
void cczp_mod_default_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *s2n)
{
    cc_size n = cczp_n(zp);
    size_t s = cczp_bitlen(zp);
    cc_assert(ccn_bitlen(2 * n, s2n) <= 2 * s);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *tmp1, *tmp2;
    cc_unit *tmpd;
    cc_size unitShift_s_minus_1 = (s - 1) / CCN_UNIT_BITS;
    cc_size unitShift_s_plus_1 = (s + 1) / CCN_UNIT_BITS;
    tmp1 = CC_ALLOC_WS(ws, 2 * n + 2 - unitShift_s_plus_1); // tmp1 is 2*n
    tmp2 = CC_ALLOC_WS(ws, 2 * n + 2);                      // tmp2 is 2+2*n
    tmpd = CC_ALLOC_WS(ws, n + 1);                          // tmpd is n+1

    ccn_setn(1 + n, tmpd, n, cczp_prime(zp));
    ccn_shift_right(2 * n - unitShift_s_minus_1,
                    tmp1,
                    &s2n[unitShift_s_minus_1],
                    (s - 1) & (CCN_UNIT_BITS - 1));
    ccn_mul_ws(ws, 1 + n, tmp2, cczp_recip(zp), tmp1);
    ccn_shift_right(2 * n + 2 - unitShift_s_plus_1,
                    tmp1,
                    &tmp2[unitShift_s_plus_1],
                    (s + 1) & (CCN_UNIT_BITS - 1));
    ccn_mul_ws(ws, n, tmp2, tmpd, tmp1);
    ccn_sub(2 * n, tmp2, s2n, tmp2);

    // First conditional subtraction (0 <= r < 3d).
    cc_unit b = ccn_sub(1 + n, tmp1, tmp2, tmpd);
    ccn_mux(1 + n, b, tmp2, tmp2, tmp1);

    // Second conditional subtraction (0 <= r < 2d).
    b = ccn_sub(1 + n, tmp1, tmp2, tmpd);
    ccn_mux(n, b, r, tmp2, tmp1);

    // 0 <= r < d.
    cc_assert(ccn_cmp(n, r, cczp_prime(zp)) < 0);
    CC_FREE_BP_WS(ws, bp);
}

void cczp_mod_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CCZP_FUNC_MOD(zp)(ws, zp, r, x);
}
