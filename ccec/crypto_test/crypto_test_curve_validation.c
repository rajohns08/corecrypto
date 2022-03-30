/* Copyright (c) (2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
//  Created by Apple Inc. on 5/7/19.
//

#include "crypto_test_curve_validation.h"

int cczpModTest (cczp_const_t zp, const char *cname)
{
    cc_unit r[cczp_n(zp)], one[cczp_n(zp)];
    cc_unit s[2 * cczp_n(zp)], t[2 * cczp_n(zp)];
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZP_MOD_WORKSPACE_N(cczp_n(zp)));
    ccn_setn(2 * cczp_n(zp), s, cczp_n(zp), cczp_prime(zp));

    ccn_seti(cczp_n(zp), one, 1);
    cczp_to_ws(ws, zp, one, one);

    cczp_mod_ws(ws, zp, r, s);
    ok(ccn_is_zero(cczp_n(zp), r), "%s cczp_mod(p) == 0", cname);

    ccn_add1(2 * cczp_n(zp), s, s, 1);
    cczp_mod_ws(ws, zp, r, s);
    ok_ccn_cmp(cczp_n(zp), r, one, "%s cczp_mod(p + 1) == 1", cname);

    ccn_sub1(2 * cczp_n(zp), s, s, 2);
    ccn_sub(cczp_n(zp), t, cczp_prime(zp), one); // p - 1
    cczp_mod_ws(ws, zp, r, s);
    ok_ccn_cmp(cczp_n(zp), r, t, "%s cczp_mod(p - 1) == p - 1", cname);

    cczp_mul_ws(ws, zp, r, s, s);
    ok_ccn_cmp(cczp_n(zp), r, one, "%a cczp_mod((p-1)^2) == 1", cname);

    CC_FREE_WORKSPACE(ws);
    return 0;
}

static void ccec_double(ccec_const_cp_t cp,
                        ccec_projective_point_t r,
                        ccec_const_projective_point_t s) {
    CC_DECL_WORKSPACE_STACK(ws, CCEC_DOUBLE_WORKSPACE_SIZE(ccec_cp_n(cp)));
    ccec_double_ws(ws,cp,r,s);
    CC_FREE_WORKSPACE_STACK(ws);
}

void evaluateCurve(ccec_const_cp_t cp, ccec_const_affine_point_t sa, ccec_const_affine_point_t ta, ccec_const_affine_point_t radd, ccec_const_affine_point_t rsub, ccec_const_affine_point_t rdbl, const cc_unit * d, ccec_const_affine_point_t rmul, const cc_unit * e,  ccec_const_affine_point_t rtmul, const char *cname)
{

    /* Validate that cczp_init generates the same reciprocal that we hardcoded in the cp. */
    cczp_decl_n(ccec_cp_n(cp), zq);
    CCZP_N(zq) = ccec_cp_n(cp);
    ccn_set(ccec_cp_n(cp), CCZP_PRIME(zq), cczp_prime(ccec_cp_zq(cp)));
    is(cczp_init(zq), 0, "Failed to init zq in evaluateCurve");
    ok_ccn_cmp(1 + ccec_cp_n(cp), cczp_recip(ccec_cp_zq(cp)), cczp_recip(zq), "%s cczq recip matches computed recip", cname);

    /* Next let's test the mod function for zp and zq. */
    cczpModTest(ccec_cp_zq(cp), cname);

    ccec_point_decl_cp(cp, sp);
    ccec_point_decl_cp(cp, tp);
    ccec_point_decl_cp(cp, rp);
    ccec_point_decl_cp(cp, db1p);
    ccec_point_decl_cp(cp, db2p);
    ccec_point_decl_cp(cp, db3p);
    ccec_affine_decl_cp(cp, ra);
    ccec_affine_decl_cp(cp, rdblla);
    ccec_affine_decl_cp(cp, rdblra);
    struct ccrng_state *rng = global_test_rng;
    
    is(ccec_projectify(cp, sp, sa, NULL), 0, "Failed in call to ccec_projectify(cp, sp, sa, NULL) in evaluateCurve");
    is(ccec_projectify(cp, tp, ta, NULL), 0, "Failed in call to ccec_projectify(cp, tp, ta, NULL) in evaluateCurve");

    /* test ccec_projectify -> ccec_affinify */
    is(ccec_affinify(cp, ra, sp),0, "Call to ccec_affinitfyin evaluateCurve has failed");
    ok_ecp_cmp(cp, ra, sa, "%s ccec_affinify(ccec_projectify(s)) == s", cname);

    /* test ccec_full_add */
    ccec_full_add(cp, rp, sp, tp);
    ccec_affinify(cp, ra, rp);
    ok_ecp_cmp(cp, ra, radd, "%s full_add R = S + T", cname);

    /* add test to ensure that correct value is returned where we're doubling points via addition and destination is in place with the first operand  in memory */
    // Generate two copies of sa with different projective coordinate representations
    is(ccec_projectify(cp, db1p, sa, rng), 0, "Failed in call to ccec_projectify(cp, db1p, sa, rng) in evaluateCurve");
    is(ccec_projectify(cp, db2p, sa, rng), 0, "Failed in call to ccec_projectify(cp, db2p, sa, rng) in evaluateCurve");
  
    // If we doublt the second representation, db2p, we should get the same value as the addition of db1p+db2p once we remove the z coordinate
    ccec_full_add(cp, db1p, db1p, db2p);
    ccec_double(cp, db3p, db2p);
    ccec_affinify(cp, rdblla, db1p);
    ccec_affinify(cp, rdblra, db3p);
    ok_ecp_cmp(cp, rdblla, rdblra, "%s Failed in verifying that doubling via ccec_full_add works when s = r", cname);
   
    /* test ccec_full_sub */
    ccec_full_sub(cp, rp, sp, tp);
    ccec_affinify(cp, ra, rp);
    ok_ecp_cmp(cp, ra, rsub, "%s full_sub R = S - T", cname);

    /* test ccec_double */
    ccec_double(cp, rp, sp);
    ccec_affinify(cp, ra, rp);
    ok_ecp_cmp(cp, ra, rdbl, "%s double R = 2S", cname);

    /* test ccec_mult */
    ccec_mult(cp, rp, d, sp, global_test_rng);
    ccec_affinify(cp, ra, rp);
    ok_ecp_cmp(cp, ra, rmul, "%s mult R = dS", cname);

    /* test ccec_twin_mult */
    ccec_twin_mult(cp, rp, d, sp, e, tp);
    ccec_affinify(cp, ra, rp);
    ok_ecp_cmp(cp, ra, rtmul, "%s twin mult R = dS + eT", cname);

    ccec_point_clear_cp(cp, sp);
    ccec_point_clear_cp(cp, tp);
    ccec_point_clear_cp(cp, rp);
    ccec_affine_clear_cp(cp, ra);
}

#define evaluate_curve_test(size,name) \
    evaluateCurve(ccec_cp_##size(), \
    (const ccec_affine_point *) name.sa, \
    (const ccec_affine_point *) name.ta, \
    (const ccec_affine_point *) name.radd, \
    (const ccec_affine_point *) name.rsub, \
    (const ccec_affine_point *) name.rdbl, \
    name.d, \
    (const ccec_affine_point *) name.rmul, \
    name.e, \
    (const ccec_affine_point *) name.rtmul, \
    #name)

int ccec_curve_validation_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    plan_tests(18*5);
    evaluate_curve_test(192, testP192);
    evaluate_curve_test(224, testP224);
    evaluate_curve_test(256, testP256);
    evaluate_curve_test(384, testP384);
    evaluate_curve_test(521, testP521);
    return 0;
}
