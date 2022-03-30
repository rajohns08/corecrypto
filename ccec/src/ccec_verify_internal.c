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

#include <stdint.h>

#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include "ccn_internal.h"
#include "cc_debug.h"
#include <corecrypto/cc_macros.h>
#include "cc_fault_canary_internal.h"

// The below helpers encode the scalar multiplications and combination
// in ECDSA.
//
// In the common configuration, we prefer to use ccec_twin_mult. Since
// this function does not support the edge case where the public point
// is the base point, we fall back to the naive implementation,
// i.e. separate multiplications followed by a single addition.
//
// If we are optimizing for small code (i.e. CC_SMALL_CODE is set), we
// typically will not use ccec_twin_mult. In this case, we resort
// directly to the naive implementation.
//
// The least-common configuration comes when CC_SMALL_CODE and
// CCEC_USE_TWIN_MULT are both set. This may happen if corecrypto is
// configured for verification only, i.e. CCEC_VERIFY_ONLY is
// set. (See the definition of CCEC_USE_TWIN_MULT in ccec_internal.h.)
// In this case, we try to use ccec_twin_mult. Since we have no
// fallback, we fail in the edge case noted above.

CC_UNUSED
static int singlemults(ccec_const_cp_t cp,
                       ccec_projective_point_t r,
                       const cc_unit *d0,
                       ccec_const_projective_point_t s,
                       const cc_unit *d1,
                       ccec_const_projective_point_t t,
                       CC_UNUSED const cc_unit *xaffine)
{
    int result = CCERR_INTERNAL;

    ccec_point_decl_cp(cp, tp);
    cc_require(ccec_mult(cp, tp, d0, s, NULL) == CCERR_OK, errOut);
    cc_require(ccec_mult(cp, r, d1, t, NULL) == CCERR_OK, errOut);
    ccec_full_add(cp, r, r, tp);

    result = CCERR_OK;

errOut:
    return result;
}

CC_UNUSED
static int fail(CC_UNUSED ccec_const_cp_t cp,
                CC_UNUSED ccec_projective_point_t r,
                CC_UNUSED const cc_unit *d0,
                CC_UNUSED ccec_const_projective_point_t s,
                CC_UNUSED const cc_unit *d1,
                CC_UNUSED ccec_const_projective_point_t t,
                CC_UNUSED const cc_unit *xaffine)
{
    return CCERR_PARAMETER;
}

#if !CC_SMALL_CODE
#define fallback singlemults
#else
#define fallback fail
#endif

CC_UNUSED
static int twinmult(ccec_const_cp_t cp,
                    ccec_projective_point_t r,
                    const cc_unit *d0,
                    ccec_const_projective_point_t s,
                    const cc_unit *d1,
                    ccec_const_projective_point_t t,
                    const cc_unit *xaffine)
{
    cc_size n = ccec_cp_n(cp);

    if (ccn_cmp(n, ccec_const_point_x(ccec_cp_g(cp), cp), xaffine) == 0) {
        return fallback(cp, r, d0, s, d1, t, xaffine);
    }

    return ccec_twin_mult(cp, r, d0, s, d1, t);
}

#if CCEC_USE_TWIN_MULT
#define computemults twinmult
#else
#define computemults singlemults
#endif

int ccec_verify_internal(ccec_pub_ctx_t key,
                         size_t digest_len,
                         const uint8_t *digest,
                         const cc_unit *r,
                         const cc_unit *s,
                         cc_fault_canary_t fault_canary_out)
{
    ccec_const_cp_t cp = ccec_ctx_cp(key);
    cczp_const_t zq = ccec_cp_zq(cp);
    cc_size n = ccec_cp_n(cp);
    int result = CCERR_INTERNAL;
    cc_unit w[n], d0[n], d1[n];
    cc_size en = CC_MAX(n, ccn_nof_size(digest_len));
    cc_unit e[en];
    size_t qbitlen = ccec_cp_order_bitlen(cp);
    ccec_point_decl_cp(cp, mg);
    ccec_point_decl_cp(cp, mk);

    // For fault canary
    size_t rsize = ccec_signature_r_s_size(key);
    uint8_t r_input[rsize];
    memset(r_input, 0xaa, rsize);
    uint8_t r_computed[rsize];
    memset(r_computed, 0xff, rsize);

    // Validate 0 < r < q
    // Validate 0 < s < q
    if (ccec_validate_scalar(cp, r) != CCERR_OK || ccec_validate_scalar(cp, s) != CCERR_OK) {
        result = CCERR_PARAMETER;
        goto errOut;
    }

    // Convert digest to a field element
    cc_require(((result = ccn_read_uint(en, e, digest_len, digest)) >= 0), errOut);
    if (digest_len * 8 > qbitlen) {
        // If the digest size is larger than q, shift away the low-order bits
        ccn_shift_right_multi(en, e, e, digest_len * 8 - qbitlen);
    }
    cczp_modn(zq, e, n, e);

    // Recover scalars d0 and d1 with:
    //    w  = s^-1 mod q
    //    d0 = e.w  mod q
    //    d1 = r.w  mod q
    // Use a fast, variable-time inversion algorithm. q and s are public.
    cc_require_action(cczp_inv_fast(zq, w, s) == CCERR_OK, errOut, result = CCERR_PARAMETER);
    cczp_mul(zq, d0, e, w);
    cczp_mul(zq, d1, r, w);

    // We require the public key to be in affine representation
    ccec_projective_point_t pub_key_point = ccec_ctx_point(key);
    cc_require_action(ccn_is_one(n, ccec_const_point_z(pub_key_point, cp)), errOut, result = CCERR_PARAMETER);

    // Projectify both points and verify the public point is on the curve
    result = ccec_projectify(cp, mg, ccec_cp_g(cp), NULL);
    cc_require(result == CCERR_OK, errOut);
    result = ccec_projectify(cp, mk, (ccec_const_affine_point_t)pub_key_point, NULL);
    cc_require(result == CCERR_OK, errOut);
    cc_require_action(ccec_is_point(cp, mk), errOut, result = CCERR_PARAMETER);

    // Multiply the points by the scalars and combine; see the above helpers
    result = computemults(cp, mg, d0, mg, d1, mk, ccec_const_point_x(pub_key_point, cp));
    cc_require(result == CCERR_OK, errOut);

    // Affinify and reduce x
    cc_require_action(ccec_affinify_x_only(cp, ccec_point_x(mg, cp), mg) == CCERR_OK, errOut, result = CCERR_PARAMETER);
    if (ccn_cmp(n, ccec_point_x(mg, cp), cczp_prime(zq)) >= 0) {
        ccn_sub(n, ccec_point_x(mg, cp), ccec_point_x(mg, cp), cczp_prime(zq));
    }

    // Verify x = r
    if (ccn_cmp(n, ccec_point_x(mg, cp), r) == 0) {
        result = CCERR_VALID_SIGNATURE;
    } else {
        result = CCERR_INVALID_SIGNATURE;
    }

    ccn_write_uint_padded_ct(n, r, rsize, r_input);
    ccn_write_uint_padded_ct(n, ccec_point_x(mg, cp), rsize, r_computed);

    cc_fault_canary_set(fault_canary_out, CCEC_FAULT_CANARY, rsize, r_input, r_computed);

errOut:
    return result;
}
