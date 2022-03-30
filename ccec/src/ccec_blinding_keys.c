/* Copyright (c) (2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccec_internal.h"
#include "cc_macros.h"

int ccec_generate_blinding_keys(ccec_const_cp_t cp,
                                struct ccrng_state *rng,
                                ccec_full_ctx_t blinding_key,
                                ccec_full_ctx_t unblinding_key)
{
    ccec_ctx_init(cp, blinding_key);
    ccec_ctx_init(cp, unblinding_key);

    cc_size n = ccec_cp_n(cp);
    cc_size n_max = CCN521_N;
    ccec_pub_ctx_decl(ccn_sizeof_n(n_max), P);
    ccec_point_decl_n(n_max, base);

    int result = ccec_generate_scalar_fips_retry(cp, rng, ccec_ctx_k(blinding_key));
    cc_require(result == CCERR_OK, err);

    result = cczp_inv(ccec_cp_zq(cp), ccec_ctx_k(unblinding_key), ccec_ctx_k(blinding_key));
    cc_require(result == CCERR_OK, err);

    // Now to perform a consistency check
    // First we'll compute public keys from
    result = ccec_projectify(cp, base, ccec_cp_g(cp), rng);
    cc_require(result == CCERR_OK, err);

    result = ccec_mult(cp, ccec_ctx_point(blinding_key), ccec_ctx_k(blinding_key), base, rng);
    cc_require(result == CCERR_OK, err);
    result = ccec_mult(cp, ccec_ctx_point(unblinding_key), ccec_ctx_k(unblinding_key), base, rng);
    cc_require(result == CCERR_OK, err);
    result = ccec_affinify(cp, (ccec_affine_point_t)ccec_ctx_point(blinding_key), ccec_ctx_point(blinding_key));
    cc_require(result == CCERR_OK, err);
    result = ccec_affinify(cp, (ccec_affine_point_t)ccec_ctx_point(unblinding_key), ccec_ctx_point(unblinding_key));
    cc_require(result == CCERR_OK, err);

    // Blinding the "unblinded" public key will give us G
    result = ccec_blind(rng, blinding_key, ccec_ctx_pub(unblinding_key), P);
    cc_require(result == CCERR_OK, err);
    cc_require(ccn_cmp(n, ccec_ctx_x(P), ccec_point_x(ccec_cp_g(cp), cp)) == 0, err);

    // Unblinding the "blinded" public key will also give us G
    result = ccec_unblind(rng, unblinding_key, ccec_ctx_pub(blinding_key), P);
    cc_require(result == CCERR_OK, err);
    cc_require(ccn_cmp(n, ccec_ctx_x(P), ccec_point_x(ccec_cp_g(cp), cp)) == 0, err);

err:
    ccec_pub_ctx_clear(ccn_sizeof_n(n_max), P);
    ccec_point_clear_n(n_max, base);
    if (result != CCERR_OK) {
        ccec_full_ctx_clear_cp(cp, blinding_key);
        ccec_full_ctx_clear_cp(cp, unblinding_key);
    }
    return result;
}

static int ccec_blinding_op(struct ccrng_state *rng, const cc_unit *scalar, const ccec_pub_ctx_t pub, ccec_pub_ctx_t pub_out)
{
    ccec_const_cp_t cp = ccec_ctx_cp(pub);
    ccec_point_decl_cp(cp, P_p);
    ccec_point_decl_cp(cp, P_b);

    int result = ccec_validate_pub_and_projectify(cp, P_p, (ccec_const_affine_point_t)ccec_ctx_point(pub), rng);
    if (result != CCERR_OK) {
        return result;
    }

    result = ccec_mult(cp, P_b, scalar, P_p, rng);
    if (result != CCERR_OK) {
        return result;
    }

    result = ccec_affinify(cp, (ccec_affine_point_t)ccec_ctx_point(pub_out), P_b);
    ccec_point_clear_cp(cp, P_p);
    ccec_point_clear_cp(cp, P_b);
    return result;
}

int ccec_blind(struct ccrng_state *rng, const ccec_full_ctx_t blinding_key, const ccec_pub_ctx_t pub, ccec_pub_ctx_t blinded_pub)
{
    return ccec_blinding_op(rng, ccec_ctx_k(blinding_key), pub, blinded_pub);
}

int ccec_unblind(struct ccrng_state *rng,
                 const ccec_full_ctx_t unblinding_key,
                 const ccec_pub_ctx_t pub,
                 ccec_pub_ctx_t unblinded_pub)
{
    return ccec_blinding_op(rng, ccec_ctx_k(unblinding_key), pub, unblinded_pub);
}
