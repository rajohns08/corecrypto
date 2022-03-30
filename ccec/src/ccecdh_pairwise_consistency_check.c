/* Copyright (c) (2015-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccec.h>
#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include <corecrypto/ccrng.h>
#include <corecrypto/cc_macros.h>
#include "cc_debug.h"

static uint8_t is_non_zero(size_t l,uint8_t *s) {
    uint8_t t=0;
    for(size_t i=0;i<l;i++) {t|=s[i];}
    return t;
}

/*!
 @function   ccecdh_fast_scalar_mult
 @abstract   Perform fast scalar multiplication.

 @discussion This function uses plain dbl-and-add scalar multiplication and
             must not be used with secret scalars. It's meant to be fast
             and doesn't aim to offer any SCA resistance.

 @param      cp             EC parameters.
 @param      R              Projective output point.
 @param      d              Non-secret scalar.
 @param      base           Base point on the chosen curve.
 @param      rng            Masking RNG.

 @returns    true for success, false for failure.
 */
#define CCECDH_FAST_SCALAR_MULT_WORKSPACE_N(n) \
    (CC_MAX(CCEC_ADD_SUB_WORKSPACE_SIZE(n), CCEC_DOUBLE_WORKSPACE_SIZE(n)))
CC_NONNULL((1, 2, 3, 4, 5))
static int ccecdh_fast_scalar_mult(ccec_const_cp_t cp,
                                   ccec_projective_point_t R,
                                   const cc_unit *d,
                                   ccec_const_affine_point_t base,
                                   struct ccrng_state *rng)
{
    cc_size n = ccec_cp_n(cp);
    ccec_point_decl_cp(cp, B);

    int rv = ccec_projectify(cp, B, base, rng);
    if (rv) {
        return rv;
    }

    // Set R := B.
    ccn_set(3 * n, ccec_point_x(R, cp), ccec_point_x(B, cp));

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCECDH_FAST_SCALAR_MULT_WORKSPACE_N(n));

    for (int i = (int)ccn_bitlen(n, d) - 2; i >= 0; i--) {
        ccec_double_ws(ws, cp, R, R);

        if (ccn_bit(d, i)) {
            ccec_full_add_ws(ws, cp, R, R, B);
        }
    }

    CC_FREE_WORKSPACE(ws);

    return CCERR_OK;
}

/*!
 @function   ccecdh_fast_compute_pub_from_priv
 @abstract   Compute a public point from a given scalar.

 @discussion This function uses plain dbl-and-add scalar multiplication and
             must not be used with secret scalars. It's meant to be fast
             and doesn't aim to offer any SCA resistance.

 @param      cp             EC parameters.
 @param      full_key       Full output key containing the scalar.
 @param      base           Base point on the chosen curve.
 @param      rng            Masking RNG.

 @returns    true for success, false for failure.
 */
CC_NONNULL((1, 2, 3, 4))
static bool ccecdh_fast_compute_pub_from_priv(ccec_const_cp_t cp,
                                              ccec_full_ctx_t full_key,
                                              ccec_const_affine_point_t base,
                                              struct ccrng_state *rng)
{
    ccec_point_decl_cp(cp, R);

    if (ccecdh_fast_scalar_mult(cp, R, ccec_ctx_k(full_key), base, rng)) {
        return false;
    }

    if (ccec_affinify(cp, (ccec_affine_point_t)ccec_ctx_point(full_key), R)) {
        return false;
    }

    return true;
}

/*!
 @function   ccecdh_fast_compute_shared_secret
 @abstract   Compute a shared secret given a scalar and a public point.

 @discussion This function uses plain dbl-and-add scalar multiplication and
             must not be used with secret scalars. It's meant to be fast
             and doesn't aim to offer any SCA resistance.

 @param      cp             EC parameters.
 @param      d              Non-secret scalar.
 @param      base           Base point on the chosen curve.
 @param      sk             Shared key output.
 @param      rng            Masking RNG.

 @returns    true for success, false for failure.
 */
CC_NONNULL((1, 2, 3, 4, 5))
static bool ccecdh_fast_compute_shared_secret(ccec_const_cp_t cp,
                                              const cc_unit *d,
                                              ccec_const_affine_point_t base,
                                              uint8_t *sk,
                                              struct ccrng_state *rng)
{
    ccec_point_decl_cp(cp, R);

    if (ccecdh_fast_scalar_mult(cp, R, d, base, rng)) {
        return false;
    }

    cc_unit x[ccec_cp_n(cp)];
    if (ccec_affinify_x_only(cp, x, R)) {
        return false;
    }

    ccn_write_uint_padded(ccec_cp_n(cp), x, ccec_cp_prime_size(cp), sk);
    return true;
}

#define CCN32_N ccn_nof(32)
static const cc_unit REF_K[CCN32_N] = { CCN32_C(60,0d,de,ed) };

bool ccecdh_pairwise_consistency_check(ccec_full_ctx_t full_key,
                                       ccec_const_affine_point_t base,
                                       struct ccrng_state *rng)
{
    ccec_const_cp_t cp = ccec_ctx_cp(full_key);

    // Use a dummy key for reference
    ccec_full_ctx_decl_cp(cp, reference_key);
    ccec_ctx_init(cp, reference_key);
    ccn_setn(ccec_cp_n(cp), ccec_ctx_k(reference_key), CCN32_N, REF_K);

    // Default to the generator as the base point.
    if (base == NULL) {
        base = ccec_cp_g(cp);
    }

    // Compute the public from the private reference key.
    if (!ccecdh_fast_compute_pub_from_priv(cp, reference_key, base, rng)) {
        return false;
    }

    // Do a ECDH with newly generate key and  received key
    {
        size_t  shared_key_size=ccec_cp_prime_size(cp);
        uint8_t shared_key1[shared_key_size];
        uint8_t shared_key2[shared_key_size];
        size_t  shared_key1_size=sizeof(shared_key1);
        size_t  shared_key2_size=sizeof(shared_key2);

        cc_clear(sizeof(shared_key1),shared_key1);
        cc_clear(sizeof(shared_key2),shared_key2);

        cc_require(0==ccecdh_compute_shared_secret(full_key, ccec_ctx_pub(reference_key),
                                     &shared_key1_size, shared_key1, rng),errOut);
        cc_require(is_non_zero(sizeof(shared_key1),shared_key1),errOut);

        // Compute the shared secret using the private reference key.
        ccec_projective_point_t pub_pt = ccec_ctx_point(ccec_ctx_pub(full_key));
        if (!ccecdh_fast_compute_shared_secret(cp, ccec_ctx_k(reference_key), (ccec_const_affine_point_t)pub_pt, shared_key2, rng)) {
            return false;
        }

        cc_require(shared_key1_size==shared_key2_size,errOut);
        cc_require(shared_key_size==shared_key1_size,errOut);
        cc_require(0==cc_cmp_safe(shared_key_size,shared_key1,shared_key2),errOut);
    }
    return true;
errOut:
    return false;
}
