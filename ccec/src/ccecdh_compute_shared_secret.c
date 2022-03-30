/* Copyright (c) (2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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
#include <corecrypto/cc_macros.h>
#include "cc_debug.h"
#include "ccec_internal.h"

/*
 Compute an ECC shared secret between private_key and public_key. Return
 the result in computed_shared_secret.
 It conforms to EC-DH from ANSI X9.63 and NIST SP800-56A, section 5.7.1.2)
 and the length of the result in bytes in computed_key_len. Return 0 iff
 successful.
 Note: The shared secret MUST be transformed with a KDF function or at
 least Hash (SHA-256) before being used.
 It shall not be used directly as a key.

 RNG may be used internally to randomize computation and prevent attacks such as timing and
 cache attacks */
int ccecdh_compute_shared_secret(ccec_full_ctx_t private_key,
                                 ccec_pub_ctx_t public_key,
                                 size_t *computed_shared_secret_len, uint8_t *computed_shared_secret,
                                 struct ccrng_state *masking_rng) {
    ccec_const_cp_t cp = ccec_ctx_cp(private_key);
    ccec_point_decl_cp(cp, r);
    ccec_point_decl_cp(cp, Q);
    int result = CCERR_INTERNAL;

    size_t max_out_len = *computed_shared_secret_len;
    /* Zero the out length in case of failure. */
    *computed_shared_secret_len = 0;

    /* Ensure the caller reserved enough space. */
    size_t p_len = ccn_write_uint_size(ccec_cp_n(cp), ccec_cp_p(cp));
    cc_require((max_out_len >= p_len), errOut);

    /* Sanity check the prime */
    cc_require(ccec_ctx_cp(private_key) == ccec_ctx_cp(public_key),errOut);

    /* Sanity check the input key */
    cc_require((ccec_validate_pub_and_projectify(cp,Q, (ccec_const_affine_point_t)ccec_ctx_point(public_key),masking_rng)==0),errOut);

    /* Sanity check for private key */
    cc_require((ccec_validate_scalar(cp,ccec_ctx_k(private_key))==0),errOut);

    /* Actual computation. Assume curve has cofactor = 1 */
    cc_require((ccec_mult(cp, r, ccec_ctx_k(private_key), Q,masking_rng) == 0),errOut);

    /* Check that result point is on the curve */
    cc_require(ccec_is_point_projective(cp,r),errOut);
    cc_require((ccec_affinify_x_only(cp, ccec_point_x(r, cp), r) == 0),errOut);

    /* Good so far: finalize output of result */
    ccn_write_uint_padded_ct(ccec_cp_n(cp), ccec_point_x(r, cp), p_len, computed_shared_secret);
    *computed_shared_secret_len = p_len;

    result = 0;

errOut:
    ccec_point_clear_cp(cp, r);
    ccec_point_clear_cp(cp, Q);
    return result;
}
