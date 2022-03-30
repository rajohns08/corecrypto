/* Copyright (c) (2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
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
#include <corecrypto/cc_macros.h>
#include "cc_debug.h"

// Similar to FIPS generation, except that the generator is an input.
static int
ccec_generate_diversified_key(ccec_const_cp_t cp,  struct ccrng_state *rng, ccec_const_affine_point_t generator, ccec_full_ctx_t key)
{
    int result=CCEC_GENERATE_KEY_DEFAULT_ERR;

    // Not particular verification made on generator since none of the EC groups
    // in corecrypto have small subgroup.

    // Init key structure
    ccec_ctx_init(cp, key);

    // Generate the private scalar
    cc_require((result = ccec_generate_scalar_fips_retry(cp,rng,ccec_ctx_k(key)))==0,errOut);

    // Generate the corresponding public key
    cc_require((result = ccec_make_pub_from_priv(cp, rng, ccec_ctx_k(key), generator,ccec_ctx_pub(key)))==0,errOut);

    // Check consistency
    result = ccecdh_pairwise_consistency_check(key, generator, rng) ? 0 : CCEC_GENERATE_KEY_CONSISTENCY;
errOut:
    return result;
}

int
ccec_rfc6637_wrap_key_diversified(ccec_pub_ctx_t generator,
                                  ccec_pub_ctx_t public_key,
                                  void *wrapped_key,
                                  unsigned long flags,
                                  uint8_t symm_alg_id,
                                  size_t key_len,
                                  const void *key,
                                  const struct ccec_rfc6637_curve *curve,
                                  const struct ccec_rfc6637_wrap *wrap,
                                  const uint8_t *fingerprint, /* 20 bytes */
                                  struct ccrng_state *rng)
{
    int res;

    /*
     * Generate an ephemeral key pair
     * We use the same generation method irrespective
     * of compact format since the sign does not matter in wrapping operations
     */
    ccec_const_cp_t cp = ccec_ctx_cp(public_key);
    ccec_full_ctx_decl_cp(cp, ephemeral_key);
    res = ccec_generate_diversified_key(cp, rng, (ccec_const_affine_point_t)ccec_ctx_point(generator), ephemeral_key);
    if (res) {return res;}

    /*
     *  Perform wrapping
     */

    res = ccec_rfc6637_wrap_core(public_key,
                                 ephemeral_key,
                                 wrapped_key, flags,
                                 symm_alg_id, key_len,
                                 key,
                                 curve, wrap,
                                 fingerprint, rng);
    ccec_full_ctx_clear_cp(cp, ephemeral_key);
    return res;
}
