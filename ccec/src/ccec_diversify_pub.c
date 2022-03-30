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
#include <corecrypto/cc_macros.h>
#include "cc_debug.h"
#include "ccec_internal.h"

size_t ccec_diversify_min_entropy_len(ccec_const_cp_t cp) {
    return ccec_scalar_fips_extrabits_min_entropy_len(cp);
}

int ccec_diversify_pub(ccec_const_cp_t cp,
                       ccec_pub_ctx_t pub_key,
                       size_t entropy_len, const uint8_t *entropy,
                       struct ccrng_state *masking_rng,
                       ccec_pub_ctx_t  diversified_generator,
                       ccec_pub_ctx_t  diversified_pub_key)
{
    int retval=-1;

    // Generate a private scalar
    cc_size n=ccn_nof_size(entropy_len);
    cc_unit r[n];
    //==========================================================================
    // Generate adequate random for private key
    // This does not preserve properties of the key so that output so that
    // care must be taken when using compact formating.
    // Valid with compact points when using ECDH and only X coordinate is used
    //==========================================================================

    // Method is from FIPS 186-4 Extra Bits method.
    //  r = entropy mod (q-1)) + 1, where entropy is interpreted as big endian.
    cc_require((retval=ccec_generate_scalar_fips_extrabits(cp,entropy_len,entropy,
                                                           r))==0,errOut);

    //==========================================================================
    // Scalar multiplication generator and public point
    //==========================================================================

    // s * generator
    cc_require((retval=ccec_make_pub_from_priv(cp, masking_rng, r, NULL, diversified_generator)==0),errOut);

    // s * pub
    cc_require((retval=ccec_make_pub_from_priv(cp, masking_rng, r, (ccec_const_affine_point_t)ccec_ctx_point(pub_key), diversified_pub_key)==0),errOut);

    // Clear temporary variables
    retval=0;

errOut:
    ccn_clear(n,r);
    return retval;
}
