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
#include "ccec_internal.h"
#include <corecrypto/ccrng.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cczp.h>
#include <corecrypto/cc_macros.h>
#include "cc_debug.h"

/* Compute the public point from k.
 k must be in the correct range and without bias */

int
ccec_make_pub_from_priv(ccec_const_cp_t cp,
                        struct ccrng_state *masking_rng,
                        const cc_unit *k,
                        ccec_const_affine_point_t generator,
                        ccec_pub_ctx_t key)
{
    int result=CCEC_GENERATE_KEY_DEFAULT_ERR;
    ccec_ctx_init(cp,key);
    cc_size n=ccec_ctx_n(key);
    ccec_point_decl_cp(cp, base);  /* Get base point G in projected form. */

    cc_require_action(ccn_cmp(n,k,cczp_prime(ccec_cp_zq(cp)))<0,errOut,
        result=CCEC_GENERATE_INVALID_INPUT);
    cc_require_action(!ccn_is_zero(n,k),errOut,
        result=CCEC_GENERATE_INVALID_INPUT);

    //==========================================================================
    // Calculate the public key for k
    //==========================================================================
    if (generator==NULL) {
        cc_require((result=ccec_projectify(cp, base, ccec_cp_g(cp), masking_rng))==0,errOut);
    } else {
        cc_require((result=ccec_validate_pub_and_projectify(cp,base, generator, masking_rng))==0,errOut);
    }
    cc_require_action(ccec_mult(cp, ccec_ctx_point(key), k, base,masking_rng) == 0  ,errOut,
                      result=CCEC_GENERATE_KEY_MULT_FAIL);
    cc_require_action(ccec_is_point_projective(cp, ccec_ctx_point(key)),errOut,
                      result=CCEC_GENERATE_NOT_ON_CURVE);
    cc_require_action(ccec_affinify(cp, (ccec_affine_point_t)ccec_ctx_point(key), ccec_ctx_point(key)) == 0,errOut,
                      result=CCEC_GENERATE_KEY_AFF_FAIL);
    ccn_seti(ccec_cp_n(cp), ccec_ctx_z(key), 1);
    ccec_point_clear_cp(cp, base);
    result=0;

errOut:
    return result;
}
