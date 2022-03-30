/* Copyright (c) (2010,2011,2012,2013,2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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
#include <corecrypto/cczp.h>
#include <corecrypto/cc_macros.h>
#include "cc_debug.h"

// Use ccn_sizeof(ccec_cp_order_bitlen(cp))) bytes for the key generation
int
ccec_generate_key_internal_legacy(ccec_const_cp_t cp,  struct ccrng_state *rng, ccec_full_ctx_t key)
{
    int result;

    // Init key structure
    ccec_ctx_init(cp, key);

    // Generate entropy for the priave scalar
    size_t random_byte_size=ccn_sizeof_n(ccec_cp_n(cp));
    uint8_t *entropy_buffer=(uint8_t *)ccec_ctx_k(key);
    cc_require((result = ccrng_generate(rng,random_byte_size,entropy_buffer))==0,errOut);

    // Generate the scalar
    cc_require((result = ccec_generate_scalar_legacy(cp,
                                                     random_byte_size,entropy_buffer,
                                                     ccec_ctx_k(key)))==0,errOut);

    /* Calculate the public key for k. */
    result=ccec_make_pub_from_priv(cp, NULL, ccec_ctx_k(key), NULL, ccec_ctx_pub(key));
errOut:
    return result;
}
