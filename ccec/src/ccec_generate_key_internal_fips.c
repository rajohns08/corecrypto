/* Copyright (c) (2014,2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
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

/* Implementation per FIPS186-4 */
int
ccec_generate_key_internal_fips(ccec_const_cp_t cp,  struct ccrng_state *rng, ccec_full_ctx_t key)
{
    int result=CCEC_GENERATE_KEY_DEFAULT_ERR;

    // Init key structure
    ccec_ctx_init(cp, key);

    // Generate the private scalar
    size_t random_size=ccn_sizeof(ccec_cp_prime_bitlen(cp)-1);
    uint8_t random_buf[random_size];
    // Burn some random to keep reproducible behavior with previous generated key (24057777)
    cc_require((result = ccrng_generate(rng,random_size,random_buf))==0,errOut);
    cc_require((result = ccec_generate_scalar_fips_retry(cp,rng,ccec_ctx_k(key)))==0,errOut);

    // Generate the corresponding public key
    result=ccec_make_pub_from_priv(cp, rng, ccec_ctx_k(key), NULL, ccec_ctx_pub(key));

errOut:
    return result;
}
