/* Copyright (c) (2013,2014,2015,2017,2018,2019) Apple Inc. All rights reserved.
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

int
ccecdh_generate_key(ccec_const_cp_t cp,  struct ccrng_state *rng, ccec_full_ctx_t key)
{
    int result;
    if((result = ccec_generate_key_internal_fips(cp,  rng, key))) return result;
    result = ccecdh_pairwise_consistency_check(key, NULL, rng) ? 0 : CCEC_GENERATE_KEY_CONSISTENCY;
    return result;
}
