/* Copyright (c) (2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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

#include <corecrypto/ccec_priv.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/cczp.h>
#include "ccec_internal.h"

int ccec_compact_transform_key(ccec_full_ctx_t key) {
    ccec_const_cp_t cp=ccec_ctx_cp(key);

    // Compute y from a given x intented to be on the curve
    // x can be a pointer to ccec_point_x(r, cp)
    cc_size n =ccec_cp_n(cp);
    cc_unit t[n];

    // https://datatracker.ietf.org/doc/draft-jivsov-ecc-compact/
    // Convention for y = min(y',p-y'), divide key space by 2 (1 security bit)
    ccn_sub(n, t, cczp_prime(ccec_cp_zp(cp)), ccec_ctx_y(key));
    if (ccn_cmp(n, t, ccec_ctx_y(key))<0)
    {   // Adjust key to match convention
        ccn_set(n,ccec_ctx_y(key),t);
        ccn_sub(n, t, cczp_prime(ccec_cp_zq(cp)), ccec_ctx_k(key));
        ccn_set(n,ccec_ctx_k(key),t);
    }
    return 0;
}

int
ccec_compact_generate_key(ccec_const_cp_t cp, struct ccrng_state *rng, ccec_full_ctx_t key)
{
    int result;

    result = ccec_generate_key_internal_fips(cp, rng, key);
    if (result) {
        return result;
    }

    result = ccec_compact_transform_key(key);
    if (result) {
        return result;
    }

    if (!ccec_pairwise_consistency_check(key, rng)) {
        return CCEC_GENERATE_KEY_CONSISTENCY;
    }

    return 0;
}
