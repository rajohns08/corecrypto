/* Copyright (c) (2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc_macros.h>
#include <corecrypto/ccdh.h>
#include "ccdh_internal.h"
#include <corecrypto/ccn.h>
#include <corecrypto/cczp.h>

#define CCN32_N ccn_nof(32)
static const cc_unit REF_X[CCN32_N] = { CCN32_C(60,0d,de,ed) };

bool ccdh_pairwise_consistency_check(ccdh_const_gp_t gp,
                                     struct ccrng_state *rng,
                                     ccdh_full_ctx_t key)
{
    ccdh_full_ctx_decl_gp(gp, ref_key);
    ccdh_ctx_init(gp, ccdh_ctx_public(ref_key));

    cczp_const_t zp = ccdh_gp_zp(gp);
    cc_size n = cczp_n(zp);
    cc_unit t[n];

    ccn_setn(n, ccdh_ctx_x(ref_key), CCN32_N, REF_X);
    cc_require(cczp_power_fast(zp, ccdh_ctx_y(ref_key), ccdh_gp_g(gp), ccdh_ctx_x(ref_key)) == 0, err);

    {
        size_t ss_nbytes = ccdh_ccn_size(gp);
        uint8_t ss1[ss_nbytes];
        uint8_t ss2[ss_nbytes];

        cc_clear(sizeof(ss1), ss1);
        cc_clear(sizeof(ss2), ss2);

        size_t ss1_nbytes = sizeof(ss1);
        cc_require(ccdh_compute_shared_secret(key, ccdh_ctx_public(ref_key), &ss1_nbytes, ss1, rng) == 0, err);

        // A faster, variable-time variant of ccdh_compute_shared_secret().
        cc_require(cczp_power_fast(zp, t, ccdh_ctx_y(key), ccdh_ctx_x(ref_key)) == 0, err);

        size_t ss2_nbytes = ccn_write_uint_size(n, t);
        ccn_write_uint_padded(n, t, ss2_nbytes, ss2);

        cc_require(ss1_nbytes == ss2_nbytes, err);
        cc_require(cc_cmp_safe(ss1_nbytes, ss1, ss2) == 0, err);
    }

    return true;

err:
    return false;
}
