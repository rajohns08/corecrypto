/* Copyright (c) (2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
#include "ccec_internal.h"

int ccec_diversify_priv_twin(ccec_const_cp_t cp,
                             const cc_unit *d,
                             size_t entropy_len,
                             const uint8_t *entropy,
                             struct ccrng_state *masking_rng,
                             ccec_full_ctx_t full)
{
    cc_size n = ccec_cp_n(cp);
    cc_unit u[n], v[n];

    int rv = ccec_diversify_twin_scalars(cp, u, v, entropy_len, entropy);
    if (rv) {
        goto cleanup;
    }

    cczp_const_t zq = ccec_cp_zq(cp);
    cc_unit *d2 = ccec_ctx_k(full);

    // d' = d * u + v
    cczp_mul(zq, d2, d, u);
    cczp_add(zq, d2, d2, v);

    // pub(full) = d' * G
    rv = ccec_make_pub_from_priv(cp, masking_rng, d2, NULL, ccec_ctx_pub(full));

cleanup:
    cc_clear(n, u);
    cc_clear(n, v);
    return rv;
}
