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

int ccec_diversify_pub_twin(ccec_const_cp_t cp,
                            const ccec_pub_ctx_t pub,
                            size_t entropy_len,
                            const uint8_t *entropy,
                            struct ccrng_state *masking_rng,
                            ccec_pub_ctx_t pub_out)
{
    cc_size n = ccec_cp_n(cp);
    cc_unit u[n], v[n];

    ccec_point_decl_cp(cp, G);
    ccec_point_decl_cp(cp, P);
    ccec_point_decl_cp(cp, S);

    // Alias T as P for readability.
    ccec_projective_point_t T = P;

    int rv = ccec_validate_pub_and_projectify(cp, P, (ccec_const_affine_point_t)ccec_ctx_point(pub), masking_rng);
    if (rv) {
        goto cleanup;
    }

    rv = ccec_projectify(cp, G, ccec_cp_g(cp), masking_rng);
    if (rv) {
        goto cleanup;
    }

    // Derive scalars u and v.
    rv = ccec_diversify_twin_scalars(cp, u, v, entropy_len, entropy);
    if (rv) {
        goto cleanup;
    }

    // S = u * P
    rv = ccec_mult(cp, S, u, P, masking_rng);
    if (rv) {
        goto cleanup;
    }

    // T = v * G
    rv = ccec_mult(cp, T, v, G, masking_rng);
    if (rv) {
        goto cleanup;
    }

    // S' = S + T
    ccec_full_add(cp, S, S, T);

    rv = ccec_affinify(cp, (ccec_affine_point_t)ccec_ctx_point(pub_out), S);

cleanup:
    cc_clear(n, u);
    cc_clear(n, v);
    ccec_point_clear_cp(cp, G);
    ccec_point_clear_cp(cp, P);
    ccec_point_clear_cp(cp, S);
    return rv;
}
