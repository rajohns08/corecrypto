/* Copyright (c) (2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
#include <corecrypto/ccspake.h>
#include "ccec_internal.h"
#include "ccspake_priv.h"

CC_NONNULL((1))
static int ccspake_lazy_gen_xy_XY(ccspake_ctx_t ctx)
{
    ccec_const_cp_t cp = ccspake_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);

    ccec_pub_ctx_decl_cp(cp, pub);
    ccec_ctx_init(cp, pub);
    int rv;

    ccec_point_decl_cp(cp, S);
    ccec_point_decl_cp(cp, T);
    ccec_point_decl_cp(cp, U);

    struct ccrng_state *rng = ccspake_ctx_rng(ctx);

    if (!ccn_is_zero(n, ccspake_ctx_xy(ctx))) {
        return CCERR_OK;
    }

    // Generate a new scalar and store it.
    cc_unit xy[n];
    if ((rv = ccec_generate_scalar_fips_retry(cp, ccspake_ctx_rng(ctx), xy))) {
        goto cleanup;
    }

    // U = base point G
    if ((rv = ccec_projectify(cp, U, ccec_cp_g(cp), rng))) {
        goto cleanup;
    }

    // S = x * U (prover) or S = y * U (verifier)
    if ((rv = ccec_mult(cp, S, xy, U, rng))) {
        goto cleanup;
    }

    // U = "random element M/N".
    if ((rv = ccec_projectify(cp, U, ccspake_ctx_MN(ctx, !ccspake_ctx_is_prover(ctx)), rng))) {
        goto cleanup;
    }

    // T = w0 * U
    if ((rv = ccec_mult(cp, T, ccspake_ctx_w0(ctx), U, rng))) {
        goto cleanup;
    }

    // X = S + T
    ccec_full_add(cp, ccec_ctx_point(pub), S, T);

    if ((rv = ccec_affinify(cp, (ccec_affine_point_t)ccec_ctx_point(pub), ccec_ctx_point(pub)))) {
        goto cleanup;
    }

    ccspake_store_pub_key(pub, ccspake_ctx_XY(ctx));
    ccn_set(n, ccspake_ctx_xy(ctx), xy);

cleanup:
    ccn_clear(n, xy);
    ccec_pub_ctx_clear_cp(cp, pub);
    ccec_point_clear_cp(cp, S);
    ccec_point_clear_cp(cp, T);
    ccec_point_clear_cp(cp, U);

    return rv;
}

int ccspake_kex_generate(ccspake_ctx_t ctx, size_t x_len, uint8_t *x)
{
    ccec_const_cp_t cp = ccspake_ctx_cp(ctx);
    size_t len = ccec_cp_prime_size(cp);
    cc_size n = ccec_cp_n(cp);
    int rv;

    CCSPAKE_EXPECT_STATES(INIT, KEX_PROCESS);

    if (x_len != 1 + len * 2) {
        return CCERR_PARAMETER;
    }

    // Generate (x, X) or (y, Y), if needed.
    if ((rv = ccspake_lazy_gen_xy_XY(ctx))) {
        return rv;
    }

    // Write the public share.
    *x++ = 0x04;
    ccn_write_uint_padded(n, ccspake_ctx_XY_x(ctx), len, x);
    ccn_write_uint_padded(n, ccspake_ctx_XY_y(ctx), len, x + len);

    CCSPAKE_ADD_STATE(KEX_GENERATE);

    return CCERR_OK;
}

int ccspake_kex_process(ccspake_ctx_t ctx, size_t y_len, const uint8_t *y)
{
    ccec_const_cp_t cp = ccspake_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);

    ccec_pub_ctx_decl_cp(cp, Q_pub);
    ccec_ctx_init(cp, Q_pub);
    int rv;

    ccec_point_decl_cp(cp, MN);
    ccec_point_decl_cp(cp, Q);
    ccec_point_decl_cp(cp, S);
    ccec_point_decl_cp(cp, T);
    ccec_point_decl_cp(cp, Z);
    ccec_point_decl_cp(cp, V);
    ccec_point_decl_cp(cp, L);

    struct ccrng_state *rng = ccspake_ctx_rng(ctx);

    CCSPAKE_EXPECT_STATES(INIT, KEX_GENERATE);

    // Import and verify our peer's share.
    if ((rv = ccspake_import_pub(Q_pub, y_len, y))) {
        goto cleanup;
    }

    // Generate (x, X) or (y, Y), if needed.
    if ((rv = ccspake_lazy_gen_xy_XY(ctx))) {
        goto cleanup;
    }

    // The peer's share must not be the same as ours.
    if (ccspake_cmp_pub_key(Q_pub, ccspake_ctx_XY(ctx)) == 0) {
        rv = CCERR_PARAMETER;
        goto cleanup;
    }

    if ((rv = ccec_projectify(cp, Q, (ccec_const_affine_point_t)ccec_ctx_point(Q_pub), rng))) {
        goto cleanup;
    }

    // Import the "random element M/N".
    if ((rv = ccec_projectify(cp, MN, ccspake_ctx_MN(ctx, ccspake_ctx_is_prover(ctx)), rng))) {
        goto cleanup;
    }

    // S = w0 * M (prover) or S = w0 * N (verifier)
    if ((rv = ccec_mult(cp, S, ccspake_ctx_w0(ctx), MN, rng))) {
        goto cleanup;
    }

    // T = Q - S
    ccec_full_sub(cp, T, Q, S);

    // Z = x * T (prover) or Z = y * T (verifier)
    if ((rv = ccec_mult(cp, Z, ccspake_ctx_xy(ctx), T, rng))) {
        goto cleanup;
    }

    if (ccspake_ctx_is_prover(ctx)) {
        // V = w1 * T
        if ((rv = ccec_mult(cp, V, ccspake_ctx_w1(ctx), T, rng))) {
            goto cleanup;
        }
    } else {
        if ((rv = ccec_validate_pub_and_projectify(cp, L, (ccec_const_affine_point_t)ccspake_ctx_L(ctx), rng))) {
            goto cleanup;
        }

        // V = y * L
        if ((rv = ccec_mult(cp, V, ccspake_ctx_xy(ctx), L, rng))) {
            goto cleanup;
        }
    }

    // Get affine coordinates.
    if ((rv = ccec_affinify(cp, (ccec_affine_point_t)Z, Z))) {
        goto cleanup;
    }
    if ((rv = ccec_affinify(cp, (ccec_affine_point_t)V, V))) {
        goto cleanup;
    }

    // Save Q, Z, and V.
    ccspake_store_pub_key(Q_pub, ccspake_ctx_Q(ctx));
    ccn_set(n, ccspake_ctx_Z_x(ctx), ccec_point_x(Z, cp));
    ccn_set(n, ccspake_ctx_Z_y(ctx), ccec_point_y(Z, cp));
    ccn_set(n, ccspake_ctx_V_x(ctx), ccec_point_x(V, cp));
    ccn_set(n, ccspake_ctx_V_y(ctx), ccec_point_y(V, cp));

    CCSPAKE_ADD_STATE(KEX_PROCESS);

cleanup:
    ccec_pub_ctx_clear_cp(cp, Q_pub);
    ccec_point_clear_cp(cp, MN);
    ccec_point_clear_cp(cp, Q);
    ccec_point_clear_cp(cp, S);
    ccec_point_clear_cp(cp, T);
    ccec_point_clear_cp(cp, Z);
    ccec_point_clear_cp(cp, V);
    ccec_point_clear_cp(cp, L);

    return rv;
}
