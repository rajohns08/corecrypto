/* Copyright (c) (2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
#include <corecrypto/ccckg.h>

#include "ccec_internal.h"
#include "ccckg_priv.h"

static
void ccckg_build_commitment(ccckg_ctx_t ctx, uint8_t *buf)
{
    const struct ccdigest_info *di = ccckg_ctx_di(ctx);
    ccec_const_cp_t cp = ccckg_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);

    ccn_write_uint_padded(n, ccckg_ctx_s(ctx), ccec_cp_order_size(cp), buf);
    cc_memcpy(buf + ccec_cp_order_size(cp), ccckg_ctx_r(ctx), di->output_size);
}

int ccckg_contributor_commit(ccckg_ctx_t ctx, size_t commitment_len, uint8_t *commitment)
{
    const struct ccdigest_info *di = ccckg_ctx_di(ctx);
    ccec_const_cp_t cp = ccckg_ctx_cp(ctx);

    uint8_t buf[ccec_cp_order_size(cp) + di->output_size];
    int rv;

    CCCKG_EXPECT_STATE(INIT);

    if (commitment_len != ccckg_sizeof_commitment(cp, di)) {
        return CCERR_PARAMETER;
    }

    // Generate a new scalar and store it.
    if ((rv = ccec_generate_scalar_fips_retry(cp, ccckg_ctx_rng(ctx), ccckg_ctx_s(ctx)))) {
        goto cleanup;
    }

    // Generate a nonce r.
    if ((rv = ccrng_generate(ccckg_ctx_rng(ctx), di->output_size, ccckg_ctx_r(ctx)))) {
        goto cleanup;
    }

    // Write the commitment.
    ccckg_build_commitment(ctx, buf);
    ccdigest(di, sizeof(buf), buf, commitment);

    CCCKG_SET_STATE(COMMIT);

cleanup:
    cc_clear(sizeof(buf), buf);

    return rv;
}

int ccckg_contributor_finish(ccckg_ctx_t ctx,
                             size_t share_len,
                             const uint8_t *share,
                             size_t opening_len,
                             uint8_t *opening,
                             ccec_pub_ctx_t P,
                             size_t sk_len,
                             uint8_t *sk)
{
    const struct ccdigest_info *di = ccckg_ctx_di(ctx);
    struct ccrng_state *rng = ccckg_ctx_rng(ctx);
    ccec_const_cp_t cp = ccckg_ctx_cp(ctx);

    ccec_point_decl_cp(cp, X);
    ccec_point_decl_cp(cp, Y);
    ccec_point_decl_cp(cp, G);
    ccec_point_decl_cp(cp, Q);
    ccec_pub_ctx_decl_cp(cp, pub);
    ccec_ctx_init(cp, pub);
    int rv;

    CCCKG_EXPECT_STATE(COMMIT);

    if (ccec_ctx_cp(P) != cp) {
        return CCERR_PARAMETER;
    }

    if (share_len != ccckg_sizeof_share(cp, di)) {
        return CCERR_PARAMETER;
    }

    if (opening_len != ccckg_sizeof_opening(cp, di)) {
        return CCERR_PARAMETER;
    }

    if ((rv = ccec_import_pub(cp, ccec_export_pub_size(pub), share, pub))) {
        goto cleanup;
    }

    if ((rv = ccec_validate_pub_and_projectify(cp, X, (ccec_const_affine_point_t)ccec_ctx_point(pub), rng))) {
        goto cleanup;
    }

    if ((rv = ccec_projectify(cp, G, ccec_cp_g(cp), rng))) {
        goto cleanup;
    }

    // Y = s * G
    if ((rv = ccec_mult(cp, Y, ccckg_ctx_s(ctx), G, rng))) {
        goto cleanup;
    }

    // Q = X + Y
    ccec_full_add(cp, Q, X, Y);

    // Export Q.
    if ((rv = ccec_affinify(cp, (ccec_affine_point_t)ccec_ctx_point(P), Q))) {
        goto cleanup;
    }

    const uint8_t *r1 = (const uint8_t *)ccckg_ctx_r(ctx);
    const uint8_t *r2 = (const uint8_t *)share + ccec_export_pub_size(pub);

    // Derive SK.
    if ((rv = ccckg_derive_sk(ctx, ccec_ctx_x(P), r1, r2, sk_len, sk))) {
        goto cleanup;
    }

    // Open the commitment.
    ccckg_build_commitment(ctx, opening);

    CCCKG_SET_STATE(FINISH);

cleanup:
    ccec_pub_ctx_clear_cp(cp, pub);
    ccec_point_clear_cp(cp, X);
    ccec_point_clear_cp(cp, Y);
    ccec_point_clear_cp(cp, G);
    ccec_point_clear_cp(cp, Q);

    return rv;
}
