/* Copyright (c) (2019) Apple Inc. All rights reserved.
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

int ccckg_owner_generate_share(ccckg_ctx_t ctx,
                               size_t commitment_len,
                               const uint8_t *commitment,
                               size_t share_len,
                               uint8_t *share)
{
    const struct ccdigest_info *di = ccckg_ctx_di(ctx);
    ccec_const_cp_t cp = ccckg_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);

    ccec_full_ctx_decl_cp(cp, S);
    ccec_ctx_init(cp, S);
    int rv;

    CCCKG_EXPECT_STATE(INIT);

    if (commitment_len != ccckg_sizeof_commitment(cp, di)) {
        return CCERR_PARAMETER;
    }

    if (share_len != ccckg_sizeof_share(cp, di)) {
        return CCERR_PARAMETER;
    }

    // Store the contributor's commitment.
    cc_memcpy(ccckg_ctx_c(ctx), commitment, commitment_len);

    // Generate a new key share.
    if ((rv = ccec_generate_key(cp, ccckg_ctx_rng(ctx), S))) {
        goto cleanup;
    }

    // Generate a nonce.
    if ((rv = ccrng_generate(ccckg_ctx_rng(ctx), di->output_size, ccckg_ctx_r(ctx)))) {
        goto cleanup;
    }

    // Store our key share's scalar.
    ccn_set(n, ccckg_ctx_s(ctx), ccec_ctx_k(S));

    // Assemble the share.
    ccec_export_pub(ccec_ctx_pub(S), share);
    cc_memcpy(share + ccec_export_pub_size(ccec_ctx_pub(S)), ccckg_ctx_r(ctx), di->output_size);

    CCCKG_SET_STATE(SHARE);

cleanup:
    ccec_full_ctx_clear_cp(cp, S);

    return rv;
}

int ccckg_owner_finish(ccckg_ctx_t ctx, size_t opening_len, const uint8_t *opening, ccec_full_ctx_t P, size_t sk_len, uint8_t *sk)
{
    const struct ccdigest_info *di = ccckg_ctx_di(ctx);
    ccec_const_cp_t cp = ccckg_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);
    int rv;

    CCCKG_EXPECT_STATE(SHARE);

    if (ccec_ctx_cp(P) != cp) {
        return CCERR_PARAMETER;
    }

    if (opening_len != ccckg_sizeof_opening(cp, di)) {
        return CCERR_PARAMETER;
    }

    uint8_t buf[di->output_size];
    ccdigest(di, opening_len, opening, buf);

    // Check the commitment.
    if (cc_cmp_safe(di->output_size, buf, ccckg_ctx_c(ctx))) {
        rv = CCERR_INTEGRITY;
        goto cleanup;
    }

    ccn_read_uint(n, ccec_ctx_k(P), ccec_cp_order_size(cp), opening);

    // Check the contributor's scalar.
    if (ccec_validate_scalar(cp, ccec_ctx_k(P))) {
        rv = CCERR_PARAMETER;
        goto cleanup;
    }

    // Add our scalar to the contributor's.
    cczp_add(ccec_cp_zq(cp), ccec_ctx_k(P), ccec_ctx_k(P), ccckg_ctx_s(ctx));

    if ((rv = ccec_make_pub_from_priv(cp, ccckg_ctx_rng(ctx), ccec_ctx_k(P), NULL, ccec_ctx_pub(P)))) {
        goto cleanup;
    }

    const uint8_t *r1 = (const uint8_t *)opening + ccec_cp_order_size(cp);
    const uint8_t *r2 = (const uint8_t *)ccckg_ctx_r(ctx);

    // Derive SK.
    if ((rv = ccckg_derive_sk(ctx, ccec_ctx_x(P), r1, r2, sk_len, sk))) {
        goto cleanup;
    }

    CCCKG_SET_STATE(FINISH);

cleanup:
    cc_clear(sizeof(buf), buf);

    return rv;
}
