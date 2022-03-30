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
#include <corecrypto/cchmac.h>
#include "ccsae.h"
#include "cc_macros.h"
#include "ccsae_priv.h"
#include "ccec_internal.h"

static void
generate_keyseed(ccec_const_cp_t cp, const struct ccdigest_info *di, const struct ccec_projective_point *P, uint8_t *keyseed)
{
    cc_size n = ccec_cp_n(cp);
    size_t tn = ccec_cp_prime_size(cp);

    uint8_t x_coord[tn];
    uint8_t zeros[32] = { 0 };

    ccn_write_uint_padded(n, ccec_point_x(P, cp), tn, x_coord);

    cchmac_di_decl(di, hc);
    cchmac_init(di, hc, 32, zeros);
    cchmac_update(di, hc, tn, x_coord);
    cchmac_final(di, hc, keyseed);

    cchmac_di_clear(di, hc);
    cc_clear(tn, x_coord);
}

int ccsae_verify_commitment(ccsae_ctx_t ctx, const uint8_t *peer_commitment)
{
    CCSAE_EXPECT_STATE(COMMIT_GENERATED);

    struct ccrng_state *rng = ccsae_ctx_rng(ctx);
    const struct ccdigest_info *di = ccsae_ctx_di(ctx);
    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    cczp_const_t zq = ccec_cp_zq(cp);
    cc_size n = ccec_cp_n(cp);
    size_t tn = ccec_cp_prime_size(cp);

    int result = CCERR_PARAMETER;
    uint8_t keyseed[di->output_size];
    cc_unit context[n];

    ccec_point_decl_cp(cp, PWE);
    ccec_point_decl_cp(cp, PEER_CE);
    ccec_point_decl_cp(cp, I1);
    ccec_point_decl_cp(cp, I2);

    ccn_read_uint(n, ccsae_ctx_peer_commitscalar(ctx), tn, peer_commitment);
    ccn_read_uint(n, ccsae_ctx_peer_CE_x(ctx), tn, peer_commitment + tn);
    ccn_read_uint(n, ccsae_ctx_peer_CE_y(ctx), tn, peer_commitment + tn + tn);

    // [WPA3] 12.4.5.4: 1 < scalar < order(cp), peer scalar / element != my scalar / element
    cc_require(!ccn_is_one(n, ccsae_ctx_peer_commitscalar(ctx)), cleanup);
    cc_require(ccec_validate_scalar(cp, ccsae_ctx_peer_commitscalar(ctx)) == CCERR_OK, cleanup);
    cc_require(ccn_cmp(n, ccsae_ctx_peer_commitscalar(ctx), ccsae_ctx_commitscalar(ctx)) != 0, cleanup);
    cc_require(ccn_cmp(n, ccsae_ctx_peer_CE_x(ctx), ccsae_ctx_CE_x(ctx)) != 0, cleanup);
    cc_require(ccn_cmp(n, ccsae_ctx_peer_CE_y(ctx), ccsae_ctx_CE_y(ctx)) != 0, cleanup);

    // [WPA3] 12.4.5.4: Point validation
    cc_require(ccec_validate_pub_and_projectify(cp, PEER_CE, (ccec_const_affine_point_t)ccsae_ctx_peer_CE(ctx), rng) == CCERR_OK,
               cleanup);

    /*
     * ccsae_ctx_PWE is the same point we found in the generate commitment step
     * so we can simply call ccec_projectify
     */
    cc_require(ccec_projectify(cp, PWE, (ccec_const_affine_point_t)ccsae_ctx_PWE(ctx), rng) == CCERR_OK, cleanup);

    // [WPA3] 12.4.5.4: I1 = peer_scalar * PWE
    cc_require(ccec_mult(cp, I1, ccsae_ctx_peer_commitscalar(ctx), PWE, rng) == CCERR_OK, cleanup);

    // [WPA3] 12.4.5.4: PWE = I1 + PEER_CE
    ccec_full_add(cp, PWE, I1, PEER_CE);

    // [WPA3] 12.4.5.4: I2 = rand * PWE
    cc_require(ccec_mult(cp, I2, ccsae_ctx_rand(ctx), PWE, rng) == CCERR_OK, cleanup);

    // [WPA3] 12.4.5.4: Generate the keyseed
    cc_require(ccec_affinify(cp, (ccec_affine_point_t)I2, I2) == CCERR_OK, cleanup);

    generate_keyseed(cp, di, I2, keyseed);

    // [WPA3] 12.4.5.4: Generate KCK, PMK
    cczp_add(zq, context, ccsae_ctx_commitscalar(ctx), ccsae_ctx_peer_commitscalar(ctx));
    ccsae_gen_kck_and_pmk(ctx, keyseed, context);

    CCSAE_ADD_STATE(COMMIT_VERIFIED);
    result = CCERR_OK;

cleanup:
    ccec_point_clear_cp(cp, PWE);
    ccec_point_clear_cp(cp, PEER_CE);
    ccec_point_clear_cp(cp, I1);
    ccec_point_clear_cp(cp, I2);
    cc_clear(di->output_size, keyseed);
    ccn_clear(n, context);
    return result;
}
