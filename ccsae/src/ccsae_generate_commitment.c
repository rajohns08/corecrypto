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
#include "ccsae.h"
#include "cc_macros.h"
#include "ccsae_priv.h"
#include "ccn_internal.h"
#include "ccec_internal.h"

int ccsae_generate_commitment_init(ccsae_ctx_t ctx)
{
    CCSAE_EXPECT_STATE(INIT);

    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);
    // Since we need to perform `ccsae_y2_from_x_ws` at the start of every `ccsae_generate_commitment_update`,
    // we want to ensure that the first time we call update we don't accidently think we have found the correct
    // element.
    ccn_set(n, ccsae_ctx_PWE_x(ctx), cczp_prime(ccec_cp_zp(cp)));

    ccsae_ctx_current_loop_iteration(ctx) = 1; // Hunting and pecking always starts with the counter = 1

    CCSAE_ADD_STATE(COMMIT_INIT);
    return CCERR_OK;
}

int ccsae_generate_commitment_partial(ccsae_ctx_t ctx,
                                      const uint8_t *A,
                                      size_t A_nbytes,
                                      const uint8_t *B,
                                      size_t B_nbytes,
                                      const uint8_t *password,
                                      size_t password_nbytes,
                                      const uint8_t *identifier,
                                      size_t identifier_nbytes,
                                      uint8_t max_num_iterations)
{
    CCSAE_EXPECT_STATES(COMMIT_UPDATE, COMMIT_INIT);
    if (max_num_iterations == 0) {
        return CCERR_PARAMETER;
    }

    // The current loop iteration starts at 1 so subtract to get the number of iterations we have performed
    uint8_t loop_iterations_complete = ccsae_ctx_current_loop_iteration(ctx) - 1;
    if (loop_iterations_complete == ccsae_ctx_max_loop_iterations(ctx)) {
        return CCERR_OK;
    }

    uint8_t actual_iterations =
        (uint8_t)CC_MIN(max_num_iterations, ccsae_ctx_max_loop_iterations(ctx) - loop_iterations_complete);

    const struct ccdigest_info *di = ccsae_ctx_di(ctx);
    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);
    unsigned char LSB = ccsae_ctx_temp_lsb(ctx);
    bool found_qr = false;

    size_t keySize = A_nbytes + B_nbytes;
    uint8_t key[keySize];
    cc_unit ytemp[n];

    ccsae_lexographic_order_key(A, A_nbytes, B, B_nbytes, key);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSAE_Y2_FROM_X_WORKSPACE_N(n));

    found_qr = ccsae_y2_from_x_ws(ws, cp, ytemp, ccsae_ctx_PWE_x(ctx));

    for (uint8_t counter = 0; counter < actual_iterations; counter++) {
        uint8_t actual_counter = ccsae_ctx_current_loop_iteration(ctx) + counter;
        ccsae_gen_password_seed(di,
                                key,
                                keySize,
                                password,
                                password_nbytes,
                                identifier,
                                identifier_nbytes,
                                actual_counter,
                                ccsae_ctx_S_PWD_SEED(ctx));

        ccsae_gen_password_value(ctx, ccsae_ctx_S_PWD_SEED(ctx), ccsae_ctx_S_PWD_VALUE(ctx));

        ccn_cond_swap(n, !found_qr, ccsae_ctx_PWE_x(ctx), ccsae_ctx_S_PWD_VALUE(ctx));
        CC_MUXU(LSB, found_qr, LSB, ccsae_ctx_S_PWD_SEED_LSB(ctx, di) & 1);
        found_qr |= ccsae_y2_from_x_ws(ws, cp, ytemp, ccsae_ctx_PWE_x(ctx));
    }
    CC_FREE_WORKSPACE(ws);

    ccsae_ctx_temp_lsb(ctx) = LSB;
    ccsae_ctx_current_loop_iteration(ctx) += actual_iterations;
    CCSAE_ADD_STATE(COMMIT_UPDATE);

    if (ccsae_ctx_current_loop_iteration(ctx) - 1 == ccsae_ctx_max_loop_iterations(ctx)) {
        return CCERR_OK;
    }
    return CCSAE_GENERATE_COMMIT_CALL_AGAIN;
}

int ccsae_generate_commitment_finalize(ccsae_ctx_t ctx, uint8_t *commitment)
{
    CCSAE_EXPECT_STATE(COMMIT_UPDATE);
    int result = CCSAE_HUNTPECK_EXCEEDED_MAX_TRIALS;
    struct ccrng_state *rng = ccsae_ctx_rng(ctx);
    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    ccec_point_decl_cp(cp, PWE);
    cc_size n = ccec_cp_n(cp);
    cc_unit ytemp[n];
    bool LSB = ccsae_ctx_temp_lsb(ctx) & 1;
    size_t tn = ccec_cp_prime_size(cp);

    if (ccsae_ctx_current_loop_iteration(ctx) - 1 < ccsae_ctx_max_loop_iterations(ctx)) {
        return CCSAE_NOT_ENOUGH_COMMIT_PARTIAL_CALLS;
    }

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSAE_Y2_FROM_X_WORKSPACE_N(n));
    bool valid_x = ccsae_y2_from_x_ws(ws, cp, ytemp, ccsae_ctx_PWE_x(ctx));
    CC_FREE_WORKSPACE(ws);
    cc_require(valid_x, cleanup); // Returns CCSAE_HUNTPECK_EXCEEDED_MAX_TRIALS

    cczp_const_decl(zp, ccec_cp_zp(cp));
    cc_require(cczp_sqrt(zp, ccsae_ctx_PWE_y(ctx), ytemp) == CCERR_OK, cleanup);
    cc_require(cczp_from(zp, ccsae_ctx_PWE_y(ctx), ccsae_ctx_PWE_y(ctx)) == CCERR_OK, cleanup);
    ccn_sub(n, ccsae_ctx_S_PWE_ym1(ctx), ccec_cp_p(cp), ccsae_ctx_PWE_y(ctx));
    ccn_cond_swap(n, ccn_bit(ccsae_ctx_PWE_y(ctx), 0) ^ LSB, ccsae_ctx_PWE_y(ctx), ccsae_ctx_S_PWE_ym1(ctx));

    // [WPA3] 12.4.5.2: Generate rand & mask
    cc_require(ccec_generate_scalar_fips_retry(cp, rng, ccsae_ctx_rand(ctx)) == CCERR_OK, cleanup);
    cc_require(ccec_generate_scalar_fips_retry(cp, rng, ccsae_ctx_S_mask(ctx)) == CCERR_OK, cleanup);

    /* 12.4.5.3: Generate the Commit Element
     * We already know ccsase_ctx_PWE is a valid point because of the above loop,
     * so we can simply call ccec_projectify.
     */
    cc_require(ccec_projectify(cp, PWE, (ccec_const_affine_point_t)ccsae_ctx_PWE(ctx), rng) == CCERR_OK, cleanup);

    // CE = mask * PWE
    cc_require(ccec_mult(cp, (ccec_projective_point_t)ccsae_ctx_CE(ctx), ccsae_ctx_S_mask(ctx), PWE, rng) == CCERR_OK, cleanup);

    cc_require(ccec_affinify(cp, (ccec_affine_point_t)ccsae_ctx_CE(ctx), (ccec_projective_point_t)ccsae_ctx_CE(ctx)) == CCERR_OK,
               cleanup);
    // CE = -CE
    cczp_sub(zp, ccsae_ctx_CE_y(ctx), ccec_cp_p(cp), ccsae_ctx_CE_y(ctx));

    // [WPA3] 12.4.5.3: Generate the Commit Scalar
    cczp_add((cczp_const_t)ccec_cp_zq(cp), ccsae_ctx_commitscalar(ctx), ccsae_ctx_rand(ctx), ccsae_ctx_S_mask(ctx));
    cc_require(!ccn_is_zero_or_one(n, ccsae_ctx_commitscalar(ctx)), cleanup);

    ccn_write_uint_padded(n, ccsae_ctx_commitscalar(ctx), tn, commitment);
    ccn_write_uint_padded(n, ccsae_ctx_CE_x(ctx), tn, commitment + tn);
    ccn_write_uint_padded(n, ccsae_ctx_CE_y(ctx), tn, commitment + 2 * tn);

    CCSAE_ADD_STATE(COMMIT_GENERATED);
    result = CCERR_OK;
cleanup:
    ccn_clear(n, ccsae_ctx_S_PWE_ym1(ctx));
    ccn_clear(n, ccsae_ctx_S_mask(ctx));
    return result;
}

int ccsae_generate_commitment(ccsae_ctx_t ctx,
                              const uint8_t *A,
                              size_t A_nbytes,
                              const uint8_t *B,
                              size_t B_nbytes,
                              const uint8_t *password,
                              size_t password_nbytes,
                              const uint8_t *identifier,
                              size_t identifier_nbytes,
                              uint8_t *commitment)
{
    int error = ccsae_generate_commitment_init(ctx);
    if (error != CCERR_OK) {
        return error;
    }

    error = ccsae_generate_commitment_partial(
        ctx, A, A_nbytes, B, B_nbytes, password, password_nbytes, identifier, identifier_nbytes, SAE_HUNT_AND_PECK_ITERATIONS);
    if (error != CCERR_OK) {
        return error;
    }

    return ccsae_generate_commitment_finalize(ctx, commitment);
}
