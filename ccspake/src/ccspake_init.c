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

int ccspake_prover_init(ccspake_ctx_t ctx,
                        ccspake_const_cp_t scp,
                        ccspake_const_mac_t mac,
                        struct ccrng_state *rng,
                        size_t aad_len,
                        const uint8_t *aad,
                        size_t w_len,
                        const uint8_t *w0,
                        const uint8_t *w1)
{
    cc_clear(ccspake_sizeof_ctx(scp), ctx);

    if (ccspake_sizeof_w(scp) != w_len) {
        return CCERR_PARAMETER;
    }

    ccec_const_cp_t cp = ccspake_cp_ec(scp);
    int rv;

    ccspake_ctx_scp(ctx) = scp;
    ccspake_ctx_mac(ctx) = mac;
    ccspake_ctx_rng(ctx) = rng;
    ccspake_ctx_aad_len(ctx) = aad_len;
    ccspake_ctx_aad(ctx) = aad;
    ccspake_ctx_is_prover(ctx) = true;
    ccspake_ctx_state(ctx) = CCSPAKE_STATE_INIT;

    if ((rv = ccec_generate_scalar_fips_extrabits(cp, w_len, w0, ccspake_ctx_w0(ctx)))) {
        return rv;
    }

    if ((rv = ccec_generate_scalar_fips_extrabits(cp, w_len, w1, ccspake_ctx_w1(ctx)))) {
        return rv;
    }

    return CCERR_OK;
}

int ccspake_verifier_init(ccspake_ctx_t ctx,
                          ccspake_const_cp_t scp,
                          ccspake_const_mac_t mac,
                          struct ccrng_state *rng,
                          size_t aad_len,
                          const uint8_t *aad,
                          size_t w0_len,
                          const uint8_t *w0,
                          size_t L_len,
                          const uint8_t *L)
{
    cc_clear(ccspake_sizeof_ctx(scp), ctx);

    ccec_const_cp_t cp = ccspake_cp_ec(scp);
    ccec_pub_ctx_decl_cp(cp, L_pub);
    ccec_ctx_init(cp, L_pub);

    if (ccspake_sizeof_w(scp) != w0_len) {
        return CCERR_PARAMETER;
    }

    if (ccspake_sizeof_point(scp) != L_len) {
        return CCERR_PARAMETER;
    }

    int rv;

    ccspake_ctx_scp(ctx) = scp;
    ccspake_ctx_mac(ctx) = mac;
    ccspake_ctx_rng(ctx) = rng;
    ccspake_ctx_aad_len(ctx) = aad_len;
    ccspake_ctx_aad(ctx) = aad;
    ccspake_ctx_is_prover(ctx) = false;
    ccspake_ctx_state(ctx) = CCSPAKE_STATE_INIT;

    if ((rv = ccec_generate_scalar_fips_extrabits(cp, w0_len, w0, ccspake_ctx_w0(ctx)))) {
        return rv;
    }

    if ((rv = ccspake_import_pub(L_pub, L_len, L))) {
        return rv;
    }

    ccspake_store_pub_key(L_pub, ccspake_ctx_L(ctx));

    return CCERR_OK;
}
