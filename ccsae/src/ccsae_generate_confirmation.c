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
#include <corecrypto/cchmac.h>
#include "ccsae.h"
#include "ccsae_priv.h"
#include "cc_debug.h"

int ccsae_generate_confirmation(ccsae_ctx_t ctx, const uint8_t *send_confirm_counter, uint8_t *confirmation)
{
    CCSAE_EXPECT_STATES(COMMIT_BOTH, CONFIRMATION_VERIFIED);

    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);
    size_t tn = ccec_cp_prime_size(cp);
    const struct ccdigest_info *di = ccsae_ctx_di(ctx);

    uint8_t scratch[ccn_sizeof_n(n)];
    cchmac_di_decl(di, hc);
    /*
     The confirmation is an HMAC of the following with the key == KCK
        1. My Send Confirm Counter (2 bytes)
        2. My Commit Scalar (tn bytes)
        3. My Commit Element (2 * tn bytes)
        4. Peer Commit Scalar (tn bytes)
        5. Peer Commit Element (2 * tn bytes)
     */

    cchmac_init(di, hc, 32, ccsae_ctx_KCK(ctx));

    cchmac_update(di, hc, 2, send_confirm_counter);

    ccn_write_uint_padded(n, ccsae_ctx_commitscalar(ctx), tn, scratch);
    cchmac_update(di, hc, tn, scratch);

    ccn_write_uint_padded(n, ccsae_ctx_CE_x(ctx), tn, scratch);
    cchmac_update(di, hc, tn, scratch);

    ccn_write_uint_padded(n, ccsae_ctx_CE_y(ctx), tn, scratch);
    cchmac_update(di, hc, tn, scratch);

    ccn_write_uint_padded(n, ccsae_ctx_peer_commitscalar(ctx), tn, scratch);
    cchmac_update(di, hc, tn, scratch);

    ccn_write_uint_padded(n, ccsae_ctx_peer_CE_x(ctx), tn, scratch);
    cchmac_update(di, hc, tn, scratch);

    ccn_write_uint_padded(n, ccsae_ctx_peer_CE_y(ctx), tn, scratch);
    cchmac_update(di, hc, tn, scratch);

    cchmac_final(di, hc, confirmation);

    cchmac_di_clear(di, hc);
    CCSAE_ADD_STATE(CONFIRMATION_GENERATED);
    return 0;
}
