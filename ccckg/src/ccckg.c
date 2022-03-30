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

#include "ccansikdf_priv.h"
#include "ccec_internal.h"
#include "ccckg_priv.h"

size_t ccckg_sizeof_ctx(ccec_const_cp_t cp, const struct ccdigest_info *di)
{
    // Need space to store a scalar and a nonce.
    // The owner needs to also store the commitment.
    return sizeof(struct ccckg_ctx) + ccec_ccn_size(cp) + ccn_sizeof(di->output_size * 8) * 2;
}

size_t ccckg_sizeof_commitment(CC_UNUSED ccec_const_cp_t cp, const struct ccdigest_info *di)
{
    return di->output_size;
}

size_t ccckg_sizeof_share(ccec_const_cp_t cp, const struct ccdigest_info *di)
{
    // A public EC key plus a nonce.
    return 1 + 2 * ccec_cp_prime_size(cp) + di->output_size;
}

size_t ccckg_sizeof_opening(ccec_const_cp_t cp, const struct ccdigest_info *di)
{
    // A scalar plus a nonce.
    return ccec_cp_order_size(cp) + di->output_size;
}

void ccckg_init(ccckg_ctx_t ctx, ccec_const_cp_t cp, const struct ccdigest_info *di, struct ccrng_state *rng)
{
    cc_clear(ccckg_sizeof_ctx(cp, di), ctx);

    ccckg_ctx_cp(ctx) = cp;
    ccckg_ctx_di(ctx) = di;
    ccckg_ctx_rng(ctx) = rng;
    ccckg_ctx_state(ctx) = CCCKG_STATE_INIT;
}

int ccckg_derive_sk(ccckg_ctx_t ctx, const cc_unit *x, const uint8_t *r1, const uint8_t *r2, size_t key_len, uint8_t *key)
{
    const struct ccdigest_info *di = ccckg_ctx_di(ctx);
    ccansikdf_x963_ctx_decl(di, key_len, kdf_ctx);
    ccec_const_cp_t cp = ccckg_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);
    int rv = CCERR_OK;

    uint8_t xbuf[ccec_cp_prime_size(cp)];
    ccn_write_uint_padded(n, x, sizeof(xbuf), xbuf);

    if ((rv = ccansikdf_x963_init(di, kdf_ctx, key_len, sizeof(xbuf), xbuf))) {
        goto cleanup;
    }

    ccansikdf_x963_update(di, kdf_ctx, di->output_size, r1);
    ccansikdf_x963_update(di, kdf_ctx, di->output_size, r2);
    ccansikdf_x963_final(di, kdf_ctx, key);

cleanup:
    ccansikdf_x963_ctx_clear(di, kdf_ctx);
    return rv;
}
