/* Copyright (c) (2014,2015,2016,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccansikdf.h>
#include "ccansikdf_priv.h"

// ccdigest_update only supports 32bit length
#define MAX_HASH_LEN UINT32_MAX

#define ccansikdf_x963_entry(_ctx_, _di_, _num_) ((void *)_ctx_->dis + ccansikdf_x963_padded_entry_size(_di_) * (_num_))

int ccansikdf_x963_init(const struct ccdigest_info *di, ccansikdf_x963_ctx_t ctx, size_t key_len, size_t Z_len, const void *Z)
{
    uint32_t i = 0;
    size_t r = cc_ceiling(key_len, di->output_size);

    ctx->klen = key_len;

    if (r >= UINT32_MAX) { // 2^32 - 1;
        return CCERR_PARAMETER;
    }

    for (i = 1; i <= r; i++) {
        uint8_t counter[4];
        CC_STORE32_BE(i, counter);

        ccdigest_ctx_t dictx = ccansikdf_x963_entry(ctx, di, i - 1);
        ccdigest_init(di, dictx);

        ccdigest_update(di, dictx, Z_len, Z);
        ccdigest_update(di, dictx, sizeof(counter), counter);
    }

    return CCERR_OK;
}

void ccansikdf_x963_update(const struct ccdigest_info *di, ccansikdf_x963_ctx_t ctx, size_t len, const void *data)
{
    size_t r = cc_ceiling(ctx->klen, di->output_size);

    if (data == NULL || len == 0) {
        return;
    }

    for (size_t i = 0; i < r; i++) {
        ccdigest_update(di, ccansikdf_x963_entry(ctx, di, i), len, data);
    }
}

void ccansikdf_x963_final(const struct ccdigest_info *di, ccansikdf_x963_ctx_t ctx, void *key)
{
    size_t r = cc_ceiling(ctx->klen, di->output_size) - 1;

    for (size_t i = 0; i < r; i++) {
        ccdigest_final(di, ccansikdf_x963_entry(ctx, di, i), key);
        key += di->output_size; // move destination pointer
    }

    uint8_t digest[di->output_size];
    ccdigest_final(di, ccansikdf_x963_entry(ctx, di, r), digest);
    cc_memcpy(key, digest, ctx->klen - r * di->output_size);
}

int ccansikdf_x963(const struct ccdigest_info *di,
                   const size_t Z_len,
                   const unsigned char *Z,
                   const size_t sharedinfo_byte_len,
                   const void *sharedinfo,
                   const size_t key_len,
                   uint8_t *key)
{
    int rv;

    ccansikdf_x963_ctx_decl(di, key_len, ctx);
    if ((rv = ccansikdf_x963_init(di, ctx, key_len, Z_len, Z))) {
        goto errOut;
    }

    ccansikdf_x963_update(di, ctx, sharedinfo_byte_len, sharedinfo);
    ccansikdf_x963_final(di, ctx, key);

errOut:
    // Clear our context since it contains information related to the output
    // key
    ccansikdf_x963_ctx_clear(di, ctx);

    return rv;
}
