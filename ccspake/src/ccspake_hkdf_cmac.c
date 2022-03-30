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
#include <corecrypto/cchkdf.h>
#include <corecrypto/cccmac.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccspake.h>
#include "ccspake_priv.h"

/*! @function ccspake_mac_hkdf_cmac_derive
 @abstract Derive a key from the shared secret using HKDF

 @param ctx     SPAKE2+ context
 @param ikm_len Length of ikm
 @param ikm     Input key material
 @param keys_len Desired length of MAC key
 @param keys     MAC key

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((1, 3, 5))
static int
ccspake_mac_hkdf_cmac_derive(ccspake_const_ctx_t ctx, size_t ikm_len, const uint8_t *ikm, size_t keys_len, uint8_t *keys)
{
    const struct ccdigest_info *di = ccspake_ctx_mac(ctx)->di;

    uint8_t label[ccspake_kdf_label_size(ctx)];
    ccspake_build_kdf_label(ctx, label);

    return cchkdf(di, ikm_len, ikm, 0, NULL, sizeof(label), label, keys_len, keys);
}

/*! @function ccspake_mac_hkdf_cmac_compute
 @abstract Generate a CMAC for key confirmation

 @param ctx      SPAKE2+ context
 @param key_len  Length of MAC key
 @param key      MAC key
 @param info_len Length of info
 @param info     Transcript to compute MAC over
 @param t_len    Desired length of the MAC
 @param t        Output buffer for the MAC

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((1, 3, 5))
static int ccspake_mac_hkdf_cmac_compute(ccspake_const_ctx_t ctx,
                                         size_t key_len,
                                         const uint8_t *key,
                                         size_t info_len,
                                         const uint8_t *info,
                                         size_t t_len,
                                         uint8_t *t)
{
    const struct ccmode_cbc *cbc = ccspake_ctx_mac(ctx)->cbc;
    return cccmac_one_shot_generate(cbc, key_len, key, info_len, info, t_len, t);
}

static ccspake_mac_decl() ccspake_mac_hkdf_cmac_aes128_sha256_decl = {
    .derive = ccspake_mac_hkdf_cmac_derive,
    .compute = ccspake_mac_hkdf_cmac_compute,
};

ccspake_const_mac_t ccspake_mac_hkdf_cmac_aes128_sha256()
{
    ccspake_mac_hkdf_cmac_aes128_sha256_decl.di = ccsha256_di();
    ccspake_mac_hkdf_cmac_aes128_sha256_decl.cbc = ccaes_cbc_encrypt_mode();
    return (ccspake_const_mac_t)&ccspake_mac_hkdf_cmac_aes128_sha256_decl;
}
