/* Copyright (c) (2012,2015,2016,2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc_config.h>

#if CCAES_MUX

#include "ccaes_ios_mux_cbc.h"

const struct ccmode_cbc *small_cbc_decrypt = &ccaes_arm_cbc_decrypt_mode;
const struct ccmode_cbc *large_cbc_decrypt = &ccaes_ios_hardware_cbc_decrypt_mode;

static int
ccaes_ios_mux_cbc_decrypt_init(const struct ccmode_cbc *cbc CC_UNUSED, cccbc_ctx *key,
                               size_t rawkey_len, const void *rawkey)
{
    int rc;
    
    cccbc_ctx *smallctx = key;
    cccbc_ctx *largectx = (cccbc_ctx *) ((uint8_t *)key + small_cbc_decrypt->size);
    
    rc = small_cbc_decrypt->init(small_cbc_decrypt, smallctx, rawkey_len, rawkey);
    rc |= large_cbc_decrypt->init(large_cbc_decrypt, largectx, rawkey_len, rawkey);
    
    return rc;
}

// This routine now calls the ios hardware routine directly so it can use the number of
// blocks processed in cases of failure to open the device or partial decryption.
static int
ccaes_ios_mux_cbc_decrypt(const cccbc_ctx *cbcctx, cccbc_iv *iv, size_t nblocks, const void *in, void *out)
{
    if (0 == nblocks) return 0;
    
    const cccbc_ctx *smallctx = cbcctx;
    const cccbc_ctx *largectx = (const cccbc_ctx *) ((const uint8_t *)cbcctx + small_cbc_decrypt->size);
    if((nblocks > AES_CBC_SWHW_CUTOVER)) {
        ccaes_hardware_aes_ctx_const_t ctx = (ccaes_hardware_aes_ctx_const_t) largectx;
        size_t processed = ccaes_ios_hardware_crypt(CCAES_HW_DECRYPT, ctx, (uint8_t *)iv, in, out, nblocks);
        nblocks -= processed;
    }
    
    if(nblocks) {
        small_cbc_decrypt->cbc(smallctx, iv, nblocks, in, out);
    }
    
    return 0;
}


const struct ccmode_cbc *ccaes_ios_mux_cbc_decrypt_mode()
{
    static struct ccmode_cbc ccaes_ios_mux_cbc_decrypt_mode;

    // Check support and performance of HW
    if (!ccaes_ios_hardware_enabled(CCAES_HW_DECRYPT|CCAES_HW_CBC)) return small_cbc_decrypt;

    ccaes_ios_mux_cbc_decrypt_mode.size = small_cbc_decrypt->size + large_cbc_decrypt->size + CCAES_BLOCK_SIZE;
    ccaes_ios_mux_cbc_decrypt_mode.block_size = CCAES_BLOCK_SIZE;
    ccaes_ios_mux_cbc_decrypt_mode.init = ccaes_ios_mux_cbc_decrypt_init;
    ccaes_ios_mux_cbc_decrypt_mode.cbc = ccaes_ios_mux_cbc_decrypt;
    ccaes_ios_mux_cbc_decrypt_mode.custom = NULL;
    return &ccaes_ios_mux_cbc_decrypt_mode;
}


#endif /* CCAES_MUX */
