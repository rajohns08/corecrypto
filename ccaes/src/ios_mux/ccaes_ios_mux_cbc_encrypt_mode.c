/* Copyright (c) (2012,2013,2015,2016,2017,2019) Apple Inc. All rights reserved.
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

const struct ccmode_cbc *small_cbc_encrypt = &ccaes_arm_cbc_encrypt_mode;
const struct ccmode_cbc *large_cbc_encrypt = &ccaes_ios_hardware_cbc_encrypt_mode;

static int
ccaes_ios_mux_cbc_encrypt_init(const struct ccmode_cbc *cbc CC_UNUSED, cccbc_ctx *key,
                               size_t rawkey_len, const void *rawkey)
{
    int rc;
    
    cccbc_ctx *smallctx = key;
    cccbc_ctx *largectx = (cccbc_ctx *) ((uint8_t *)key + small_cbc_encrypt->size);
    
    rc = small_cbc_encrypt->init(small_cbc_encrypt, smallctx, rawkey_len, rawkey);
    rc |= large_cbc_encrypt->init(large_cbc_encrypt, largectx, rawkey_len, rawkey);
    
    return rc;
}

// This routine now calls the ios hardware routine directly so it can use the number of
// blocks processed in cases of failure to open the device or partial encryption.
static int
ccaes_ios_mux_cbc_encrypt(const cccbc_ctx *cbcctx, cccbc_iv *iv, size_t nblocks, const void *in, void *out)
{
    if (0 == nblocks) return 0;
    
    const cccbc_ctx *smallctx = cbcctx;
    const cccbc_ctx *largectx = (const cccbc_ctx *) ((const uint8_t *)cbcctx + small_cbc_encrypt->size);
    if((nblocks > AES_CBC_SWHW_CUTOVER)) {
        ccaes_hardware_aes_ctx_const_t ctx = (ccaes_hardware_aes_ctx_const_t) largectx;
        size_t processed = ccaes_ios_hardware_crypt(CCAES_HW_ENCRYPT, ctx, (uint8_t*)iv, in, out, nblocks);
        nblocks -= processed;
    }

    if(nblocks) {
        small_cbc_encrypt->cbc(smallctx, iv, nblocks, in, out);
    }
    
    return 0;
}


const struct ccmode_cbc *ccaes_ios_mux_cbc_encrypt_mode(void)
{
    static struct ccmode_cbc ccaes_ios_mux_cbc_encrypt_mode;

    // Check support and performance of HW
    if (!ccaes_ios_hardware_enabled(CCAES_HW_ENCRYPT|CCAES_HW_CBC)) return small_cbc_encrypt;

    ccaes_ios_mux_cbc_encrypt_mode.size = small_cbc_encrypt->size + large_cbc_encrypt->size + CCAES_BLOCK_SIZE;
    ccaes_ios_mux_cbc_encrypt_mode.block_size = CCAES_BLOCK_SIZE;
    ccaes_ios_mux_cbc_encrypt_mode.init = ccaes_ios_mux_cbc_encrypt_init;
    ccaes_ios_mux_cbc_encrypt_mode.cbc = ccaes_ios_mux_cbc_encrypt;
    ccaes_ios_mux_cbc_encrypt_mode.custom = NULL;
    return &ccaes_ios_mux_cbc_encrypt_mode;
}



#endif /* CCAES_MUX */
