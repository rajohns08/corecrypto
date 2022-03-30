/* Copyright (c) (2017,2018,2019) Apple Inc. All rights reserved.
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

#include "ccaes_ios_mux_ctr.h"
#include "ccaes_vng_ctr.h"

const struct ccmode_ctr *small_ctr_crypt = NULL; // Set at runtime
const struct ccmode_ctr *large_ctr_crypt = &ccaes_ios_hardware_ctr_crypt_mode;

static int
ccaes_ios_mux_crypt_init(const struct ccmode_ctr *ctr CC_UNUSED, ccctr_ctx *key,
                               size_t rawkey_len, const void *rawkey,const void *iv)
{
    int rc;
    
    ccctr_ctx *smallctx = key;
    ccctr_ctx *largectx = (ccctr_ctx *) ((uint8_t *)key + small_ctr_crypt->size);
    
    rc =  small_ctr_crypt->init(small_ctr_crypt, smallctx, rawkey_len, rawkey, iv);
    rc |= large_ctr_crypt->init(large_ctr_crypt, largectx, rawkey_len, rawkey, iv);
    
    return rc;
}

// This routine now calls the ios hardware routine directly so it can use the number of
// blocks processed in cases of failure to open the device or partial decryption.
static int
ccaes_ios_mux_ctr_crypt(ccctr_ctx *ctrctx, size_t nbytes, const void *in, void *out)
{
    if (0 == nbytes) return 0;
    ccctr_ctx *smallctx = ctrctx;
    ccctr_ctx *largectx = (ccctr_ctx *) ((uint8_t *)ctrctx + small_ctr_crypt->size);
    // First use the existing pad
    size_t  pad_offset = CCMODE_CTR_KEY_PAD_OFFSET(smallctx);
    uint8_t *pad = (uint8_t *)CCMODE_CTR_KEY_PAD(smallctx);
    while ((nbytes>0)&&(pad_offset<CCAES_BLOCK_SIZE)) {
        *(uint8_t*)out++ = *(const uint8_t*)in++ ^ pad[pad_offset++];
        --nbytes;
    };
    CCMODE_CTR_KEY_PAD_OFFSET(smallctx) = pad_offset;

    // Use HW if over the cutover
    if((nbytes > AES_CTR_SWHW_CUTOVER*CCAES_BLOCK_SIZE)) {
        ccaes_hardware_aes_ctx_const_t ctx = (ccaes_hardware_aes_ctx_const_t) largectx;
        size_t processed = ccaes_ios_hardware_crypt(CCAES_HW_ENCRYPT|CCAES_HW_CTR, ctx, (uint8_t *)CCMODE_CTR_KEY_CTR(smallctx), in, out, nbytes/CCAES_BLOCK_SIZE);
        nbytes -= (processed*CCAES_BLOCK_SIZE);
        in = (const uint8_t*)in + (processed*CCAES_BLOCK_SIZE);
        out = (uint8_t*)out + (processed*CCAES_BLOCK_SIZE);
    }

    // Finish with the SW
    if(nbytes) {
        small_ctr_crypt->ctr(smallctx, nbytes, in, out);
    }
    
    return 0;
}


const struct ccmode_ctr *ccaes_ios_mux_ctr_crypt_mode()
{
    static struct ccmode_ctr ccaes_ios_mux_ctr_crypt_mode;
    static struct ccmode_ctr sw_mode;
    ccaes_vng_ctr_crypt_mode_setup(&sw_mode);
    small_ctr_crypt = &sw_mode;

    // Check support and performance of HW
    if (!ccaes_ios_hardware_enabled(CCAES_HW_DECRYPT|CCAES_HW_CTR)) return small_ctr_crypt;

    ccaes_ios_mux_ctr_crypt_mode.size = small_ctr_crypt->size + large_ctr_crypt->size + CCAES_BLOCK_SIZE;
    ccaes_ios_mux_ctr_crypt_mode.block_size = 1;
    ccaes_ios_mux_ctr_crypt_mode.ecb_block_size = CCAES_BLOCK_SIZE;
    ccaes_ios_mux_ctr_crypt_mode.init = ccaes_ios_mux_crypt_init;
    ccaes_ios_mux_ctr_crypt_mode.setctr = ccmode_ctr_setctr;
    ccaes_ios_mux_ctr_crypt_mode.ctr = ccaes_ios_mux_ctr_crypt;
    ccaes_ios_mux_ctr_crypt_mode.custom = NULL;
    return &ccaes_ios_mux_ctr_crypt_mode;
}


#endif /* CCAES_MUX */
