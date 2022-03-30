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
#include "ccaes_ios_hardware.h"
#include "cc_debug.h"
#include "cc_macros.h"
#include "ccmode_internal.h"

int
ccaes_ios_hardware_ctr_init(const struct ccmode_ctr *mode, ccctr_ctx *key,
                            size_t rawkey_len, const void *rawkey,const void *iv)
{
    int status = 0;
    ccaes_hardware_aes_ctx_t ctx = (ccaes_hardware_aes_ctx_t) key;
    status = ccaes_ios_hardware_common_init(CCAES_HW_CTR,ctx,rawkey_len,rawkey);
    cc_require(status==0,errOut);
    status = ccaes_ios_hardware_ctr_setctr(mode, key, iv);
    ctx->padLength=0;
errOut:
    return status;
}

int
ccaes_ios_hardware_ctr_setctr(const struct ccmode_ctr *mode CC_UNUSED, ccctr_ctx *key, const void *ctr)
{
    ccaes_hardware_aes_ctx_t ctx = (ccaes_hardware_aes_ctx_t) key;
    cc_memcpy(&ctx->ctrBytes[0], ctr, sizeof(ctx->ctrBytes));
    // Discard the remaining pad if any
    ctx->padLength=0;
    cc_clear(sizeof(ctx->padBytes),ctx->padBytes);
    return 0;
}

int
ccaes_ios_hardware_ctr_crypt(ccctr_ctx *ctrctx, size_t nbytes,
                             const void *in, void *out) {

    const int operation = CCAES_HW_CTR | CCAES_HW_ENCRYPT;
    ccaes_hardware_aes_ctx_t ctx = (ccaes_hardware_aes_ctx_t)ctrctx;
    // First, process from the precomputed pad (key stream)
    size_t read_from_pad_nbytes = CC_MIN(nbytes,ctx->padLength);
    if (read_from_pad_nbytes>sizeof(ctx->padBytes)) {
        read_from_pad_nbytes=0; // Defensive check, should not happen.
    }
    cc_xor(read_from_pad_nbytes,out,in,&ctx->padBytes[sizeof(ctx->padBytes)-ctx->padLength]);
    ctx->padLength -= read_from_pad_nbytes;

    // Move pointers forward
    in = (const uint8_t *)in + read_from_pad_nbytes;
    out = (uint8_t *)out + read_from_pad_nbytes;
    nbytes -= read_from_pad_nbytes;

    // Process whole blocks
    size_t process_blocks = nbytes / CCAES_BLOCK_SIZE;
    process_blocks = ccaes_ios_hardware_crypt(operation,ctx,ctx->ctrBytes,in,out,process_blocks);

    // Process what is left
    size_t process_blocks_nbytes = (process_blocks*CCAES_BLOCK_SIZE);
    cc_assert(process_blocks_nbytes<=nbytes);
    
    // Move pointers forward
    in = (const uint8_t *)in + process_blocks_nbytes;
    out = (uint8_t *)out + process_blocks_nbytes;
    nbytes -= process_blocks_nbytes;

    // If more to process, we use the pad buffer
    cc_assert(ccaes_hardware_block_threshold*CCAES_BLOCK_SIZE<=sizeof(ctx->padBytes));
    if (nbytes>0) {
        // Fill up pad buffer
        cc_assert(ctx->padLength==0);
        cc_assert((sizeof(ctx->padBytes) % CCAES_BLOCK_SIZE) == 0);
        cc_clear(sizeof(ctx->padBytes),ctx->padBytes);
        process_blocks=ccaes_ios_hardware_crypt(operation,ctx,ctx->ctrBytes,ctx->padBytes,ctx->padBytes,(sizeof(ctx->padBytes)/CCAES_BLOCK_SIZE));

        ctx->padLength = process_blocks*CCAES_BLOCK_SIZE;

        // Process from pad buffer
        read_from_pad_nbytes = CC_MIN(nbytes,ctx->padLength);
        cc_xor(read_from_pad_nbytes,out,in,&ctx->padBytes[sizeof(ctx->padBytes)-ctx->padLength]);
        ctx->padLength -= read_from_pad_nbytes;
        nbytes -= read_from_pad_nbytes;
    }
    return (nbytes==0)?0:CCMODE_INTERNAL_ERROR;
}



#endif /* CCAES_MUX */

