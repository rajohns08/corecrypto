/* Copyright (c) (2010,2011,2012,2015,2016,2017,2019) Apple Inc. All rights reserved.
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

static int
ccaes_ios_hardware_cbc_encrypt(const cccbc_ctx *cbcctx, cccbc_iv *iv, size_t nblocks,
                               const void *in, void *out)
{
    ccaes_hardware_aes_ctx_const_t ctx = (ccaes_hardware_aes_ctx_const_t) cbcctx;
    (void) ccaes_ios_hardware_crypt(CCAES_HW_ENCRYPT, ctx, (uint8_t *)iv, in, out, nblocks);
    return 0;
}

const struct ccmode_cbc ccaes_ios_hardware_cbc_encrypt_mode = {
    .size = sizeof(struct ccaes_hardware_aes_ctx),
    .block_size = CCAES_BLOCK_SIZE,
    .init = ccaes_ios_hardware_cbc_init,
    .cbc = ccaes_ios_hardware_cbc_encrypt,
    .custom = NULL,
};

#endif /* CCAES_MUX */
