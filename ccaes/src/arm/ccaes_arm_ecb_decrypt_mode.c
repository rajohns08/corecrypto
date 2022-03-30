/* Copyright (c) (2011,2012,2014,2015,2016,2018,2019) Apple Inc. All rights reserved.
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
#include <corecrypto/ccmode.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/cc_priv.h>

#include "arm_aes.h"

#if CCAES_ARM_ASM

#if defined(__arm64__)
extern int ccaes_arm_decrypt_key(const struct ccmode_ecb *, ccecb_ctx *, size_t, const void *);
extern int ccaes_arm_decrypt_ecb(const ccecb_ctx *, size_t, const void *, void *);
const struct ccmode_ecb ccaes_arm_ecb_decrypt_mode = {
    .size = sizeof(ccaes_arm_decrypt_ctx),
    .block_size = CCAES_BLOCK_SIZE,
    .init = ccaes_arm_decrypt_key,
    .ecb = ccaes_arm_decrypt_ecb,
};
#else

static int init_wrapper(const struct ccmode_ecb *ecb CC_UNUSED, ccecb_ctx *key,
                        size_t rawkey_len, const void *rawkey)
{
    ccaes_arm_decrypt_ctx *ctx = (ccaes_arm_decrypt_ctx *) key;
    uint32_t alignkey[rawkey_len/sizeof(uint32_t)];

    cc_memcpy(alignkey, rawkey, rawkey_len); /* arm implementation requires 32bits aligned key */
    
    return ccaes_arm_decrypt_key((const unsigned char *)alignkey, (int)rawkey_len, ctx);
}

#if CC_ACCELERATECRYPTO
#include "AccelerateCrypto.h"
#endif

/* cbc encrypt or decrypt nblocks from in to out. */
static int ecb_wrapper(const ccecb_ctx *key, size_t nblocks, const void *in,
                       void *out)
{
    const ccaes_arm_decrypt_ctx *ctx = (const ccaes_arm_decrypt_ctx *) key;

#if CC_KERNEL
	if ((((int)in&0x03)==0) && (((int)out&0x03)==0)) {        // both in and out are word aligned, which is needed in assembly implementation
#endif
        while(nblocks--) {
#if CC_ACCELERATECRYPTO
            if (AccelerateCrypto_AES_decrypt(in, out, (const AccelerateCrypto_AES_ctx *) ctx)) {
#else
            if (ccaes_arm_decrypt(in, out, ctx)) {
#endif
                return -1;
            }
            in += CCAES_BLOCK_SIZE;
            out += CCAES_BLOCK_SIZE;
        }
#if CC_KERNEL
    } else {
        uint32_t tin[CCAES_BLOCK_SIZE/sizeof(uint32_t)];
        uint32_t tout[CCAES_BLOCK_SIZE/sizeof(uint32_t)];
        while(nblocks--) {
            cc_memcpy((void*)tin, in, CCAES_BLOCK_SIZE);
#if CC_ACCELERATECRYPTO
            if (AccelerateCrypto_AES_decrypt((const void *)tin, (void *)tout, (const AccelerateCrypto_AES_ctx *) ctx)) {
#else
            if (ccaes_arm_decrypt((const unsigned char*)tin, (unsigned char *)tout, ctx)) {
#endif
                return -1;
            }
            cc_memcpy(out, (void*)tout, CCAES_BLOCK_SIZE);
            in += CCAES_BLOCK_SIZE;
            out += CCAES_BLOCK_SIZE;
        }
    }
#endif
    return 0;
}

const struct ccmode_ecb ccaes_arm_ecb_decrypt_mode = {
    .size = sizeof(ccaes_arm_decrypt_ctx),
    .block_size = CCAES_BLOCK_SIZE,
    .init = init_wrapper,
    .ecb = ecb_wrapper,
};
#endif

#endif /* CCAES_ARM_ASM */

