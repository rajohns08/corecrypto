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

#ifndef _CORECRYPTO_CCAES_IOS_HARDWARE_CBC_H_
#define _CORECRYPTO_CCAES_IOS_HARDWARE_CBC_H_

#include <corecrypto/cc_config.h>

#if CCAES_MUX

#include <stdint.h>
#include <string.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/cc_priv.h>

#define CCAES_HW_PRECOMPUTATION_NBLOCKS 8
#define CCAES_HW_ENCRYPT (1<<0)
#define CCAES_HW_DECRYPT (0<<0)
#define CCAES_HW_MODE    (1<<1)
#define CCAES_HW_CTR     (1<<1)
#define CCAES_HW_CBC     (0<<1)
#define AES_MAX_KEYSIZE 	CCAES_KEY_SIZE_256

typedef struct ccaes_hardware_aes_ctx {
    uint8_t keyBytes[AES_MAX_KEYSIZE];
    uint8_t padBytes[CCAES_BLOCK_SIZE*CCAES_HW_PRECOMPUTATION_NBLOCKS];
    uint8_t ctrBytes[CCAES_BLOCK_SIZE];
	size_t  keyLength;
    size_t  padLength;
    uint32_t init_complete;
} *ccaes_hardware_aes_ctx_t;

typedef const struct ccaes_hardware_aes_ctx* ccaes_hardware_aes_ctx_const_t;

extern size_t ccaes_hardware_block_quantum;
extern size_t ccaes_hardware_block_threshold;
extern uint32_t ccaes_hardware_support;

int
ccaes_ios_hardware_common_init(int operation, ccaes_hardware_aes_ctx_t ctx, size_t rawkey_len, const void *rawkey);

/* CBC support */

int
ccaes_ios_hardware_cbc_init(const struct ccmode_cbc *cbc CC_UNUSED, cccbc_ctx *key,
                            size_t rawkey_len, const void *rawkey);

/* CTR support */
int
ccaes_ios_hardware_ctr_init(const struct ccmode_ctr *ctr CC_UNUSED, ccctr_ctx *key,
                            size_t rawkey_len, const void *rawkey,const void *iv);

int
ccaes_ios_hardware_ctr_setctr(const struct ccmode_ctr *mode CC_UNUSED, ccctr_ctx *key, const void *ctr);

int
ccaes_ios_hardware_ctr_crypt(ccctr_ctx *ctrctx, size_t nbytes,
                                 const void *in, void *out);


/* Common to CTR and CBC support
   Returns the number of processed blocks
 */
size_t
ccaes_ios_hardware_crypt(int operation, ccaes_hardware_aes_ctx_const_t ctx, uint8_t *iv,
                                    const void *in, void *out, size_t nblocks);


size_t ccaes_get_hardware_threshold(void);
size_t ccaes_get_hardware_quantum(void);

#endif /* CCAES_MUX */

#endif /* _CORECRYPTO_CCAES_IOS_HARDWARE_CBC_H_ */
