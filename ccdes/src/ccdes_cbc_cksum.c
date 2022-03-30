/* Copyright (c) (2012,2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccdes.h>
#include "ltc_des.h"
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccrng.h>

uint32_t
ccdes_cbc_cksum(const void *in, void *out, size_t in_nbytes,
                         const void *key, size_t key_nbytes, const void *ivec)
{
    const uint8_t *input = in;
    const uint8_t *inputiv = ivec;
    int rc;
    uint32_t uiv[2];
    uint32_t work[2] = { 0, 0 };
    ccecb_ctx_decl(sizeof(ltc_des_keysched), ecbdes);
    rc=ccdes_ltc_setup(NULL, ecbdes, key_nbytes, key);
    if (rc!=0) {
        // Usually we use error handling or at least input RNG handle,
        // Making an exception here to accomodate existing code
        cc_memset(work, 0xAA,sizeof(work)); // In case the RNG return NULL
        struct ccrng_state *rng=ccrng(NULL);
        if (rng != NULL) {
            ccrng_generate(rng,sizeof(work),work);
        }
        goto errOut;
    }
    ltc_des_keysched *des = (ltc_des_keysched *) &ecbdes;

    CC_LOAD32_BE(uiv[0], inputiv+0);
    CC_LOAD32_BE(uiv[1], inputiv+4);

    while (in_nbytes >= 8) {
        CC_LOAD32_BE(work[0], input+0);
        CC_LOAD32_BE(work[1], input+4);

        work[0] ^= uiv[0]; work[1] ^= uiv[1];
        desfunc((uint32_t *)work, des->ek);
        uiv[0] = work[0]; uiv[1] = work[1];

        in_nbytes -= 8;
        input += 8;
    }
    if (in_nbytes) {
        uint8_t tmp[8];
        cc_memcpy(tmp, input, in_nbytes);
        cc_clear(8 - in_nbytes,tmp + in_nbytes);
        CC_LOAD32_BE(work[0], tmp+0);
        CC_LOAD32_BE(work[1], tmp+4);

        work[0] ^= uiv[0]; work[1] ^= uiv[1];
        desfunc((uint32_t *)work, des->ek);
    }
errOut:
    if (out) {
        uint8_t *output = out;
        CC_STORE32_BE(work[0],output+0);
        CC_STORE32_BE(work[1],output+4);
    }

    uiv[0] = 0; work[0] = 0; uiv[1] = 0;
    ccecb_ctx_clear(sizeof(ltc_des_keysched), ecbdes);
    return work[1];
}
