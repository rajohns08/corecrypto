/* Copyright (c) (2010,2011,2012,2014,2015,2016,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccmode_internal.h"
#include <corecrypto/cc.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cc_priv.h>

/* c -> ecb -> xor iv -> p, iv = c, p += 1, c += 1. */
int ccmode_cbc_decrypt(const cccbc_ctx *key, cccbc_iv *iv,
                       size_t nblocks, const void *in, void *out) {
    const struct ccmode_ecb *ecb = ccmode_cbc_key_ecb(key);
    const ccecb_ctx *ecb_key = ccmode_cbc_key_ecb_key(key);
    if (nblocks) {
        const unsigned char *ct = in;
        unsigned char *pt = out;
        cc_unit tmp[ccn_nof_size(ecb->block_size)];
        for (;;) {
            ecb->ecb(ecb_key, 1, ct, tmp);
            /* We assume block_size % CCN_UNIT_SIZE == 0 which is true
               for CC_UNIT size up to 64 bits. */
            for (size_t x = 0; x < ecb->block_size; ++x) {
                uint8_t tmpy = ((uint8_t *)iv)[x] ^ ((uint8_t *)tmp)[x];
                ((uint8_t *)iv)[x] = ct[x];
                pt[x] = tmpy;
            }
            
            if (--nblocks) {
                pt += ecb->block_size;
                ct += ecb->block_size;
            } else {
                break;
            }
        }
    }
    
    return 0;
}
