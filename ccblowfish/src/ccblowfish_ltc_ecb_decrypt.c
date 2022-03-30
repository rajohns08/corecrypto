/* Copyright (c) (2010,2011,2012,2015,2016,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

/*
 * Parts of this code adapted from LibTomCrypt
 *
 * LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

#include <corecrypto/ccblowfish.h>
#include <corecrypto/cc_priv.h>
#include "ltc_blowfish.h"

/*!
 Decrypts a block of text with Blowfish
 @param ct The input ciphertext (8 bytes)
 @param pt The output plaintext (8 bytes)
 @param skey The key as scheduled 
 */
#ifdef LTC_CLEAN_STACK
static int _ltc_blowfish_ecb_decrypt(const ccecb_ctx *skey, size_t nblocks, const void *in, void *out)
#else
static int ccblowfish_ltc_ecb_decrypt(const ccecb_ctx *skey, size_t nblocks, const void *in, void *out)
#endif
{
    uint32_t L, R;
    int r;
#ifndef __GNUC__
    const uint32_t *S1, *S2, *S3, *S4;
#endif
    const unsigned char *ct = in;
    unsigned char *pt = out;
    const ltc_blowfish_keysched *xkey = (const ltc_blowfish_keysched *)skey;
    
#ifndef __GNUC__
    S1 = xkey->S[0];
    S2 = xkey->S[1];
    S3 = xkey->S[2];
    S4 = xkey->S[3];
#endif
    
    while(nblocks--) {
        /* load it */
        CC_LOAD32_BE(R, &ct[0]);
        CC_LOAD32_BE(L, &ct[4]);
        
        /* undo last keying */
        R ^= xkey->K[17];
        L ^= xkey->K[16];
        
        /* do 16 rounds */
        for (r = 15; r > 0; ) {
            L ^= LTC_F(R); R ^= xkey->K[r--];
            R ^= LTC_F(L); L ^= xkey->K[r--];
            L ^= LTC_F(R); R ^= xkey->K[r--];
            R ^= LTC_F(L); L ^= xkey->K[r--];
        }
        
        /* store */
        CC_STORE32_BE(L, &pt[0]);
        CC_STORE32_BE(R, &pt[4]);
        
        pt += CCBLOWFISH_BLOCK_SIZE;
        ct += CCBLOWFISH_BLOCK_SIZE;
    }
    
    return 0;
}

#ifdef LTC_CLEAN_STACK
static int ccblowfish_ltc_ecb_decrypt(const ccecb_ctx *skey, size_t nblocks, const void *in, void *out)
{
    int err = _ltc_blowfish_ecb_decrypt(skey, nblocks, in, out);
    
    ltc_burn_stack(sizeof(uint32_t) * 2 + sizeof(int));
    return err;
}
#endif


const struct ccmode_ecb ccblowfish_ltc_ecb_decrypt_mode = {
    .size = sizeof(ltc_blowfish_keysched),
    .block_size = CCBLOWFISH_BLOCK_SIZE,
    .init = ccblowfish_ltc_setup,
    .ecb = ccblowfish_ltc_ecb_decrypt
};
