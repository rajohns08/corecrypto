/* Copyright (c) (2011,2013,2015,2016,2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccrsa_priv.h>

int
ccrsa_decrypt_eme_pkcs1v15_blinded(struct ccrng_state *blinding_rng,
                           ccrsa_full_ctx_t key,
                           size_t *r_size, uint8_t *r,
                           size_t s_size, const uint8_t *s)
{
    size_t m_size = ccrsa_block_size(ccrsa_ctx_public(key));
    cc_size n=ccrsa_ctx_n(key);
    cc_unit tmp[n];
    int err;
    
    if(*r_size<m_size) return CCRSA_INVALID_INPUT;
    *r_size=m_size;

    if(ccn_read_uint(n, tmp, s_size, s)) return CCRSA_INVALID_INPUT;

    // RSA decryption
    if ((err = ccrsa_priv_crypt_blinded(blinding_rng, key, tmp, tmp)) == 0) {

        // Padding decoding
        err = ccrsa_eme_pkcs1v15_decode(r_size, r, m_size, tmp);
    }

    ccn_clear(n,tmp);
    return err;
}

