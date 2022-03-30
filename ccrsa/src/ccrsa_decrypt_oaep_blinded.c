/* Copyright (c) (2011,2012,2013,2015,2016,2019) Apple Inc. All rights reserved.
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
#include <corecrypto/cc_macros.h>


int
ccrsa_decrypt_oaep_blinded(struct ccrng_state *blinding_rng,
                   ccrsa_full_ctx_t key,
                   const struct ccdigest_info* di,
                   size_t *r_size, uint8_t *r,
                   size_t c_size, const uint8_t *c,
                   size_t parameter_data_len,
                   const uint8_t *parameter_data)
{
    size_t m_size = ccrsa_block_size(ccrsa_ctx_public(key));
    cc_size n=ccrsa_ctx_n(key);
    cc_unit tmp[n];
    int err;

    // Sanity check (PKCS1 v2.2, section 7.1.2, Length checking 1.c)
    if (m_size<di->output_size*2+2) {
        return CCRSA_INVALID_CONFIG;
    }

    // Output buffer is too small
    // (PKCS1 v2.2, section 7.1.2, Output definition)
    if(*r_size<m_size-di->output_size*2-2) {
        return CCRSA_INVALID_INPUT;
    }

    // The ciphertext does not match the expected size
    // Sanity check (PKCS1 v2.2, section 7.1.2, Length checking 1.b)
    if ((c_size<m_size)
        || (ccn_read_uint(n, tmp, c_size, c))) {
        return CCRSA_INVALID_INPUT;
    }

    // RSA decryption
    if ((err = ccrsa_priv_crypt_blinded(blinding_rng, key, tmp, tmp)) == 0) {

        // Padding decoding
        err = ccrsa_oaep_decode_parameter(di, r_size, r, m_size, tmp,
                                      parameter_data_len, parameter_data);
    }
    ccn_clear(n,tmp);
    return err;
}
