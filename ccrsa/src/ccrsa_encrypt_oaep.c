/* Copyright (c) (2011,2012,2013,2015,2016,2018,2019,2020) Apple Inc. All rights reserved.
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
ccrsa_encrypt_oaep(ccrsa_pub_ctx_t key,
                   const struct ccdigest_info* di,
                   struct ccrng_state *rng,
                   size_t *r_size, uint8_t *r,
                   size_t s_size, const uint8_t *s,
                   size_t parameter_data_len,
                   const uint8_t *parameter_data)
{
    size_t m_size = ccrsa_block_size(key);
    cc_size n=ccrsa_ctx_n(key);
    cc_unit tmp[n];
    ccn_clear(n, tmp);
    int err;

    if ((m_size==0) || ccn_is_zero_or_one(ccrsa_ctx_n(key), ccrsa_ctx_m(key))) {
        return CCRSA_KEY_ERROR;
    }

    if(*r_size<m_size) {
        return CCRSA_INVALID_INPUT;
    }

    *r_size=m_size;
    err = ccrsa_oaep_encode_parameter(di, rng, m_size, tmp, s_size, s,
                                      parameter_data_len, parameter_data);
    if(err) return err;

    err = ccrsa_pub_crypt(key, tmp, tmp);
    if(err) return err;

    /* we need to write leading zeroes if necessary */
    ccn_write_uint_padded_ct(n, tmp, m_size, r);

    return 0;
}
