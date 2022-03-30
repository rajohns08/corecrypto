/* Copyright (c) (2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccec_priv.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccwrap.h>
#include "ccec_internal.h"

struct ccec_rfc6637_unwrap {
    struct ccec_rfc6637 *pgp;
    const struct ccmode_ecb * (*dec)(void);
};

struct ccec_rfc6637_unwrap ccec_rfc6637_unwrap_sha256_kek_aes128 = {
    .pgp = &ccec_rfc6637_sha256_kek_aes128,
    .dec = ccaes_ecb_decrypt_mode,
};

struct ccec_rfc6637_unwrap ccec_rfc6637_unwrap_sha512_kek_aes256 = {
    .pgp = &ccec_rfc6637_sha512_kek_aes256,
    .dec = ccaes_ecb_decrypt_mode,
};

int
ccec_rfc6637_unwrap_key(ccec_full_ctx_t private_key,
                        size_t *key_len,
                        void *key,
                        unsigned long flags,
                        uint8_t *symm_key_alg,
                        const struct ccec_rfc6637_curve *curve,
                        const struct ccec_rfc6637_unwrap *unwrap,
                        const uint8_t *fingerprint,
                        size_t wrapped_key_len,
                        const void  *wrapped_key)
{
    const struct ccdigest_info *di = unwrap->pgp->difun();
    const uint8_t *wkey = wrapped_key;
    int res;

    if (di->output_size < unwrap->pgp->keysize)
        return -1;

    if (wrapped_key_len < 5)
        return -1;

    size_t wkey_size = CC_BITLEN_TO_BYTELEN(((size_t)wkey[0] << 8) | wkey[1]);
    if (wkey_size > wrapped_key_len - 2 - 1)
        return -1;

    size_t wrapped_size = wkey[2 + wkey_size];
    if ((flags & CCEC_RFC6637_DEBUG_KEYS)) {
        if (wrapped_key_len < 2 + wkey_size + 1 + wrapped_size)
            return -1;
    } else if (wrapped_key_len != 2 + wkey_size + 1 + wrapped_size) {
        return -1;
    }

    /*
     * Generate a empheral keypair and share keypublic key
     */

    ccec_const_cp_t cp = ccec_ctx_cp(private_key);

    ccec_pub_ctx_decl_cp(cp, ephemeral_key); ccec_ctx_init(cp, ephemeral_key);

    /*
     * There is no ccec_NNN_IMPORT_pub_size()
     */
    if (ccec_export_pub_size(ephemeral_key) == wkey_size) {
        res = ccec_import_pub(cp, wkey_size, &wkey[2], ephemeral_key);
    } else if ((flags & CCEC_RFC6637_COMPACT_KEYS) && ccec_compact_export_size(0, ephemeral_key) >= wkey_size) {
        res = ccec_compact_import_pub(cp, wkey_size, &wkey[2], ephemeral_key);
    } else {
        res = -1;
    }
    if (res)
        return res;

    size_t skey_size = ccec_cp_prime_size(cp);

    uint8_t skey[skey_size];
    res = ccecdh_compute_shared_secret(private_key, ephemeral_key, &skey_size, skey, NULL);
    if (res)
        return res;
    
    /*
     * KDF
     */
    uint8_t hash[di->output_size];
    
    ccec_rfc6637_kdf(di, curve, unwrap->pgp, skey_size, skey, 20, fingerprint, hash);
    cc_clear(sizeof(skey), skey);

    /*
     * unwrap
     */
    
    const struct ccmode_ecb *ecbmode = unwrap->dec();
    
    ccecb_ctx_decl(ccecb_context_size(ecbmode), ecb);
    ccecb_init(ecbmode, ecb, unwrap->pgp->keysize, hash);
    cc_clear(sizeof(hash), hash);


    uint8_t m[wrapped_size];
    size_t m_size = wrapped_size;
    
    res = ccwrap_auth_decrypt(ecbmode, ecb, wrapped_size, &wkey[2 + wkey_size + 1], &m_size, m);
    ccecb_ctx_clear(ccecb_context_size(ecbmode), ecb);
    if (res)
        return res;

    /*
     * validate key
     */

    if (m_size < 1 || m_size > sizeof(m) - 1)
        return -1;

    *symm_key_alg = m[0];

    uint8_t padding = m[m_size - 1];

    /*
     * Don't need to make this constant time since ccwrap_auth_decrypt() have a checksum.
     */
    if (padding > m_size - 1 - 2)
        return -1;

    size_t n;
    for (n = 0; n < padding; n++)
        if (m[m_size - 1 - n] != padding)
            return -1;

    if (*key_len >= m_size - 1 - 2 - padding)
        *key_len = m_size - 1 - 2 - padding;
    else
        return -1;

    /*
     * validate key checksum
     */

    uint16_t cksum = pgp_key_checksum(*key_len, m + 1);
    if (((cksum >> 8) & 0xff) != m[1 + *key_len] || (cksum & 0xff) != m[1 + *key_len + 1])
        return -1;

    cc_memcpy(key, m + 1, *key_len);

    return res;
}
