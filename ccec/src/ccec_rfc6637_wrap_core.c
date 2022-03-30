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

struct ccec_rfc6637_wrap {
    struct ccec_rfc6637 *pgp;
    const struct ccmode_ecb * (*enc)(void);
};

struct ccec_rfc6637_wrap ccec_rfc6637_wrap_sha256_kek_aes128 = {
    .pgp = &ccec_rfc6637_sha256_kek_aes128,
    .enc = ccaes_ecb_encrypt_mode,
};

struct ccec_rfc6637_wrap ccec_rfc6637_wrap_sha512_kek_aes256 = {
    .pgp = &ccec_rfc6637_sha512_kek_aes256,
    .enc = ccaes_ecb_encrypt_mode,
};


int
ccec_rfc6637_wrap_core(ccec_pub_ctx_t  public_key,
                       ccec_full_ctx_t ephemeral_key,
                      void *wrapped_key,
                      unsigned long flags,
                      uint8_t symm_alg_id,
                      size_t key_len,
                      const void *key,
                      const struct ccec_rfc6637_curve *curve,
                      const struct ccec_rfc6637_wrap *wrap,
                      const uint8_t *fingerprint, /* 20 bytes */
                      struct ccrng_state *rng)
{
    const struct ccdigest_info *di = wrap->pgp->difun();
    size_t n;
    uint8_t m[40];
    int res;
    if (key_len > sizeof(m) - 1 - 2 - 1) /* ALG-ID, CHECKSUM, pkcs5 padding */
        return -1;

    if (di->output_size < wrap->pgp->keysize)
        return -1;

    size_t skey_size = ccec_cp_prime_size(ccec_ctx_cp(public_key));
    uint8_t skey[skey_size];

    res = ccecdh_compute_shared_secret(ephemeral_key, public_key, &skey_size, skey,rng);
    if (res)
        return res;

    /*
     * generate m(essage)
     */

    m[0] = symm_alg_id;
    cc_memcpy(&m[1], key, key_len);
    uint16_t cksum = pgp_key_checksum(key_len, key);
    m[1 + key_len + 0] = (cksum >> 8) & 0xff;
    m[1 + key_len + 1] = (cksum     ) & 0xff;
    size_t padbyte = sizeof(m) - 1 - key_len - 2;
    for (n = 1 + key_len + 2; n < sizeof(m); n++)
        m[n] = (uint8_t)padbyte;

    /*
     * KDF
     */
    uint8_t hash[di->output_size];

    ccec_rfc6637_kdf(di, curve, wrap->pgp, skey_size, skey, 20, fingerprint, hash);
    cc_clear(skey_size, skey);

    /* MPI(public_key) | len(C) (byte) | C */
    uint8_t *output = wrapped_key;

    size_t  ephemeral_key_size=ccec_rfc6637_wrap_pub_size(ccec_ctx_pub(ephemeral_key),flags);
    uint8_t epkey[ephemeral_key_size];
    if (flags & CCEC_RFC6637_COMPACT_KEYS)
        ccec_compact_export(0, epkey, ephemeral_key);
    else
        ccec_export_pub(ccec_ctx_pub(ephemeral_key), epkey);

    size_t t = sizeof(epkey) * 8;
    output[0] = (t >> 8) & 0xff;
    output[1] = (t     ) & 0xff;
    cc_memcpy(&output[2], epkey, sizeof(epkey));
    output[2 + sizeof(epkey) + 0] = sizeof(m);
    cc_memcpy(&output[2 + sizeof(epkey) + 1], m, sizeof(m));

    /*
     * wrap
     */

    const struct ccmode_ecb *ecbmode = wrap->enc();

    ccecb_ctx_decl(ccecb_context_size(ecbmode), ecb);
    ccecb_init(ecbmode, ecb, wrap->pgp->keysize, hash);
    cc_clear(sizeof(hash),hash);

    size_t obytes;

    res = ccwrap_auth_encrypt(ecbmode, ecb, sizeof(m), m, &obytes, &output[2 + sizeof(epkey) + 1]);
    ccecb_ctx_clear(ccecb_context_size(ecbmode), ecb);
    assert (obytes == sizeof(m) + ecbmode->block_size / 2);

    output[2 + sizeof(epkey) + 0] = (uint8_t)obytes;

    if (flags & CCEC_RFC6637_DEBUG_KEYS) {
        output[2 + sizeof(epkey) + 1 + obytes] = (uint8_t)key_len;
        output[2 + sizeof(epkey) + 1 + obytes + 1] = (uint8_t)skey_size;
        cc_memcpy(&output[2 + sizeof(epkey) + 1 + obytes + 2], key, key_len);
        cc_memcpy(&output[2 + sizeof(epkey) + 1 + obytes + 2 + key_len], skey, skey_size);
    }

    return res;
}
