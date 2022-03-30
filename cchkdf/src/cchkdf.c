/* Copyright (c) (2014,2015,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cchkdf.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/cc.h>
#include <corecrypto/cc_priv.h>

int cchkdf_extract(const struct ccdigest_info *di,
                   size_t salt_nbytes,
                   const void *salt,
                   size_t ikm_nbytes,
                   const void *ikm,
                   void *prk)
{
    uint8_t nullSalt[di->output_size];

    if (salt_nbytes == 0) {
        cc_clear(sizeof(nullSalt), nullSalt);
        salt = nullSalt;
        salt_nbytes = sizeof(nullSalt);
    }
    cchmac(di, salt_nbytes, salt, ikm_nbytes, ikm, prk);

    return 0;
}

int cchkdf_expand(const struct ccdigest_info *di,
                  size_t ikm_nbytes,
                  const void *ikm,
                  size_t info_nbytes,
                  const void *info,
                  size_t dk_nbytes,
                  void *dk)
{
    uint8_t key[di->output_size];
    size_t i, n, offset, Tlen;
    uint8_t T[di->output_size];
    uint8_t b;
    cchmac_di_decl(di, hc);

    n = (dk_nbytes / di->output_size) + ((dk_nbytes % di->output_size) ? 1 : 0);
    if (n > 255) {
        return -1;
    }

    // Initialize the local key material to the intermediate key material, or PRK
    cc_memcpy(key, ikm, ikm_nbytes);

    Tlen = 0;
    offset = 0;
    for (i = 1; i <= n; ++i) {
        cchmac_init(di, hc, di->output_size, key);
        cchmac_update(di, hc, Tlen, T);
        cchmac_update(di, hc, info_nbytes, info);
        b = (uint8_t)i;
        cchmac_update(di, hc, 1, &b);
        cchmac_final(di, hc, T);
        cc_memcpy(&dk[offset], T, (i != n) ? sizeof(T) : (dk_nbytes - offset));
        offset += sizeof(T);
        Tlen = sizeof(T);
    }

    cchmac_di_clear(di, hc);
    return 0;
}

int cchkdf(const struct ccdigest_info *di,
           size_t ikm_nbytes,
           const void *ikm,
           size_t salt_nbytes,
           const void *salt,
           size_t info_nbytes,
           const void *info,
           size_t dk_nbytes,
           void *dk)
{
    uint8_t key[di->output_size];

    int result = cchkdf_extract(di, salt_nbytes, salt, ikm_nbytes, ikm, key);
    if (result == 0) {
        result = cchkdf_expand(di, sizeof(key), key, info_nbytes, info, dk_nbytes, dk);
    }

    return result;
}
