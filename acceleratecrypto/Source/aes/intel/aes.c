/* Copyright (c) (2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#if (defined(__x86_64__) || defined(__i386__))
#include <stddef.h>
#include "config.h"
#include "AccelerateCrypto.h"


extern int aes_encrypt_aesni(const void *in, void *out, const AccelerateCrypto_AES_ctx *key);
extern int aes_decrypt_aesni(const void *in, void *out, const AccelerateCrypto_AES_ctx *key);
extern int aes_encrypt_nonaesni(const void *in, void *out, const AccelerateCrypto_AES_ctx *key);
extern int aes_decrypt_nonaesni(const void *in, void *out, const AccelerateCrypto_AES_ctx *key);

int AccelerateCrypto_AES_encrypt(const void *in, void *out, const AccelerateCrypto_AES_ctx *key)
{
    if (HAS_AESNI()) return aes_encrypt_aesni(in, out, key);
    else 
        return aes_encrypt_nonaesni(in, out, key);
}

int AccelerateCrypto_AES_decrypt(const void *in, void *out, const AccelerateCrypto_AES_ctx *key)
{
    if (HAS_AESNI()) return aes_decrypt_aesni(in, out, key);
    else 
        return aes_decrypt_nonaesni(in, out, key);
}

#endif  // (defined(__x86_64__) || defined(__i386__))

