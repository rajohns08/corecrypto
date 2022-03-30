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

#include <stddef.h>
#include "config.h"
#include "AccelerateCrypto.h"

#if defined(__x86_64__)

extern void AccelerateCrypto_SHA512_compress_ssse3(uint64_t *state, size_t num, const void *buf) __asm__("_AccelerateCrypto_SHA512_compress_ssse3");
extern void AccelerateCrypto_SHA512_compress_AVX1(uint64_t *state, size_t num, const void *buf) __asm__("_AccelerateCrypto_SHA512_compress_AVX1");
extern void AccelerateCrypto_SHA512_compress_AVX2(uint64_t *state, size_t num, const void *buf)__asm__("_AccelerateCrypto_SHA512_compress_AVX2");

void  AccelerateCrypto_SHA512_compress(uint64_t *state, size_t num, const void *buf)
{
    if (HAS_AVX2()) AccelerateCrypto_SHA512_compress_AVX2(state, num, buf);
    else if (HAS_AVX1()) AccelerateCrypto_SHA512_compress_AVX1(state, num, buf);
    else 
        AccelerateCrypto_SHA512_compress_ssse3(state, num, buf);  
}
#endif  // defined(__x86_64__)
