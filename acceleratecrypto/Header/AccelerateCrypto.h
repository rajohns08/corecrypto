/* Copyright (c) (2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef AccelerateCrypto_h
#define AccelerateCrypto_h

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/*! @abstract SHA-1 160-bit digest update for numBlocks chunks of 64-byte (512-bit) data.
 *
 *  @discussion
 *  This routine is optimized for x86_64 (SSE3,AVX1,AVX2), arm64 (CRYPTO), and armv7 (NEON).
 *
 *  @param state (input/output) Array of 5 uint32_t elements.
 *
 *  @param numBlocks (input) Number of 64-byte data chunks.
 *
 *  @param data (input) Array of size numBlocks*64 input bytes. 
 */
void AccelerateCrypto_SHA1_compress(uint32_t *state, size_t numBlocks, const void *data);

/*! @abstract SHA-256 256-bit digest update for numBlocks chunks of 64-byte (512-bit) data.
 *
 *  @discussion
 *  This routine is optimized for x86_64 (SSE3,AVX1,AVX2), arm64 (CRYPTO), and armv7 (NEON).
 *
 *  @param state (input/output) Array of 8 uint32_t elements.
 *
 *  @param numBlocks (input) Number of 64-byte data chunks.
 *
 *  @param data (input) Array of size numBlocks*64 input bytes. 
 */
void AccelerateCrypto_SHA256_compress(uint32_t *state, size_t numBlocks, const void *data);

#if defined(__arm64__)
void AccelerateCrypto_SHA256_compress_arm64neon(uint32_t *state, size_t numBlocks, const void *data);
#endif

/*! @abstract SHA-512 512-bit digest update for numBlocks chunks of 128-byte (1,024-bit) data.
 *
 *  @discussion
 *  This routine is optimized for x86_64 (SSE3,AVX1,AVX2), arm64 (NEON), and armv7 (NEON).
 *
 *  @param state (input/output) Array of 8 uint64_t elements.
 *
 *  @param numBlocks (input) Number of 128-byte data chunks.
 *
 *  @param data (input) Array of size numBlocks*128 input bytes. 
 */
void AccelerateCrypto_SHA512_compress(uint64_t *state, size_t numBlocks, const void *data);

#if defined(__arm64__)
void AccelerateCrypto_SHA512_compress_hwassist(uint64_t *state, size_t numBlocks, const void *data);
#endif

/* AES expanded key context */
#define KS_LENGTH   60
typedef struct
{   uint32_t ks[KS_LENGTH]; // maximum expanded key length = (14+1)*16 bytes = 15*16/4 = 60 uint32 words
    uint32_t rn;            // rn = 16*(10,12,14) for AES-128,192,256
} AccelerateCrypto_AES_ctx;


/*! @abstract AES function encrypts a 16-byte input buffer to a 16-byte output buffer according to 
 *  a given input expanded key context.
 *
 *  @discussion
 *  This routine is optimized for x86_64 (aesni), arm64 (CRYPTO), and armv7 (NEON).
 *
 *  @param in (input) Array of 16-byte message.
 *
 *  @param out (output) Array of 16-byte encrypted message.
 *
 *  @param key (input) Expanded key context for encryption.
 * 
 *  @return 0 on success; otherwise a nonzero number indicating failure in the encrypt function.
 *
 */
int AccelerateCrypto_AES_encrypt(const void *in, void *out, const AccelerateCrypto_AES_ctx *key);

/*! @abstract AES function decrypts a 16-byte input buffer to a 16-byte output buffer according to 
 *  a given input expanded key context.
 *
 *  @discussion
 *  This routine is optimized for x86_64 (aesni), arm64 (CRYPTO), and armv7 (NEON).
 *
 *  @param in (input) Array of 16-byte encrypted message.
 *
 *  @param out (output) Array of 16-byte decrypted message.
 *
 *  @param key (input) Expanded key context for decryption.
 *
 *  @return 0 on success; otherwise a nonzero number indicating failure in the decrypt function.
 *
 */
int AccelerateCrypto_AES_decrypt(const void *in, void *out, const AccelerateCrypto_AES_ctx *key);

#if defined(__arm64__)
int AccelerateCrypto_ecb_AES_encrypt(const AccelerateCrypto_AES_ctx *key, uint32_t nblocks, const void *in, void *out);
int AccelerateCrypto_ecb_AES_decrypt(const AccelerateCrypto_AES_ctx *key, uint32_t nblocks, const void *in, void *out);
#endif

#ifdef __cplusplus
}
#endif // __cplusplus

#endif  /* AccelerateCrypto_h */

