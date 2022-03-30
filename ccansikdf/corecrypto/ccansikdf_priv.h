/* Copyright (c) (2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
#ifndef _CORECRYPTO_CCANSIKDF_PRIV_H_
#define _CORECRYPTO_CCANSIKDF_PRIV_H_

#include <corecrypto/ccansikdf.h>

/*
 Streaming API for ASNI x9.63 KDF.
 */

/*! @function ccansikdf_x963_init
 @abstract Initializes an ANSI x9.63 KDF context

 @param di      Digest information
 @param ctx     ANSI x9.63 KDF context
 @param key_len Byte length of key data to derive
 @param Z_len   Length of Z
 @param Z       Shared secret value

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((1, 2, 5))
int ccansikdf_x963_init(const struct ccdigest_info *di, ccansikdf_x963_ctx_t ctx, size_t key_len, size_t Z_len, const void *Z);

/*! @function ccansikdf_x963_update
 @abstract Feeds shared data into the KDF

 @param di   Digest information
 @param ctx  ANSI x9.63 KDF context
 @param len  Length of data
 @param data Shared data
 */
CC_NONNULL((1, 2))
void ccansikdf_x963_update(const struct ccdigest_info *di, ccansikdf_x963_ctx_t ctx, size_t len, const void *data);

/*! @function ccansikdf_x963_final
 @abstract Finalizes a KDF context and derives key data

 @param di  Digest information
 @param ctx ANSI x9.63 KDF context
 @param key Key data
 */
CC_NONNULL((1, 2, 3))
void ccansikdf_x963_final(const struct ccdigest_info *di, ccansikdf_x963_ctx_t ctx, void *key);

#endif /* _CORECRYPTO_CCANSIKDF_PRIV_H_ */
