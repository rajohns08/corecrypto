/* Copyright (c) (2014,2015,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef corecrypto_ccansikdf_h
#define corecrypto_ccansikdf_h

#include <corecrypto/ccdigest.h>
#include <corecrypto/cc_priv.h>

struct ccansikdf_x963_ctx {
    size_t klen;
    CC_ALIGNED(8) struct ccdigest_ctx dis[1];
} CC_ALIGNED(8);

typedef struct ccansikdf_x963_ctx *ccansikdf_x963_ctx_t;

#define ccansikdf_x963_padded_entry_size(_di_) (cc_ceiling(sizeof(struct ccdigest_ctx) + ccdigest_di_size(_di_), 8) * 8)
#define ccansikdf_x963_storage_size(_di_, _klen_) cc_ceiling(_klen_, _di_->output_size) * ccansikdf_x963_padded_entry_size(_di_)
#define ccansikdf_x963_ctx_decl(_di_, _klen_, _name_) \
    cc_ctx_decl(struct ccansikdf_x963_ctx, ccansikdf_x963_storage_size(_di_, _klen_), _name_)
#define ccansikdf_x963_ctx_clear(_di_, _name_) cc_clear(ccansikdf_x963_storage_size(_di_, _name_->klen), _name_)

/*
 ANSI x9.63 KDF as per x9.63-2011 specification.
 with granularity in bytes.

 Input: The input to the key derivation function is:
 1. A byte string Z that is the shared secret value, of byte length lenZ.
 2. An integer keydatalen that is the length in byte of the keying data to be generated. keydatalen shall be less than (2^32–1)
 hashlen
 3. A byte string SharedInfo that consists of some data shared by the two entities intended to share the secret value Z. The total
 byte length of Z and SharedInfo must be at most maxhashlen – 4.

 Approved digest functions are for output >= 224bit that is SHA-224 and beyond.
 SHA-1 is not forbidden but should only be used for interroperability requirements.
 */

CC_NONNULL((1, 3, 7))
int ccansikdf_x963(const struct ccdigest_info *di,
                   const size_t Z_len,
                   const unsigned char *Z,
                   const size_t sharedinfo_byte_len,
                   const void *sharedinfo,
                   const size_t key_len,
                   uint8_t *key);

#endif
