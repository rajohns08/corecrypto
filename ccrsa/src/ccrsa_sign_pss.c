/* Copyright (c) (2015,2016,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccrsa_internal.h"

int ccrsa_sign_pss(const ccrsa_full_ctx_t key,
                   const struct ccdigest_info *hashAlgorithm,
                   const struct ccdigest_info *MgfHashAlgorithm,
                   size_t saltSize,
                   struct ccrng_state *rng,
                   size_t hSize,
                   const uint8_t *mHash,
                   size_t *sigSize,
                   uint8_t *sig)
{
    return ccrsa_sign_pss_blinded(ccrng(NULL), key, hashAlgorithm, MgfHashAlgorithm, saltSize, rng, hSize, mHash, sigSize, sig);
}

int ccrsa_sign_pss_msg(ccrsa_full_ctx_t key,
                       const struct ccdigest_info *hashAlgorithm,
                       const struct ccdigest_info *MgfHashAlgorithm,
                       size_t salt_nbytes,
                       struct ccrng_state *rng,
                       size_t msg_nbytes,
                       const uint8_t *msg,
                       size_t *sig_nbytes,
                       uint8_t *sig)
{
    uint8_t digest[hashAlgorithm->output_size];
    ccdigest(hashAlgorithm, msg_nbytes, msg, digest);

    return ccrsa_sign_pss(
        key, hashAlgorithm, MgfHashAlgorithm, salt_nbytes, rng, hashAlgorithm->output_size, digest, sig_nbytes, sig);
}
