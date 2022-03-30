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

#include <corecrypto/ccecies.h>

#include <corecrypto/ccec_priv.h>
#include <corecrypto/ccmode.h>
#include "ccansikdf_priv.h"
#include "ccecies_internal.h"
#include "cc_debug.h"
#include <corecrypto/cc_macros.h>

int ccecies_encrypt_gcm_composite(ccec_pub_ctx_t public_key,
                                  const ccecies_gcm_t ecies,
                                  uint8_t *exported_public_key, /* output - length from ccecies_pub_key_nbytes */
                                  uint8_t *ciphertext,          /* output - length same as plaintext_nbytes */
                                  uint8_t *mac_tag,             /* output - length ecies->mac_nbytesgth */
                                  size_t plaintext_nbytes,
                                  const uint8_t *plaintext,
                                  size_t sharedinfo1_nbytes,
                                  const void *sharedinfo1,
                                  size_t sharedinfo2_nbytes,
                                  const void *sharedinfo2)
{
    int status = CCERR_INTERNAL;
    // Buffers for key material
    size_t shared_secret_nbytes = ccec_cp_prime_size(ccec_ctx_cp(public_key));
    uint8_t shared_secret[shared_secret_nbytes];

    // ECDH - Ephemeral-static
    ccec_const_cp_t cp = ccec_ctx_cp(public_key);
    ccec_full_ctx_decl_cp(cp, ephemeral_key);

    // Generate ephemeral EC key pair
    cc_assert(ecies->rng != NULL);
    status = ccecdh_generate_key(cp, ecies->rng, ephemeral_key);
    cc_require(status == 0, errOut);

#if CC_DEBUG_ECIES
    ccec_print_full_key("Ephemeral key", ephemeral_key);
#endif

    // 2) ECDH with input public key
    status = ccecdh_compute_shared_secret(ephemeral_key, public_key, &shared_secret_nbytes, shared_secret, ecies->rng);
    cc_require(status == 0, errOut);

    // Key derivation and symmetric encryption
    status = ccecies_encrypt_gcm_from_shared_secret_composite(public_key,
                                                              ecies,
                                                              ccec_ctx_pub(ephemeral_key),
                                                              shared_secret_nbytes,
                                                              shared_secret,
                                                              plaintext_nbytes,
                                                              plaintext,
                                                              sharedinfo1_nbytes,
                                                              sharedinfo1,
                                                              sharedinfo2_nbytes,
                                                              sharedinfo2,
                                                              exported_public_key,
                                                              ciphertext,
                                                              mac_tag);
    cc_require(status == 0, errOut);

errOut:
    // Clear key material info
    cc_clear(sizeof(shared_secret), shared_secret);
    return status;
}

int ccecies_encrypt_gcm(ccec_pub_ctx_t public_key,
                        const ccecies_gcm_t ecies,
                        size_t plaintext_nbytes,
                        const uint8_t *plaintext,
                        size_t sharedinfo1_nbytes,
                        const void *sharedinfo1,
                        size_t sharedinfo2_nbytes,
                        const void *sharedinfo2,
                        size_t *encrypted_blob_nbytes,
                        uint8_t *encrypted_blob /* output */
)
{
    int status = CCERR_INTERNAL;
    size_t pub_key_size = ccecies_pub_key_size(public_key, ecies);
    size_t output_nbytes = ccecies_encrypt_gcm_ciphertext_size(public_key, ecies, plaintext_nbytes);

    // Check there is room for result
    cc_require_action(output_nbytes <= *encrypted_blob_nbytes, errOut, status = CCERR_PARAMETER);

    // Do it
    status = ccecies_encrypt_gcm_composite(public_key,
                                           ecies,
                                           encrypted_blob,
                                           encrypted_blob + pub_key_size,
                                           encrypted_blob + pub_key_size + plaintext_nbytes,
                                           plaintext_nbytes,
                                           plaintext,
                                           sharedinfo1_nbytes,
                                           sharedinfo1,
                                           sharedinfo2_nbytes,
                                           sharedinfo2);
    cc_require(status == 0, errOut);
    *encrypted_blob_nbytes = output_nbytes;
errOut:
    if (status) {
        cc_clear(*encrypted_blob_nbytes, encrypted_blob);
    }
    return status;
}
