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

#include <corecrypto/ccecies_priv.h>
#include <corecrypto/ccec_priv.h>
#include <corecrypto/ccmode.h>
#include "ccansikdf_priv.h"
#include "ccecies_internal.h"
#include "cc_debug.h"
#include <corecrypto/cc_macros.h>

/*!
 @function   ccecies_make_shared_secret_from_ecdh_priv
 @abstract   Import the public key, compute the resulting ECDH shared secret

 @param  ecies                  Input:  ECIES configurations
 @param  full_key               Input:  EC public key of the destination
 @param  serialized_public_key_nbytes Input: Size of serialized pub key in bytes
 @param  serialized_public_key  Input: Pointer to the ephemeral public key buffer, must of size
 @param  shared_secret_nbytes            Input:  Size of the shared_secret buffer
 @param  shared_secret                   Output: ECDH shared secret computed
 @return 0 if success, see cc_error.h otherwise

 */
CC_NONNULL((1, 2, 4, 6))
static int ccecies_make_shared_secret_from_ecdh_priv(const ccecies_gcm_t ecies,
                                                     ccec_full_ctx_t full_key,
                                                     size_t serialized_public_key_nbytes,
                                                     const uint8_t *serialized_public_key,
                                                     size_t shared_secret_nbytes,
                                                     uint8_t *shared_secret)
{
    int status = CCERR_INTERNAL;

    // Contexts
    ccec_const_cp_t cp = ccec_ctx_cp(full_key);
    ccec_pub_ctx_decl_cp(cp, public_key);

    // Import public key from ciphertext
    status = ccecies_import_eph_pub(cp, ecies, serialized_public_key_nbytes, serialized_public_key, public_key);
    cc_require(status == 0, errOut);

#if CC_DEBUG_ECIES
    ccec_print_public_key("Ephemeral public key", public_key);
#endif

    // ECDH - Ephemeral-static
    status = ccecdh_compute_shared_secret(full_key, public_key, &shared_secret_nbytes, shared_secret, ecies->rng);
    cc_require(status == 0, errOut);

errOut:
    ccec_pub_ctx_clear_cp(cp, public_key);
    return status;
}

int ccecies_decrypt_gcm_composite(ccec_full_ctx_t full_key,
                                  const ccecies_gcm_t ecies,
                                  uint8_t *plaintext, /* output - expect length ccecies_decrypt_gcm_plaintext_size */
                                  size_t sharedinfo1_nbytes,
                                  const void *sharedinfo1,
                                  size_t sharedinfo2_nbytes,
                                  const void *sharedinfo2,
                                  size_t ciphertext_nbytes,
                                  const uint8_t *ciphertext,
                                  const uint8_t *serialized_public_key, /* expect length from ccecies_pub_key_size */
                                  const uint8_t *received_tag           /* expect length ecies->mac_length */
)
{
    int status = CCERR_INTERNAL;
    size_t serialized_public_key_nbytes = ccecies_pub_key_size_cp(ccec_ctx_cp(full_key), ecies);

    // Buffer for key material
    size_t shared_secret_nbytes = ccec_cp_prime_size(ccec_ctx_cp(full_key));
    uint8_t shared_secret[shared_secret_nbytes];

    // ECDH
    status = ccecies_make_shared_secret_from_ecdh_priv(
        ecies, full_key, serialized_public_key_nbytes, serialized_public_key, shared_secret_nbytes, shared_secret);
    cc_require(status == 0, errOut);

    status = ccecies_decrypt_gcm_from_shared_secret_composite(ccec_ctx_cp(full_key),
                                                              ecies,
                                                              shared_secret_nbytes,
                                                              shared_secret,
                                                              ciphertext_nbytes,
                                                              serialized_public_key, /* expect length from ccecies_pub_key_size */
                                                              ciphertext,
                                                              received_tag, /* expect length ecies->mac_length */
                                                              sharedinfo1_nbytes,
                                                              sharedinfo1,
                                                              sharedinfo2_nbytes,
                                                              sharedinfo2,
                                                              plaintext /* output */
    );

errOut:
    if (status) {
        // On error, wipe the decrypted data
        cc_clear(ciphertext_nbytes, plaintext);
    }
    // Clear key material info
    cc_clear(sizeof(shared_secret), shared_secret);
    return status;
}

int ccecies_decrypt_gcm(ccec_full_ctx_t full_key,
                        const ccecies_gcm_t ecies,
                        size_t encrypted_blob_nbytes,
                        const uint8_t *encrypted_blob,
                        size_t sharedinfo1_byte_nbytes,
                        const void *sharedinfo1,
                        size_t sharedinfo2_byte_nbytes,
                        const void *sharedinfo2,
                        size_t *plaintext_nbytes,
                        uint8_t *plaintext /* output */
)
{
    int status = CCERR_INTERNAL;
    size_t output_nbytes;
    size_t pub_key_size = ccecies_pub_key_size(ccec_ctx_pub(full_key), ecies);

    // Check input coherence
    status = CCERR_PARAMETER;
    output_nbytes = ccecies_decrypt_gcm_plaintext_size(full_key, ecies, encrypted_blob_nbytes);
    cc_require(output_nbytes > 0, errOut);
    cc_require(output_nbytes <= *plaintext_nbytes, errOut);

    // Do it
    status = ccecies_decrypt_gcm_composite(full_key,
                                           ecies,
                                           plaintext,
                                           sharedinfo1_byte_nbytes,
                                           sharedinfo1,
                                           sharedinfo2_byte_nbytes,
                                           sharedinfo2,
                                           output_nbytes,
                                           encrypted_blob + pub_key_size,
                                           encrypted_blob,
                                           encrypted_blob + pub_key_size + output_nbytes);
    cc_require(status == 0, errOut);
    *plaintext_nbytes = output_nbytes;

errOut:
    if (status) {
        cc_clear(*plaintext_nbytes, plaintext);
    }
    return status;
}
