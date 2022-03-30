/* Copyright (c) (2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
#include <corecrypto/cc_debug.h>
#include <corecrypto/ccrsa.h>
#include <corecrypto/ccrsa_priv.h>

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_rsa_enc_dec.h"

//defined as a macro because cc_assert() doesn't exist in release build and the compiler creates unused function error
#define local_ccrsa_priv_n(fk)  ccn_nof(ccrsa_pubkeylength(ccrsa_ctx_public(fk)))

// Test RSA Encryption and Decryption
int fipspost_post_rsa_enc_dec(uint32_t fips_mode)
{
    /* Encrypt/Decrypt */
    size_t nbits=2048;
    cc_size n = ccn_nof(nbits);
    ccrsa_full_ctx_decl(ccn_sizeof(nbits), full_key);
    ccrsa_ctx_n(full_key)=n;

    int status = 0;

    // Import the key
    if (0 != ccrsa_import_priv(full_key, fipspost_post_rsa_test_key_nbytes, fipspost_post_rsa_test_key))
    {
        failf("import");
        return CCPOST_GENERIC_FAILURE;
    }

    ccrsa_pub_ctx_t pub_key = ccrsa_ctx_public(full_key);
    post_assert(n == local_ccrsa_priv_n(full_key));

    const unsigned char cleartext_data[] = "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x30\x31\x32\x33\x34\x35\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x30\x31\x32\x33\x34\x35\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x30\x31\x32\x33\x34\x35\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x30\x31\x32\x33\x34\x35\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x30\x31\x32\x33\x34\x35\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x30\x31\x32\x33\x34\x35\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x30\x31\x32\x33\x34\x35\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x30\x31\x32\x33\x34\x35";
    cc_unit cleartext[n];
    status = ccn_read_uint(n, cleartext, sizeof(cleartext_data)-1, cleartext_data);
    post_assert(status == 0);
    const unsigned char *expected_ciphertext_data = POST_FIPS_RESULT_STR("\x53\xff\x13\x93\xc0\x9d\xc3\xf2\xd1\xa0\x02\x4b\x30\xcb\xa3\x16\x8e\xb5\x99\x59\x24\x3b\x93\x40\x2e\xbb\xf2\xd3\x16\x05\x19\x15\xfe\x0d\x08\x32\x06\x1b\xb7\x79\x8a\x90\x18\x18\x1d\x99\x28\x97\x63\x44\x9f\x4d\x27\x23\x71\x45\x42\xe3\x6f\x4e\xef\x97\xc5\x5f\x1f\x7e\x03\x4d\x5d\xb6\x65\x40\x2d\xcf\xde\x89\xa2\xa5\x61\xaf\x5a\xe0\x7a\x32\xe7\x7c\xc7\x65\xf1\xc2\xf7\xee\x58\x05\xf6\x81\x99\xe9\x1b\xe1\xa0\x6a\x23\x5c\xd8\x4c\x34\x0e\xb6\xdc\x9d\xff\xce\x6e\x93\x63\x57\x02\x7b\x83\xe2\x0a\xd0\xd6\x02\x0d\x56\x45\x15\xfc\xda\x1d\x41\xf9\xdb\xe3\x23\xd9\x8d\x35\xb2\x75\xae\xd9\x3c\x8c\xe8\xaf\x76\x9d\xe1\x89\x08\x38\xc9\x12\x64\x4d\xcb\xca\xbf\x95\x32\x39\x8f\xb5\x4d\xc1\xa1\xcf\x81\x1c\x56\x54\x31\xcf\x5d\x02\xc4\xbe\x79\x2f\x6f\x9a\x91\xa4\x5e\x02\xf6\xc9\x0a\x24\x53\x7f\xff\x2f\xae\xe3\x5c\x26\xee\x2c\x30\x8c\x2a\x54\xc2\x6c\x9b\xc4\x73\x27\x6b\x1d\x68\x76\x98\xc2\xfd\x76\x8b\x8f\x42\xe7\x08\xa5\xd1\xd0\xec\x3c\x89\xc2\x2b\x50\xdd\x7a\x76\xf2\x4b\x4c\xbe\x3f\x01\xd1\x39\x5b\x9d\x90\x38\x93\xcc\x82\x05\x01\x52\x5f");
    cc_unit expected_ciphertext[n];
    status = ccn_read_uint(n, expected_ciphertext, strlen((const char *)expected_ciphertext_data), expected_ciphertext_data);
    post_assert(status == 0);

    cc_unit encrypted_result[n], decrypted_result[n];

    /* Enc / Dec */
    // Encrypt cleartext into encrypted_result
    if (0 != ccrsa_pub_crypt(pub_key, encrypted_result, cleartext))
    {
        failf("ccrsa_pub_crypt");
        ccrsa_full_ctx_clear(ccn_sizeof(nbits), full_key);
        return CCPOST_GENERIC_FAILURE;
    }

    // Verify encrypted_result != cleartext
    if (0 == ccn_cmp(n, encrypted_result, cleartext))
    {
        failf("RSA pub crypt");
        ccrsa_full_ctx_clear(ccn_sizeof(nbits), full_key);
        return CCPOST_GENERIC_FAILURE;
    }

    // Verify encrypted_result == expected_ciphertext
    if (0 != ccn_cmp(n, encrypted_result, expected_ciphertext))
    {
        failf("encrypted_result != expected_ciphertext");
        ccrsa_full_ctx_clear(ccn_sizeof(nbits), full_key);
        return CCPOST_GENERIC_FAILURE;
    }

    // Decrypt the expected_ciphertext into decrypted_result
    if (0 != ccrsa_priv_crypt(full_key, decrypted_result, expected_ciphertext))
    {
        failf("ccrsa_priv_crypt");
        ccrsa_full_ctx_clear(ccn_sizeof(nbits), full_key);
        return CCPOST_GENERIC_FAILURE;
    }

    // Verify decrypted_result == cleartext
    if (0 != ccn_cmp(n, decrypted_result, cleartext))
    {
        failf("decrypted_result != cleartext");
        ccrsa_full_ctx_clear(ccn_sizeof(nbits), full_key);
        return CCPOST_KAT_FAILURE;
    }

    return 0;
}
