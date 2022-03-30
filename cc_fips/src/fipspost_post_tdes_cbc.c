/* Copyright (c) (2017,2018,2019) Apple Inc. All rights reserved.
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
#include <corecrypto/ccdes.h>

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_tdes_cbc.h"

// Test the TDES CBC mode
int fipspost_post_tdes_cbc(uint32_t fips_mode)
{
    size_t keyLength = 24;

    // TDES Encryption Test Data
    unsigned char* keyEncryptBuffer = (unsigned char*)"\x5e\xe4\xdb\x0c\xdf\xdf\x71\x9e\x40\xfc\x96\x2d\x2f\x31\xf4\x16\xd9\xaa\x0f\x22\x8d\x89\xe0\x7f";
    unsigned char* ivEncryptBuffer = (unsigned char*)"\x88\x13\x7a\x56\x2b\xea\xb0\xe2";
    unsigned char* inputEncryptBuffer = (unsigned char*)"\xb9\x09\x69\xd0\x50\x3f\x61\xf3";

    unsigned char* outputEncryptBuffer;
    outputEncryptBuffer = POST_FIPS_RESULT_STR("\x68\xc0\x6c\x8a\xf7\x72\xab\xff");


    // TDES Decryption Test Data
    unsigned char* keyDecryptBuffer = (unsigned char*)"\x68\x88\x8a\x1b\xba\xe5\x77\x23\x89\x61\x3e\x8e\xdf\x6a\xfd\x3b\x8b\x85\x69\xce\x70\x60\x7d\x6b";
    unsigned char* ivDecryptBuffer = (unsigned char*)"\x47\x2f\x3a\xcb\x19\x70\x7d\xe8";
    unsigned char* inputDecryptBuffer = (unsigned char*)"\x61\xe3\x3a\x22\xad\x7c\xfa\x71";
    unsigned char* outputDecryptBuffer = (unsigned char*)"\x75\xda\xfe\x5c\x63\x1c\xeb\x35";

    unsigned char outputBuffer[CCDES_BLOCK_SIZE];
    int memCheckResult = CCPOST_GENERIC_FAILURE; // Guilty until proven


    const struct ccmode_cbc*  cbc_mode_dec = ccdes3_cbc_decrypt_mode();
    const struct ccmode_cbc*  cbc_mode_enc = ccdes3_cbc_encrypt_mode();

    // Encryption Test
    if (cccbc_one_shot(cbc_mode_enc, keyLength, keyEncryptBuffer,
                       ivEncryptBuffer, 1,  inputEncryptBuffer, outputBuffer)) {
        failf("cycle");
        return CCPOST_KAT_FAILURE;
    }

    memCheckResult  = memcmp(outputEncryptBuffer, outputBuffer, CCDES_BLOCK_SIZE);

    if (memCheckResult == 0)
    {
        // Decryption Test
        if (cccbc_one_shot(cbc_mode_dec, keyLength, keyDecryptBuffer,
                           ivDecryptBuffer, 1,  inputDecryptBuffer, outputBuffer)) {
            failf("cycle");
            return CCPOST_KAT_FAILURE;
        }

        memCheckResult = memcmp(outputDecryptBuffer, outputBuffer, CCDES_BLOCK_SIZE);
    }

    if (memCheckResult)
    {
        failf("cycle");
        return CCPOST_KAT_FAILURE;
    }

    return memCheckResult; // passed
}
