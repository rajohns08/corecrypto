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
#include <corecrypto/ccaes.h>

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_aes_ecb.h"

int fipspost_post_aes_ecb(uint32_t fips_mode)
{
    size_t key128Length = 16;
    //KEY = e680747f14e8a6ee00bba6bd6557ae51
    unsigned char* key_data;
    key_data = POST_FIPS_RESULT_STR("\xe6\x80\x74\x7f\x14\xe8\xa6\xee\x00\xbb\xa6\xbd\x65\x57\xae\x51");

    //PLAINTEXT = 7fea96f90fbae12a857f5c97e0cba579
    unsigned char* plaintext_data =  (unsigned char *)"\x7f\xea\x96\xf9\x0f\xba\xe1\x2a\x85\x7f\x5c\x97\xe0\xcb\xa5\x79";
    //CIPHERTEXT = 3d30e6364585461671aa671026b2ecd9
    unsigned char* ciphertext_data = (unsigned char *)"\x3d\x30\xe6\x36\x45\x85\x46\x16\x71\xaa\x67\x10\x26\xb2\xec\xd9";

    const struct ccmode_ecb* ecm_mode = ccaes_ecb_encrypt_mode();

    unsigned char output[16];

    if (ccecb_one_shot(ecm_mode, key128Length, key_data, 1, plaintext_data, output)) {
        failf("encrypt");
        return CCPOST_LIBRARY_ERROR;
    }

    if (memcmp(ciphertext_data, output, 16))
    {
        failf("encrypt");
        return CCPOST_KAT_FAILURE;
    }

    unsigned char decrypted_output[16];
    const struct ccmode_ecb* decrypt_ecm_mode = ccaes_ecb_decrypt_mode();

    if (ccecb_one_shot(decrypt_ecm_mode, key128Length, key_data, 1, output, decrypted_output)) {
        failf("decrypt");
        return CCPOST_LIBRARY_ERROR;
    }

    if (memcmp(plaintext_data, decrypted_output, 16))
    {
        failf("decrypt");
        return CCPOST_KAT_FAILURE;
    }

    return 0; // passed
}
