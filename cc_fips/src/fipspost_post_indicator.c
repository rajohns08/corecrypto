/* Copyright (c) (2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <stdarg.h>
#include <stdio.h>

#include <corecrypto/ccaes.h>
#if !(CC_USE_L4)
#include <corecrypto/ccblowfish.h>
#include <corecrypto/cccast.h>
#include <corecrypto/ccdes.h>
#endif // !(CC_USE_L4)
#include <corecrypto/ccdh.h>
#include <corecrypto/ccdh_gp.h>
#include <corecrypto/ccdrbg.h>
#include <corecrypto/cchkdf.h>
#include <corecrypto/ccec.h>
#include <corecrypto/ccec25519.h>
#include <corecrypto/ccecies.h>
#include <corecrypto/cccmac.h>
#include <corecrypto/cchmac.h>
#if !(CC_KERNEL)
#include <corecrypto/ccmd2.h>
#include <corecrypto/ccmd4.h>
#endif // !(CC_KERNEL)
#include <corecrypto/ccmd5.h>
#include <corecrypto/ccnistkdf.h>
#include <corecrypto/ccpbkdf2.h>
#if !(CC_KERNEL || CC_USE_L4)
#include <corecrypto/ccrc2.h>
#endif // !(CC_KERNEL || CC_USE_L4)
#include <corecrypto/ccrc4.h>
#if !(CC_KERNEL)
#include <corecrypto/ccripemd.h>
#endif // !(CC_KERNEL)
#include <corecrypto/ccrsa.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccwrap.h>

#include "fipspost_indicator.h"
#include "fipspost_post_integrity.h"
#include "fipspost_post_indicator.h"

int fipspost_post_indicator(uint32_t fips_mode)
{
    (void)fips_mode;
    int success = 1;

    /// FIPS
    success &= fips_allowed(fipspost_post_integrity, 0);

    /// AES
    for (size_t key_byte_length = 16; key_byte_length <= 32; key_byte_length += 8) {
#if (CC_USE_L4)
        if (key_byte_length != 24) {
            success &= fips_allowed_mode(&ccaes_skg_cbc_encrypt_mode, key_byte_length);
            success &= fips_allowed_mode(&ccaes_skg_cbc_decrypt_mode, key_byte_length);
        }
#endif // (CC_USE_L4)
        success &= fips_allowed_mode(ccaes_cbc_encrypt_mode(), key_byte_length);
        success &= fips_allowed_mode(ccaes_cbc_decrypt_mode(), key_byte_length);
        success &= fips_allowed_mode(ccaes_ccm_encrypt_mode(), key_byte_length);
        success &= fips_allowed_mode(ccaes_ccm_decrypt_mode(), key_byte_length);
#if !(CC_KERNEL) /// CFB not available in kernel.
        success &= fips_allowed_mode(ccaes_cfb8_encrypt_mode(), key_byte_length);
        success &= fips_allowed_mode(ccaes_cfb8_decrypt_mode(), key_byte_length);
        success &= fips_allowed_mode(ccaes_cfb_encrypt_mode(), key_byte_length);
        success &= fips_allowed_mode(ccaes_cfb_decrypt_mode(), key_byte_length);
#endif // !(CC_KERNEL)
#if !(CC_USE_L4)
        success &= fips_allowed_mode(ccaes_cbc_encrypt_mode(), key_byte_length);
#endif // !(CC_USE_L4)
        success &= fips_allowed_mode(ccaes_ecb_encrypt_mode(), key_byte_length);
        success &= fips_allowed_mode(ccaes_ecb_decrypt_mode(), key_byte_length);
#if (CC_USE_L4)
        if (key_byte_length != 24) {
            success &= fips_allowed_mode(&ccaes_skg_ecb_encrypt_mode, key_byte_length);
            success &= fips_allowed_mode(&ccaes_skg_ecb_decrypt_mode, key_byte_length);
        }
#endif // (CC_USE_L4)                                         // !(CC_USE_L4)
        success &= fips_allowed_mode(ccaes_gcm_encrypt_mode(), key_byte_length); /// GMAC
        success &= fips_allowed_mode(ccaes_gcm_decrypt_mode(), key_byte_length); /// GMAC
#if !(CC_KERNEL)                                                                 /// OFB not available in kernel.
        success &= fips_allowed_mode(ccaes_ofb_crypt_mode(), key_byte_length);
#endif                                                                           // !(CC_KERNEL)
        success &= fips_allowed_mode(ccaes_ecb_encrypt_mode(), key_byte_length); /// AES_KW
        success &= fips_allowed_mode(ccaes_ecb_decrypt_mode(), key_byte_length); /// AES_KW
        if (key_byte_length != 24) {
            success &= fips_allowed_mode(ccaes_xts_encrypt_mode(), key_byte_length);
            success &= fips_allowed_mode(ccaes_xts_decrypt_mode(), key_byte_length);
        }
    }

    /// DRBG handled through direct hash or symmetric algorithm verification.

    /// ECC
    success &= fips_allowed(ccec_generate_key_fips, 1, ccec_cp_224());
    success &= fips_allowed(ccec_generate_key_fips, 1, ccec_cp_256());
    success &= fips_allowed(ccec_generate_key_fips, 1, ccec_cp_384());
    success &= fips_allowed(ccec_generate_key_fips, 1, ccec_cp_521());
    success &= fips_allowed(ccec_sign, 1, ccec_cp_224());
    success &= fips_allowed(ccec_sign, 1, ccec_cp_256());
    success &= fips_allowed(ccec_sign, 1, ccec_cp_384());
    success &= fips_allowed(ccec_sign, 1, ccec_cp_521());
    success &= fips_allowed(ccec_verify, 1, ccec_cp_224());
    success &= fips_allowed(ccec_verify, 1, ccec_cp_256());
    success &= fips_allowed(ccec_verify, 1, ccec_cp_384());
    success &= fips_allowed(ccec_verify, 1, ccec_cp_521());

    /// HMAC
    success &= fips_allowed(cchmac, 1, ccsha1_di());
    success &= fips_allowed(cchmac, 1, ccsha224_di());
    success &= fips_allowed(cchmac, 1, ccsha256_di());
    success &= fips_allowed(cchmac, 1, ccsha384_di());
    success &= fips_allowed(cchmac, 1, ccsha512_di());

    /// DH / ECDH
#if !(CC_KERNEL)
    success &= fips_allowed(ccdh_compute_shared_secret, 1, ccsrp_gp_rfc5054_2048());
    success &= fips_allowed(ccecdh_compute_shared_secret, 1, ccec_cp_256());
    success &= fips_allowed(ccecdh_compute_shared_secret, 1, ccec_cp_384());
#endif // !(CC_KERNEL)

    /// KDF
#if !(CC_USE_L4 || CC_KERNEL)
    success &= fips_allowed(ccnistkdf_ctr_cmac, 1, 16);
    success &= fips_allowed(ccnistkdf_ctr_cmac, 1, 24);
    success &= fips_allowed(ccnistkdf_ctr_cmac, 1, 32);
#endif // !(CC_USE_L4 || CC_KERNEL)
#if (!(CC_USE_L4 || CC_KERNEL) || (__x86_64__ && CC_KERNEL))
    success &= fips_allowed(ccnistkdf_ctr_hmac, 1, ccsha1_di());
    success &= fips_allowed(ccnistkdf_ctr_hmac, 1, ccsha224_di());
    success &= fips_allowed(ccnistkdf_ctr_hmac, 1, ccsha256_di());
    success &= fips_allowed(ccnistkdf_ctr_hmac, 1, ccsha384_di());
    success &= fips_allowed(ccnistkdf_ctr_hmac, 1, ccsha512_di());
    success &= fips_allowed(ccnistkdf_ctr_hmac_fixed, 1, ccsha1_di()); // KDF_HMAC
    success &= fips_allowed(ccnistkdf_ctr_hmac_fixed, 1, ccsha224_di());
    success &= fips_allowed(ccnistkdf_ctr_hmac_fixed, 1, ccsha256_di());
    success &= fips_allowed(ccnistkdf_ctr_hmac_fixed, 1, ccsha384_di());
    success &= fips_allowed(ccnistkdf_ctr_hmac_fixed, 1, ccsha512_di());
    success &= fips_allowed(ccnistkdf_fb_hmac, 1, ccsha1_di());
    success &= fips_allowed(ccnistkdf_fb_hmac, 1, ccsha224_di());
    success &= fips_allowed(ccnistkdf_fb_hmac, 1, ccsha256_di());
    success &= fips_allowed(ccnistkdf_fb_hmac, 1, ccsha384_di());
    success &= fips_allowed(ccnistkdf_fb_hmac, 1, ccsha512_di());
#endif // (!(CC_USE_L4 || CC_KERNEL) || (__x86_64__ && CC_KERNEL))
    success &= fips_allowed(ccpbkdf2_hmac, 1, ccsha1_di());
    success &= fips_allowed(ccpbkdf2_hmac, 1, ccsha224_di());
    success &= fips_allowed(ccpbkdf2_hmac, 1, ccsha256_di());
    success &= fips_allowed(ccpbkdf2_hmac, 1, ccsha384_di());
    success &= fips_allowed(ccpbkdf2_hmac, 1, ccsha512_di());

    /// Digest
#if !(CC_USE_L4)
    success &= fips_allowed(ccmd5_di, 0);
#endif // !(CC_USE_L4)
    success &= fips_allowed(ccsha1_di, 0);
    success &= fips_allowed(ccsha224_di, 0);
    success &= fips_allowed(ccsha256_di, 0);
    success &= fips_allowed(ccsha384_di, 0);
    success &= fips_allowed(ccsha512_di, 0);

    /// NDRNG
    success &= fips_allowed(ccrng_uniform, 0);

    /// RSA
    for (size_t key_bit_length = 2048; key_bit_length <= 4096; key_bit_length += 1024) {
        success &= fips_allowed(ccrsa_generate_key, 1, key_bit_length);
        success &= fips_allowed(ccrsa_generate_fips186_key, 1, key_bit_length);
#if !(TARGET_OS_BRIDGE && CC_KERNEL)
#if !(CC_USE_L4) /// ccrsa_sign_pss is not in L4.
        success &= fips_allowed(ccrsa_sign_pss, 1, key_bit_length);
#endif // !(CC_USE_L4)
        success &= fips_allowed(ccrsa_sign_pkcs1v15, 1, key_bit_length);
#endif // !(TARGET_OS_BRIDGE && CC_KERNEL)
    }
    for (size_t key_bit_length = 1024; key_bit_length <= 4096; key_bit_length += 1024) {
        success &= fips_allowed(ccrsa_verify_pss_digest, 1, key_bit_length);
        success &= fips_allowed(ccrsa_verify_pkcs1v15_digest, 1, key_bit_length);
    }

    /// TDES
#if (CC_KERNEL)
    for (size_t key_byte_length = 16; key_byte_length <= 32; key_byte_length += 8) {
        success &= fips_allowed_mode(ccdes3_ecb_encrypt_mode(), key_byte_length);
        success &= fips_allowed_mode(ccdes3_ecb_decrypt_mode(), key_byte_length);
    }
#endif // (CC_KERNEL)

    /// Not appproved algoriithms.
    /// Blowfish.
#if !(CC_USE_L4)
    success &= !fips_allowed_mode(ccblowfish_ecb_decrypt_mode(), 16);
    success &= !fips_allowed_mode(ccblowfish_ecb_encrypt_mode(), 16);
    success &= !fips_allowed_mode(ccblowfish_cbc_decrypt_mode(), 16);
    success &= !fips_allowed_mode(ccblowfish_cbc_encrypt_mode(), 16);
    success &= !fips_allowed_mode(ccblowfish_cfb_decrypt_mode(), 16);
    success &= !fips_allowed_mode(ccblowfish_cfb_encrypt_mode(), 16);
    success &= !fips_allowed_mode(ccblowfish_cfb8_decrypt_mode(), 16);
    success &= !fips_allowed_mode(ccblowfish_cfb8_encrypt_mode(), 16);
    success &= !fips_allowed_mode(ccblowfish_ctr_crypt_mode(), 16);
    success &= !fips_allowed_mode(ccblowfish_ofb_crypt_mode(), 16);
#endif // !(CC_USE_L4)

    /// Cast.
#if !(CC_USE_L4)
    success &= !fips_allowed_mode(cccast_ecb_decrypt_mode(), 16);
    success &= !fips_allowed_mode(cccast_ecb_encrypt_mode(), 16);
    success &= !fips_allowed_mode(cccast_cbc_decrypt_mode(), 16);
    success &= !fips_allowed_mode(cccast_cbc_encrypt_mode(), 16);
    success &= !fips_allowed_mode(cccast_cfb_decrypt_mode(), 16);
    success &= !fips_allowed_mode(cccast_cfb_encrypt_mode(), 16);
    success &= !fips_allowed_mode(cccast_cfb8_decrypt_mode(), 16);
    success &= !fips_allowed_mode(cccast_cfb8_encrypt_mode(), 16);
    success &= !fips_allowed_mode(cccast_ctr_crypt_mode(), 16);
    success &= !fips_allowed_mode(cccast_ofb_crypt_mode(), 16);
#endif // !(CC_USE_L4)

    /// DES - TDES
#if !(CC_USE_L4)
    success &= !fips_allowed_mode(ccdes_ecb_decrypt_mode(), 16);
    success &= !fips_allowed_mode(ccdes_ecb_encrypt_mode(), 16);
    success &= !fips_allowed_mode(ccdes_cbc_decrypt_mode(), 16);
    success &= !fips_allowed_mode(ccdes_cbc_encrypt_mode(), 16);
    success &= !fips_allowed_mode(ccdes_cfb_decrypt_mode(), 16);
    success &= !fips_allowed_mode(ccdes_cfb_encrypt_mode(), 16);
    success &= !fips_allowed_mode(ccdes_cfb8_decrypt_mode(), 16);
    success &= !fips_allowed_mode(ccdes_cfb8_encrypt_mode(), 16);
    success &= !fips_allowed_mode(ccdes_ctr_crypt_mode(), 16);
    success &= !fips_allowed_mode(ccdes_ofb_crypt_mode(), 16);
#if !(CC_KERNEL)
    success &= !fips_allowed_mode(ccdes3_ecb_encrypt_mode(), 16);
    success &= !fips_allowed_mode(ccdes3_ecb_decrypt_mode(), 16);
#endif // !(CC_KERNEL)
    success &= !fips_allowed_mode(ccdes3_cbc_decrypt_mode(), 16);
    success &= !fips_allowed_mode(ccdes3_cbc_encrypt_mode(), 16);
    success &= !fips_allowed_mode(ccdes3_cfb_decrypt_mode(), 16);
    success &= !fips_allowed_mode(ccdes3_cfb_encrypt_mode(), 16);
    success &= !fips_allowed_mode(ccdes3_cfb8_decrypt_mode(), 16);
    success &= !fips_allowed_mode(ccdes3_cfb8_encrypt_mode(), 16);
    success &= !fips_allowed_mode(ccdes3_ctr_crypt_mode(), 16);
    success &= !fips_allowed_mode(ccdes3_ofb_crypt_mode(), 16);
#endif // !(CC_USE_L4)
    /// ECIES
    success &= !fips_allowed(ccecies_encrypt_gcm, 0);
    success &= !fips_allowed(ccecies_decrypt_gcm, 0);
    /// ED25519
    success &= !fips_allowed(cced25519_make_key_pair, 0);
    success &= !fips_allowed(cced25519_sign, 0);
    success &= !fips_allowed(cced25519_verify, 0);
    /// KDF
    success &= !fips_allowed(cchkdf, 0);
    /// MD2/4
#if !(CC_KERNEL)
    success &= !fips_allowed(&ccmd2_ltc_di, 0);
    success &= !fips_allowed(&ccmd4_ltc_di, 0);
#endif // !(CC_KERNEL)
    /// OMAC
    success &= !fips_allowed(ccomac_update, 0);
    /// RC2/4
#if !(CC_KERNEL || CC_USE_L4)
    success &= !fips_allowed_mode(ccrc2_ecb_decrypt_mode(), 16);
    success &= !fips_allowed_mode(ccrc2_ecb_encrypt_mode(), 16);
    success &= !fips_allowed_mode(ccrc2_cbc_decrypt_mode(), 16);
    success &= !fips_allowed_mode(ccrc2_cbc_encrypt_mode(), 16);
    success &= !fips_allowed_mode(ccrc2_cfb_decrypt_mode(), 16);
    success &= !fips_allowed_mode(ccrc2_cfb_encrypt_mode(), 16);
    success &= !fips_allowed_mode(ccrc2_cfb8_decrypt_mode(), 16);
    success &= !fips_allowed_mode(ccrc2_cfb8_encrypt_mode(), 16);
    success &= !fips_allowed_mode(ccrc2_ctr_crypt_mode(), 16);
    success &= !fips_allowed_mode(ccrc2_ofb_crypt_mode(), 16);
    success &= !fips_allowed(ccrc4, 0);
#endif // !(CC_KERNEL || CC_USE_L4)
    /// RIPEMD
#if !(CC_KERNEL)
    success &= !fips_allowed(&ccrmd160_ltc_di, 0);
#endif // !(CC_KERNEL)

    /// These tests must fail.
    success &= !fips_allowed(NULL, 0);
    success &= !fips_allowed(NULL, 1, 42);
    success &= !fips_allowed_mode(ccaes_ecb_encrypt_mode(), 12);
#if !(CC_USE_L4)
    success &= !fips_allowed_mode(ccdes3_ecb_encrypt_mode(), 42);
    success &= !fips_allowed_mode(ccdes_ecb_encrypt_mode(), 12);
#endif // !(CC_USE_L4)

    return !success;
}
