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
#include <corecrypto/ccdes.h>
#include <corecrypto/ccdh.h>
#include <corecrypto/ccdh_gp.h>
#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccec.h>
#include <corecrypto/cccmac.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccmd5.h>
#include <corecrypto/ccnistkdf.h>
#include <corecrypto/ccpbkdf2.h>
#include <corecrypto/ccrsa.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccwrap.h>

#include "fipspost_indicator.h"
#include "fipspost_post_integrity.h"

int fips_allowed_mode(const void *mode, size_t key_byte_length)
{
    if (mode == ccaes_cbc_encrypt_mode() || mode == ccaes_cbc_decrypt_mode()) {
        return key_byte_length == 16 || key_byte_length == 24 || key_byte_length == 32;
    }
#if (CC_USE_L4)
    if (mode == &ccaes_skg_cbc_encrypt_mode || mode == &ccaes_skg_cbc_decrypt_mode) {
        return key_byte_length == 16 || key_byte_length == 32;
    }
#endif // (CC_USE_L4)
    if (mode == ccaes_ccm_encrypt_mode() || mode == ccaes_ccm_decrypt_mode()) {
        return key_byte_length == 16 || key_byte_length == 24 || key_byte_length == 32;
    }
#if !(CC_KERNEL) /// CFB not available in kernel.
    if (mode == ccaes_cfb8_encrypt_mode() || mode == ccaes_cfb8_decrypt_mode()) {
        return key_byte_length == 16 || key_byte_length == 24 || key_byte_length == 32;
    }
    if (mode == ccaes_cfb_encrypt_mode() || mode == ccaes_cfb_decrypt_mode()) {
        return key_byte_length == 16 || key_byte_length == 24 || key_byte_length == 32;
    }
#endif // !(CC_KERNEL)
#if !(CC_USE_L4)
    if (mode == ccaes_cbc_encrypt_mode()) {
        return key_byte_length == 16 || key_byte_length == 24 || key_byte_length == 32;
    }
#endif // !(CC_USE_L4)
    if (mode == ccaes_ctr_crypt_mode()) {
        return key_byte_length == 16 || key_byte_length == 24 || key_byte_length == 32;
    }
#if (CC_KERNEL)
    /// WARNING: Since mode functions are the same for all symmetric algorithms, TDES has to be dealt with here.
    if (mode == ccaes_ecb_encrypt_mode() || mode == ccaes_ecb_decrypt_mode() || mode == ccdes3_ecb_encrypt_mode() ||
        mode == ccdes3_ecb_decrypt_mode()) {
        return key_byte_length == 16 || key_byte_length == 24 || key_byte_length == 32;
    }
#else  // (CC_KERNEL)
    if (mode == ccaes_ecb_encrypt_mode() || mode == ccaes_ecb_decrypt_mode()) {
        return key_byte_length == 16 || key_byte_length == 24 || key_byte_length == 32;
    }
#endif // (CC_KERNEL)
#if (CC_USE_L4)
    if (mode == &ccaes_skg_ecb_encrypt_mode || mode == &ccaes_skg_ecb_decrypt_mode) {
        return key_byte_length == 16 || key_byte_length == 32;
    }
#endif // (CC_USE_L4)
    if (mode == ccaes_gcm_encrypt_mode() || mode == ccaes_gcm_decrypt_mode()) {
        return key_byte_length == 16 || key_byte_length == 24 || key_byte_length == 32;
    }
#if !(CC_KERNEL) /// OFB not available in kernel.
    if (mode == ccaes_ofb_crypt_mode()) {
        return key_byte_length == 16 || key_byte_length == 24 || key_byte_length == 32;
    }
#endif // !(CC_KERNEL)
    if (mode == ccaes_ecb_encrypt_mode() || mode == ccaes_ecb_decrypt_mode()) {
        return key_byte_length == 16 || key_byte_length == 24 || key_byte_length == 32;
    }
    if (mode == ccaes_xts_encrypt_mode() || mode == ccaes_xts_decrypt_mode()) {
        return key_byte_length == 16 || key_byte_length == 32;
    }
    return 0;
}

int fips_allowed(const void *function, size_t num_args, ...)
{
    va_list ap;
    va_start(ap, num_args);
    int success = 0;

    if (num_args == 0) {
        /// FIPS
        if (function == fipspost_post_integrity) {
            success = 1;
        }
        /// Digest
        if (function == ccsha1_di || function == ccsha224_di || function == ccsha256_di || function == ccsha384_di ||
            function == ccsha512_di) {
            success = 1;
        }
#if !(CC_USE_L4)
        if (function == ccmd5_di) {
            success = 1;
        }
#endif // !(CC_USE_L4)
       /// NDRNG
        if (function == ccrng_uniform) {
            success = 1;
        }
    }

    if (num_args == 1) {
        /// ECC
        if (function == ccec_generate_key_fips || function == ccec_sign || function == ccec_verify) {
            const ccec_const_cp_t cp = va_arg(ap, ccec_const_cp_t);
            success = cp == ccec_cp_224() || cp == ccec_cp_256() || cp == ccec_cp_384() || cp == ccec_cp_521();
        }

        /// HMAC
        if (function == cchmac) {
            const struct ccdigest_info *digest = va_arg(ap, struct ccdigest_info *);
            success = digest == ccsha1_di() || digest == ccsha224_di() || digest == ccsha256_di() || digest == ccsha384_di() ||
                      digest == ccsha512_di();
        }

        /// DH / ECDH
#if !(CC_KERNEL)
        if (function == ccdh_compute_shared_secret) {
            const ccdh_const_gp_t cp = va_arg(ap, ccdh_const_gp_t);
            success = cp == ccsrp_gp_rfc5054_2048();
        }
        if (function == ccecdh_compute_shared_secret) {
            const ccec_const_cp_t cp = va_arg(ap, ccec_const_cp_t);
            success = cp == ccec_cp_256() || cp == ccec_cp_384();
        }
#endif // !(CC_KERNEL)

        /// KDF
#if !(CC_USE_L4 || CC_KERNEL)
        if (function == ccnistkdf_ctr_cmac) {
            const size_t key_byte_length = va_arg(ap, size_t);
            success = key_byte_length == 16 || key_byte_length == 24 || key_byte_length == 32;
        }
#endif // !(CC_USE_L4 || CC_KERNEL)
#if (!(CC_USE_L4 || CC_KERNEL) || (__x86_64__ && CC_KERNEL))
        if (function == ccnistkdf_ctr_hmac || function == ccnistkdf_ctr_hmac_fixed || function == ccnistkdf_fb_hmac) {
            const struct ccdigest_info *digest = va_arg(ap, struct ccdigest_info *);
            success = digest == ccsha1_di() || digest == ccsha224_di() || digest == ccsha256_di() || digest == ccsha384_di() ||
                      digest == ccsha512_di();
        }
#endif // (!(CC_USE_L4 || CC_KERNEL) || (__x86_64__ && CC_KERNEL))
        if (function == ccpbkdf2_hmac) {
            const struct ccdigest_info *digest = va_arg(ap, struct ccdigest_info *);
            success = digest == ccsha1_di() || digest == ccsha224_di() || digest == ccsha256_di() || digest == ccsha384_di() ||
                      digest == ccsha512_di();
        }

        /// RSA
        if (function == ccrsa_generate_key || function == ccrsa_generate_fips186_key) {
            const size_t key_bit_length = va_arg(ap, size_t);
            success = key_bit_length == 2048 || key_bit_length == 3072 || key_bit_length == 4096;
        }
#if !(TARGET_OS_BRIDGE && CC_KERNEL)
#if !(CC_USE_L4) /// ccrsa_sign_pss is not in L4.
        if (function == ccrsa_sign_pss) {
            const size_t key_bit_length = va_arg(ap, size_t);
            success = key_bit_length == 2048 || key_bit_length == 3072 || key_bit_length == 4096;
        }
#endif // !(CC_USE_L4)
        if (function == ccrsa_sign_pkcs1v15) {
            const size_t key_bit_length = va_arg(ap, size_t);
            success = key_bit_length == 2048 || key_bit_length == 3072 || key_bit_length == 4096;
        }
#endif // !(TARGET_OS_BRIDGE && CC_KERNEL)
        if (function == ccrsa_verify_pss_digest || function == ccrsa_verify_pkcs1v15_digest) {
            const size_t key_bit_length = va_arg(ap, size_t);
            success = key_bit_length == 1024 || key_bit_length == 2048 || key_bit_length == 3072 || key_bit_length == 4096;
        }
    }

    va_end(ap);
    return success;
}
