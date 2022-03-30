/* Copyright (c) (2015,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccec_priv.h>
#include <corecrypto/ccder.h>

/* ECRandomizedPublicKey ::=   SEQUENCE {
 generator    OCTET STRING,
 publicKey    OCTET STRING
 } */

size_t ccec_der_export_diversified_pub_size(
    ccec_pub_ctx_t  diversified_generator,
    ccec_pub_ctx_t  diversified_key,
    unsigned long flags) {
    (void)diversified_key;
    (void)diversified_generator;
    size_t len;

    if (flags&CCEC_EXPORT_COMPACT_DIVERSIFIED_KEYS) {
        len = ccder_sizeof(CCDER_CONSTRUCTED_SEQUENCE,
                          ccder_sizeof_raw_octet_string(ccec_compact_export_size(0,diversified_key))
                        + ccder_sizeof_raw_octet_string(ccec_compact_export_size(0,diversified_generator)));
    } else {
        len = ccder_sizeof(CCDER_CONSTRUCTED_SEQUENCE,
                           ccder_sizeof_raw_octet_string(ccec_x963_export_size(0,diversified_key))
                           + ccder_sizeof_raw_octet_string(ccec_x963_export_size(0,diversified_generator)));
    }
    return len;
}

uint8_t *ccec_der_export_diversified_pub(
    ccec_pub_ctx_t  diversified_generator,
    ccec_pub_ctx_t  diversified_key,
    unsigned long flags,
    size_t der_len, uint8_t *der) {

    uint8_t *der_end=der+der_len;
    uint8_t *tmp_end=NULL;
    if (flags&CCEC_EXPORT_COMPACT_DIVERSIFIED_KEYS) {
        uint8_t tmp_key[ccec_compact_export_size(0,diversified_key)];
        ccec_compact_export(0, tmp_key, (ccec_full_ctx_t)diversified_key);

        uint8_t tmp_gen[ccec_compact_export_size(0,diversified_key)];
        ccec_compact_export(0, tmp_gen, (ccec_full_ctx_t)diversified_generator);

        tmp_end=ccder_encode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE, der_end, der,
                                            ccder_encode_raw_octet_string(sizeof(tmp_gen),tmp_gen, der,
                                            ccder_encode_raw_octet_string(sizeof(tmp_key),tmp_key, der, der_end)));
    }
    else {
        uint8_t tmp_key[ccec_x963_export_size(0,diversified_key)];
        ccec_x963_export(0, tmp_key, (ccec_full_ctx_t)diversified_key);

        uint8_t tmp_gen[ccec_x963_export_size(0,diversified_key)];
        ccec_x963_export(0, tmp_gen, (ccec_full_ctx_t)diversified_generator);

        tmp_end=ccder_encode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE, der_end, der,
                                            ccder_encode_raw_octet_string(sizeof(tmp_gen),tmp_gen, der,
                                            ccder_encode_raw_octet_string(sizeof(tmp_key),tmp_key, der, der_end)));
    }
    return tmp_end;
}
