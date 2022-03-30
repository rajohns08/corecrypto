/* Copyright (c) (2014,2015,2016,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccder.h>

/* RFC 5915 */
/* version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1), */
/* privateKey     OCTET STRING, */
/* parameters [0] ECParameters {{ NamedCurve }} OPTIONAL, */
/* publicKey  [1] BIT STRING OPTIONAL */

size_t
ccder_encode_eckey_size(size_t priv_size, ccoid_t oid, size_t pub_size)
{
    size_t size =
    ccder_sizeof_uint64(1) +
    ccder_sizeof(CCASN1_OCTET_STRING, priv_size);

    if (CCOID(oid))
        size += ccder_sizeof(CCDER_CONTEXT_SPECIFIC|CCDER_CONSTRUCTED|0, ccder_sizeof_oid(oid));

    if (pub_size) {
        size_t bitlen = ccder_sizeof(CCDER_BIT_STRING, pub_size + 1);
        size += ccder_sizeof(CCDER_CONTEXT_SPECIFIC|CCDER_CONSTRUCTED|1, bitlen);
    }

    return ccder_sizeof(CCDER_CONSTRUCTED_SEQUENCE, size);
}

uint8_t *
ccder_encode_eckey(size_t priv_size, const uint8_t *priv_key,
                            ccoid_t oid,
                            size_t pub_size, const uint8_t *pub_key,
                            uint8_t *der, uint8_t *der_end)
{
    uint8_t *tmp_end = der_end;

    if (pub_size) {
        size_t bitlen = ccder_sizeof(CCDER_BIT_STRING, pub_size + 1);
        tmp_end = ccder_encode_tl(CCDER_CONTEXT_SPECIFIC|CCDER_CONSTRUCTED|1, bitlen, der,
                                  ccder_encode_tl(CCDER_BIT_STRING, pub_size + 1, der,
                                                  ccder_encode_body(1, (const uint8_t *)"\x00", der,
                                                                    ccder_encode_body(pub_size, pub_key, der, tmp_end))));
    }
    if (CCOID(oid) && tmp_end) {
        size_t oidlen = ccder_sizeof_oid(oid);
        tmp_end = ccder_encode_tl(CCDER_CONTEXT_SPECIFIC|CCDER_CONSTRUCTED|0, oidlen, der,
                                  ccder_encode_oid(oid, der, tmp_end));
    }
    if (tmp_end) {
        tmp_end=ccder_encode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE, der_end, der,
                    ccder_encode_uint64(1, der,
                                        ccder_encode_implicit_raw_octet_string(
                                        CCDER_OCTET_STRING, priv_size, priv_key, der, tmp_end)));
    }
    return tmp_end;
}

