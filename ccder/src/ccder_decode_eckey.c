/* Copyright (c) (2012,2015,2016,2019) Apple Inc. All rights reserved.
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

/* RFC 5915

 ECPrivateKey ::= SEQUENCE {
 version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 privateKey     OCTET STRING,
 parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 publicKey  [1] BIT STRING OPTIONAL

 }
*/

const uint8_t *
ccder_decode_eckey(uint64_t *version,
                                  size_t *priv_size, const uint8_t **priv_key,
                                  ccoid_t *oid,
                                  size_t *pub_size, const uint8_t **pub_key,
                                  const uint8_t *der, const uint8_t *der_end) {
    const uint8_t *der_ptr = der, *der_tmp;
    size_t der_len = 0;

    der_ptr = ccder_decode_sequence_tl(&der_end,  der_ptr, der_end);

    /*  version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1), */
    der_ptr = ccder_decode_uint64(version, der_ptr, der_end);
    if (*version != 1) return NULL;

    /* privateKey     OCTET STRING, */
    der_ptr = ccder_decode_tl(CCDER_OCTET_STRING, &der_len, der_ptr, der_end);

    if (der_ptr) {
        *priv_key = der_ptr;
        *priv_size = der_len;
        der_ptr += der_len;
    }

    /* parameters [0] ECParameters {{ NamedCurve }} OPTIONAL, */
    der_tmp = ccder_decode_tl(CCDER_CONTEXT_SPECIFIC|CCDER_CONSTRUCTED|0,
                              &der_len, der_ptr, der_end);
    if (der_tmp) {
        der_ptr = der_tmp;
        der_ptr = ccder_decode_oid(oid, der_ptr, der_ptr + der_len);
    } else {
        *oid = (ccoid_t){ NULL };
    }

    /* publicKey  [1] BIT STRING OPTIONAL */
    der_tmp = ccder_decode_tl(CCDER_CONTEXT_SPECIFIC|CCDER_CONSTRUCTED|1,
                              &der_len, der_ptr, der_end);
    if (der_tmp) {
        der_ptr = ccder_decode_bitstring(pub_key, pub_size, der_tmp, der_tmp + der_len);
    } else {
        *pub_key = NULL;
        *pub_size = 0;
    }
    
    return der_ptr;
}

