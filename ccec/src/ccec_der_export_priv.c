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

#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include <corecrypto/ccder.h>

/*  version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1), */
/* privateKey     OCTET STRING, */
/* parameters [0] ECParameters {{ NamedCurve }} OPTIONAL, */
/* publicKey  [1] BIT STRING OPTIONAL */


size_t
ccec_der_export_priv_size(ccec_full_ctx_t key, ccoid_t key_oid, int includePublic)
{
    ccec_const_cp_t cp = ccec_ctx_cp(key);
    size_t priv_size = ccec_cp_order_size(cp);
    size_t pub_size = 0;

    if (includePublic)
        pub_size = ccec_export_pub_size(ccec_ctx_pub(key));
    return ccder_encode_eckey_size(priv_size, key_oid, pub_size);
}

int
ccec_der_export_priv(ccec_full_ctx_t key, ccoid_t key_oid, int includePublic, size_t out_len, void *out)
{
    ccec_const_cp_t cp = ccec_ctx_cp(key);
    uint8_t *der_end = ((uint8_t *)out) + out_len;
    uint8_t *tmp;

    size_t priv_size = ccec_cp_order_size(cp);
    uint8_t priv_key[priv_size];

    ccn_write_uint_padded_ct(ccec_cp_n(cp), ccec_ctx_k(key), priv_size, priv_key);

    size_t pub_size = 0;
    if (includePublic) {
        pub_size = ccec_export_pub_size(ccec_ctx_pub(key));
    }
    uint8_t pub_key[pub_size + 1];
    if (includePublic)
        ccec_export_pub(ccec_ctx_pub(key), pub_key);

    tmp = ccder_encode_eckey(priv_size, priv_key, key_oid, pub_size, pub_key, out, der_end);
    if (tmp != out) return -1;
    return 0;
}
