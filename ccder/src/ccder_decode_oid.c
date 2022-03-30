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

const uint8_t *
ccder_decode_oid(ccoid_t *oidp,
                                const uint8_t *der, const uint8_t *der_end) {
    size_t len;
    const uint8_t *body = ccder_decode_tl(CCDER_OBJECT_IDENTIFIER, &len,
                                          der, der_end);
    if (body) {
        CCOID(*oidp) = der;
        return body + len;
    }

    return NULL;
}
