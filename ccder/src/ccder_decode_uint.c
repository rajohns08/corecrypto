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
#include <corecrypto/ccder_priv.h>
#include "ccder_internal.h"

static const uint8_t *ccder_decode_uint_internal(cc_size n, cc_unit *r, const uint8_t *der, const uint8_t *der_end, bool strict)
{
    size_t len;
    der = ccder_decode_tl_internal(CCDER_INTEGER, &len, der, der_end, strict);
    
    if (der && (der + len) <= der_end) {
        // Find most significant byte
        der = ccder_decode_uint_skip_leading_zeroes(&len, der);

        // Transform the byte array in cc_unit array
        if (!r || !der || ccn_read_uint(n, r, len, der) < 0) {
            goto errOut;
        }
        return der + len;
    }
errOut:
    return NULL;
}

const uint8_t *ccder_decode_uint_strict(cc_size n, cc_unit *r, const uint8_t *der, const uint8_t *der_end)
{
    return ccder_decode_uint_internal(n, r, der, der_end, true);
}

const uint8_t *ccder_decode_uint(cc_size n, cc_unit *r, const uint8_t *der, const uint8_t *der_end)
{
    return ccder_decode_uint_internal(n, r, der, der_end, false);
}
