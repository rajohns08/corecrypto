/* Copyright (c) (2012,2015,2018,2019) Apple Inc. All rights reserved.
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
#include "ccder_internal.h"

const uint8_t *
ccder_decode_tl_internal(ccder_tag expected_tag, size_t *lenp, const uint8_t *der, const uint8_t *der_end, bool strict)
{
    ccder_tag tag;
    der = ccder_decode_tag(&tag, der, der_end);
    if (!der || tag != expected_tag) {
        return NULL;
    }
    
    if (strict) {
        return ccder_decode_len_strict(lenp, der, der_end);
    } else {
        return ccder_decode_len(lenp, der, der_end);
    }
}

const uint8_t *ccder_decode_tl_strict(ccder_tag expected_tag, size_t *lenp, const uint8_t *der, const uint8_t *der_end)
{
    return ccder_decode_tl_internal(expected_tag, lenp, der, der_end, true);
}

const uint8_t *ccder_decode_tl(ccder_tag expected_tag, size_t *lenp, const uint8_t *der, const uint8_t *der_end)
{
    return ccder_decode_tl_internal(expected_tag, lenp, der, der_end, false);
}
