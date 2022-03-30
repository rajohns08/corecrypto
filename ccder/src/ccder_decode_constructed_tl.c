/* Copyright (c) (2012,2015,2017,2019) Apple Inc. All rights reserved.
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

static const uint8_t *ccder_decode_constructed_tl_internal(ccder_tag expected_tag,
                                                  const uint8_t **body_end,
                                                  const uint8_t *der,
                                                  const uint8_t *der_end,
                                                  bool strict)
{
    size_t len;
    *body_end = der; // In case of failure, this is the end
    
    der = ccder_decode_tl_internal(expected_tag, &len, der, der_end, strict);
    
    if (der) {
        *body_end = der + len;
    }
    return der;
}

const uint8_t *
ccder_decode_constructed_tl_strict(ccder_tag expected_tag, const uint8_t **body_end, const uint8_t *der, const uint8_t *der_end)
{
    return ccder_decode_constructed_tl_internal(expected_tag, body_end, der, der_end, true);
}

const uint8_t *
ccder_decode_constructed_tl(ccder_tag expected_tag, const uint8_t **body_end, const uint8_t *der, const uint8_t *der_end)
{
    return ccder_decode_constructed_tl_internal(expected_tag, body_end, der, der_end, false);
}
