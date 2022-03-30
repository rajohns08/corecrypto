/* Copyright (c) (2012,2015,2019) Apple Inc. All rights reserved.
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

const uint8_t *ccder_decode_sequence_tl_strict(const uint8_t **body_end, const uint8_t *der, const uint8_t *der_end)
{
    return ccder_decode_constructed_tl_strict(CCDER_CONSTRUCTED_SEQUENCE, body_end, der, der_end);
}

const uint8_t *ccder_decode_sequence_tl(const uint8_t **body_end, const uint8_t *der, const uint8_t *der_end)
{
    return ccder_decode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE, body_end, der, der_end);
}
