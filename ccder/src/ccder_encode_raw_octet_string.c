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

uint8_t *
ccder_encode_raw_octet_string(size_t s_size, const uint8_t *s,
                                       const uint8_t *der, uint8_t *der_end) {
    return ccder_encode_implicit_raw_octet_string(CCDER_OCTET_STRING, s_size, s, der, der_end);
}
