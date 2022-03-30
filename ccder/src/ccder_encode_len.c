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

#include <stdint.h>

uint8_t *
ccder_encode_len(size_t l, const uint8_t *der, uint8_t *der_end) {
    if ((sizeof(size_t) > 4) && (l>UINT32_MAX)) {
        return NULL; // Not supported
    }
    if        (l <= 0x0000007f) {
        if (der + 1 > der_end) return NULL;
        *--der_end = (uint8_t)(l      );
    } else if (l <= 0x000000ff) {
        if (der + 2 > der_end) return NULL;
        *--der_end = (uint8_t)(l      );
        *--der_end = 0x81;
    } else if (l <= 0x0000ffff) {
        if (der + 3 > der_end) return NULL;
        *--der_end = (uint8_t)(l      );
        *--der_end = (uint8_t)(l >>  8);
        *--der_end = 0x82;
    } else if (l <= 0x00ffffff) {
        if (der + 4 > der_end) return NULL;
        *--der_end = (uint8_t)(l      );
        *--der_end = (uint8_t)(l >>  8);
        *--der_end = (uint8_t)(l >> 16);
        *--der_end = 0x83;
    } else {
        if (der + 5 > der_end) return NULL;
        *--der_end = (uint8_t)(l      );
        *--der_end = (uint8_t)(l >>  8);
        *--der_end = (uint8_t)(l >> 16);
        *--der_end = (uint8_t)(l >> 24);
        *--der_end = 0x84;
    }
    return der_end;
}

