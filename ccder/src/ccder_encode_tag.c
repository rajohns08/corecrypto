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
ccder_encode_tag(ccder_tag tag, const uint8_t *der, uint8_t *der_end) {
#ifdef CCDER_MULTIBYTE_TAGS
    uint8_t tag0 = (tag >> (sizeof(ccder_tag) * 8 - 8));
    ccder_tag num = (tag & CCDER_TAGNUM_MASK);
    if (num < 0x1f) {
        /* 5 bit (minus all ones) tag num. */
        if (der + 1 > der_end) return NULL;
        *--der_end = (uint8_t)((tag0 & 0xe0) | num);
    } else {
        if (num <= 0x7f) {
            /* 7 bit or smaller tag num. */
            if (der + 2 > der_end) return NULL;
            *--der_end = (uint8_t)num;
        } else if (num <= 0x3fff) {
            /* 14 bit or smaller tag num. */
            if (der + 3 > der_end) return NULL;
            *--der_end = num & 0x7f;
            *--der_end = (uint8_t)(num >>  7) | 0x80;
        } else if (num <= 0x1fffff) {
            /* 21 bit or smaller tag num. */
            if (der + 4 > der_end) return NULL;
            *--der_end = num & 0x7f;
            *--der_end = (uint8_t)(num >>  7) | 0x80;
            *--der_end = (uint8_t)(num >> 14) | 0x80;
        } else if (num <= 0xfffffff) {
            /* 28 bit or smaller tag num. */
            if (der + 5 > der_end) return NULL;
            *--der_end = num & 0x7f;
            *--der_end = (uint8_t)(num >>  7) | 0x80;
            *--der_end = (uint8_t)(num >> 14) | 0x80;
            *--der_end = (uint8_t)(num >> 21) | 0x80;
        } else {
            /* 35 bit or smaller tag num. */
            if (der + 6 > der_end) return NULL;
            *--der_end = num & 0x7f;
            *--der_end = (uint8_t)(num >>  7) | 0x80;
            *--der_end = (uint8_t)(num >> 14) | 0x80;
            *--der_end = (uint8_t)(num >> 21) | 0x80;
            *--der_end = (uint8_t)(num >> 28) | 0x80;
        }
        *--der_end = tag0 | 0x1f;
    }
    return der_end;
#else
    if (der < der_end)
        *--der_end = tag;
    return der_end;
#endif /* !CCDER_MULTIBYTE_TAGS */
}
