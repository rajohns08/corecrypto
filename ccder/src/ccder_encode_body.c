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
#include <corecrypto/cc_priv.h>

uint8_t *
ccder_encode_body(size_t size, const uint8_t *body, const uint8_t *der, uint8_t *der_end) {
    if (der + size > der_end)
        return NULL;
    cc_memmove(der_end - size, body, size);
    return der_end - size;
}
