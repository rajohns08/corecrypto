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

static const uint8_t *ccder_decode_len_internal(size_t *lenp, const uint8_t *der, const uint8_t *der_end, bool strict)
{
    if (der && der < der_end) {
        size_t len = *der++;
        if (len < 0x80) {
        } else if (len == 0x81) {
            if (der_end - der < 1)
                goto errOut;
            len = *der++;
            if (strict && (len < 0x80)) {
                goto errOut;
            }
        } else if (len == 0x82) {
            if (der_end - der < 2)
                goto errOut;
            len = (size_t)*(der++) << 8;
            len += *der++;
            if (strict && (len <= 0xff)) {
                goto errOut;
            }
        } else if (len == 0x83) {
            if (der_end - der < 3)
                goto errOut;
            len = (size_t)*(der++) << 16;
            len += (size_t)*(der++) << 8;
            len += *(der++);
            if (strict && (len <= 0xffff)) {
                goto errOut;
            }
        } else {
            goto errOut;
        }
        if ((size_t)(der_end - der) >= len) {
            *lenp = len;
            return der;
        }
    }
errOut:
    return NULL;
}

const uint8_t *ccder_decode_len_strict(size_t *lenp, const uint8_t *der, const uint8_t *der_end)
{
    return ccder_decode_len_internal(lenp, der, der_end, true);
}


const uint8_t *ccder_decode_len(size_t *lenp, const uint8_t *der, const uint8_t *der_end)
{
    return ccder_decode_len_internal(lenp, der, der_end, false);
}
