/* Copyright (c) (2015,2016,2019) Apple Inc. All rights reserved.
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

const uint8_t *
ccder_decode_uint_n(cc_size *n,
                    const uint8_t *der, const uint8_t *der_end) {
    size_t len;
    der = ccder_decode_tl(CCDER_INTEGER, &len, der, der_end);
    if (der && (der+len)<=der_end) {
        
        // Find most significant byte
        der=ccder_decode_uint_skip_leading_zeroes(&len, der);

        // Exit on error
        if (!der) goto errOut;
        
        // Convert size in number of cc_unit
        if (n) *n=ccn_nof_size(len);
        return der+len;
    }
errOut:
    *n=0;
    return NULL;
}
