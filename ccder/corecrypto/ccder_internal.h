/* Copyright (c) (2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */


#ifndef ccder_internal_h
#define ccder_internal_h

CC_NONNULL((2, 4))
const uint8_t *ccder_decode_tl_internal(ccder_tag expected_tag, size_t *lenp, const uint8_t *der, const uint8_t *der_end, bool strict);

#endif /* ccder_internal_h */
