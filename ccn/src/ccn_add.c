/* Copyright (c) (2010,2015,2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccn.h>

#if !CCN_ADD_ASM
#if !CCN_UINT128_SUPPORT_FOR_64BIT_ARCH

cc_unit ccn_add(cc_size count, cc_unit *r, const cc_unit *s, const cc_unit *t)
{
    cc_unit carry = 0;

    for (cc_size i = 0; i < count; i++) {
        carry += s[i] & CCN_UNIT_LOWER_HALF_MASK;
        carry += t[i] & CCN_UNIT_LOWER_HALF_MASK;
        cc_unit lo = carry & CCN_UNIT_LOWER_HALF_MASK;
        carry >>= CCN_UNIT_HALF_BITS;

        carry += s[i] >> CCN_UNIT_HALF_BITS;
        carry += t[i] >> CCN_UNIT_HALF_BITS;
        r[i] = (carry << CCN_UNIT_HALF_BITS) | lo;
        carry >>= CCN_UNIT_HALF_BITS;
    }

    return carry;
}

#else

cc_unit ccn_add(cc_size count, cc_unit *r, const cc_unit *s, const cc_unit *t)
{
    cc_dunit carry = 0;

    for (cc_size i = 0; i < count; i++) {
        carry += (cc_dunit)s[i] + t[i];
        r[i] = (cc_unit)carry;
        carry >>= CCN_UNIT_BITS;
    }

    return (cc_unit)carry;
}

#endif /* !CCN_UINT128_SUPPORT_FOR_64BIT_ARCH */
#endif /* !CCN_ADD_ASM */
