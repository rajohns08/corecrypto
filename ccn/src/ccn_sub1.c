/* Copyright (c) (2011,2015,2018,2019,2020) Apple Inc. All rights reserved.
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

#if !CCN_SUB1_ASM
#if !CCN_UINT128_SUPPORT_FOR_64BIT_ARCH

cc_unit ccn_sub1(cc_size n, cc_unit *r, const cc_unit *s, cc_unit v)
{
    if (n == 0) {
        return v; // pass the input to the output
    }

    cc_unit borrow = ccn_sub(1, r, s, &v);

    for (cc_size i = 1; i < n; i++) {
        borrow = (s[i] & CCN_UNIT_LOWER_HALF_MASK) - borrow;
        cc_unit lo = borrow & CCN_UNIT_LOWER_HALF_MASK;
        borrow >>= CCN_UNIT_BITS - 1;

        borrow = (s[i] >> CCN_UNIT_HALF_BITS) - borrow;
        r[i] = (borrow << CCN_UNIT_HALF_BITS) | lo;
        borrow >>= CCN_UNIT_BITS - 1;
    }

    return borrow;
}

#else

cc_unit ccn_sub1(cc_size n, cc_unit *r, const cc_unit *s, cc_unit v)
{
    if (n == 0) {
        return v; // pass the input to the output
    }

    cc_dunit borrow = v;

    for (cc_size i = 0; i < n; i++) {
        borrow = (cc_dunit)s[i] - borrow;
        r[i] = (cc_unit)borrow;
        borrow >>= CCN_UNIT_BITS * 2 - 1;
    }

    return (cc_unit)borrow;
}

#endif /* !CCN_UINT128_SUPPORT_FOR_64BIT_ARCH */
#endif /* !CCN_SUB1_ASM */
