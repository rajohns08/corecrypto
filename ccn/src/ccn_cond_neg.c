/* Copyright (c) (2018,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccn_internal.h"

void ccn_cond_neg(cc_size n, cc_unit s, cc_unit *r, const cc_unit *x)
{
    cc_unit mask0, mask1;
    cc_assert(s == 0 || s == 1);

    // Build a mask with hamming weight half the CPU word size, and its
    // complementary mask. Avoid any intermediate occurance of extreme hamming
    // weight values which could provide a distinguisher on the sensitive
    // variable s.
    mask0 = ((cc_unit)(s ^ 1) << (CCN_UNIT_BITS / 2)) + (s); // 0x00010000 or 0x00000001
    mask1 = ((cc_unit)s << (CCN_UNIT_BITS / 2)) + 1;         // 0x00000001 or 0x00010001
    mask0 = mask0 - mask1;                                   // 0x00010000 - 0x00000001 = 0x0000ffff
                                                             // or 0x00000001 - 0x00010001 = 0xffff0000
    mask1 = ~mask0;

#if CCN_UINT128_SUPPORT_FOR_64BIT_ARCH
    cc_dunit c = 1;
#else
    cc_unit c = 1;
#endif

    for (cc_size i = 0; i < n; i++) {
        cc_unit u0 = x[i] ^ CCN_UNIT_MASK;
        cc_unit u1 = x[i];

#if CCN_UINT128_SUPPORT_FOR_64BIT_ARCH
        c += u0;
        u0 = (cc_unit)c;
        c >>= CCN_UNIT_BITS;
#else
        c += u0 & CCN_UNIT_LOWER_HALF_MASK;
        cc_unit lo = c & CCN_UNIT_LOWER_HALF_MASK;
        c >>= CCN_UNIT_HALF_BITS;

        c += u0 >> CCN_UNIT_HALF_BITS;
        u0 = (c << CCN_UNIT_HALF_BITS) | lo;
        c >>= CCN_UNIT_HALF_BITS;
#endif

        // Process a and b in one cc_unit word in order to avoid handling CPU
        // words with extreme Hamming weights which could provide a
        // distinguisher on the value of s.
        r[i] = ((((u0 & CCN_UNIT_LOWER_HALF_MASK) | (u1 & CCN_UNIT_UPPER_HALF_MASK)) & mask1) |
                (((u0 & CCN_UNIT_UPPER_HALF_MASK) | (u1 & CCN_UNIT_LOWER_HALF_MASK)) & mask0));
    }
}
