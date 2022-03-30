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

void ccn_cond_shift_right_carry(cc_size n, cc_unit s, cc_unit *r, const cc_unit *a, size_t k, cc_unit c)
{
    cc_unit mask0, mask1;
    cc_assert(s == 0 || s == 1);
    cc_assert(k < CCN_UNIT_BITS);
    cc_assert(c < (CC_UNIT_C(1) << k));

    // Build a mask with hamming weight half the CPU word size, and its
    // complementary mask. Avoid any intermediate occurance of extreme hamming
    // weight values which could provide a distinguisher on the sensitive
    // variable s.
    mask0 = ((cc_unit)(s ^ 1) << (CCN_UNIT_BITS / 2)) + (s); // 0x00010000 or 0x00000001
    mask1 = ((cc_unit)s << (CCN_UNIT_BITS / 2)) + 1;         // 0x00000001 or 0x00010001
    mask0 = mask0 - mask1;                                   // 0x00010000 - 0x00000001 = 0x0000ffff
                                                             // or 0x00000001 - 0x00010001 = 0xffff0000
    mask1 = ~mask0;

    cc_unit knz; // k≠0?
    CC_HEAVISIDE_STEP(knz, k);
    cc_unit kmask = -knz;

    cc_unit m = CCN_UNIT_BITS - k - (knz ^ 1);

    for (cc_size i = n - 1; i < n; i--) {
        cc_unit u0 = ((c << m) & kmask) | (a[i] >> k);
        cc_unit u1 = a[i];

        c = a[i];

        // Process a and b in one cc_unit word in order to avoid handling CPU
        // words with extreme Hamming weights which could provide a
        // distinguisher on the value of s.
        r[i] = ((((u0 & CCN_UNIT_LOWER_HALF_MASK) | (u1 & CCN_UNIT_UPPER_HALF_MASK)) & mask1) |
                (((u0 & CCN_UNIT_UPPER_HALF_MASK) | (u1 & CCN_UNIT_LOWER_HALF_MASK)) & mask0));
    }
}

void ccn_cond_shift_right(cc_size n, cc_unit s, cc_unit *r, const cc_unit *a, size_t k)
{
    ccn_cond_shift_right_carry(n, s, r, a, k, 0);
}
