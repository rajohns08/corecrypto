/* Copyright (c) (2016,2017,2018,2019) Apple Inc. All rights reserved.
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

/* Conditionally swap the content of r0 and r1 buffers in constant time
 r0:r1 <- r1*k1 + s0*(k1-1)  */
void ccn_cond_swap(cc_size n, cc_unit ki, cc_unit *r0, cc_unit *r1)
{
    cc_unit mask0, mask1;
    cc_assert(ki == 0 || ki == 1);
    // Build a mask with hamming weight half the CPU word size, and its complementary mask
    // Avoid any intermediate occurance of extreme hamming weight values which could provide a distinguisher on the sensitive variable ki
    mask0 = ((ki ^ 1) << (CCN_UNIT_BITS / 2)) + (ki); // 0x00010000 or 0x00000001
    mask1 = (ki << (CCN_UNIT_BITS / 2)) + 1;          // 0x00000001 or 0x00010001
    mask0 = mask0 - mask1;                            // 0x00010000 - 0x00000001 = 0x0000ffff
                                                      // or 0x00000001 - 0x00010001 = 0xffff0000
    mask1 = ~mask0;
    // Copy involving the possible operands
    for (cc_size i = 0; i < n; i++) {
        cc_unit u0 = r0[i];
        cc_unit u1 = r1[i];
        // Processing r0 and r1 in one cc_unit word in order to avoid handling CPU words with extreme
        // Hamming weights which could provide a distinguisher on the value of ki
        r0[i] = ((((u0 & CCN_UNIT_LOWER_HALF_MASK) | (u1 & CCN_UNIT_UPPER_HALF_MASK)) & mask0) |
                 (((u0 & CCN_UNIT_UPPER_HALF_MASK) | (u1 & CCN_UNIT_LOWER_HALF_MASK)) & mask1));
        r1[i] = ((((u0 & CCN_UNIT_LOWER_HALF_MASK) | (u1 & CCN_UNIT_UPPER_HALF_MASK)) & mask1) |
                 (((u0 & CCN_UNIT_UPPER_HALF_MASK) | (u1 & CCN_UNIT_LOWER_HALF_MASK)) & mask0));
    }
}
