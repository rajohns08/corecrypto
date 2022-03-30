/* Copyright (c) (2010,2015,2016,2019) Apple Inc. All rights reserved.
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

#if !CCN_CMP_ASM

#include <corecrypto/cc_priv.h>
#include "../corecrypto/ccn_op.h"

// constant time comparison when assembly is not available
int ccn_cmp(cc_size n, const cc_unit *s, const cc_unit *t)
{
    cc_unit six=0,tix=0;
    cc_unit sel;

    for (cc_size ix=0;ix<n;ix++) {
        sel = ccop_eq(s[ix], t[ix]); // ~0 iff (s[ix] == t[ix]), 0 otherwise
        six = ccop_sel(sel, six, s[ix]); // Keep the values of the most significant difference
        tix = ccop_sel(sel, tix, t[ix]);
    }

    // compute the difference
    int d1 = ccop_neq(six, tix)&1; // 0 if (=), 1 otherwise
    int d2 = ccop_lt(six, tix)&2;  // 2 if (-), 0 otherwise

    return d1-d2;
}

#endif /* !CCN_CMP_ASM */
