/* Copyright (c) (2010,2011,2015,2018,2019) Apple Inc. All rights reserved.
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

#if !CCN_N_ASM

#include <corecrypto/cc_priv.h>

#define CCN_N_DEBUG (CORECRYPTO_DEBUG && 0)

// Non constant time version for reference.
#if CCN_N_DEBUG
static cc_size ccn_n_ref(cc_size n, const cc_unit *s) {
    while (n-- && s[n] == 0) {}
    return n + 1;
}
#endif

// Constant time implementation when assembly is not available.
cc_size ccn_n(cc_size n, const cc_unit *s) {
    cc_unit s_tmp;
    cc_size ms_ix=0;
    for (cc_size ix = 1; ix <= n; ix++) {
        CC_HEAVISIDE_STEP(s_tmp, s[ix - 1]); // 1 iff (s[ix]!=0)
        // Keep the (index+1) of the most significant non zero cc_unit
        CC_MUXU(ms_ix, s_tmp, ix, ms_ix);
    }
#if CCN_N_DEBUG
    cc_assert(ms_ix == ccn_n_ref(n,s));
#endif
    return ms_ix;
}


#endif
