/* Copyright (c) (2014,2015,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccec_priv.h>

void ccec_compact_export_pub(void *out, ccec_pub_ctx_t key)
{
    ccec_const_cp_t cp = ccec_ctx_cp(key);
    size_t len = ccec_cp_prime_size(cp);
    cc_size n = ccec_cp_n(cp);
    
    // https://datatracker.ietf.org/doc/draft-jivsov-ecc-compact/
    // Export x directly
    ccn_write_uint_padded(n, ccec_ctx_x(key), len, out);
}

