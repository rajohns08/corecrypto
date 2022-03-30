/* Copyright (c) (2010,2011,2012,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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
#include "ccec_internal.h"

void ccec_x963_export(const int fullkey, void *out, ccec_full_ctx_t key)
{
    ccec_const_cp_t cp = ccec_ctx_cp(key);
    size_t p_size = ccec_cp_prime_size(cp);
    size_t q_size = ccec_cp_order_size(cp);
    cc_size n = ccec_cp_n(cp);
    uint8_t *ix = out;

    *ix++ = 0x04;
    ccn_write_uint_padded_ct(n, ccec_ctx_x(key), p_size, out + 1);
    ccn_write_uint_padded_ct(n, ccec_ctx_y(key), p_size, out + 1 + p_size);
    if(fullkey) ccn_write_uint_padded_ct(n, ccec_ctx_k(key), q_size, out + 1 + 2*p_size);
}
