/* Copyright (c) (2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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
#include <corecrypto/cc_macros.h>
#include "cc_debug.h"
#include "ccec_internal.h"

size_t ccec_compact_import_priv_size(size_t in_len) {
    switch (in_len) {
        case 48: return 192;
        case 56: return 224;
        case 64: return 256;
        case 96: return 384;
        case 132: return 521;
        default: return 0;
    }
}

int ccec_compact_import_priv(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_full_ctx_t key) {
    int result=-1;

    /* Length must be twice the size of p */
    cc_require((in_len == (ccec_cp_prime_size(cp)+ccec_cp_order_size(cp))),errOut);

    /* Init struct */
    ccec_ctx_init(cp, key);

    /* Import the public part */
    cc_require(ccec_compact_import_pub(cp, in_len>>1, in,ccec_ctx_pub(key))==0,errOut);

    /* Import the private part */
    cc_require(ccn_read_uint(ccec_cp_n(cp), ccec_ctx_k(key), in_len>>1, in+(in_len>>1))==0,errOut);

    result=0;
errOut:
    return result;
}
