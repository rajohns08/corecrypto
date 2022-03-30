/* Copyright (c) (2010,2011,2014,2015,2016,2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccrsa_priv.h>
#include "cczp_internal.h"

int ccrsa_pub_crypt(ccrsa_pub_ctx_t ctx, cc_unit *r, const cc_unit *s) {

    size_t ebitlen = ccn_bitlen(ccrsa_ctx_n(ctx), ccrsa_ctx_e(ctx));

    // Reject e<=1 and m<=1 as a valid key.
    if (   (ebitlen<=1)
        || (ccn_is_zero_or_one(ccrsa_ctx_n(ctx), ccrsa_ctx_m(ctx)))) {
        return CCRSA_KEY_ERROR;
    }

    // Proceed
    return cczp_mm_power_fast(ccrsa_ctx_zm(ctx), r, s, ccrsa_ctx_e(ctx));
}
