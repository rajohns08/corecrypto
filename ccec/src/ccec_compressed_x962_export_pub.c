/* Copyright (c) (2014,2015,2018,2020) Apple Inc. All rights reserved.
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


size_t ccec_compressed_x962_export_pub_size(ccec_const_cp_t cp)
{
    return (ccec_cp_prime_size(cp) + 1);
}

int ccec_compressed_x962_export_pub(const ccec_pub_ctx_t key, uint8_t *out)
{
    ccec_const_cp_t cp = ccec_ctx_cp(key);
    size_t len = ccec_cp_prime_size(cp);
    cc_size n = ccec_cp_n(cp);
    int result = CCERR_OK;
    
    // Export x directly
    result = ccn_write_uint_padded_ct(n, ccec_ctx_x(key), len, (uint8_t *)out + 1);
    result = result > 0 ? 0 : result; //Don't return values bigger than 0 if output was padded.

    // Compute parity of y, and add corresponding byte (0x2to the front of output.
    out[0] = 0x02 + (ccec_ctx_y(key)[0] & 1);
    return result;
}
