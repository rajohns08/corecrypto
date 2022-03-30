/* Copyright (c) (2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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
#include <corecrypto/ccrng.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cczp.h>
#include <corecrypto/cc_macros.h>
#include "cc_debug.h"
#include "ccec_internal.h"

/* Make a scalar k in the good range */
/* This approach induces a bias on the generated scalar so that is method is not
 recommend. It is here to reconstruct deterministic keys made with
 this method */
int
ccec_generate_scalar_legacy(ccec_const_cp_t cp,
                            size_t entropy_len, const uint8_t *entropy,
                            cc_unit *k)
{
    int result=CCEC_GENERATE_KEY_DEFAULT_ERR;

    /* Get base point G in projected form. */
    cczp_const_t zq = ccec_cp_zq(cp);
    cc_size n=ccec_cp_n(cp);

    /* Generate a random private key k. */
    if (entropy_len<ccn_sizeof_n(n)) {
        return CCEC_GENERATE_NOT_ENOUGH_ENTROPY;
    }

    cc_memcpy(k,entropy,ccn_sizeof_n(n)); // Copy entropy

    // Truncate the MSB bits
    cc_size lbits = ccec_cp_order_bitlen(cp) & (CCN_UNIT_BITS - 1);
    if (lbits) {
        cc_unit msuMask = (~CC_UNIT_C(0)) >> (CCN_UNIT_BITS - lbits);
        k[n - 1] &= msuMask;
    }

    /* Adjust k to be in the correct range */
    /* If k >= q -> k -= q.  Since 2q doesn't fit in the number of bits used
     to represent k the resulting k is guarenteed to be < q. */
    if (ccn_cmp(n, k, cczp_prime(zq)) >= 0) {
        ccn_sub(n, k, k, cczp_prime(zq));
    }
    result=0; // success
    return result;
}
