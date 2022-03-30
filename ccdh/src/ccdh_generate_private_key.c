/* Copyright (c) (2015-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccdh_internal.h"
#include "cc_debug.h"
#include <corecrypto/cc_macros.h>

#define MAX_RETRY 100

int ccdh_generate_private_key(ccdh_const_gp_t gp, cc_unit *x, struct ccrng_state *rng)
{
    int result=CCDH_ERROR_DEFAULT;
    int cmp_result=1;
    size_t i=0;
    size_t l;
    size_t rand_bitlen = 0;
    cc_unit upper_bound[ccdh_gp_n(gp)];
    ccn_zero(ccdh_gp_n(gp), x);
    ccn_zero(ccdh_gp_n(gp), upper_bound);

    l=ccdh_gp_l(gp);

    // Pre-requisite, per PKCS #3 (section 6)
    cc_require_action((l<=ccdh_gp_prime_bitlen(gp)),
                      errOut,result = CCDH_INVALID_DOMAIN_PARAMETER);

    // Generate the random private key x
    // (following pkcs#3 section 7.1 when order is not present)
    // Three cases
    // a) order q is available
    //    0 < x < q-1
    // b) "l" is set, 2^(l-1) <= x < 2^l
    //      upper bound is implicitely met
    //      lower bound is met by setting MS bit
    // c) "l"==0, 0 < x < p-1

    // "l" <= bitlengh(order)+64 is a security risk due to the biais it causes
    // Using the order to generate the key is more secure and efficient
    // and therefore takes precedence.

    if (ccdh_gp_order_bitlen(gp)>0)
    {
        // Upper bound: 0 < x <=q-2
        ccn_sub1(ccdh_gp_n(gp), upper_bound, ccdh_gp_order(gp), 2);
        rand_bitlen=ccdh_gp_order_bitlen(gp);
    }
    else if (l>=1) {
        // Bounds are implicitely met
        cc_require(((result = ccn_random_bits(l, x, rng)) == 0),errOut);
        ccn_set_bit(x, l-1, 1); // 2^(l-1)
        cmp_result=0; // Not entering the loop below
    }
    else {
        // Upper bound: 0 < x <=p-2
        ccn_sub1(ccdh_gp_n(gp), upper_bound, ccdh_gp_prime(gp), 2);
        rand_bitlen=ccdh_gp_prime_bitlen(gp);
    }

    // Try until finding an integer in the correct range
    // This avoids biais in key generation that occurs when using mod.
    for (i = 0; i < MAX_RETRY && cmp_result>0; i++)
    {
        /* Random bits */
        cc_require(((result = ccn_random_bits(rand_bitlen, x, rng)) == 0),errOut);

        /* Check bound */
        cmp_result = ccn_cmp(ccdh_gp_n(gp), x, upper_bound);  // -1, 0  ok
        cmp_result += 2*ccn_is_zero(ccdh_gp_n(gp),x);   // 0 ok
    }

    // Check that an integer has been found.
    if (i >= MAX_RETRY)
    {
        result = CCDH_GENERATE_KEY_TOO_MANY_TRIES;
    }
    else
    {
        result = 0;
    }
errOut:
    return result;
}
