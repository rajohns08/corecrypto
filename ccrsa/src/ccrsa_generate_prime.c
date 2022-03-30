/* Copyright (c) (2011-2013,2015-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccrsa_internal.h"
#include <corecrypto/ccrng.h>

/* The recommended number of Miller-Rabin iterations. */
#define CCRSA_PRIME_DEPTH 16

int ccrsa_generate_prime(cc_size nbits,
                         cc_unit *p,
                         const cc_unit *e,
                         struct ccrng_state *rng,
                         struct ccrng_state *rng_mr)
{
    cc_size n = ccn_nof(nbits);

    if (n == 0) {
        return CCERR_PARAMETER;
    }

    /* Public exponent must be odd. */
    if ((e[0] & 1) == 0) {
        return CCERR_PARAMETER;
    }

    cc_size ne = ccn_n(n, e);

    while (1) {
        /* Generate nbit wide random ccn. */
        int rv = ccn_random_bits(nbits, p, rng);
        if (rv) {
            break;
        }

        ccn_set_bit(p, nbits - 1, 1); /* Set high bit. */
        ccn_set_bit(p, nbits - 2, 1); /* Set second highest bit per X9.31. */
        ccn_set_bit(p, 0, 1);         /* Set low bit. */

        /* Check that p is a prime and gcd(p-1,e) == 1. */
        rv = ccrsa_is_valid_prime(n, p, ne, e, CCRSA_PRIME_DEPTH, rng_mr);

        /* We found a prime. */
        if (rv == 1) {
            return CCERR_OK;
        }

        /* The operation failed. */
        if (rv < 0) {
            return rv;
        }
    }

    return CCERR_INTERNAL;
}
