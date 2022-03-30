/* Copyright (c) (2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccdh.h>
#include "ccdh_internal.h"

int ccdh_init_gp_from_bytes(ccdh_gp_t gp, cc_size n,
                            size_t p_nbytes, const uint8_t *p,
                            size_t g_nbytes, const uint8_t *g,
                            size_t q_nbytes, const uint8_t *q,
                            size_t l_bits)
{
    int status;

    /* initialize prime, and g */
    CCDH_GP_N(gp) = n;

    status = ccn_read_uint(n, CCDH_GP_PRIME(gp), p_nbytes, p);
    status |= ccn_read_uint(n, CCDH_GP_G(gp), g_nbytes, g);
    
    // Use loaded primes to see if it matches known groups
    ccdh_const_gp_t known_group = ccdh_ccn_lookup_gp(n, CCDH_GP_PRIME(gp), n, CCDH_GP_G(gp));
    
    // If group is a known group we copy reciprocal, q and l parameters from known source.
    // Otherwise we read in whatever was provided as a q and l, and compare the reciprocal (i.e, init zp on prime).
    if (known_group != NULL) {
        status |= ccdh_copy_gp(gp, known_group);
        if (ccdh_gp_l(gp) == CCDH_MAX_GROUP_EXPONENT_BIT_LENGTH) { // Max Length is unfortunately also default for not included.
            CCDH_GP_L(gp) = l_bits; // There was no assigned group length in the lookup, use length provided.
        }
    } else {
        if (q) {
            status |= ccn_read_uint(n, CCDH_GP_Q(gp), q_nbytes, q);
            CCDH_GP_L(gp) = CCDH_MAX_GROUP_EXPONENT_BIT_LENGTH;  // Setting should be ignored, but it setup defensively.
        } else { // 0 has a special meaning: max key length
            CCDH_GP_L(gp) = l_bits;
        }
        
        status |= cczp_init(CCDH_GP_ZP(gp)); // Compute reciprocal
    }
    ccdh_ramp_gp_exponent(l_bits, gp); // Ensure exponent length l is at least CCDH_MIN_GROUP_EXPONENT_BIT_LENGTH
    
    return status;
}
