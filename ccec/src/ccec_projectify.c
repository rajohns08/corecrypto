/* Copyright (c) (2010,2011,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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
#include "cczp_internal.h"

// Convert point from affine to jacobian projective coordinates
int ccec_projectify(ccec_const_cp_t cp, ccec_projective_point_t r, ccec_const_affine_point_t s,
                     struct ccrng_state *masking_rng) {
    int status;
    cczp_const_decl(zp, ccec_cp_zp(cp));

    cc_assert((void *)r!=(const void*) s); // Points must differ

#if CCEC_DEBUG
    ccec_alprint(cp, "ccec_projectify input", s);
#endif

    // Initialize z
#if CCEC_MASKING
    // Randomized z coordinate
    if (masking_rng) {
        cc_size bitlen=ccec_cp_prime_bitlen(cp);
        status=ccn_random_bits(bitlen-1, ccec_point_z(r, cp), masking_rng);
        ccn_set_bit(ccec_point_z(r, cp), bitlen-2, 1);
        cczp_sqr(zp, ccec_point_x(r, cp), ccec_point_z(r, cp));                       // Z^2 (mtgR^-1)
        cczp_mul(zp, ccec_point_y(r, cp), ccec_point_x(r, cp), ccec_point_z(r, cp));  // Z^3 (mtgR^-2)

        // Set point coordinate from Z, Z^2, Z^3
        cczp_mul(zp, ccec_point_x(r, cp), ccec_point_x(r, cp), ccec_const_point_x(s, cp)); // x.Z^2.mtgR (mtgR^-3)
        cczp_mul(zp, ccec_point_y(r, cp), ccec_point_y(r, cp), ccec_const_point_y(s, cp)); // y.Z^3.mtgR (mtgR^-4)
                                                                                              // Z.mtgR     (mtgR^-1)
        cczp_to(zp, ccec_point_x(r, cp), ccec_point_x(r, cp));      // x.Z^2.mtgR (mtgR^-2)
        cczp_to(zp, ccec_point_y(r, cp), ccec_point_y(r, cp));      // y.Z^3.mtgR (mtgR^-3)
                                                                    // Z.mtgR     (mtgR^-1)
    } else
#endif
    // Fixed z coordinate
    {
        ccn_seti(ccec_cp_n(cp), ccec_point_z(r, cp),1);
        (void) masking_rng;

        // Set point in the arithmetic representation
        cczp_to(zp, ccec_point_x(r, cp), ccec_const_point_x(s, cp));
        cczp_to(zp, ccec_point_y(r, cp), ccec_const_point_y(s, cp));
        cczp_to(zp, ccec_point_z(r, cp), ccec_point_z(r, cp));
        status=0;
    }
#if CCEC_DEBUG
    ccec_plprint(cp, "ccec_projectify output", r);
#endif
    return status;
}
