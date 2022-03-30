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
#include "ccec_internal.h"
#include "cczp_internal.h"

bool
ccec_is_point(ccec_const_cp_t cp, ccec_const_projective_point_t s)
{
    // Works for affine (Z=1) and projective.
    // also work whether or not Montgomery arithmetic is used
    // as long as a and b are represented in montgomery form if involved in a
    // multiplication.
    return ccec_is_point_projective(cp, s);
}

bool
ccec_is_point_projective(ccec_const_cp_t cp, ccec_const_projective_point_t s)
{
    cczp_const_decl(zp, ccec_cp_zp(cp));
    cc_size n  = ccec_cp_n(cp);

    /* For Jacobian representation */
    cc_unit t[n], u[n], z4[n];
    cczp_sqr(zp, u, ccec_const_point_z(s, cp));              // u = sz^2
    cczp_mul(zp, t, u, ccec_cp_b(cp));                       // t = b*sz^2
    cczp_sqr(zp, z4, u);                                     // z4 = sz^4
    cczp_add(zp, u, ccec_const_point_x(s, cp), ccec_const_point_x(s, cp));  // u = 2sx
    cczp_add(zp, u, u, ccec_const_point_x(s, cp));           // u = 3sx
    cczp_sub(zp, t, t, u);                                   // t = b*sz^2 - 3sx
    cczp_mul(zp, t, t, z4);                                  // t = b*sz^6 - 3sx*sz^4
    cczp_sqr(zp, u, ccec_const_point_x(s, cp));              // u = sx^2
    cczp_mul(zp, u, u, ccec_const_point_x(s, cp));           // u = sx^3
    cczp_add(zp, t, t, u);                                   // t = sx^3 + b*sz^6 - 3sx*sz^4
    cczp_sqr(zp, u, ccec_const_point_y(s, cp));              // u = sy^2
    return (ccn_cmp(n, u, t) == 0);
}
