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
#include <corecrypto/cc_macros.h>
#include "cc_debug.h"

static bool
is_in_field(ccec_const_cp_t cp, const cc_unit *t)
{
    if (ccn_cmp(ccec_cp_n(cp),cczp_prime(ccec_cp_zp(cp)),t)>0)
    {
        return true;
    }
    return false;
}


/* Check that a public key is compatible with the domain parameter */
int
ccec_validate_pub_and_projectify(ccec_const_cp_t cp,
                                 ccec_projective_point_t r,
                                 ccec_const_affine_point_t public_point,
                                 struct ccrng_state *masking_rng) {

    int result = -1;

    /* Check that coordinates are compatible with underlying field */
    cc_require(is_in_field(cp,ccec_const_point_x(public_point,cp)),errOut);
    cc_require(is_in_field(cp,ccec_const_point_y(public_point,cp)),errOut);

    /* Point in projective coordinates */
    cc_require((result=ccec_projectify(cp, r, public_point,masking_rng))==0,errOut);

    /* Check that point is on the curve */
    cc_require_action(ccec_is_point(cp,r),errOut,result=-1);

    result = 0; // No error

errOut:
    return result;
}
