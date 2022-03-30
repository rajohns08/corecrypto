/* Copyright (c) (2011,2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
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
#include <corecrypto/cc_macros.h>

int ccdh_generate_key(ccdh_const_gp_t gp, struct ccrng_state *rng, ccdh_full_ctx_t key)
{
    int rv;
    ccdh_ctx_init(gp, ccdh_ctx_public(key));
    const cc_unit *g = ccdh_gp_g(gp);

    cc_unit *x = ccdh_ctx_x(key);
    cc_unit *y = ccdh_ctx_y(key);

    /* Generate the private key: x per PKCS #3 */
    cc_require((rv = ccdh_generate_private_key(gp, x, rng)) == CCERR_OK, errOut);

    /* Generate the public key: y=g^x mod p */
    cc_require((rv = cczp_mm_power_ssma(ccdh_gp_zp(gp), y, g, x)) == CCERR_OK, errOut);

    /* Check that 1 < Y < p-1 and 1 = Y^q (mod p)  */
    cc_require((rv = ccdh_check_pub(gp, ccdh_ctx_public(key))) == CCERR_OK, errOut);

    if (!ccdh_pairwise_consistency_check(gp, rng, key)) {
        rv = CCDH_GENERATE_KEY_CONSISTENCY;
        goto errOut;
    }

    rv = CCERR_OK;

errOut:
    return rv;
}
