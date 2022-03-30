/* Copyright (c) (2011,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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
#include <corecrypto/cczp.h>

int ccdh_import_priv(ccdh_const_gp_t gp, size_t in_len, const uint8_t *in,
                     ccdh_full_ctx_t key)
{
    const cc_unit *g = ccdh_gp_g(gp);
    ccdh_ctx_init(gp, ccdh_ctx_public(key));

    cc_unit *x = ccdh_ctx_x(key);
    cc_unit *y = ccdh_ctx_y(key);


    if ((ccn_read_uint(ccdh_gp_n(gp), x, in_len, in)))
        return CCDH_INVALID_INPUT;

    if (ccn_cmp(ccdh_gp_n(gp), x, cczp_prime(ccdh_gp_zp(gp))) >= 0)
        return CCDH_SAFETY_CHECK;

    /* Generate the public key: y=g^x mod p */
    if (cczp_mm_power(ccdh_gp_zp(gp), y, g, x))
        return CCDH_ERROR_DEFAULT;

    return 0;
}
