/* Copyright (c) (2011,2012,2014,2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cczp_internal.h"
#include "ccn_internal.h"

int cczp_init(cczp_t zp)
{
    CCZP_FUNCS(zp) = CCZP_FUNCS_DEFAULT;
    CCZP_BITLEN(zp) = ccn_bitlen(cczp_n(zp), cczp_prime(zp));
    return ccn_make_recip(cczp_n(zp), CCZP_RECIP(zp), cczp_prime(zp));
}

void cczp_init_ws(cc_ws_t ws, cczp_t zp)
{
    CCZP_FUNCS(zp) = CCZP_FUNCS_DEFAULT;
    CCZP_BITLEN(zp) = ccn_bitlen(cczp_n(zp), cczp_prime(zp));
    ccn_make_recip_ws(ws, cczp_n(zp), CCZP_RECIP(zp), cczp_prime(zp));
}

void cczp_init_with_recip(cczp_t zp, const cc_unit *recip)
{
    CCZP_FUNCS(zp) = CCZP_FUNCS_DEFAULT;
    CCZP_BITLEN(zp) = ccn_bitlen(cczp_n(zp), cczp_prime(zp));
    ccn_set(cczp_n(zp) + 1, CCZP_RECIP(zp), recip);
}
