/* Copyright (c) (2011,2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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
#include <corecrypto/cc_priv.h>

#include "cc_debug.h"

/* DEPRECATED - Urgent to migrate to ccdh_compute_shared_secret */
int ccdh_compute_key(ccdh_full_ctx_t private_key, ccdh_pub_ctx_t public_key,
                     cc_unit *r) {
    int result = CCDH_ERROR_DEFAULT;
    ccdh_const_gp_t gp = ccdh_ctx_gp(private_key);
    cc_size n=ccdh_gp_n(gp);
    size_t tmp_len=CC_BITLEN_TO_BYTELEN(ccdh_gp_prime_bitlen(gp));
    uint8_t tmp[tmp_len];
    cc_clear(tmp_len,tmp);

    /* Validated the public key */
    result = ccdh_compute_shared_secret(private_key,public_key,&tmp_len,tmp,ccrng(NULL));
    ccn_read_uint(n, r, tmp_len, tmp);
    cc_clear(tmp_len,tmp);
    return result;
}
