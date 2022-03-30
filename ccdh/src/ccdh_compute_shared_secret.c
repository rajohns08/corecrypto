/* Copyright (c) (2011,2014,2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
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

/* Compute an DH shared secret between private_key and public_key. Return
   the result in computed_key and the
   length of the result in bytes in *computed_key_len.  Return 0 iff
   successful. */
int ccdh_compute_shared_secret(ccdh_full_ctx_t private_key,
                               ccdh_pub_ctx_t public_key,
                               size_t *computed_shared_secret_len,
                               uint8_t *computed_shared_secret,
                               struct ccrng_state *blinding_rng) {
    int result = CCDH_ERROR_DEFAULT;
    ccdh_const_gp_t gp = ccdh_ctx_gp(private_key);
    cc_size n=ccdh_gp_n(gp);
    cc_unit r[n];
    

    size_t outlen=CC_BITLEN_TO_BYTELEN(ccdh_gp_prime_bitlen(gp));

    if (outlen>*computed_shared_secret_len) {
        return CCDH_INVALID_INPUT;
    }

    /* Validated the public key */
    result = ccdh_check_pub(gp, public_key);
    if(result!=0)
    {
        goto errOut;
    }

    /* Actual computation */
    ccdh_power_blinded(blinding_rng, gp, r, ccdh_ctx_y(public_key), ccdh_ctx_x(private_key));

    /* Result can't be 0 (computation issue) or 1 (y in the group) or p-1, where p is size of group*/
    result = CCDH_INVALID_INPUT;
    outlen = ccn_write_uint_size(n, r);
    if (ccdh_valid_shared_secret(n, r, gp) && outlen <= *computed_shared_secret_len)
    {
        result = 0;
        ccn_write_uint_padded(n, r, outlen, computed_shared_secret);
        *computed_shared_secret_len=outlen;
    } else {
        *computed_shared_secret=0;
    }

errOut:
    ccn_clear(n,r);
    return result;
}
