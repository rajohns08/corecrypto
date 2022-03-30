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

/*
    Based on reference code from <http://ed25519.cr.yp.to/> and <http://bench.cr.yp.to/supercop.html>.
*/

#include <corecrypto/ccec25519.h>
#include <corecrypto/ccec25519_priv.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccrng.h>
#include "cced25519_priv.h"

//==============================================================================
//    cced25519_make_pub
//==============================================================================

int cced25519_make_pub(const struct ccdigest_info *di, ccec25519pubkey pk, const ccec25519secretkey sk)
{
    uint8_t h[64];
    ge_p3 A;
    ASSERT_DIGEST_SIZE(di);
    cc_assert(sizeof(ccec25519key) == 32);
    ccdigest(di, sizeof(ccec25519key), sk, h);
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    ge_scalarmult_base(&A, h);
    ge_p3_tobytes(pk, &A);
    cc_clear(sizeof(h), h);
    return 0;
}

//==============================================================================
//	cced25519_make_key_pair
//==============================================================================

void cced25519_make_key_pair(const struct ccdigest_info *di, struct ccrng_state *rng, ccec25519pubkey pk, ccec25519secretkey sk)
{
    cc_assert(sizeof(ccec25519key) == 32);
    ccrng_generate(rng, sizeof(ccec25519key), sk);
    cced25519_make_pub(di, pk, sk);
}
