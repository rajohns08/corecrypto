/* Copyright (c) (2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
*/

#include <corecrypto/cc_macros.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccn.h>
#include "ccn_internal.h"
#include <corecrypto/cczp.h>
#include "cczp_internal.h"

#define MAX_RETRY 100

#define NUMBER_OF_EXTRABITS 64

/*
 cczp_generate_non_zero_element follows the FIPS186-4 "Extra Bits" method
 for generating values within a particular range.
 */

int cczp_generate_random_element(cczp_const_t zp, struct ccrng_state *rng, cc_unit *output)
{
    int result;
    cc_size bitlen = cczp_bitlen(zp) + NUMBER_OF_EXTRABITS;
    cc_size n = cczp_n(zp);
    cc_size np = ccn_nof(bitlen);

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCN_DIV_EUCLID_WORKSPACE_SIZE(np, n));
    result = cczp_generate_random_element_ws(ws, zp, rng, output);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return result;
}

int cczp_generate_random_element_ws(cc_ws_t ws, cczp_const_t zp, struct ccrng_state *rng, cc_unit *output)
{
    int result;
    cc_size bitlen = cczp_bitlen(zp) + NUMBER_OF_EXTRABITS;
    cc_size n = cczp_n(zp);
    cc_size np = ccn_nof(bitlen);
    cc_unit r[np];

    cc_require(((result = ccn_random_bits(bitlen, r, rng)) == 0), cleanup);
    
    // We are computing output = r % q => output is in the range [0, q)
    cc_require((result = ccn_mod_ws(ws, n, output, np, r, n, cczp_prime(zp))) == 0, cleanup);

cleanup:
    return result;
}
