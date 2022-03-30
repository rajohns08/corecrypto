/* Copyright (c) (2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
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
#include <corecrypto/ccrng.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cczp.h>
#include <corecrypto/cc_macros.h>
#include "ccec_internal.h"

#define MAX_RETRY 100

/* Make a scalar k in the good range and without bias */
/* Implementation per FIPS186-4 - "Extra bits" */

/* requires at least CC_BITLEN_TO_BYTELEN(ccec_cp_order_bitlen(cp)+64) of entropy
 Compute k as k=(entropy mod (q-1) + 1) */
#define NUMBER_OF_EXTRABITS 64

#define CCEC_GENERATE_SCALAR_PKA_WORKSPACE_N(n, nk) \
    ((n) + (nk) + CCN_DIV_EUCLID_WORKSPACE_SIZE(nk, n))

int ccec_generate_scalar_pka(ccec_const_cp_t cp, size_t entropy_len,
                             const uint8_t *entropy, cc_unit *k)
{
    int retval=CCEC_GENERATE_KEY_DEFAULT_ERR;
    cczp_const_t zq = ccec_cp_zq(cp);
    cc_size n = cczp_n(zq);
    cc_size nk = ccn_nof_size(entropy_len);

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_GENERATE_SCALAR_PKA_WORKSPACE_N(n, nk));
    CC_DECL_BP_WS(ws, bp);

    cc_unit *kn = CC_ALLOC_WS(ws, nk);
    cc_unit *qm2 = CC_ALLOC_WS(ws, n);

    // Minimum size for the entropy
    cc_require_action(entropy_len>=CC_BITLEN_TO_BYTELEN(ccec_cp_order_bitlen(cp)+NUMBER_OF_EXTRABITS),
                      errOut,retval=CCEC_GENERATE_NOT_ENOUGH_ENTROPY);

    // Method is from FIPS 186-4 Extra Bits method.
    //  k = entropy mod (q-1)) + 1, where entropy is interpreted as big endian.
    cc_require((retval=ccn_read_uint(nk,kn,entropy_len,entropy))==0,errOut);

    /* Store q-2 in x */
    ccn_sub1(n,qm2,cczp_prime(zq),2);

    /* Compute r = (c mod (q-2)) + 2 via regular division to protect the entropy. */
    cc_require((retval=ccn_mod_ws(ws, n, k, nk, kn, n, qm2))==0,errOut);
    ccn_add1(n,k,k,2); // We know there is no carry happening here
    retval=0;

errOut:
    CC_FREE_BP_WS(ws, bp);
    CC_FREE_WORKSPACE(ws);
    return retval;
}
