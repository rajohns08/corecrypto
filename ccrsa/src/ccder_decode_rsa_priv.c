/* Copyright (c) (2012,2014,2015,2016,2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccrsa_priv.h>
#include <corecrypto/ccder_rsa.h>
#include "cc_macros.h"

const uint8_t *ccder_decode_rsa_priv(const ccrsa_full_ctx_t key, const uint8_t *der, const uint8_t *der_end) {
    cc_size n = ccrsa_ctx_n(key);
    cc_size pqn = n/2+1;
    cc_unit tmpP[pqn], tmpQ[pqn];
     
	cc_unit version_0[1] = {0x00};
    
    der = ccder_decode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE, &der_end, der, der_end);
    der = ccder_decode_uint(1, version_0, der, der_end);
    der = ccder_decode_uint(n, ccrsa_ctx_m(key), der, der_end);
    der = ccder_decode_uint(n, ccrsa_ctx_e(key), der, der_end);
    der = ccder_decode_uint(n, ccrsa_ctx_d(key), der, der_end);
    
    // need to determine exactly how many units are needed for P&Q before stuffing them into the key.
    if((der = ccder_decode_uint(pqn, tmpP, der, der_end)) == NULL) {goto errOut;}
    CCZP_N(ccrsa_ctx_private_zp(key)) = ccn_nof(ccn_bitlen(pqn, tmpP));
    ccn_set(cczp_n(ccrsa_ctx_private_zp(key)), CCZP_PRIME(ccrsa_ctx_private_zp(key)), tmpP);
    cc_require_action(cczp_init(ccrsa_ctx_private_zp(key))==0,errOut,der=NULL);
    
    if((der = ccder_decode_uint(pqn, tmpQ, der, der_end)) == NULL) {goto errOut;}
    CCZP_N(ccrsa_ctx_private_zq(key)) = ccn_nof(ccn_bitlen(pqn, tmpQ));
    ccn_set(cczp_n(ccrsa_ctx_private_zq(key)), CCZP_PRIME(ccrsa_ctx_private_zq(key)), tmpQ);
    cc_require_action(cczp_init(ccrsa_ctx_private_zq(key))==0,errOut,der=NULL);
    
    der = ccder_decode_uint(cczp_n(ccrsa_ctx_private_zp(key)), ccrsa_ctx_private_dp(key), der, der_end);
    der = ccder_decode_uint(cczp_n(ccrsa_ctx_private_zq(key)), ccrsa_ctx_private_dq(key), der, der_end);
    der = ccder_decode_uint(cczp_n(ccrsa_ctx_private_zp(key)), ccrsa_ctx_private_qinv(key), der, der_end);
    cc_require_action(cczp_init(ccrsa_ctx_zm(key))==0,errOut,der=NULL);
errOut:
    ccn_clear(pqn,tmpP);
    ccn_clear(pqn,tmpQ);
    return der;
}
