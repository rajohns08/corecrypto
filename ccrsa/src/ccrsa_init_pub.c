/* Copyright (c) (2011,2015,2017,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_memory.h"
#include "ccrsa_internal.h"

void ccrsa_init_pub_ws(cc_ws_t ws, ccrsa_pub_ctx_t pubk, const cc_unit *modulus, const cc_unit *e)
{
    CC_DECL_BP_WS(ws, bp);

    cc_size n = ccrsa_ctx_n(pubk);
    ccn_set(n, ccrsa_ctx_m(pubk), modulus);
    cczp_init_ws(ws, ccrsa_ctx_zm(pubk));
    ccn_set(n, ccrsa_ctx_e(pubk), e);

    CC_FREE_BP_WS(ws, bp);
}

int ccrsa_init_pub(ccrsa_pub_ctx_t pubk, const cc_unit *modulus, const cc_unit *e)
{
    cc_size n = ccrsa_ctx_n(pubk);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_INIT_PUB_WORKSPACE_N(n));
    ccrsa_init_pub_ws(ws, pubk, modulus, e);
    CC_FREE_WORKSPACE(ws);
    return CCERR_OK;
}
