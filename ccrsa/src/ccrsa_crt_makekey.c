/* Copyright (c) (2019,2020) Apple Inc. All rights reserved.
*
* corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
* is contained in the License.txt file distributed with corecrypto) and only to
* people who accept that license. IMPORTANT:  Any license rights granted to you by
* Apple Inc. (if any) are limited to internal use within your organization only on
* devices and computers you own or control, for the sole purpose of verifying the
* security characteristics and correct functioning of the Apple Software.  You may
* not, directly or indirectly, redistribute the Apple Software or any portions thereof.
*/

#include "ccn_internal.h"
#include "cczp_internal.h"
#include "ccrsa_internal.h"
#include "cc_macros.h"

int ccrsa_crt_makekey_ws(cc_ws_t ws, ccrsa_full_ctx_t fk)
{
    int status;

    cczp_t zm = ccrsa_ctx_zm(fk);
    cczp_t zp = ccrsa_ctx_private_zp(fk);
    cczp_t zq = ccrsa_ctx_private_zq(fk);

    cc_size n = cczp_n(zm);
    cc_size pn = cczp_n(zp);
    cc_size qn = cczp_n(zq);

    CC_DECL_BP_WS(ws, bp);
    // Need two more units for zlambda in case zp->n = zq->n + 1 but
    // zm->n = zq->n * 2. In that case ccn_lcm() needs a 2n result,
    // which is zp->n * 2 = zm->n + 2, even if the lcm won't be that big.
    cc_unit *zlambda = CC_ALLOC_WS(ws, n + 2);
    cc_unit *pm1 = CC_ALLOC_WS(ws, n);
    cc_unit *qm1 = CC_ALLOC_WS(ws, n);

    /* modulus = p * q */
    /* p might be one whole unit longer than q, but the public modulus will
     never be more than pbits + qbits bits, and qbits is at most two bits less
     than pbits. */
    assert(ccn_cmpn(ccn_n(pn, cczp_prime(zp)), cczp_prime(zp),
                    ccn_n(qn, cczp_prime(zq)), cczp_prime(zq)) > 0);

    /* Compute m = p * q. We can't use ccn_mul() when cczp_n(zp) > cczp_n(zq)
       so just emulate it here. */
    ccn_clear(n, CCZP_PRIME(zm));
    for (size_t i = 0; i < qn; i++) {
        CCZP_PRIME(zm)[pn + i] = ccn_addmul1(pn, CCZP_PRIME(zm) + i, cczp_prime(zp), cczp_prime(zq)[i]);
    }

    cczp_init_ws(ws, zm);

    // Compute p-1, q-1.
    ccn_set(pn, pm1, cczp_prime(zp));
    ccn_setn(pn, qm1, qn, cczp_prime(zq));

    // Since p, q are odd we just clear bit 0 to subtract 1.
    cc_assert((pm1[0] & 1) && (qm1[0] & 1));
    pm1[0] &= ~CC_UNIT_C(1);
    qm1[0] &= ~CC_UNIT_C(1);

    // lambda = lcm(p-1, q-1)
    ccn_clear(n, zlambda);
    ccn_lcm_ws(ws, pn, zlambda, pm1, qm1);

    const cc_unit *e = ccrsa_ctx_e(fk);
    cc_unit *d = ccrsa_ctx_d(fk);

    // Compute d = e^(-1) (mod lcm(p-1, q-1)) (X9.31's "lambda function")
    cc_require((status = ccn_invmod_ws(ws, n, d, ccn_n(n, e), e, zlambda)) == 0, errOut);

    /* dp = d mod (p-1) */
    cc_require((status = ccn_mod_ws(ws, pn, ccrsa_ctx_private_dp(fk), n, d, pn, pm1)) == 0, errOut);

    /* dq = d mod (q-1) */
    cc_require((status = ccn_mod_ws(ws, pn, ccrsa_ctx_private_dq(fk), n, d, pn, qm1)) == 0, errOut);

    /* qInv = q^(-1) mod p. This requires q to be at least as long as p with
       proper zero padding. Obviously qInv can be as big as p too. */
    ccn_setn(pn, ccrsa_ctx_private_qinv(fk), qn, cczp_prime(zq));
    cc_require_action(cczp_inv_ws(ws, zp, ccrsa_ctx_private_qinv(fk), ccrsa_ctx_private_qinv(fk)) == 0, errOut,
        status = CCRSA_KEYGEN_MODULUS_CRT_INV_ERROR);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return status;
}

int ccrsa_crt_makekey(ccrsa_full_ctx_t fk)
{
    cc_size n = ccrsa_ctx_n(fk);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_CRT_MAKEKEY_WORKSPACE_N(n));
    int rv = ccrsa_crt_makekey_ws(ws, fk);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
