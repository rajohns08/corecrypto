/* Copyright (c) (2010,2011,2012,2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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
#include "cczp_internal.h"
#include "ccn_internal.h"

#include <corecrypto/cc_macros.h>
#include "cc_debug.h"
/*
 * power/mod using Chinese Remainder Theorem.
 *
 * result becomes base^d (mod m).
 *
 *
 * p, q such that m = p*q
 * reciprocals of p, q
 * dp = d mod (p-1)
 * dq = d mod (q-1)
 * qinv = q^(-1) mod p
 *
 */

#define SCA_MASK_BITSIZE 32
#define SCA_MASK_MASK  (((((cc_unit)1)<<(SCA_MASK_BITSIZE-1))-1) <<1 | 1)    /* required to be a power of 2 */
#define SCA_MASK_N ccn_nof(SCA_MASK_BITSIZE)
#define NB_MASK 6*SCA_MASK_N   // p, dp, mp, q, dq, mq

#define CCRSA_CRT_POWER_BLINDED_WORKSPACE_N(nm, nu)                                                 \
    (5 * nu + NB_MASK + CC_MAX_EVAL(CCZP_MM_POWER_WORKSPACE_N(nu, CCZP_POWER_SSMA_WORKSPACE_N(nu)), \
                          CC_MAX_EVAL(CCN_DIV_USE_RECIP_WORKSPACE_SIZE(nm + 1, nu),                 \
                                      CCZP_MUL_WORKSPACE_N(nu))                                     \
                        )                                                                           \
    )
static int ccrsa_crt_power_blinded( struct ccrng_state *blinding_rng,
                           ccrsa_full_ctx_t fk,
                           cc_unit *r,            /* OUTPUT */
                           const cc_unit *x      /* base (plaintext/ciphertext) */
                           )
{

    cczp_t zm=ccrsa_ctx_zm(fk);
    cczp_t zp=ccrsa_ctx_private_zp(fk); /* zp * zq = public modulus */
    cczp_t zq=ccrsa_ctx_private_zq(fk);
    const cc_unit *dp=ccrsa_ctx_private_dp(fk); /* d mod (p-1)   cczp_n(zp) sized */
    const cc_unit *dq=ccrsa_ctx_private_dq(fk); /* d mod (q-1)   cczp_n(zq) sized */
    const cc_unit *qinv=ccrsa_ctx_private_qinv(fk); /* q^(-1) mod p  cczp_n(zp) sized */
    cc_size nm=cczp_n(zm);
    cc_size nq=cczp_n(zq);
    cc_size np=cczp_n(zp);
    cc_size nu=np+SCA_MASK_N; // np >=nq, checked below
    int status=CCRSA_PRIVATE_OP_ERROR;
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_CRT_POWER_BLINDED_WORKSPACE_N(nm, nu));
    CC_DECL_BP_WS(ws, bp);
    cc_unit *tmp =  CC_ALLOC_WS(ws, 2*nu);
    cc_unit *tmp2 = CC_ALLOC_WS(ws, nu);
    cc_unit *sp =   CC_ALLOC_WS(ws, nu);
    cc_unit *sq =   CC_ALLOC_WS(ws, nu);
    cc_unit *rnd =  CC_ALLOC_WS(ws, NB_MASK);

    // Allocate a ZP which will be used to extend p and q for randomization
    cczp_decl_n(nu,zu_masked);

    // Sanity check on supported key length
    cc_require_action((cczp_bitlen(zp) >= cczp_bitlen(zq)) && (np>=nq),
                      errOut,status=CCRSA_KEY_ERROR);      // No supported here.
    cc_require_action(blinding_rng!=NULL,
                      errOut,status=CCRSA_INVALID_CONFIG); // No supported here.

    // Random for masking
    cc_assert(SCA_MASK_N==1); // because we use mul1 for masks
    cc_require((status=ccn_random(NB_MASK, rnd, blinding_rng))==0,errOut);

    /*------------ Step 1 ------------------*/
    /*
        Modulus blinding:   q_star = rnd[0]*q
        Exponent blinding: dq_star = dq + rnd[1]*(q-1)
        Base blinding:     mq_star = (x + rnd[2]*q) Mod q_star
     */

    /* q_star:=q*cstq; */
    CCZP_N(zu_masked)=nq+SCA_MASK_N;
    *(CCZP_PRIME(zu_masked)+nq)=ccn_mul1(nq,CCZP_PRIME(zu_masked),cczp_prime(zq),SCA_MASK_MASK & (rnd[0] | 1)); /* q_star:=q*cstq; */
    cczp_init_ws(ws, zu_masked);

    /* mq = m + k2.q mod q_star */
    ccn_setn(cczp_n(zm)+1,tmp,nq,cczp_prime(zq)); // q
    ccn_set_bit(tmp,0,0);  // q - 1
    ccn_set(nq,tmp2,dq);   // dq
    tmp2[nq]=ccn_addmul1(nq,tmp2,tmp,SCA_MASK_MASK & rnd[1]);          /* tmp2 = dq + rnd*(q-1) */
    tmp[nq]=ccn_mul1(nq,tmp,cczp_prime(zq),SCA_MASK_MASK & rnd[2]);    /* tmp = mask0*q */
    ccn_addn(cczp_n(zm)+1,tmp,tmp,cczp_n(zm),x);       /* tmp = x + mask*q */
    cczp_modn_ws(ws, zu_masked, tmp, cczp_n(zm)+1, tmp);      /* tmp = x + mask*q mod q_star */
    /* Ignoring cczp_power_ssma_ws error code; arguments guaranteed to be valid. */
    status=cczp_mm_power_ssma_ws(ws, zu_masked, sq, tmp, tmp2); /* sq = (tmp ^ dq) mod q_star */
    cc_assert(status==0);(void) status; // Public key validation will follow, we don't want to early abort here.

    /*
        Modulus blinding:   p_star = rnd[3]*p
        Exponent blinding: dp_star = dp + rnd[4]*(p-1)
        Base blinding:     mp_star = (x + rnd[5]*p) Mod p_star
    */

    /* p_star:=p*cstp; */
    CCZP_N(zu_masked)=np+SCA_MASK_N;
    *(CCZP_PRIME(zu_masked)+np)=ccn_mul1(np,CCZP_PRIME(zu_masked),cczp_prime(zp),SCA_MASK_MASK & (rnd[3] | 1)); /* p_star:=p*cstp; */
    cczp_init_ws(ws, zu_masked);

    /* mp = m + k1.p mod p_star */
    ccn_setn(cczp_n(zm)+1,tmp,np,cczp_prime(zp)); // p
    ccn_set_bit(tmp,0,0);  // p - 1
    ccn_set(np,tmp2,dp);   // dp
    tmp2[np]=ccn_addmul1(np,tmp2,tmp,SCA_MASK_MASK & rnd[4]);          /* tmp2 = dp + rnd*(p-1) */
    tmp[np]=ccn_mul1(np, tmp, cczp_prime(zp), SCA_MASK_MASK & rnd[5]); /* tmp = mask*p */
    ccn_addn(cczp_n(zm)+1,tmp, tmp,cczp_n(zm), x);     /* tmp = x + mask*p */
    cczp_modn_ws(ws, zu_masked, tmp, cczp_n(zm)+1, tmp);      /* tmp = x + mask*p mod p_star */
    /* Ignoring cczp_power_ssma_ws error code; arguments guaranteed to be valid. */
    status=cczp_mm_power_ssma_ws(ws, zu_masked, sp, tmp, tmp2); /* sp = (tmp ^ dp) mod p_star */
    cc_assert(status==0);(void) status; // Public key validation will follow, we don't want to early abort here.

    /*------------ Step 2 ------------------\n
     Garner recombination (requires 2*p>q, which is verified if |p|==|q|)
        with 0 < cstp,cstq < SCA_MASK
        pstar*(2*SCA_MASK) > q*SCA_MASK >= qstar

        Values remain randomized as long as possible to protect all the operations
        tmp = (sp+(2*SCA_MASK)*p_star)-sq mod p_star
        tmp = tmp * qInv mod p_star
        tmp = tmp * q
        tmp = tmp + sq
        r = tmp mod n     Finally removes the randomization
    */
    ccn_setn(nu+2, tmp, nu, cczp_prime(zu_masked));
    ccn_shift_left_multi(nu+2, tmp, tmp, SCA_MASK_BITSIZE+1);   // 2*SCA_MASK_MASK*cstp*p
    ccn_addn(nu+2,tmp,tmp,nu,sp);                               // 2*SCA_MASK_MASK*cstp*p + sp
    cc_unit c = ccn_subn(nu+2, tmp, tmp, nq+SCA_MASK_N, sq);    // tmp: t = (sp + (2*SCA_MASK_MASK)*p_star) - sq
    cc_assert(c==0);(void)c;                    // Sanity check that there is no borrow
    cczp_modn_ws(ws, zu_masked, sp, nu+2, tmp); // sp: = t mod p_star
    ccn_setn(nu, tmp, np, qinv);                // handle nq < np
    cczp_mul_ws(ws, zu_masked, sp, sp, tmp);    // sp: t = (sp * qinv) mod p_star
    ccn_setn(nu, tmp2, nq, cczp_prime(zq));     // tmp2: q

    ccn_mul_ws(ws,nu, tmp, tmp2, sp);             // tmp: t = t * q
    ccn_addn(2*nu, tmp, tmp, nq+SCA_MASK_N, sq);  // tmp: t = t + sq
    ws->start=tmp2; // reclaim space for final reduction
    cczp_modn_ws(ws, zm, r, 2*nu, tmp);           // r: t mod m
    status=0;
errOut:
    CC_FREE_BP_WS(ws, bp);
    sp=NULL; /* Analyser warning */
    // Clear working buffers
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    cczp_clear_n(nu,zu_masked);
    return status;
}

int ccrsa_priv_crypt_blinded(struct ccrng_state *blinding_rng, ccrsa_full_ctx_t fk, cc_unit *out, const cc_unit *in) {
    int status=CCRSA_PRIVATE_OP_ERROR;
    int status_compare=CCRSA_PRIVATE_OP_ERROR;
    cc_unit cond;
    cc_unit tmp_in[ccrsa_ctx_n(fk)]; //vla
    ccn_set(ccrsa_ctx_n(fk),tmp_in,in);

    // Reject dp=1 or dq=1 as a valid key because e=1 is not acceptable.
    // by definition dp*e=1 mod (p-1) and dq*e=1 mod (p-1)
    if ((ccn_bitlen(cczp_n(ccrsa_ctx_private_zp(fk)), ccrsa_ctx_private_dp(fk))<=1)
        || (ccn_bitlen(cczp_n(ccrsa_ctx_private_zq(fk)), ccrsa_ctx_private_dq(fk))<=1)
        || (ccn_bitlen(ccrsa_ctx_n(fk),ccrsa_ctx_e(fk))<=1)
        ) {
        return CCRSA_KEY_ERROR;
    }
    if (ccn_cmp(ccrsa_ctx_n(fk),tmp_in,ccrsa_ctx_m(fk))>=0) {
        return CCRSA_INVALID_INPUT; // x >= m is not a valid input
    }

    // Proceed
    status = ccrsa_crt_power_blinded(blinding_rng, fk, out, in);

    // Verify that the computation is correct
    {
        int rc;
        cc_unit tmp[ccrsa_ctx_n(fk)];//vla
        /* Ignoring cczp_power_fast error code; arguments guaranteed to be valid. */
        rc=cczp_mm_power_fast(ccrsa_ctx_zm(fk), tmp, out, ccrsa_ctx_e(fk));
        cc_assert(rc==0); // Sanity check
        rc|=cc_cmp_safe(ccn_sizeof_n(ccrsa_ctx_n(fk)),tmp,tmp_in);

        // Process comparison return value
        CC_MUXU(status_compare,rc,CCRSA_PRIVATE_OP_ERROR,rc);
    }

    // Process return value
    CC_HEAVISIDE_STEP(cond,status); // cond=(status==0)?0:1;
    CC_MUXU(status,cond,status,status_compare);

    // Clear output on error
    cc_memset(tmp_in, 0xAA, ccn_sizeof_n(ccrsa_ctx_n(fk)));
    CC_HEAVISIDE_STEP(cond, status); // cond=(status==0)?0:1;
    ccn_mux(ccrsa_ctx_n(fk), cond, out, tmp_in, out);
    return status;
}
