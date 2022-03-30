/* Copyright (c) (2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
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
#include "cczp_internal.h"
#include <corecrypto/cc_macros.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/cc_memory.h>

#define SCA_MASK_BITSIZE 32
#define SCA_MASK_MSBIT (((cc_unit)1)<<(SCA_MASK_BITSIZE-1))
#define SCA_MASK_MASK  ((SCA_MASK_MSBIT-1) <<1 | 1)    /* required to be a power of 2 */
#define SCA_MASK_N ccn_nof(SCA_MASK_BITSIZE)
#define NB_MASK 3*SCA_MASK_N   // base, exponent, modulus

#define CCDH_POWER_BLINDED_WORKSPACE_N(n)                                 \
    (3 * (n) + SCA_MASK_N + CC_MAX_EVAL(CCZP_MM_INIT_WORKSPACE_N(n),      \
                              CC_MAX_EVAL(CCZP_POWER_SSMA_WORKSPACE_N(n), \
                                CC_MAX_EVAL(CCZP_TO_WORKSPACE_N(n),       \
                                            CCZP_FROM_WORKSPACE_N(n))     \
                              )                                           \
                            )                                             \
    )

int ccdh_power_blinded(struct ccrng_state *blinding_rng, ccdh_const_gp_t gp,
                       cc_unit *r, const cc_unit *s, const cc_unit *e)
{
    int status;

    // Allocate a ZP which will be used to extend p for randomization
    cc_size np=ccdh_gp_n(gp);
    cc_size nu=np+SCA_MASK_N;
    cczp_decl_n(nu,zu_masked);
    cczp_mm_decl_n(nu, zpmm);

    // (s<p) requirement enforced during public key verification, here for debug only
    cc_assert(ccn_cmp(np, s, ccdh_gp_prime(gp)) < 0);

    // Allocate working memory
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCDH_POWER_BLINDED_WORKSPACE_N(nu));
    CC_DECL_BP_WS(ws, bp);
    cc_unit *e0=CC_ALLOC_WS(ws, SCA_MASK_N);
    cc_unit *e1=CC_ALLOC_WS(ws, nu);
    cc_unit *s_star=CC_ALLOC_WS(ws, nu);
    cc_unit *tmp=CC_ALLOC_WS(ws, nu);

    // Random for masking. One call to reduce latency
    cc_unit rnd[SCA_MASK_N*NB_MASK];
    cc_require((status=ccn_random(NB_MASK, rnd, blinding_rng))==0,errOut);

    /*
     Modulus blinding:   p_star = rnd[0]*p
     Exponent blinding:  e1 = e/rnd[1], e0 = e % rnd[1]
       such that (e1*rnd[1] + e0) == e
     Base blinding:      s_star = (x + rnd[2]*p) mod p_star
     */

    /* Modulus blinding:   p_star = rnd[0]*p */
    cc_assert(SCA_MASK_N==1); // because we use mul1 for masks
    CCZP_N(zu_masked)=nu;
    rnd[0] &= SCA_MASK_MASK; // truncate as needed
    rnd[0] |= (SCA_MASK_MSBIT|1); // Odd and big
    *(CCZP_PRIME(zu_masked)+np)=ccn_mul1(np,CCZP_PRIME(zu_masked),ccdh_gp_prime(gp),rnd[0]);
    cczp_init_ws(ws, zu_masked);

    /* Exponent blinding:  e1 = e/rnd[1], e0 = e % rnd[1] */
    rnd[1] &= SCA_MASK_MASK; // truncate as needed
    rnd[1] |= SCA_MASK_MSBIT; // non zero and big
    cc_require((status=ccn_div_euclid_ws(ws, nu, e1, SCA_MASK_N, e0, np, e, SCA_MASK_N, &rnd[1]))==0,errOut);

    /* Base blinding:      s_star = (x + rnd[2]*p) mod p_star */
    ccn_set(np,tmp,s);
    rnd[2] &= SCA_MASK_MASK; // truncate as needed
    tmp[np]=ccn_addmul1(np,tmp,ccdh_gp_prime(gp), rnd[2]);    /* tmp = rnd[2] * p */
    cc_require((status=cczp_modn_ws(ws, zu_masked,s_star,nu,tmp))==0,errOut);

#if 0 //CORECRYPTO_DEBUG
    ccn_lprint(np,"p     ", ccdh_gp_prime(gp));
    ccn_lprint(nu,"p_star", CCZP_PRIME(zu_masked));
    ccn_lprint(np,"e     ", e);
    ccn_lprint(SCA_MASK_N,"rnd[0]   ", &rnd[0]);
    ccn_lprint(SCA_MASK_N,"rnd[1]   ", &rnd[1]);
    ccn_lprint(SCA_MASK_N,"rnd[2]   ", &rnd[2]);
    ccn_lprint(np,"s     ", s);
    ccn_lprint(nu,"s_star", s_star);

    ccn_mul1(nu,tmp,e1,rnd[1]);
    ccn_add1(nu,tmp,tmp,*e0);
    cc_assert(ccn_cmp(np,tmp,e)==0);
#endif

    cczp_mm_init_ws(ws, zpmm, nu, cczp_prime(zu_masked));
    cczp_to_ws(ws, zpmm, s_star, s_star);

    /* Actual computations */
    cc_require((status=cczp_power_ssma_ws(ws, zpmm, tmp, s_star, e1))==0,errOut);   /* s_star^e1 */
    ccn_setn(nu,e1,SCA_MASK_N,&rnd[1]);
    cc_require((status=cczp_power_ssma_ws(ws, zpmm, tmp, tmp, e1))==0,errOut);   /* (s_star^e1)^rnd[1] */
    ccn_setn(nu,e1,SCA_MASK_N,e0);
    cc_require((status=cczp_power_ssma_ws(ws, zpmm, s_star, s_star, e1))==0,errOut);/* s_star^e0 */
    cczp_mul_ws(ws, zpmm, s_star, s_star, tmp); /* (s_star^e1)^rnd[1] * s_star^e0 = s_star^e */

    cczp_from_ws(ws, zpmm, s_star, s_star);
    status=cczp_modn_ws(ws,ccdh_gp_zp(gp),r,nu,s_star);

errOut:
    CC_FREE_BP_WS(ws, bp);
    // Clear working buffers
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    cczp_mm_clear_n(nu, zpmm);
    cczp_clear_n(nu,zu_masked);
    return status;
}
