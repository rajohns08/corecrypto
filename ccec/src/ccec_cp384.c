/* Copyright (c) (2010,2011,2012,2014,2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
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
#include "ccec_internal.h"
#include "ccn_internal.h"

// 2^768 mod Q.
static const cc_unit RR_MOD_Q[CCN384_N] = {
    CCN384_C(0c,84,ee,01,2b,39,bf,21,3f,b0,5b,7a,28,26,68,95,d4,0d,49,17,4a,ab,1c,c5,bc,3e,48,3a,fc,b8,29,47,ff,3d,81,e5,df,1a,a4,19,2d,31,9b,24,19,b4,09,a9)
};

// 2^384 mod Q.
static const cc_unit R1_MOD_Q[CCN384_N] = {
    CCN384_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,38,9c,b2,7e,0b,c8,d2,20,a7,e5,f2,4d,b7,4f,58,85,13,13,e6,95,33,3a,d6,8d)
};

// -((q % 2^w)^-1 % 2^w)
static const cc_unit Q0_INV = (cc_unit)0x6ed46089e88fdc45;

// q - 2 (mod 2^192)
static const cc_unit Q_EXP[CCN384_N] = {
    CCN384_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,c7,63,4d,81,f4,37,2d,df,58,1a,0d,b2,48,b0,a7,7a,ec,ec,19,6a,cc,c5,29,71)
};

#define A(i) ccn32_32_parse(a,i)
#define Anil ccn32_32_null

static void ccn_mod_384(CC_UNUSED cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *a) {
    cc_assert(cczp_n(zp) == CCN384_N);
    cc_unit s1[CCN384_N] = { ccn384_32(  Anil,  Anil,  Anil,  Anil,  Anil, A(23), A(22), A(21),  Anil,  Anil,  Anil,  Anil) };
    cc_unit s3[CCN384_N] = { ccn384_32( A(20), A(19), A(18), A(17), A(16), A(15), A(14), A(13), A(12), A(23), A(22), A(21)) };
    cc_unit s4[CCN384_N] = { ccn384_32( A(19), A(18), A(17), A(16), A(15), A(14), A(13), A(12), A(20),  Anil, A(23),  Anil) };
    cc_unit s5[CCN384_N] = { ccn384_32(  Anil,  Anil,  Anil,  Anil, A(23), A(22), A(21), A(20),  Anil,  Anil,  Anil,  Anil) };
    cc_unit s6[CCN384_N] = { ccn384_32(  Anil,  Anil,  Anil,  Anil,  Anil,  Anil, A(23), A(22), A(21),  Anil,  Anil, A(20)) };
    cc_unit d1[CCN384_N] = { ccn384_32( A(22), A(21), A(20), A(19), A(18), A(17), A(16), A(15), A(14), A(13), A(12), A(23)) };
    cc_unit d2[CCN384_N] = { ccn384_32(  Anil,  Anil,  Anil,  Anil,  Anil,  Anil,  Anil, A(23), A(22), A(21), A(20),  Anil) };
    cc_unit d3[CCN384_N] = { ccn384_32(  Anil,  Anil,  Anil,  Anil,  Anil,  Anil,  Anil, A(23), A(23),  Anil,  Anil,  Anil) };

    cc_unit carry;
    ccn_add(ccn_nof(160)+1, d2, d2, d3);  // smaller size and no carry possible
    ccn_add(ccn_nof(224)+1, s1, s1, s1);  // smaller size and no carry possible, alternatively cc_shiftl(s1, 1) but add is currently faster.
    ccn_add(ccn_nof(256)+1, s5, s5, s1);  // smaller size and no carry possible
    ccn_add(ccn_nof(256)+1, s5, s5, s6);  // smaller size and no carry possible

    carry = ccn_add(CCN384_N, r, a, &a[CCN384_N]);
    carry += ccn_add(CCN384_N, r, r, s3);
    carry += ccn_add(CCN384_N, r, r, s4);
    carry += ccn_add(CCN384_N, r, r, s5);
    carry -= ccn_sub(CCN384_N, d1, cczp_prime(zp), d1);
    carry += ccn_add(CCN384_N, r, r, d1);
    carry -= ccn_sub(CCN384_N, r, r, d2);

    // Prepare to reduce once more.
    cc_unit t[CCN384_N] = { ccn384_32( Anil, Anil, Anil, Anil, Anil, Anil, Anil, carry, carry, Anil, Anil, carry) };
    cc_unit u[CCN384_N] = { ccn384_32( Anil, Anil, Anil, Anil, Anil, Anil, Anil, Anil, Anil, Anil, carry, Anil) };

    // Reduce r mod p384.
    (void)ccn_sub(CCN384_N, t, t, u);
    carry = ccn_add(CCN384_N, t, t, r);

    // One extra reduction (subtract p).
    cc_unit k = ccn_sub(CCN384_N, r, t, cczp_prime(zp));

    // Keep the extra reduction if carry=1 or k=0.
    ccn_mux(CCN384_N, carry | (k ^ 1), r, r, t);

    /* Sanity for debug */
    cc_assert(ccn_cmp(CCN384_N, r, cczp_prime(zp)) < 0);
}

/*
 * p384 - 2 = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffd
 *
 * A straightforward square-multiply implementation will need 384S+318M.
 * cczp_power_fast() with a fixed 2-bit window needs roughly 384S+192M.
 *
 * By dividing the exponent into the windows
 *   0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff, 0xfffffffe, 0xffffffff, 0x0000000000000000fffffffd
 * we can get away with only 383S+19M.
 */
static int ccn_inv_384(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CC_DECL_BP_WS(ws, bp);
    cc_unit *t0 = CC_ALLOC_WS(ws, CCN384_N);
    cc_unit *t1 = CC_ALLOC_WS(ws, CCN384_N);
    cc_unit *t2 = CC_ALLOC_WS(ws, CCN384_N);
    int result = CCZP_INV_NO_INVERSE;

    // t2 := x^2
    cczp_sqr_ws(ws, zp, t2, x);

    // t1 := x^3
    cczp_mul_ws(ws, zp, t1, t2, x);

    // t0 := x^0xd
    cczp_sqr_times_ws(ws, zp, t1, t1, 2);
    cczp_mul_ws(ws, zp, t0, t1, x);

    // t1 := x^0xf
    cczp_mul_ws(ws, zp, t1, t0, t2);

    // t0 := x^0xfd
    cczp_sqr_times_ws(ws, zp, t1, t1, 4);
    cczp_mul_ws(ws, zp, t0, t0, t1);

    // t1 := x^0xff
    cczp_mul_ws(ws, zp, t1, t0, t2);

    // t0 := x^0xfffd
    cczp_sqr_times_ws(ws, zp, t1, t1, 8);
    cczp_mul_ws(ws, zp, t0, t0, t1);

    // t1 := x^0xffff
    cczp_mul_ws(ws, zp, t1, t0, t2);

    // t0 := x^0xfffffffd
    cczp_sqr_times_ws(ws, zp, t1, t1, 16);
    cczp_mul_ws(ws, zp, t0, t0, t1);

    // t1 := x^0xffffffff
    cczp_mul_ws(ws, zp, t1, t0, t2);

    // t2 := x^0xffffffffffffffff
    cczp_sqr_times_ws(ws, zp, t2, t1, 32);
    cczp_mul_ws(ws, zp, t2, t2, t1);

    // t2 := x^0xffffffffffffffffffffffff
    cczp_sqr_times_ws(ws, zp, t2, t2, 32);
    cczp_mul_ws(ws, zp, t2, t2, t1);

    // t1 := x^0xffffffffffffffffffffffffffffffffffffffffffffffff
    cczp_sqr_times_ws(ws, zp, t1, t2, 96);
    cczp_mul_ws(ws, zp, t1, t1, t2);

    // t2 := 0xfffffffe
    cczp_mul_ws(ws, zp, t2, t0, x);

    // t1 := x^0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    cczp_sqr_times_ws(ws, zp, t1, t1, 32);
    cczp_mul_ws(ws, zp, t1, t1, t2);
    cczp_mul_ws(ws, zp, t1, t1, x);

    // t1 := x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe
    cczp_sqr_times_ws(ws, zp, t1, t1, 32);
    cczp_mul_ws(ws, zp, t1, t1, t2);

    // t2 := 0xffffffff
    cczp_mul_ws(ws, zp, t2, t2, x);

    // t1 := x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff
    cczp_sqr_times_ws(ws, zp, t1, t1, 32);
    cczp_mul_ws(ws, zp, t1, t1, t2);

    // t1 := x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffd
    cczp_sqr_times_ws(ws, zp, t1, t1, 96);
    cczp_mul_ws(ws, zp, t1, t1, t0);

    // r*x = 1 (mod p)?
    cczp_mul_ws(ws, zp, t0, t1, x);
    if (!cczp_is_one_ws(ws, zp, t0)) {
        goto errOut;
    }

    ccn_set(CCN384_N, r, t1);
    result = CCERR_OK;

errOut:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

static cczp_funcs_decl_mod_inv(cczp_p384_funcs, ccn_mod_384, ccn_inv_384);

CC_NONNULL_ALL
static int ccn_q384_inv(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CC_DECL_BP_WS(ws, bp);
    cc_unit *t0 = CC_ALLOC_WS(ws, CCN384_N);
    cc_unit *t1 = CC_ALLOC_WS(ws, CCN384_N);
    cc_unit *t2 = CC_ALLOC_WS(ws, CCN384_N);
    int result = CCZP_INV_NO_INVERSE;

    cczp_t zpmm = (cczp_t)CC_ALLOC_WS(ws, cczp_mm_nof_n(CCN384_N));
    cczp_mm_init_precomp(zpmm, CCN384_N, cczp_prime(zp), Q0_INV, R1_MOD_Q, RR_MOD_Q);
    cczp_to_ws(ws, zpmm, t2, x);

    // t0 := x^2
    cczp_sqr_ws(ws, zpmm, t0, t2);

    // t0 := x^3
    cczp_mul_ws(ws, zpmm, t0, t0, t2);

    // t0 := x^0xf
    cczp_sqr_times_ws(ws, zpmm, t1, t0, 2);
    cczp_mul_ws(ws, zpmm, t0, t0, t1);

    // t0 := x^0xff
    cczp_sqr_times_ws(ws, zpmm, t1, t0, 4);
    cczp_mul_ws(ws, zpmm, t0, t0, t1);

    // t0 := x^0xffff
    cczp_sqr_times_ws(ws, zpmm, t1, t0, 8);
    cczp_mul_ws(ws, zpmm, t0, t0, t1);

    // t0 := x^0xffffffff
    cczp_sqr_times_ws(ws, zpmm, t1, t0, 16);
    cczp_mul_ws(ws, zpmm, t0, t0, t1);

    // t0 := x^0xffffffffffffffff
    cczp_sqr_times_ws(ws, zpmm, t1, t0, 32);
    cczp_mul_ws(ws, zpmm, t0, t0, t1);

    // t1 := x^0xffffffffffffffffffffffffffffffff
    cczp_sqr_times_ws(ws, zpmm, t1, t0, 64);
    cczp_mul_ws(ws, zpmm, t1, t1, t0);

    // t0 := x^0xffffffffffffffffffffffffffffffffffffffffffffffff
    cczp_sqr_times_ws(ws, zpmm, t1, t1, 64);
    cczp_mul_ws(ws, zpmm, t0, t0, t1);

    // t0 := x^0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973
    for (size_t bit = 191; bit < 192; --bit) {
        cczp_sqr_ws(ws, zpmm, t0, t0);

        if (ccn_bit(Q_EXP, bit)) {
            cczp_mul_ws(ws, zpmm, t0, t0, t2);
        }
    }

    // r*x = 1 (mod q)?
    cczp_mul_ws(ws, zpmm, t1, t0, t2);
    if (!cczp_is_one_ws(ws, zpmm, t1)) {
        goto errOut;
    }

    cczp_from_ws(ws, zpmm, r, t0);
    result = CCERR_OK;

errOut:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

static cczp_funcs_decl_inv(cczp_q384_funcs, ccn_q384_inv);

static const ccec_cp_decl(384) ccec_cp384 =
{
    .hp = {
        .n = CCN384_N,
        .bitlen = 384,
        .funcs = &cczp_p384_funcs
    },
    .p = {
        CCN384_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,fe,ff,ff,ff,ff,00,00,00,00,00,00,00,00,ff,ff,ff,ff)
    },
    .pr = {
        CCN384_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,01,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,00,00,00,01),1
    },
    .b = {
        CCN384_C(b3,31,2f,a7,e2,3e,e7,e4,98,8e,05,6b,e3,f8,2d,19,18,1d,9c,6e,fe,81,41,12,03,14,08,8f,50,13,87,5a,c6,56,39,8d,8a,2e,d1,9d,2a,85,c8,ed,d3,ec,2a,ef)
    },
    .gx = {
        CCN384_C(aa,87,ca,22,be,8b,05,37,8e,b1,c7,1e,f3,20,ad,74,6e,1d,3b,62,8b,a7,9b,98,59,f7,41,e0,82,54,2a,38,55,02,f2,5d,bf,55,29,6c,3a,54,5e,38,72,76,0a,b7)
    },
    .gy = {
        CCN384_C(36,17,de,4a,96,26,2c,6f,5d,9e,98,bf,92,92,dc,29,f8,f4,1d,bd,28,9a,14,7c,e9,da,31,13,b5,f0,b8,c0,0a,60,b1,ce,1d,7e,81,9d,7a,43,1d,7c,90,ea,0e,5f)
    },
    .hq = {
        .n = CCN384_N,
        .bitlen = 384,
        .funcs = &cczp_q384_funcs
    },
    .q = {
        CCN384_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,c7,63,4d,81,f4,37,2d,df,58,1a,0d,b2,48,b0,a7,7a,ec,ec,19,6a,cc,c5,29,73)
    },
    .qr = {
        CCN384_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,38,9c,b2,7e,0b,c8,d2,20,a7,e5,f2,4d,b7,4f,58,85,13,13,e6,95,33,3a,d6,8d),1
    }
};

ccec_const_cp_t ccec_cp_384(void)
{
    return (ccec_const_cp_t)(const struct cczp *)(const cc_unit*)&ccec_cp384;
}
